// Simulation state layer: manages several independent "devices" in one browser
// tab. Every member has its OWN DeviceIdentity + GroupSession + localStorage
// keystore — there is deliberately no shared secret between the cards.

import { DeviceIdentity, type SerializedIdentity } from "../crypto/identity.js";
import { GroupSession, newGroupId } from "../crypto/groupSession.js";
import type { DecryptedMessage } from "../crypto/groupSession.js";
import type { GroupCommit, GroupEvent, MemberPublic, StoredEvent } from "../crypto/protocol.js";
import { RelayClient } from "./relayClient.js";

const LS_MEMBERS = "e2ee-demo:members";
const LS_GROUP = "e2ee-demo:groupId";

export interface ChatLine {
  eventId?: string;
  epoch: number;
  senderId: string;
  generation?: number;
  text: string;
  kind: "plain" | "blocked" | "system";
  detail?: string;
  incoming: boolean;
}

export class MemberSim {
  identity: DeviceIdentity;
  session: GroupSession;
  lines: ChatLine[] = [];

  constructor(identity: DeviceIdentity) {
    this.identity = identity;
    this.session = new GroupSession(identity);
  }

  get id(): string {
    return this.identity.id;
  }
  get name(): string {
    return this.identity.displayName;
  }
}

export class Simulation {
  members: MemberSim[] = [];
  groupId: string | null = null;
  /** raw server log, shared reference data (the "attacker" also reads this) */
  serverLog: StoredEvent[] = [];
  readonly relay = new RelayClient();
  private changeListeners = new Set<() => void>();

  onChange(fn: () => void): () => void {
    this.changeListeners.add(fn);
    return () => this.changeListeners.delete(fn);
  }
  private emit(): void {
    this.changeListeners.forEach((fn) => fn());
  }

  // ------------------------------------------------------------ persistence

  private loadKeystores(): SerializedIdentity[] {
    try {
      return JSON.parse(localStorage.getItem(LS_MEMBERS) ?? "[]") as SerializedIdentity[];
    } catch {
      return [];
    }
  }
  private saveKeystores(): void {
    Promise.all(this.members.map((m) => m.identity.serialize())).then((all) =>
      localStorage.setItem(LS_MEMBERS, JSON.stringify(all)),
    );
  }

  async init(): Promise<void> {
    const stored = this.loadKeystores();
    if (stored.length > 0) {
      for (const data of stored) {
        const id = await DeviceIdentity.restore(data);
        this.members.push(new MemberSim(id));
      }
      this.groupId = localStorage.getItem(LS_GROUP);
      if (this.groupId) {
        this.serverLog = await this.relay.fetchEvents(this.groupId);
        await this.catchUpAll();
      }
    }
  }

  async addMember(displayName: string): Promise<MemberSim> {
    const identity = await DeviceIdentity.create(displayName);
    const sim = new MemberSim(identity);
    this.members.push(sim);
    this.saveKeystores();
    this.emit();
    return sim;
  }

  /** Replace a member's device with brand new keypairs (post-compromise recovery). */
  async rotateDevice(sim: MemberSim, newName?: string): Promise<MemberPublic> {
    const identity = await DeviceIdentity.create(newName ?? `${sim.name} (new device)`);
    sim.identity = identity;
    sim.session = new GroupSession(identity);
    sim.lines.push({
      epoch: -1,
      senderId: sim.id,
      text: `🔑 Device rotated: new identity ${identity.id.slice(0, 8)}… (old keypair destroyed)`,
      kind: "system",
      incoming: false,
    });
    this.saveKeystores();
    this.emit();
    return identity.publicMember();
  }

  memberName(id: string): string {
    return this.members.find((m) => m.id === id)?.name ?? id.slice(0, 8);
  }

  // ------------------------------------------------------------ group ops

  async createGroup(creator: MemberSim, memberSims: MemberSim[]): Promise<void> {
    const groupId = await newGroupId();
    const publics = await Promise.all(memberSims.map((m) => m.identity.publicMember()));
    const commit = await creator.session.createGroup(groupId, publics);
    const stored = await this.relay.postEvent(groupId, commit);
    this.groupId = groupId;
    localStorage.setItem(LS_GROUP, groupId);
    this.serverLog.push(stored);
    await this.distribute(stored);
    this.emit();
  }

  async commitRoster(admin: MemberSim, next: MemberPublic[], reason: "add" | "remove" | "rotate"): Promise<void> {
    if (!this.groupId) throw new Error("no group");
    const commit: GroupCommit = await admin.session.updateRoster(next, reason);
    const stored = await this.relay.postEvent(this.groupId, commit);
    this.serverLog.push(stored);
    await this.distribute(stored);
    this.emit();
  }

  async addMembers(admin: MemberSim, newcomers: MemberSim[]): Promise<void> {
    const next = await Promise.all(
      [...this.currentRosterSims(), ...newcomers].map((m) => m.identity.publicMember()),
    );
    await this.commitRoster(admin, next, "add");
  }

  async removeMembers(admin: MemberSim, victims: MemberSim[]): Promise<void> {
    const victimIds = new Set(victims.map((v) => v.id));
    const survivors = this.currentRosterSims().filter((m) => !victimIds.has(m.id));
    const next = await Promise.all(survivors.map((m) => m.identity.publicMember()));
    await this.commitRoster(admin, next, "remove");
  }

  /** Publish a rotate commit that swaps in new device key material. */
  async publishRotation(admin: MemberSim, replacements: Map<string, MemberPublic>): Promise<void> {
    const next = this.currentRosterSims().map((m) => replacements.get(m.id) ?? m.identity.publicMember());
    await this.commitRoster(admin, await Promise.all(next), "rotate");
  }

  currentRosterSims(): MemberSim[] {
    if (this.members.length === 0) return [];
    const admin = this.members.find((m) => m.session.currentEpoch >= 0) ?? this.members[0]!;
    const rosterIds = new Set(admin.session.roster().map((m) => m.id));
    return this.members.filter((m) => rosterIds.has(m.id));
  }

  async send(sender: MemberSim, plaintext: string): Promise<void> {
    if (!this.groupId) throw new Error("no group");
    const event = await sender.session.sendMessage(plaintext);
    const stored = await this.relay.postEvent(this.groupId, event);
    this.serverLog.push(stored);
    await this.distribute(stored);
    this.emit();
  }

  // ------------------------------------------------------------ fan-out

  /** Give one stored event to every simulated member (as the relay would). */
  async distribute(stored: StoredEvent): Promise<void> {
    for (const sim of this.members) {
      await this.ingestOne(sim, stored);
    }
  }

  private async ingestOne(sim: MemberSim, stored: StoredEvent): Promise<void> {
    const ev: GroupEvent = stored.event;
    try {
      const result = await sim.session.ingest(ev);
      if (result.blocked) {
        sim.lines.push({
          eventId: stored.eventId,
          epoch: ev.epoch,
          senderId: ev.kind === "message" ? ev.senderId : "server",
          text:
            ev.kind === "commit"
              ? `🔒 Commit epoch ${ev.epoch}: no envelope for this member — key not recoverable`
              : "🔒 Undecryptable message (no key material for this epoch)",
          kind: "blocked",
          detail: result.reason,
          incoming: true,
        });
      } else if (result.message) {
        const m: DecryptedMessage = result.message;
        sim.lines.push({
          eventId: stored.eventId,
          epoch: m.epoch,
          senderId: m.senderId,
          generation: m.generation,
          text: m.plaintext,
          kind: "plain",
          incoming: m.senderId !== sim.id,
        });
      } else if (result.commit) {
        sim.lines.push({
          eventId: stored.eventId,
          epoch: result.commit.epoch,
          senderId: result.commit.adminId,
          text: `📢 Epoch ${result.commit.epoch} started (${result.commit.reason}), ${result.commit.members.length} members`,
          kind: "system",
          incoming: true,
        });
      }
    } catch (err) {
      const message = (err as Error).message;
      // Replays are benign in the demo (relay echo + SSE can redeliver); the
      // engine still rejects them cryptographically, we just don't spam the UI.
      if (message.includes("replayed")) return;
      sim.lines.push({
        eventId: stored.eventId,
        epoch: ev.epoch,
        senderId: "error",
        text: `⚠️ Rejected: ${message}`,
        kind: "blocked",
        incoming: true,
      });
    }
  }

  /** Re-feed the whole server log to every member (used at startup). */
  async catchUpAll(): Promise<void> {
    for (const sim of this.members) {
      for (const stored of this.serverLog) await this.ingestOne(sim, stored);
    }
    this.emit();
  }

  async resetAll(): Promise<void> {
    localStorage.removeItem(LS_MEMBERS);
    localStorage.removeItem(LS_GROUP);
    this.members = [];
    this.groupId = null;
    this.serverLog = [];
    this.emit();
  }
}
