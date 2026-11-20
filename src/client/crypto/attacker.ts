// Side-channel attacker tool.
//
// Threat model assumed: the attacker obtains a victim device's FULL exported
// keystore (private signing + ECDH keys) AND a complete dump of everything the
// relay server ever stored (all commits, all ciphertext messages). This is the
// strongest realistic attacker: they can sign as the victim and replay offline
// forever. The guarantees that must still hold are group-membership based:
//
//   - a member who joined at epoch k cannot decrypt epochs < k
//   - a member removed at epoch k cannot decrypt epochs >= k
//   - after a key rotation, a device holding only the OLD keypair cannot open
//     anything in the new epoch
//
// The tool never re-implements protocol shortcuts: it drives the real
// GroupSession and reports exactly which events decrypt and which fail.

import { DeviceIdentity, type SerializedIdentity } from "./identity.js";
import { GroupSession } from "./groupSession.js";
import type { GroupEvent, StoredEvent } from "./protocol.js";

export interface AttackAttempt {
  eventId: string;
  epoch: number;
  kind: string;
  outcome: "decrypted" | "blocked" | "error";
  detail: string;
  plaintext?: string;
}

export interface AttackReport {
  attackerId: string;
  attackerName: string;
  scenario: string;
  heldEpochs: number[];
  totalEvents: number;
  decrypted: number;
  blocked: number;
  errors: number;
  attempts: AttackAttempt[];
  /** Per-epoch roll-up: how many messages were read vs denied. */
  epochSummary: Record<number, { decrypted: number; blocked: number }>;
  /** Human-readable verdict lines. */
  verdict: string[];
}

export class SideChannelAttacker {
  readonly session: GroupSession;
  readonly identity: DeviceIdentity;

  /**
   * Construct from a stolen/exported device keystore.
   * The attacker starts with exactly that device's key material — nothing else.
   */
  static async withStolenDevice(stolen: SerializedIdentity): Promise<SideChannelAttacker> {
    const identity = await DeviceIdentity.restore(stolen);
    return new SideChannelAttacker(identity);
  }

  private constructor(identity: DeviceIdentity) {
    this.identity = identity;
    this.session = new GroupSession(identity);
  }

  /**
   * Feed the attacker the raw server dump. They ingest every event in order,
   * exactly as a normal client would — the difference is which envelopes are
   * addressed to them and which epochs therefore yield secret material.
   */
  async runAttack(scenario: string, dump: StoredEvent[]): Promise<AttackReport> {
    const attempts: AttackAttempt[] = [];
    const epochSummary: Record<number, { decrypted: number; blocked: number }> = {};

    for (const stored of dump) {
      const ev: GroupEvent = stored.event;
      const epoch = ev.epoch;
      const summary = (epochSummary[epoch] ??= { decrypted: 0, blocked: 0 });
      try {
        const result = await this.session.attemptDecrypt(ev);
        if (result.blocked) {
          summary.blocked += 1;
          attempts.push({
            eventId: stored.eventId,
            epoch,
            kind: ev.kind,
            outcome: "blocked",
            detail: result.reason ?? "no access",
          });
        } else if (result.message) {
          summary.decrypted += 1;
          attempts.push({
            eventId: stored.eventId,
            epoch,
            kind: "message",
            outcome: "decrypted",
            detail: "sender-key ratchet derived the message key",
            plaintext: result.message.plaintext,
          });
        } else {
          // commit that admitted the attacker: secret material installed
          attempts.push({
            eventId: stored.eventId,
            epoch,
            kind: "commit",
            outcome: "decrypted",
            detail: `epoch ${epoch} secret recovered from personal envelope`,
          });
        }
      } catch (err) {
        summary.blocked += 1;
        attempts.push({
          eventId: stored.eventId,
          epoch,
          kind: ev.kind,
          outcome: "error",
          detail: (err as Error).message,
        });
      }
    }

    const decrypted = attempts.filter((a) => a.outcome === "decrypted").length;
    const blocked = attempts.filter((a) => a.outcome !== "decrypted").length;
    const diag = this.session.diagnostic();

    return {
      attackerId: this.identity.id,
      attackerName: this.identity.displayName,
      scenario,
      heldEpochs: diag.heldEpochs,
      totalEvents: dump.length,
      decrypted,
      blocked,
      errors: attempts.filter((a) => a.outcome === "error").length,
      attempts,
      epochSummary,
      verdict: this.buildVerdict(scenario, epochSummary),
    };
  }

  private buildVerdict(
    scenario: string,
    summary: Record<number, { decrypted: number; blocked: number }>,
  ): string[] {
    const lines: string[] = [];
    for (const epoch of Object.keys(summary)
      .map(Number)
      .sort((a, b) => a - b)) {
      const s = summary[epoch]!;
      const status =
        s.decrypted > 0 && s.blocked === 0
          ? "READABLE (expected if attacker was a member in this epoch)"
          : s.decrypted === 0 && s.blocked > 0
            ? "FULLY DENIED ✓"
            : `partial: ${s.decrypted} read, ${s.blocked} denied`;
      lines.push(`epoch ${epoch}: ${status}`);
    }
    lines.push(`Scenario "${scenario}": attacker holds secret material for epochs [${this.session
      .diagnostic()
      .heldEpochs.join(", ")}]`);
    return lines;
  }
}
