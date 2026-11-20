// GroupSession: the core end-to-end encryption engine.
//
// Security model implemented here:
//
//   1. Membership is epoch-based. Every Commit picks a FRESH random 32-byte
//      epoch secret and ECIES-seals it once per roster member. It is never
//      derived from the previous epoch secret, so a removed member holding the
//      old secret cannot compute the new one.
//
//   2. Late joiners only ever receive epoch secrets for epochs at/after their
//      first Commit. Historical ciphertext stays undecryptable: they lack both
//      the old epoch secret and the old senders' derived chain keys.
//
//   3. Within an epoch each sender has an independent HKDF ratchet. Message
//      keys are one-way derived and the chain key advances on every message,
//      giving forward secrecy against a later device compromise. Committing a
//      new epoch zeroizes old chain keys (bounded retention window).
//
//   4. Every Commit and every message carries an ECDSA signature; the server
//      stores opaque blobs and cannot forge either.

import {
  aesGcmOpen,
  aesGcmSeal,
  eciesOpen,
  eciesSeal,
  hkdf,
  importECDHPublic,
  importSigningPublic,
  initChainKey,
  memberId,
  messageAAD,
  randomBytes,
  ratchet,
  sign,
  verify,
} from "./primitives.js";
import {
  commitSignedFields,
  messageSignedFields,
  type GroupCommit,
  type GroupEvent,
  type GroupMessage,
  type MemberPublic,
} from "./protocol.js";
import { b64ToBytes, bytesToB64, fromUtf8, utf8, type Bytes } from "./util.js";
import { DeviceIdentity } from "./identity.js";

export interface DecryptedMessage {
  groupId: string;
  epoch: number;
  senderId: string;
  generation: number;
  plaintext: string;
}

export interface IngestResult {
  type: "commit" | "message";
  commit?: GroupCommit;
  message?: DecryptedMessage;
  /** true when a commit/message arrived that this member is not allowed to read */
  blocked?: boolean;
  reason?: string;
}

interface EpochState {
  epoch: number;
  /** raw epoch secret; zeroized when the epoch is evicted */
  secret: Bytes;
  members: MemberPublic[];
  adminId: string;
  /** my own sending chain — undefined until I first send in this epoch */
  sendChainKey?: Bytes;
  sendGeneration: number;
  /** latest observed chain key per other sender (for ordered receive) */
  recvChain: Map<string, { chainKey: Bytes; generation: number }>;
  /** cached derived message keys for out-of-order delivery: key = sender|generation */
  skippedKeys: Map<string, Bytes>;
  /** generations already accepted (replay defense) */
  seenGenerations: Map<string, Set<number>>;
}

/** Hard cap on cached skipped message keys per epoch (bounded key storage). */
const MAX_SKIPPED_KEYS = 256;
/** Number of past epochs whose material is retained before zeroization. */
const EPOCH_RETENTION = 3;

export class GroupSession {
  readonly identity: DeviceIdentity;
  private epochs = new Map<number, EpochState>();
  private latestEpoch = -1;
  /** roster of the latest epoch, for building commits */
  private currentRoster: MemberPublic[] = [];
  private currentAdminId = "";
  /** whether THIS device is in the latest epoch's roster */
  private currentMembership = false;

  constructor(identity: DeviceIdentity) {
    this.identity = identity;
  }

  get groupId(): string | undefined {
    return this.latestEpoch >= 0 ? this.epochGroupId : undefined;
  }
  private epochGroupId = "";

  get currentEpoch(): number {
    return this.latestEpoch;
  }

  roster(): MemberPublic[] {
    return this.currentRoster;
  }

  isMember(): boolean {
    return this.currentMembership;
  }

  // ------------------------------------------------------------------ commit

  /** Build and locally apply the genesis commit for a new group. */
  async createGroup(groupId: string, members: MemberPublic[]): Promise<GroupCommit> {
    if (!members.some((m) => m.id === this.identity.id)) {
      throw new Error("creator must be a member");
    }
    return this.buildCommit(groupId, 0, members, "create");
  }

  /** Build a commit replacing the roster (add / remove / device rotation). */
  async updateRoster(
    nextMembers: MemberPublic[],
    reason: "add" | "remove" | "rotate",
  ): Promise<GroupCommit> {
    if (this.latestEpoch < 0) throw new Error("not part of a group yet");
    if (this.currentAdminId !== this.identity.id) {
      throw new Error("only the group admin can change membership");
    }
    if (!nextMembers.some((m) => m.id === this.currentAdminId)) {
      throw new Error("cannot remove the admin (admin transfer is out of scope)");
    }
    return this.buildCommit(this.epochGroupId, this.latestEpoch + 1, nextMembers, reason);
  }

  private async buildCommit(
    groupId: string,
    epoch: number,
    members: MemberPublic[],
    reason: string,
  ): Promise<GroupCommit> {
    const freshSecret = randomBytes(32); // FRESH entropy — never KDF(oldSecret)
    const envelopes = [];
    for (const m of members) {
      const pub = await importECDHPublic(m.ecdhPub);
      const sealed = await eciesSeal(pub, freshSecret);
      envelopes.push({ memberId: m.id, sealed });
    }
    const unsigned = {
      kind: "commit" as const,
      groupId,
      epoch,
      members,
      adminId: this.identity.id,
      envelopes,
      reason,
    };
    const signature = await sign(this.identity.sigKey.privateKey!, commitSignedFields(unsigned));
    const commit: GroupCommit = { ...unsigned, signature };
    await this.handleCommit(commit);
    return commit;
  }

  // ----------------------------------------------------------------- message

  /** Encrypt a plaintext application message under the current epoch. */
  async sendMessage(plaintext: string): Promise<GroupMessage> {
    const st = this.epochs.get(this.latestEpoch);
    if (!st) throw new Error("no active epoch");
    if (!st.members.some((m) => m.id === this.identity.id)) {
      throw new Error("removed members cannot send");
    }
    if (!st.sendChainKey) {
      st.sendChainKey = await initChainKey(st.secret, this.identity.id);
      st.sendGeneration = 0;
    }
    const { messageKey, nextChainKey } = await ratchet(st.sendChainKey);
    const generation = st.sendGeneration;
    st.sendChainKey = nextChainKey; // forward secrecy: old chain key overwritten
    st.sendGeneration = generation + 1;

    const iv = randomBytes(12);
    const aad = messageAAD(this.epochGroupId, st.epoch, this.identity.id, generation);
    const ct = await aesGcmSeal(messageKey, iv, utf8(plaintext), aad);
    const unsigned = {
      kind: "message" as const,
      groupId: this.epochGroupId,
      epoch: st.epoch,
      senderId: this.identity.id,
      generation,
      iv: bytesToB64(iv),
      ct: bytesToB64(ct),
    };
    const signature = await sign(this.identity.sigKey.privateKey!, messageSignedFields(unsigned));
    return { ...unsigned, signature };
  }

  // ------------------------------------------------------------------ ingest

  /** Process one server event (commit or message). */
  async ingest(event: GroupEvent): Promise<IngestResult> {
    if (event.kind === "commit") return this.handleCommit(event);
    return this.handleMessage(event);
  }

  private async handleCommit(commit: GroupCommit): Promise<IngestResult> {
    // Idempotency: the same signed commit may arrive twice (local application
    // at build time + relay echo / SSE replay / startup catch-up). A commit we
    // have already fully applied is a no-op, never an error.
    if (this.epochs.has(commit.epoch)) {
      return { type: "commit", commit };
    }
    // --- structural / authenticity validation (even non-members validate) ---
    const admin = commit.members.find((m) => m.id === commit.adminId);
    if (!admin) throw new Error("commit admin not present in roster");
    const adminSigKey = await importSigningPublic(admin.sigPub);
    const okSig = await verify(adminSigKey, commitSignedFields(commit), commit.signature);
    if (!okSig) throw new Error("invalid commit signature");

    // On every transition the admin must match the previously known admin
    // (prevents the server from substituting an alternate signed history).
    if (this.latestEpoch >= 0 && commit.adminId !== this.currentAdminId) {
      throw new Error("unexpected admin change");
    }
    for (const m of commit.members) {
      if ((await memberId(m.sigPub)) !== m.id) {
        throw new Error("member id not bound to its signature key");
      }
    }
    if (commit.envelopes.length !== commit.members.length) {
      throw new Error("envelope/roster count mismatch");
    }
    if (new Set(commit.members.map((m) => m.id)).size !== commit.members.length) {
      throw new Error("duplicate member ids");
    }

    const mine = commit.envelopes.find((e) => e.memberId === this.identity.id);
    if (!mine) {
      // No envelope for us: either we were never a member, or we have just been
      // removed. We obtain NO secret material for this epoch, and our roster
      // membership ends here. Roster/admin bookkeeping still advances so the
      // UI and later commits see the current state.
      this.latestEpoch = commit.epoch;
      this.epochGroupId = commit.groupId;
      this.currentRoster = commit.members;
      this.currentAdminId = commit.adminId;
      this.currentMembership = false;
      return { type: "commit", commit, blocked: true, reason: "no envelope addressed to this member" };
    }

    // Contiguity is enforced only once we have joined. A member's FIRST
    // decryptable commit may land at any epoch: a late joiner legitimately
    // receives the whole earlier log (commits with no envelope for it) before
    // the first epoch it is admitted to.
    if (this.latestEpoch >= 0 && commit.epoch !== this.latestEpoch + 1) {
      throw new Error(`non-contiguous epoch: have ${this.latestEpoch}, got ${commit.epoch}`);
    }

    // Decrypt the fresh epoch secret from our personal envelope.
    const secret = await eciesOpen(this.identity.ecdhKey.privateKey!, mine.sealed);
    const state: EpochState = {
      epoch: commit.epoch,
      secret,
      members: commit.members,
      adminId: commit.adminId,
      sendGeneration: 0,
      recvChain: new Map(),
      skippedKeys: new Map(),
      seenGenerations: new Map(),
    };
    this.epochs.set(commit.epoch, state);
    this.latestEpoch = commit.epoch;
    this.epochGroupId = commit.groupId;
    this.currentRoster = commit.members;
    this.currentAdminId = commit.adminId;
    this.currentMembership = true;
    this.evictOldEpochs();
    return { type: "commit", commit };
  }

  private evictOldEpochs() {
    const keep = new Set<number>();
    for (let e = this.latestEpoch; e > this.latestEpoch - EPOCH_RETENTION && e >= 0; e--) keep.add(e);
    for (const [epoch, st] of this.epochs) {
      if (!keep.has(epoch)) {
        st.secret.fill(0);
        st.sendChainKey?.fill(0);
        for (const v of st.recvChain.values()) v.chainKey.fill(0);
        for (const v of st.skippedKeys.values()) v.fill(0);
        this.epochs.delete(epoch);
      }
    }
  }

  private async handleMessage(msg: GroupMessage): Promise<IngestResult> {
    const st = this.epochs.get(msg.epoch);
    if (!st) {
      return {
        type: "message",
        blocked: true,
        reason: `no key material for epoch ${msg.epoch} (member joined later or was removed)`,
      };
    }
    const sender = st.members.find((m) => m.id === msg.senderId);
    if (!sender) {
      return { type: "message", blocked: true, reason: "sender not in epoch roster" };
    }

    // Authenticity first: signature over the full message including generation.
    const senderSigKey = await importSigningPublic(sender.sigPub);
    const okSig = await verify(senderSigKey, messageSignedFields(msg), msg.signature);
    if (!okSig) throw new Error("invalid message signature");

    const seen = st.seenGenerations.get(msg.senderId) ?? new Set<number>();
    if (seen.has(msg.generation)) throw new Error("replayed message");

    const aad = messageAAD(msg.groupId, msg.epoch, msg.senderId, msg.generation);
    const cacheKey = `${msg.senderId}|${msg.generation}`;
    let messageKey: Bytes | undefined = st.skippedKeys.get(cacheKey);

    if (!messageKey) {
      // Derive (or ratchet forward to) the sender's chain.
      let entry = st.recvChain.get(msg.senderId);
      if (!entry) {
        entry = { chainKey: await initChainKey(st.secret, msg.senderId), generation: 0 };
        st.recvChain.set(msg.senderId, entry);
      }
      if (msg.generation < entry.generation) {
        throw new Error("stale generation (key already deleted)");
      }
      while (entry.generation < msg.generation) {
        const r = await ratchet(entry.chainKey);
        const skippedCacheKey = `${msg.senderId}|${entry.generation}`;
        if (st.skippedKeys.size >= MAX_SKIPPED_KEYS) {
          throw new Error("skipped-key cache limit exceeded");
        }
        st.skippedKeys.set(skippedCacheKey, r.messageKey);
        entry.chainKey = r.nextChainKey;
        entry.generation += 1;
      }
      const r = await ratchet(entry.chainKey);
      messageKey = r.messageKey;
      entry.chainKey = r.nextChainKey;
      entry.generation += 1;
    } else {
      st.skippedKeys.delete(cacheKey);
    }

    let plainBytes: Bytes;
    try {
      plainBytes = await aesGcmOpen(
        messageKey,
        b64ToBytes(msg.iv),
        b64ToBytes(msg.ct),
        aad,
      );
    } catch {
      throw new Error("GCM authentication failed (wrong key or tampered ciphertext)");
    }
    messageKey.fill(0);
    seen.add(msg.generation);
    st.seenGenerations.set(msg.senderId, seen);

    return {
      type: "message",
      message: {
        groupId: msg.groupId,
        epoch: msg.epoch,
        senderId: msg.senderId,
        generation: msg.generation,
        plaintext: fromUtf8(plainBytes),
      },
    };
  }

  /**
   * Diagnostic snapshot used by the side-channel tool: which epochs does this
   * device actually hold secret material for? A removed/never-joined device will
   * show gaps — and decryption of those epochs provably fails.
   */
  diagnostic(): { latestEpoch: number; heldEpochs: number[]; member: boolean } {
    return {
      latestEpoch: this.latestEpoch,
      heldEpochs: [...this.epochs.keys()].sort((a, b) => a - b),
      member: this.isMember(),
    };
  }

  /**
   * Best-effort attempt to decrypt raw wire events with whatever material this
   * session holds. The side-channel attacker tool calls this directly: a
   * well-formed protocol answer must come back as `blocked`, never plaintext.
   */
  async attemptDecrypt(event: GroupEvent): Promise<IngestResult> {
    return this.ingest(event);
  }
}

/** Convenience: deterministic-looking group ids without external deps. */
export async function newGroupId(): Promise<string> {
  const raw = randomBytes(12);
  const hex = [...raw].map((b) => b.toString(16).padStart(2, "0")).join("");
  return `grp_${hex}`;
}

/** Re-exported for the attacker tool. */
export { hkdf };
