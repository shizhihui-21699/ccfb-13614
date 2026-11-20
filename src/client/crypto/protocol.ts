// Wire protocol types. Every event the server stores is a plain JSON object
// whose sensitive fields are base64 ciphertext / opaque key material.
// The server never needs to parse or validate anything beyond groupId/epoch.

/** Public half of a member's key material. */
export interface MemberPublic {
  /** id = hex(sha256(SPKI(sigPub)).slice(0,16)) — bound to the signature key */
  id: string;
  /** P-256 signature verification key, SPKI base64 */
  sigPub: string;
  /** P-256 ECDH public key, raw point base64 (encapsulation target) */
  ecdhPub: string;
}

/** A Commit rekeys the group: new epoch secret, fan-out encrypted to the new roster. */
export interface CommitEnvelope {
  /** member id this envelope is addressed to */
  memberId: string;
  /** ECIES(EpochSecret) under that member's ECDH public key */
  sealed: { epk: string; iv: string; ct: string };
}

export interface GroupCommit {
  kind: "commit";
  groupId: string;
  /** epoch of the NEW state (genesis = 0) */
  epoch: number;
  /** full roster in force from this epoch onward */
  members: MemberPublic[];
  /** member id of the admin who authored / signed the commit */
  adminId: string;
  /** epoch-secret envelopes, one per member (random ES, never derived from old ES) */
  envelopes: CommitEnvelope[];
  /** optional human-readable reason: "create" | "add" | "remove" | "rotate" */
  reason: string;
  /** ECDSA over the canonical JSON of every field above (excluding signature) */
  signature: string;
}

/** A single application message inside an epoch (sender-key ratchet). */
export interface GroupMessage {
  kind: "message";
  groupId: string;
  epoch: number;
  senderId: string;
  /** position on the sender's ratchet chain, starting at 0 per epoch */
  generation: number;
  iv: string;
  ct: string;
  /** ECDSA over canonical JSON of all preceding fields */
  signature: string;
}

/** Union type of everything persisted/forwarded by the server. */
export type GroupEvent = GroupCommit | GroupMessage;

export interface StoredEvent {
  eventId: string;
  timestamp: number;
  event: GroupEvent;
}

/** Fields covered by the commit signature. */
export function commitSignedFields(c: Omit<GroupCommit, "signature">): unknown {
  return {
    kind: c.kind,
    groupId: c.groupId,
    epoch: c.epoch,
    members: c.members,
    adminId: c.adminId,
    envelopes: c.envelopes,
    reason: c.reason,
  };
}

/** Fields covered by the message signature. */
export function messageSignedFields(m: Omit<GroupMessage, "signature">): unknown {
  return {
    kind: m.kind,
    groupId: m.groupId,
    epoch: m.epoch,
    senderId: m.senderId,
    generation: m.generation,
    iv: m.iv,
    ct: m.ct,
  };
}
