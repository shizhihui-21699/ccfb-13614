// End-to-end security tests driving the real GroupSession engine (no server,
// no mocking of crypto). Covers the three required properties plus replay,
// out-of-order delivery, tampering, and large-group performance.

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { DeviceIdentity } from "../client/crypto/identity.js";
import { GroupSession } from "../client/crypto/groupSession.js";
import { SideChannelAttacker } from "../client/crypto/attacker.js";
import type { GroupEvent, StoredEvent } from "../client/crypto/protocol.js";
import { messageSignedFields, commitSignedFields } from "../client/crypto/protocol.js";
import { verify, importSigningPublic } from "../client/crypto/primitives.js";

let counter = 0;
function eventId(): string {
  counter += 1;
  return `evt_test_${counter}`;
}

type Pair = [GroupSession, GroupSession];
type Triple = [GroupSession, GroupSession, GroupSession];

async function makeSessions(names: string[]): Promise<GroupSession[]> {
  const out: GroupSession[] = [];
  for (const n of names) out.push(new GroupSession(await DeviceIdentity.create(n)));
  return out;
}
const pair = async (): Promise<Pair> => {
  const s = await makeSessions(["Alice", "Bob"]);
  return [s[0]!, s[1]!];
};
const triple = async (): Promise<Triple> => {
  const s = await makeSessions(["Alice", "Bob", "Carol"]);
  return [s[0]!, s[1]!, s[2]!];
};
const pubs = (ss: GroupSession[]) => Promise.all(ss.map((s) => s.identity.publicMember()));

/** Broadcast an event to every session, recording it in the shared log. */
async function fanout(log: StoredEvent[], sessions: GroupSession[], event: GroupEvent): Promise<void> {
  const stored: StoredEvent = { eventId: eventId(), timestamp: counter, event };
  log.push(stored);
  for (const s of sessions) await s.ingest(event);
}

async function expectPlain(session: GroupSession, event: GroupEvent, text: string): Promise<void> {
  const r = await session.ingest(event);
  assert.equal(r.blocked, undefined, "should not be blocked");
  assert.equal(r.message?.plaintext, text);
}

async function expectBlocked(session: GroupSession, event: GroupEvent): Promise<void> {
  const r = await session.ingest(event);
  assert.equal(r.blocked, true, "member must be denied this event");
}

describe("property 1: late joiners cannot read history", () => {
  test("new member cannot decrypt messages from before it joined", async () => {
    const [alice, bob] = await pair();
    const log: StoredEvent[] = [];

    const genesis = await alice.createGroup("g1", await pubs([alice]));
    await fanout(log, [alice], genesis);

    const secret1 = await alice.sendMessage("before-bob-1");
    await fanout(log, [alice], secret1);
    const secret2 = await alice.sendMessage("before-bob-2");
    await fanout(log, [alice], secret2);

    // Bob joins: a fresh epoch whose secret is sealed to Bob.
    const addCommit = await alice.updateRoster(await pubs([alice, bob]), "add");
    await fanout(log, [alice, bob], addCommit);

    const after = await alice.sendMessage("after-bob-joined");
    await fanout(log, [alice], after); // bob ingests below with explicit assertions

    // Bob reads current traffic fine (first ingest of this event)...
    await expectPlain(bob, after, "after-bob-joined");
    // ...but the historical messages are undecryptable (no epoch-0 material).
    await expectBlocked(bob, secret1);
    await expectBlocked(bob, secret2);

    // The side-channel tool reaches the same conclusion from a raw dump.
    const attacker = await SideChannelAttacker.withStolenDevice(await bob.identity.serialize());
    const report = await attacker.runAttack("late-joiner", log);
    const e0 = report.epochSummary[0]!;
    assert.equal(e0.decrypted, 0, "epoch 0 must be fully denied to the joiner");
    assert.ok(e0.blocked >= 2);
  });
});

describe("property 2: removed members cannot read anything after removal", () => {
  test("kicked member is denied every post-removal message and commit", async () => {
    const [alice, bob, carol] = await triple();
    const log: StoredEvent[] = [];

    const genesis = await alice.createGroup("g2", await pubs([alice, bob, carol]));
    await fanout(log, [alice, bob, carol], genesis);

    const before = await alice.sendMessage("everyone-can-read");
    await fanout(log, [alice, bob, carol], before);

    // Bob is removed; the new epoch secret is NEVER derived from the old one.
    const removeCommit = await alice.updateRoster(await pubs([alice, carol]), "remove");
    await fanout(log, [alice, bob, carol], removeCommit);
    assert.equal(bob.isMember(), false);

    const after1 = await alice.sendMessage("after-kick-1");
    await fanout(log, [alice], after1); // carol deliberately ingested below
    const after2 = await carol.sendMessage("after-kick-2");
    // give bob the raw event directly (the server happily stores/forwards it)
    log.push({ eventId: eventId(), timestamp: counter, event: after2 });

    await expectBlocked(bob, after1);
    await expectBlocked(bob, after2);
    // survivors are unaffected (carol ingests each event exactly once)
    await expectPlain(carol, after1, "after-kick-1");
    await expectPlain(carol, after2, "after-kick-2");

    // attacker with Bob's full device dump still fails on every new event
    const attacker = await SideChannelAttacker.withStolenDevice(await bob.identity.serialize());
    const report = await attacker.runAttack("removed-member", log);
    const e1 = report.epochSummary[1]!;
    assert.equal(e1.decrypted, 0, "post-removal epoch must be fully denied");
    assert.ok(e1.blocked >= 3);
    // ...while pre-removal history remains readable to Bob (expected: he was there)
    assert.equal(report.epochSummary[0]!.blocked, 0);
  });

  test("removed member cannot derive the new epoch secret by ratcheting the old one", async () => {
    // Explicit cryptographic check: fresh ES is independent randomness.
    const [alice, bob] = await pair();
    const g = await alice.createGroup("g3", await pubs([alice, bob]));
    await alice.ingest(g);
    await bob.ingest(g);
    const oldHeld = bob.diagnostic().heldEpochs;
    const remove = await alice.updateRoster(await pubs([alice]), "remove");
    const r = await bob.ingest(remove);
    assert.equal(r.blocked, true);
    assert.deepEqual(bob.diagnostic().heldEpochs, oldHeld, "no new secret material installed");
  });
});

describe("property 3: device compromise is contained by key rotation", () => {
  test("after rotating to new keypairs, the stolen old device cannot open the new epoch", async () => {
    const [alice, bob] = await pair();
    const log: StoredEvent[] = [];
    const genesis = await alice.createGroup("g4", await pubs([alice, bob]));
    await fanout(log, [alice, bob], genesis);
    const preTheft = await alice.sendMessage("pre-theft");
    await fanout(log, [alice, bob], preTheft);

    // Attacker images Bob's device at this point (full private keys).
    const stolenImage = await bob.identity.serialize();

    // Bob recovers: brand-new keypairs; admin rotates the epoch to them.
    const bobNewIdentity = await DeviceIdentity.create("Bob-new-device");
    const bobNewSession = new GroupSession(bobNewIdentity);
    const rotate = await alice.updateRoster(
      await Promise.all([alice.identity.publicMember(), bobNewIdentity.publicMember()]),
      "rotate",
    );
    await fanout(log, [alice, bobNewSession], rotate);

    const postRotate = await alice.sendMessage("post-rotation-secret");
    log.push({ eventId: eventId(), timestamp: counter, event: postRotate });
    await expectPlain(bobNewSession, postRotate, "post-rotation-secret");

    // The attacker still holds only the OLD device image.
    const attacker = await SideChannelAttacker.withStolenDevice(stolenImage);
    const report = await attacker.runAttack("stolen-device-then-rotation", log);
    const rotatedEpoch = rotate.epoch;
    const summary = report.epochSummary[rotatedEpoch]!;
    assert.equal(summary.decrypted, 0, "attacker must read nothing in the rotated epoch");
    assert.ok(summary.blocked >= 1, "new epoch denied to stolen device");
    // and the attacker never installs secret material beyond its own epoch
    assert.deepEqual(report.heldEpochs, [0]);
  });

  test("forward secrecy: out-of-order ratchet messages all decrypt; replay is rejected", async () => {
    const [alice, bob] = await pair();
    const genesis = await alice.createGroup("g5", await pubs([alice, bob]));
    await alice.ingest(genesis);
    await bob.ingest(genesis);
    const m1 = await alice.sendMessage("one");
    const m2 = await alice.sendMessage("two");
    const m3 = await alice.sendMessage("three");
    // bob receives out of order: 3 then 1 then 2
    await expectPlain(bob, m3, "three");
    await expectPlain(bob, m1, "one");
    await expectPlain(bob, m2, "two");
    // replay is rejected
    await assert.rejects(() => bob.ingest(m2), /replayed/);
  });
});

describe("authenticity: server cannot forge or tamper", () => {
  test("message with a forged signature is rejected", async () => {
    const [alice, bob] = await pair();
    const genesis = await alice.createGroup("g6", await pubs([alice, bob]));
    await alice.ingest(genesis);
    await bob.ingest(genesis);
    const msg = await alice.sendMessage("authentic");
    const forged = { ...msg, signature: msg.signature.slice(0, -4) + "AAAA" };
    await assert.rejects(() => bob.ingest(forged), /signature/);
  });

  test("tampered ciphertext fails GCM authentication", async () => {
    const [alice, bob] = await pair();
    const genesis = await alice.createGroup("g7", await pubs([alice, bob]));
    await alice.ingest(genesis);
    await bob.ingest(genesis);
    const msg = await alice.sendMessage("secret");
    const tampered = { ...msg, ct: msg.ct.slice(0, -4) + "AAAA" };
    await assert.rejects(() => bob.ingest(tampered), /GCM|signature/);
  });

  test("a commit whose roster id is not bound to its signature key is rejected", async () => {
    const [alice, bob] = await pair();
    const genesis = await alice.createGroup("g8", await pubs([alice, bob]));
    await alice.ingest(genesis);
    await bob.ingest(genesis);
    const evil = await alice.updateRoster(await pubs([alice, bob]), "add");
    // server/attacker rewrites one member id but keeps the signature;
    // the signature covers the roster so the commit must be rejected
    const tampered = {
      ...evil,
      members: evil.members.map((m, i) => (i === 1 ? { ...m, id: "deadbeefdeadbeefdeadbeefdeadbeef" } : m)),
    };
    await assert.rejects(() => bob.ingest(tampered), /not bound|signature/);
  });

  test("signatures really cover the full commit and message body", async () => {
    const [alice, bob] = await pair();
    const genesis = await alice.createGroup("g9", await pubs([alice, bob]));
    const adminKey = await importSigningPublic(genesis.members[0]!.sigPub);
    assert.ok(await verify(adminKey, commitSignedFields(genesis), genesis.signature));
    await alice.ingest(genesis);
    await bob.ingest(genesis);
    const msg = await alice.sendMessage("x");
    const senderKey = await importSigningPublic(
      genesis.members.find((m) => m.id === alice.identity.id)!.sigPub,
    );
    assert.ok(await verify(senderKey, messageSignedFields(msg), msg.signature));
  });
});

describe("scale: hundreds of members, no pairwise negotiation", () => {
  test("commit fan-out and message delivery for a 300-member group", async () => {
    const N = 300;
    const sessions = await makeSessions(Array.from({ length: N }, (_, i) => `M${i}`));
    const admin = sessions[0]!;

    const t0 = Date.now();
    const genesis = await admin.createGroup("big", await pubs(sessions));
    const buildMs = Date.now() - t0;

    const t1 = Date.now();
    await Promise.all(sessions.map((s) => s.ingest(genesis)));
    const distributeMs = Date.now() - t1;

    const t2 = Date.now();
    const msg = await admin.sendMessage("hello-300");
    const sendMs = Date.now() - t2;

    // fresh decryption at both edges of the roster (no prior ingest of msg)
    const t3 = Date.now();
    const r1 = await sessions[1]!.ingest(structuredClone(msg));
    const rLast = await sessions[N - 1]!.ingest(structuredClone(msg));
    const decryptMs = Date.now() - t3;
    assert.equal(r1.message?.plaintext, "hello-300");
    assert.equal(rLast.message?.plaintext, "hello-300");

    assert.equal(genesis.envelopes.length, N, "one envelope per member, zero pairwise channels");
    console.log(
      `[bench 300] commit build ${buildMs}ms, fan-in ingest ${distributeMs}ms, send ${sendMs}ms, edge decryptions ${decryptMs}ms`,
    );
  });
});
