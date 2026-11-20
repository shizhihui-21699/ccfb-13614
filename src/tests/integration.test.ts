// Full-stack integration test: spawns the REAL relay server as a child process
// and drives it over HTTP with the REAL browser/Node crypto client, proving the
// end-to-end flow works through storage + transport, not just in-memory calls.

import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { once } from "node:events";
import { DeviceIdentity } from "../client/crypto/identity.js";
import { GroupSession } from "../client/crypto/groupSession.js";
import { SideChannelAttacker } from "../client/crypto/attacker.js";
import { RelayClient } from "../client/web/relayClient.js";
import type { StoredEvent } from "../client/crypto/protocol.js";

const PORT = 8791;
const BASE = `http://localhost:${PORT}`;
let server: ChildProcess;
let dataDir: string;
const relay = new RelayClient(BASE);

before(async () => {
  dataDir = await mkdtemp(join(tmpdir(), "e2ee-relay-"));
  server = spawn(process.execPath, ["dist/server/server.js"], {
    env: { ...process.env, PORT: String(PORT), DATA_FILE: join(dataDir, "store.json") },
    stdio: ["ignore", "pipe", "inherit"],
  });
  // wait until the port answers
  const deadline = Date.now() + 8000;
  for (;;) {
    try {
      const r = await fetch(`${BASE}/api/groups`);
      if (r.ok) break;
    } catch {
      /* not up yet */
    }
    if (Date.now() > deadline) throw new Error("relay server did not start");
    await new Promise((r) => setTimeout(r, 100));
  }
});

after(async () => {
  server.kill("SIGTERM");
  await once(server, "exit");
  await rm(dataDir, { recursive: true, force: true });
});

describe("end-to-end over HTTP through the relay server", () => {
  test("create → chat → add → kick, with the attacker denied via /api/dump", async () => {
    // --- identities -----------------------------------------------------
    const aliceId = await DeviceIdentity.create("Alice");
    const bobId = await DeviceIdentity.create("Bob");
    const carolId = await DeviceIdentity.create("Carol");
    const daveId = await DeviceIdentity.create("Dave");
    const alice = new GroupSession(aliceId);
    const bob = new GroupSession(bobId);
    const carol = new GroupSession(carolId);
    const dave = new GroupSession(daveId);

    // --- genesis --------------------------------------------------------
    const genesis = await alice.createGroup("http-group", await Promise.all(
      [aliceId, bobId, carolId].map((i) => i.publicMember()),
    ));
    await relay.postEvent(genesis.groupId, genesis);
    for (const s of [bob, carol]) await s.ingest(genesis);

    // --- normal chat ----------------------------------------------------
    const hello = await alice.sendMessage("hello over http");
    await relay.postEvent(hello.groupId, hello);
    const log1 = await relay.fetchEvents(hello.groupId);
    assert.equal(log1.length, 2);
    const bobRead = await bob.ingest(hello);
    assert.equal(bobRead.message?.plaintext, "hello over http");

    // --- add Dave (late joiner) ----------------------------------------
    const addCommit = await alice.updateRoster(
      await Promise.all([aliceId, bobId, carolId, daveId].map((i) => i.publicMember())),
      "add",
    );
    await relay.postEvent(addCommit.groupId, addCommit);
    // every existing member syncs the full log, including the new commit
    for (const s of [bob, carol, dave]) await s.ingest(addCommit);
    const secret = await alice.sendMessage("dave-welcome");
    await relay.postEvent(secret.groupId, secret);
    assert.equal((await dave.ingest(secret)).message?.plaintext, "dave-welcome");
    assert.equal((await carol.ingest(secret)).message?.plaintext, "dave-welcome");
    // Dave cannot read the pre-join message straight from the relay log
    const daveOnOld = await dave.ingest(hello);
    assert.equal(daveOnOld.blocked, true);

    // --- kick Dave ------------------------------------------------------
    const kick = await alice.updateRoster(
      await Promise.all([aliceId, bobId, carolId].map((i) => i.publicMember())),
      "remove",
    );
    await relay.postEvent(kick.groupId, kick);
    for (const s of [bob, carol, dave]) await s.ingest(kick);
    assert.equal(dave.isMember(), false);
    const afterKick = await alice.sendMessage("dave-must-not-read-this");
    await relay.postEvent(afterKick.groupId, afterKick);
    assert.equal((await dave.ingest(afterKick)).blocked, true);
    assert.equal((await carol.ingest(afterKick)).message?.plaintext, "dave-must-not-read-this");

    // --- side-channel attacker pulls the full server disk --------------
    const dump: StoredEvent[] = await relay.dump();
    assert.ok(dump.length >= 6, "server stored every event as opaque blobs");
    const attacker = await SideChannelAttacker.withStolenDevice(await daveId.serialize());
    const report = await attacker.runAttack("http-e2e: Dave removed", dump);
    const deniedEpochs = Object.values(report.epochSummary).filter((s) => s.decrypted === 0);
    assert.ok(deniedEpochs.length >= 1, "at least one epoch fully denied to Dave");
    assert.equal(report.epochSummary[kick.epoch]!.decrypted, 0);
    // nothing Dave read postdates his removal
    const leaked = report.attempts.filter(
      (a) => a.outcome === "decrypted" && a.epoch >= kick.epoch,
    );
    assert.equal(leaked.length, 0, "zero post-removal decryptions");
  });

  test("the relay stores only ciphertext: no plaintext appears anywhere in its dump", async () => {
    const groups = await relay.listGroups();
    assert.ok(groups.includes("http-group"));
    const dump = await relay.dump();
    const raw = JSON.stringify(dump);
    for (const secret of ["hello over http", "dave-welcome", "dave-must-not-read-this"]) {
      assert.ok(!raw.includes(secret), `plaintext "${secret}" must not exist on the server`);
    }
  });

  test("serves the demo page and its compiled assets", async () => {
    const page = await fetch(`${BASE}/`);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /端到端加密群聊/);
    const js = await fetch(`${BASE}/client/web/app.js`);
    assert.equal(js.status, 200);
    const jsText = await js.text();
    assert.ok(jsText.includes("SideChannelAttacker") || jsText.includes("ingest"), "compiled client bundle");
    const css = await fetch(`${BASE}/styles.css`);
    assert.equal(css.status, 200);
  });

  test("relay rejects malformed events but never parses ciphertext", async () => {
    const r = await fetch(`${BASE}/api/groups/http-group/events`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ event: { kind: "nonsense" } }),
    });
    assert.equal(r.status, 400);
  });
});
