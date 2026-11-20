// End-to-end demo script (Node, talks to a running relay over HTTP).
// Mirrors every button in the browser demo and prints the security evidence
// the side-channel attacker produces at each stage.
//
// Usage: npm run build && node scripts/demo-scenario.mjs [baseUrl]

const BASE = process.argv[2] ?? "http://localhost:8795";

const { DeviceIdentity } = await import("../dist/client/crypto/identity.js");
const { GroupSession, newGroupId } = await import("../dist/client/crypto/groupSession.js");
const { SideChannelAttacker } = await import("../dist/client/crypto/attacker.js");

async function post(groupId, event) {
  const r = await fetch(`${BASE}/api/groups/${groupId}/events`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ event }),
  });
  if (!r.ok) throw new Error(`post failed ${r.status}: ${await r.text()}`);
  return (await r.json()).stored;
}
const dump = async () => (await (await fetch(`${BASE}/api/dump`)).json()).events;
const pubs = async (ids) => Promise.all(ids.map((i) => i.publicMember()));
const line = (s) => console.log(`\n${"─".repeat(72)}\n${s}\n${"─".repeat(72)}`);

// ---- 1. identities -------------------------------------------------------
line("1) 创建设备身份（每个设备独立签名密钥 + ECDH 密钥）");
const aliceId = await DeviceIdentity.create("Alice（管理员）");
const bobId = await DeviceIdentity.create("Bob");
const carolId = await DeviceIdentity.create("Carol");
const daveId = await DeviceIdentity.create("Dave（后来加入又被踢）");
const alice = new GroupSession(aliceId);
const bob = new GroupSession(bobId);
const carol = new GroupSession(carolId);
const dave = new GroupSession(daveId);
for (const i of [aliceId, bobId, carolId, daveId]) {
  console.log(`  ${i.displayName.padEnd(22)} id=${i.id}`);
}

// ---- 2. genesis + early chat --------------------------------------------
line("2) Alice 建群（epoch 0），群内先聊两条 Dave 永远看不到的消息");
const groupId = await newGroupId();
const genesis = await alice.createGroup(groupId, await pubs([aliceId, bobId, carolId]));
await post(groupId, genesis);
for (const s of [bob, carol]) await s.ingest(genesis);
for (const text of ["历史消息 A：季度营收数字", "历史消息 B：收购计划细节"]) {
  const ev = await alice.sendMessage(text);
  await post(groupId, ev);
  for (const s of [bob, carol]) await s.ingest(ev);
}
console.log("  已发送 2 条 epoch-0 历史消息");

// ---- 3. Dave joins -------------------------------------------------------
line("3) 加 Dave：Alice 发布新 commit，生成全新随机 ES，只封装给新名单（无两两协商）");
const addCommit = await alice.updateRoster(await pubs([aliceId, bobId, carolId, daveId]), "add");
const addStored = await post(groupId, addCommit);
console.log(`  commit epoch=${addCommit.epoch}，envelope 数=${addCommit.envelopes.length}（=成员数）`);
for (const s of [bob, carol, dave]) await s.ingest(addCommit);
const welcome = await alice.sendMessage("欢迎 Dave 入群");
await post(groupId, welcome);
for (const s of [bob, carol, dave]) {
  const r = await s.ingest(welcome);
  console.log(`  ${s.identity.displayName.padEnd(22)} 读到: "${r.message?.plaintext ?? "🔒 " + r.reason}"`);
}
const historyEvent = (await dump())[1].event;
const daveHistory = await dave.ingest(historyEvent);
console.log(`  Dave 尝试读入群前历史 → ${daveHistory.blocked ? "🔒 被拒绝（无 epoch-0 密钥）" : "❌ 泄露"}`);

// ---- 4. Dave is kicked ---------------------------------------------------
line("4) 踢 Dave：又是全新随机 ES，envelope 名单里没有 Dave");
const kick = await alice.updateRoster(await pubs([aliceId, bobId, carolId]), "remove");
await post(groupId, kick);
for (const s of [bob, carol, dave]) await s.ingest(kick);
const secretMsg = await alice.sendMessage("Dave 走了，说正事：新预算方案");
await post(groupId, secretMsg);
for (const s of [bob, carol]) await s.ingest(secretMsg);
const daveAttempt = await dave.ingest(secretMsg);
console.log(`  Dave 被踢后读新消息 → ${daveAttempt.blocked ? "🔒 被拒绝: " + daveAttempt.reason : "❌ 泄露: " + daveAttempt.message?.plaintext}`);

// ---- 5. device theft + rotation ------------------------------------------
line("5) 模拟 Bob 设备被盗 → Bob 换新密钥对，Alice 做 rotate commit");
const stolenBobImage = await bobId.serialize(); // 攻击者此刻镜像走 Bob 私钥
const bobNewId = await DeviceIdentity.create("Bob（新设备）");
const bobNew = new GroupSession(bobNewId);
const rotate = await alice.updateRoster(
  await Promise.all([aliceId, bobNewId, carolId].map((i) => i.publicMember())),
  "rotate",
);
await post(groupId, rotate);
for (const s of [carol, bobNew]) await s.ingest(rotate);
const postRotate = await carol.sendMessage("rotate 之后的安全消息");
await post(groupId, postRotate);
const bobNewRead = await bobNew.ingest(postRotate);
console.log(`  Bob 新设备读到 → "${bobNewRead.message?.plaintext}"（旧设备拿不到这个 epoch 的 ES）`);

// ---- 6. side-channel attack evidence -------------------------------------
line("6) 旁路攻击：攻击者持有被盗私钥 + 拉取服务器全量磁盘转储");
const fullDump = await dump();
console.log(`  服务器磁盘事件总数: ${fullDump.length}，明文出现次数检查:`);
const raw = JSON.stringify(fullDump);
for (const secret of ["季度营收", "收购计划", "新预算方案", "rotate 之后的安全消息"]) {
  console.log(`    "${secret}" 在服务器存储中出现: ${raw.includes(secret) ? "❌ 是" : "✓ 否（全是密文）"}`);
}

const attackDave = await (await SideChannelAttacker.withStolenDevice(await daveId.serialize()))
  .runAttack("Dave：迟到加入 + 随后被踢", fullDump);
console.log("\n  【攻击者 = Dave】");
for (const v of attackDave.verdict) console.log("    " + v);
console.log(`    汇总: 解密 ${attackDave.decrypted} 条 / 被拒 ${attackDave.blocked} 条`);

const attackBob = await (await SideChannelAttacker.withStolenDevice(stolenBobImage))
  .runAttack("Bob：旧设备被盗、密钥已 rotate", fullDump);
console.log("\n  【攻击者 = 被盗的 Bob 旧设备】");
for (const v of attackBob.verdict) console.log("    " + v);
console.log(`    汇总: 解密 ${attackBob.decrypted} 条 / 被拒 ${attackBob.blocked} 条`);
const leaked = attackBob.attempts.filter((a) => a.outcome === "decrypted" && a.epoch >= rotate.epoch);
console.log(`    rotate 后泄露消息数: ${leaked.length} ${leaked.length === 0 ? "✓" : "❌"}`);

line("演示完成");
console.log(`Relay 仍在运行: ${BASE} ，浏览器打开即可使用图形界面`);
