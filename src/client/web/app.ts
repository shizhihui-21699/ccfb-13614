// Demo page controller. Renders one card per simulated device and wires the
// group-operation / attacker controls to the Simulation state layer.

import { Simulation, MemberSim, type ChatLine } from "./sim.js";
import { SideChannelAttacker, type AttackReport } from "../crypto/attacker.js";
import type { StoredEvent } from "../crypto/protocol.js";

const sim = new Simulation();
const $ = (sel: string): HTMLElement => document.querySelector(sel)!;

function shortId(id: string): string {
  return id.slice(0, 8);
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!,
  );
}

// ------------------------------------------------------------- member cards

function renderCards(): void {
  const host = $("#member-cards");
  host.innerHTML = "";
  for (const m of sim.members) host.appendChild(buildCard(m));
}

function buildCard(m: MemberSim): HTMLElement {
  const card = document.createElement("div");
  const adminId = sim.members.find((x) => x.session.currentEpoch >= 0)?.session.roster()[0]?.id;
  const inRoster = m.session.currentEpoch < 0 || m.session.isMember();
  card.className = `card ${adminId === m.id ? "admin" : ""} ${!inRoster ? "excluded" : ""}`;

  const diag = m.session.diagnostic();
  card.innerHTML = `
    <div class="card-head">
      <div class="card-name">
        ${escapeHtml(m.name)}
        ${adminId === m.id ? '<span class="role-tag">ADMIN</span>' : ""}
        ${!inRoster ? '<span class="role-tag out">已移出群</span>' : ""}
      </div>
      <div class="card-meta">id ${shortId(m.id)}…</div>
      <div class="card-meta">sig ${escapeHtml(m.identity.sigPubSpkiB64.slice(0, 28))}…</div>
      <div class="diag">
        当前 epoch: <b>${diag.latestEpoch < 0 ? "—" : diag.latestEpoch}</b> ·
        持有密钥的 epoch: <b>[${diag.heldEpochs.join(", ")}]</b>
      </div>
    </div>
    <div class="chat" data-chat></div>
    <div class="composer">
      <input data-input placeholder="${inRoster ? "以该成员身份发消息…" : "已不在群内，无法发送"}"
        ${inRoster ? "" : "disabled"} />
      <button data-send class="btn primary" ${inRoster ? "" : "disabled"}>发送</button>
    </div>`;

  const chat = card.querySelector("[data-chat]")!;
  for (const line of m.lines) chat.appendChild(buildLine(line, m));
  chat.scrollTop = chat.scrollHeight;

  const input = card.querySelector<HTMLInputElement>("[data-input]")!;
  const send = (): void => {
    const text = input.value.trim();
    if (!text) return;
    input.value = "";
    sim.send(m, text).catch((err) => alert(err.message));
  };
  card.querySelector("[data-send")!.addEventListener("click", send);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") send();
  });
  return card;
}

function buildLine(line: ChatLine, viewer: MemberSim): HTMLElement {
  const div = document.createElement("div");
  const cls =
    line.kind === "system" ? "sys" : line.kind === "blocked" ? "blocked" : line.incoming ? "in" : "out";
  div.className = `msg ${cls}`;
  const who =
    line.kind === "system"
      ? ""
      : line.kind === "blocked"
        ? `<span class="who">🔒 访问拒绝</span>`
        : `<span class="who">${escapeHtml(line.senderId === viewer.id ? viewer.name : sim.memberName(line.senderId))}</span>`;
  const epoch = line.epoch >= 0 ? `<span class="epoch">e${line.epoch}${line.generation !== undefined ? `:${line.generation}` : ""}</span>` : "";
  div.innerHTML = `${who}${escapeHtml(line.text)}${epoch}${line.detail ? `<span class="detail">${escapeHtml(line.detail)}</span>` : ""}`;
  return div;
}

// ------------------------------------------------------------- controls

function renderSelects(): void {
  const rosterIds = new Set(sim.currentRosterSims().map((m) => m.id));
  const fill = (sel: HTMLSelectElement, filter: (m: MemberSim) => boolean, empty: string): void => {
    const prev = sel.value;
    sel.innerHTML = "";
    const opts = sim.members.filter(filter);
    if (opts.length === 0) sel.add(new Option(empty, ""));
    for (const m of opts) sel.add(new Option(`${m.name} (${shortId(m.id)})`, m.id));
    if ([...sel.options].some((o) => o.value === prev)) sel.value = prev;
  };
  fill($("#sel-add") as HTMLSelectElement, (m) => !rosterIds.has(m.id), "（群外无成员）");
  fill($("#sel-remove") as HTMLSelectElement, (m) => rosterIds.has(m.id), "（群内无成员）");
  fill($("#sel-rotate") as HTMLSelectElement, () => true, "（无成员）");
  fill($("#sel-attacker") as HTMLSelectElement, () => true, "（无成员）");
}

function renderServerView(): void {
  const el = $("#server-view");
  if (sim.serverLog.length === 0) {
    el.textContent = "（暂无）";
    return;
  }
  el.textContent = sim.serverLog
    .map((s: StoredEvent) => JSON.stringify(s, null, 1))
    .join("\n\n");
}

function renderAll(): void {
  $("#group-badge").textContent = sim.groupId ? `群 ${sim.groupId.slice(0, 18)}…` : "未建群";
  renderCards();
  renderSelects();
  renderServerView();
}

// ------------------------------------------------------------- actions

$("#btn-add-member").addEventListener("click", async () => {
  const input = $("#new-member-name") as HTMLInputElement;
  const name = input.value.trim();
  if (!name) return alert("请输入成员名称");
  input.value = "";
  await sim.addMember(name);
});

$("#btn-bootstrap").addEventListener("click", async () => {
  if (sim.groupId) return alert("群已存在，可先重置演示");
  const names = ["Alice", "Bob", "Carol"];
  for (const n of names) if (!sim.members.some((m) => m.name === n)) await sim.addMember(n);
  const [alice, bob, carol] = sim.members;
  if (!alice || !bob || !carol) return;
  await sim.createGroup(alice, [alice, bob, carol]);
});

$("#btn-add").addEventListener("click", async () => {
  const id = ($("#sel-add") as HTMLSelectElement).value;
  const newcomer = sim.members.find((m) => m.id === id);
  const admin = sim.members.find((m) => m.id === sim.currentRosterSims()[0]?.id);
  if (!newcomer || !admin) return alert("没有可加入的成员");
  await sim.addMembers(admin, [newcomer]);
});

$("#btn-remove").addEventListener("click", async () => {
  const id = ($("#sel-remove") as HTMLSelectElement).value;
  const victim = sim.members.find((m) => m.id === id);
  const admin = sim.members.find((m) => m.id === sim.currentRosterSims()[0]?.id);
  if (!victim || !admin) return alert("没有可移除的成员");
  if (victim.id === admin.id) return alert("不能移除管理员");
  await sim.removeMembers(admin, [victim]);
});

$("#btn-rotate").addEventListener("click", async () => {
  const id = ($("#sel-rotate") as HTMLSelectElement).value;
  const victim = sim.members.find((m) => m.id === id);
  const admin = sim.members.find((m) => m.id === sim.currentRosterSims()[0]?.id);
  if (!victim || !admin) return;
  // 1) victim generates a brand-new device identity (old keypair considered stolen)
  const freshPub = await sim.rotateDevice(victim);
  // 2) admin commits a rotate epoch sealing the new epoch secret to the new key
  await sim.publishRotation(admin, new Map([[victim.id, freshPub]]));
});

// ------------------------------------------------------------- attacker

$("#btn-export").addEventListener("click", async () => {
  const id = ($("#sel-attacker") as HTMLSelectElement).value;
  const target = sim.members.find((m) => m.id === id);
  if (!target) return;
  const exported = await target.identity.serialize();
  const blob = new Blob([JSON.stringify(exported, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `stolen-device-${target.name}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
});

$("#btn-attack").addEventListener("click", async () => {
  const id = ($("#sel-attacker") as HTMLSelectElement).value;
  const target = sim.members.find((m) => m.id === id);
  if (!target) return;
  const dump = await sim.relay.dump(); // attacker pulls the whole server disk
  const stolen = await target.identity.serialize(); // attacker holds the device keystore
  const attacker = await SideChannelAttacker.withStolenDevice(stolen);
  const scenario = labelScenario(target);
  const report = await attacker.runAttack(scenario, dump);
  renderReport(report);
});

function labelScenario(target: MemberSim): string {
  const inRoster = target.session.isMember();
  const held = target.session.diagnostic().heldEpochs;
  if (!inRoster && held.length > 0 && held[0]! > 0) return `late-joiner: ${target.name} 入群前的历史应全部不可读`;
  if (!inRoster) return `removed-member: ${target.name} 被踢后的新消息应全部不可读`;
  return `current-member baseline: ${target.name} 应能读自己 epoch 内的消息`;
}

function renderReport(r: AttackReport): void {
  const host = $("#attack-report");
  host.innerHTML = "";

  const verdict = document.createElement("div");
  verdict.className = "verdict";
  const lines = [
    `攻击者: ${r.attackerName} (${r.attackerId.slice(0, 12)}…)`,
    `场景: ${r.scenario}`,
    `服务器事件总数: ${r.totalEvents}`,
    `成功解密: ${r.decrypted}   被拒绝: ${r.blocked}`,
    `攻击者实际持有密钥的 epoch: [${r.heldEpochs.join(", ")}]`,
    "",
    ...r.verdict.map((l) =>
      l.includes("FULLY DENIED")
        ? l.replace("FULLY DENIED ✓", "✓ 完全拒绝（一条也解不开）")
        : l.replace("READABLE", "可读（成员期内，符合预期）"),
    ),
  ];
  verdict.textContent = lines.join("\n");
  host.appendChild(verdict);

  const table = document.createElement("table");
  table.className = "attempts";
  table.innerHTML = `<thead><tr><th>事件</th><th>epoch</th><th>类型</th><th>结果</th><th>细节 / 明文</th></tr></thead>`;
  const tbody = document.createElement("tbody");
  for (const a of r.attempts) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(a.eventId.slice(-8))}</td>
      <td>${a.epoch}</td>
      <td>${a.kind}</td>
      <td class="outcome-${a.outcome}">${a.outcome === "decrypted" ? "解密成功" : a.outcome === "blocked" ? "拒绝 ✓" : "协议错误"}</td>
      <td>${escapeHtml(a.plaintext ? `明文="${a.plaintext}"` : a.detail)}</td>`;
    tbody.appendChild(tr);
  }
  table.appendChild(tbody);
  host.appendChild(table);
}

// ------------------------------------------------------------- live updates

let unsubscribe: (() => void) | null = null;
const knownEventIds = new Set<string>();

/** Subscribe to the live SSE feed once a group exists (idempotent). */
function subscribe(groupId: string): void {
  if (unsubscribe) return;
  for (const s of sim.serverLog) knownEventIds.add(s.eventId);
  unsubscribe = sim.relay.stream(groupId, async (stored) => {
    // Relay echoes our own POSTs back too; dedupe by event id so every event
    // is ingested exactly once per member (replay protection rejects repeats).
    if (knownEventIds.has(stored.eventId)) return;
    knownEventIds.add(stored.eventId);
    sim.serverLog.push(stored);
    await sim.distribute(stored);
  });
}

async function main(): Promise<void> {
  await sim.init();
  sim.onChange(() => {
    renderAll();
    if (sim.groupId) subscribe(sim.groupId);
  });
  $("#btn-reset").addEventListener("click", async () => {
    if (!confirm("清空所有本地设备密钥和群状态？（服务器数据需手动删除 data/store.json）")) return;
    unsubscribe?.();
    unsubscribe = null;
    knownEventIds.clear();
    await sim.resetAll();
  });
  renderAll();
  if (sim.groupId) subscribe(sim.groupId);
}

main().catch((err) => {
  console.error(err);
  alert(`初始化失败: ${err.message}`);
});
