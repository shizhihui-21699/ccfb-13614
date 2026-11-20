# 端到端加密群聊（Epoch + Sender-Key Ratchet）

服务器只做**转发和存储**,永远看不到明文。所有密码学运算在客户端（浏览器或 Node）
用标准 WebCrypto 完成。代码为 TypeScript,浏览器客户端与 Node 测试共用同一套加密引擎。

## 它解决什么

| 需求 | 机制 |
| --- | --- |
| 新人看不到入群前的消息 | 每个成员变更产生新 **epoch**,新人只拿到加入那一刻及之后的 epoch secret(ES);历史 epoch 的 ES 从未封装给它 |
| 被踢者之后一条也解不开 | 新 ES 是**全新随机字节**,不是 `KDF(oldES, …)`;被踢者不在新 commit 的封装名单里,数学上无法获得新 ES |
| 设备被盗不连累群历史 | ① 每条消息的 sender key 单向棘轮,旧消息密钥用后即删（前向安全）;② 受害者生成全新密钥对后管理员做 rotate commit,被盗旧设备的公钥不在新名单,新 epoch 对它完全不可解 |
| 加人/踢人不做两两协商 | 一次 commit = O(n) 次**单向 ECIES 封装**（管理员→各成员）,没有任何 n² 握手;发消息是 O(1) 对称运算 |
| 几百人规模 | 实测 300 人群:commit 构建 ~50ms,入群同步 ~650ms（300 次 ECIES 解封并行）,单条发送/解密 <1ms |

## 协议结构

```
GroupCommit（成员变更，管理员 ECDSA 签名）
├─ epoch: 单调递增
├─ members: 完整新名单 [{id, sigPub(SPKI), ecdhPub(raw point)}]
├─ envelopes: 对每个成员 ECIES(全新随机 32B EpochSecret, 成员 ECDH 公钥)
└─ reason: create | add | remove | rotate

GroupMessage（epoch 内聊天，发送者 ECDSA 签名）
├─ generation: 该发送者链上的序号
├─ AES-256-GCM(消息密钥, 明文, AAD=groupId|epoch|senderId|generation)
└─ 消息密钥来自 HKDF 棘轮:
     chainKey₀ = HKDF(ES, "sender-chain/<senderId>")
     (msgKeyₙ, chainKeyₙ₊₁) = HKDF(chainKeyₙ)   // 单向,旧 key 用后覆盖
```

**为什么新 ES 必须是纯随机而不是从旧 ES 派生**:如果用 `ES_new = KDF(ES_old)`,
被踢者持有 `ES_old` 就能自己算出所有未来密钥,踢人形同虚设。随机 ES + 按名单封装
保证访问控制完全由"谁能解开自己的 envelope"决定。

**身份绑定**:`memberId = SHA256(SPKI(sigPub))` 的前 16 字节。服务器无法把某个 id
重新映射到另一把公钥——所有签名校验都会失败。

## 目录

```
src/client/crypto/
  primitives.ts    WebCrypto 原语:ECDH-P256 / ECDSA-P256 / HKDF / AES-GCM / ECIES / 棘轮
  protocol.ts      线上 JSON 格式与签名覆盖域
  identity.ts      设备身份（签名密钥对 + ECDH 密钥对,可导出以模拟设备被盗）
  groupSession.ts  核心引擎:commit 处理、消息加解密、乱序缓存、重放防御、旧 epoch 清零
  attacker.ts      旁路攻击工具:拿被盗密钥库 + 服务器全量转储,逐条尝试并出证据报告
src/client/web/    浏览器演示（无框架,原生 DOM + SSE 实时刷新）
src/server/        零依赖 relay:HTTP 存储/转发 + SSE,不解析任何密文
src/tests/         14 个测试:三大安全属性、伪造/篡改、重放、乱序、300 人规模、HTTP 全链路
scripts/           构建辅助与命令行演示剧本
```

## 运行

```bash
npm install
npm run build
npm start                      # http://localhost:8787 （PORT / DATA_FILE 可覆盖）
# 另开一个终端,跑命令行完整剧本（建群→加人→踢人→被盗 rotate→攻击证据）:
node scripts/demo-scenario.mjs http://localhost:8787

npm test                       # 14 项测试（含自动拉起服务器的 HTTP 集成测试）
```

### 浏览器演示操作流

1. **一键初始化 3 人群** —— Alice 建群,三张卡片各自独立密钥库
2. 任意成员卡片里发消息,其他人实时（SSE）解密显示
3. "创建设备"加一个 Dave,再用"加人（新 Epoch）"把他拉进群——他会看到入群前
   历史显示为 🔒 不可解密
4. "踢人（新 Epoch）"踢掉 Dave——他卡片里之后每条消息都是 🔒
5. 选一个成员"模拟设备被盗 → 换密钥并 Rotate"
6. 在第 3 区选 Dave（或被盗成员）点"用该设备的密钥发起离线攻击":工具拉取
   `/api/dump` 全量服务器磁盘 + 使用导出的私钥,逐条事件尝试,输出每-epoch
   的 `FULLY DENIED ✓` 证据表
7. 第 4 区可直接查看服务器磁盘上的原始内容——全是 base64 密文和不透明 blob

## 安全边界（诚实说明）

- **管理员单点模型**:成员变更由固定管理员签名。管理员转移、多管理员投票未实现。
- **被踢者仍可读到被踢之前的历史**:这是端到端群聊的固有属性（它本来就持有那些密钥）;
  本设计保证的是**之后**的消息一条读不到,且棘轮让被盗设备的可读窗口随发送推进缩小。
- **吊销依赖 commit 延迟**:rotate 之前已加密的消息对旧密钥仍可读,前向安全由棘轮
  在每个 epoch 内逐消息收敛。
- **拒绝服务/垃圾消息**:relay 不做鉴权,任何人可 POST 格式合法的 blob;真实部署需在
  外层加账号鉴权（不影响 E2EE 本身,签名仍在客户端验证）。
- 演示用 P-256;生产可平移到 X25519/Ed25519,接口都集中在 `primitives.ts`。
- 密钥在演示中可导出（为了模拟被盗);生产环境应使用 non-extractable 密钥 + 平台密钥库。
