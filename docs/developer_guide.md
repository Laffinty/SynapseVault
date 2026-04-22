# SynapseVault 开发者指南

## 目录

1. [架构概览](#架构概览)
2. [模块描述与文件映射](#模块描述与文件映射)
3. [数据流](#数据流)
4. [P2P 协议规范](#p2p-协议规范)
5. [如何添加新 UI 面板](#如何添加新-ui-面板)
6. [如何添加新 P2P 消息类型](#如何添加新-p2p-消息类型)
7. [测试策略](#测试策略)
8. [构建与发布流程](#构建与发布流程)
9. [CRDT 冲突解决策略](#crdt-冲突解决策略)
10. [区块链出块机制](#区块链出块机制)

---

## 架构概览

```
┌─────────────────────────────────────────┐
│                GUI (egui)                │
│  ┌─────────┐ ┌─────────┐ ┌──────────┐  │
│  │UnlockWin│ │ Panels  │ │ Dialogs  │  │
│  └────┬────┘ └────┬────┘ └────┬─────┘  │
└───────┼───────────┼───────────┼────────┘
        │           │           │
┌───────┼───────────┼───────────┼────────┐
│       ▼           ▼           ▼        │
│     App State (SynapseVaultApp)        │
│  ┌─────────┐ ┌─────────┐ ┌──────────┐  │
│  │ Session │ │ Groups  │ │ Secrets  │  │
│  └────┬────┘ └────┬────┘ └────┬─────┘  │
└───────┼───────────┼───────────┼────────┘
        │           │           │
┌───────┼───────────┼───────────┼────────┐
│       ▼           ▼           ▼        │
│  Modules (crypto / storage / p2p ...)  │
│  ┌─────────┐ ┌─────────┐ ┌──────────┐  │
│  │  Auth   │ │ Storage │ │   P2P    │  │
│  │ Crypto  │ │  Audit  │ │  RBAC    │  │
│  └─────────┘ └─────────┘ └──────────┘  │
└─────────────────────────────────────────┘
```

---

## 模块描述与文件映射

| 模块 | 路径 | 职责 |
|------|------|------|
| **Auth** | `src/auth/` | 设备指纹、密钥文件生成/解码、解锁流程 |
| **Crypto** | `src/crypto/` | Argon2id KDF、HKDF、XChaCha20-Poly1305、ed25519 签名 |
| **Group** | `src/group/` | 群组管理、成员状态、加入请求/审批、组密钥 |
| **P2P** | `src/p2p/` | libp2p 传输、gossipsub、mdns、协议消息、事件循环 |
| **RBAC** | `src/rbac/` | 角色定义、使用审批策略、权限检查 |
| **Secret** | `src/secret/` | 密码条目 CRUD、加密存储、剪贴板、导入导出 |
| **Storage** | `src/storage/` | SQLite 数据库初始化、Schema 迁移、SQLCipher 加密 |
| **Audit** | `src/audit/` | 审计事件定义、日志记录、查询、导出（JSON/CSV） |
| **Blockchain** | `src/blockchain/` | 区块结构、Merkle 树、共识、链存储、出块逻辑 |
| **Sync** | `src/sync/` | CRDT 引擎、冲突合并、同步快照、vector clock |
| **UI** | `src/ui/` | egui 面板、主题、弹窗、解锁窗口、布局组件 |

---

## 数据流

### 核心流程：unlock → group → secret → audit → blockchain

```
1. Unlock
   用户输入主密码
        │
        ▼
   Argon2id 派生 master_key
        │
        ▼
   HKDF 派生 db_key / keyfile_key
        │
        ▼
   解密 ed25519 私钥 → UnlockedSession

2. Group
   创建组 / 加入组
        │
        ▼
   P2P 广播 GroupAnnounce / JoinRequest
        │
        ▼
   Admin 审批 → 成员加入组

3. Secret
   创建/更新/删除密码
        │
        ▼
   本地 SQLite 写入（SQLCipher 加密）
        │
        ▼
   P2P 广播 SecretOp（gossipsub）
        │
        ▼
   远程节点 CRDT 合并 → 更新本地状态

4. Audit
   密码操作触发审计事件
        │
        ▼
   本地审计表写入
        │
        ▼
   P2P 广播 AuditEventsBatch

5. Blockchain
   操作累积到阈值（50 ops / 60s）
        │
        ▼
   Admin 签名生成新区块
        │
        ▼
   本地区块链存储 + P2P 广播
```

---

## P2P 协议规范

### Topic 命名

```
synapsevault/{group_id}/{category}
```

- `category`: `secrets` | `control` | `chain`
- 示例: `synapsevault/g1/secrets`

### 消息信封

所有 gossipsub 消息使用 `P2pMessageEnvelope` 包装：

```rust
pub struct P2pMessageEnvelope {
    pub nonce: u64,        // 单调递增随机值，用于重放检测
    pub payload: P2pMessage,
}
```

### 消息类型

| 消息 | Topic | 说明 |
|------|-------|------|
| `GroupAnnounce` | control | 群组广播 |
| `JoinRequest` | control | 申请加入 |
| `JoinApproved` | control | 审批通过 |
| `JoinRejected` | control | 审批拒绝 |
| `SecretOp` | secrets | 密码增删改 |
| `SecretSyncRequest` | secrets | 请求全量同步 |
| `SecretSyncResponse` | secrets | 全量同步响应 |
| `RoleChange` | control | 角色变更 |
| `AuditEventsBatch` | chain | 审计事件批次 |
| `ChainSyncRequest` | chain | 链同步请求 |
| `ChainSyncResponse` | chain | 链同步响应 |
| `Heartbeat` | control | 保活心跳 |

---

## 如何添加新 UI 面板

1. **创建面板文件**：在 `src/ui/` 下新建 `{panel_name}_panel.rs`，实现 `render_{panel_name}_panel(app, ctx, ui)`。
2. **注册 Panel 枚举**：在 `src/app.rs` 的 `Panel` enum 中添加新变体。
3. **注册路由**：在 `src/ui/main_layout.rs` 的 `render_main_layout` 中 `match app.current_panel` 添加分支。
4. **添加导航按钮**：在 `src/ui/side_panel.rs` 的按钮列表中添加新入口。
5. **添加状态字段**（如需要）：在 `SynapseVaultApp` 中添加相关状态字段。

---

## 如何添加新 P2P 消息类型

1. **定义消息**：在 `src/p2p/protocol.rs` 的 `P2pMessage` enum 中添加新变体。
2. **序列化支持**：确保新变体实现 `Serialize + Deserialize`（使用 `serde` derive 即可）。
3. **事件转换**：在 `src/p2p/event_loop.rs` 的 `handle_p2p_message` 中匹配新变体，转换为 `P2pEvent`。
4. **处理事件**：在 `src/app.rs` 或相关模块中处理新的 `P2pEvent` 变体。
5. **广播接口**（如需要）：在 `src/p2p/gossip.rs` 的 `GossipManager` 中添加广播方法。
6. **添加测试**：在 `src/p2p/protocol.rs` 的 tests 中添加序列化/反序列化测试。

---

## 测试策略

| 类型 | 位置 | 工具 | 说明 |
|------|------|------|------|
| **单元测试** | `src/**/mod.rs` 或 `src/**/tests` | `cargo test` | 模块级函数测试 |
| **集成测试** | `tests/*.rs` | `cargo test --test <name>` | 跨模块流程测试 |
| **渗透测试** | `tests/pentest.rs` | `cargo test --test pentest` | 重放攻击、泛洪测试 |
| **基准测试** | `benches/*.rs` | `cargo bench` | 性能基准 |
| **Miri** | 全项目 | `cargo +nightly miri test` | 内存安全检测（排除 I/O 测试） |

### Miri 注意事项

- 所有涉及文件 I/O、网络、剪贴板、GUI 的测试模块已标记 `#[cfg(all(test, not(miri)))]`。
- 运行 Miri 时仅对纯计算模块（crypto、sync、rbac 等）进行检测。

---

## 构建与发布流程

### 开发构建

```bash
cargo check          # 快速检查
cargo clippy -- -W clippy::all -W clippy::unwrap_used
cargo test --all     # 运行全部测试
cargo audit          # 安全审计
```

### Release 构建

```bash
cargo build --release
```

Release 配置（`Cargo.toml`）：

```toml
[profile.release]
opt-level = 3
lto = true
strip = true
codegen-units = 1
```

### 跨平台发布

CI 已配置三平台矩阵（Ubuntu / Windows / macOS），自动构建并打包产物。

---

## CRDT 冲突解决策略

SynapseVault 使用 **Last-Writer-Wins (LWW)** + **版本号** 的混合策略。

### 合并规则

1. **版本号优先**：version 高的一方胜出。
2. **时间戳次之**：version 相同则 updated_at 新的一方胜出。
3. **确定性仲裁**：version 和 updated_at 都相同，则比较 `created_by` 字典序。

### 删除优先

- 只要有一方删除，另一方版本号不高出则删除生效。
- 若保留方版本号明显更高，则保留（视为删除后的恢复）。

### 实现位置

- `src/sync/merge.rs`：`merge_secret_entries`、`ConflictResolver`
- `src/sync/crdt_engine.rs`：`CrdtEngine::apply_op`

---

## 区块链出块机制

### 双阈值触发

区块生产由 `BlockProducer` 管理，满足以下任一条件即触发：

1. **操作数阈值**：累积未打包操作数达到 **50 条**。
2. **时间阈值**：距离上次出块超过 **60 秒**。

### 出块流程

1. `try_produce_block()` 检查阈值。
2. 收集待打包操作，计算 Merkle 根。
3. Admin 使用组签名私钥签名区块。
4. 区块追加到本地区块链，保存到 SQLite。
5. 通过 P2P 广播 `AuditEventsBatch`（简化版区块同步）。

### 验证

- `verify_merkle_root()` 重新计算 Merkle 根并与区块内存储值比对。
- 公钥一致性验证防止篡改。

### 实现位置

- `src/blockchain/chain.rs`：`BlockProducer`、`Blockchain`
- `src/blockchain/consensus.rs`：`produce_block`、`verify_merkle_root`
- `src/blockchain/merkle.rs`：`compute_merkle_root`
