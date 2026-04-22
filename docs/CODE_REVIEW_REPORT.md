# SynapseVault 项目整体 CODE REVIEW 报告

> **审查日期**：2026-04-22  
> **对标文档**：`docs/SynapseVault构建方案文档.md`  
> **审查维度**：功能完成度、安全与健壮性、编码规范性、与方案文档偏差  
> **测试基线**：`cargo test` 205 个测试全部通过，`cargo check` / `cargo clippy` 通过

---

## 一、执行摘要

SynapseVault 项目在架构层面完整覆盖了构建方案中定义的六大核心需求，各模块职责边界清晰，密码学选型严格遵循文档要求，测试覆盖率高（205 个测试全部通过）。整体代码质量处于中上水平，但在**安全擦除可靠性**、**gossipsub 网络参数合规性**、**错误处理完整性**以及**部分模块的健壮性边界**方面存在需要改进的项。

**综合评级：B+（良好，部分关键项需修复）**

---

## 二、功能完成度评估

### 2.1 六条核心需求覆盖情况

| # | 核心需求 | 完成状态 | 说明 |
|---|---------|---------|------|
| 1 | 同一网段局域网共享 / 纯分布式 / 自动同步 / 无中心认证 | ✅ 基本实现 | `libp2p` + `mDNS` + `gossipsub` + `CRDT` 全部到位，Swarm 构建与事件循环完整 |
| 2 | 分权管理：Admin / FreeUser / AuditUser | ✅ 完整实现 | RBAC 三角色体系、`check_permission`、`change_role`、`request_usage`/`approve_usage` 均实现并通过测试 |
| 3 | 强制密钥文件 + 密码双认证 / 成熟加密算法 | ✅ 完整实现 | Argon2id + XChaCha20-Poly1305 + ed25519 + HKDF 完整链路实现，.key 文件格式符合文档 10.4 节 |
| 4 | egui GUI / 创建组 / 自动发现 / Admin 确认 | ✅ 基本实现 | 解锁窗口、组管理、密码库、权限、审计面板全部存在；mDNS 发现 ↔ gossip 广播桥接逻辑待完善 |
| 5 | 审计日志：时间、设备指纹、IP、链上 ID | ⚠️ 部分实现 | 审计事件结构完整，本地日志记录完善；**P2P 广播的 AuditEventBrief 丢失 device_fingerprint / peer_id / signature 校验** |
| 6 | 区块链不可篡改审计 | ✅ 基本实现 | PoA 轻量链、Merkle 树、创世块、链验证、分叉处理、DB 持久化均实现；**AuditEvent 本身未包含 ed25519 签名** |

### 2.2 各模块文件完成度

| 模块 | 文件数 | 完成度 | 关键缺失/偏差 |
|------|--------|--------|--------------|
| `auth/` | 3 | 95% | `secure_zero` 包装了 `zeroize`，但 `UnlockedSession::zeroize` 对 `SigningKey` 的擦除方式存疑 |
| `crypto/` | 4 | 98% | 密码学实现与文档一致；`calibrate_argon2_params` 存在但 `reset_password` 未使用 |
| `group/` | 3 | 90% | 组创建、成员管理、CRDT OR-Set 均实现；`reject_join` 为空壳实现 |
| `rbac/` | 2 | 95% | 权限矩阵、角色变更、使用审批完整；`AuditUser` 审计日志权限未做自身过滤 |
| `secret/` | 4 | 92% | CRUD、per-secret 加密、分页、搜索、导入导出、剪贴板均实现；列表 `tags` 序列化格式前后不一致 |
| `p2p/` | 5 | 85% | Swarm、Noise、mDNS、gossipsub 均封装；**mesh 参数与文档要求不一致**；事件循环为骨架级 |
| `sync/` | 3 | 90% | CRDT 引擎、LWW 冲突解决、快照均实现；向量时钟在 `ops_since` 中的逻辑可优化 |
| `blockchain/` | 5 | 93% | Block、Chain、Merkle、PoA、Validator 均实现；多 Admin 出块轮换预留但未深度集成 |
| `audit/` | 3 | 88% | 事件结构、日志写入、导出均实现；**AuditEvent 缺少 ed25519 签名字段** |
| `storage/` | 3 | 95% | SQLCipher、Schema、迁移完整；Schema 与文档 4.8 节基本一致 |
| `ui/` | 12 | 90% | 解锁窗口、主布局、各面板、弹窗均存在；egui immediate mode 状态管理规范 |

### 2.3 测试覆盖

- **单元测试**：166 个，全部通过（含 crypto、auth、group、rbac、secret、blockchain、sync、p2p 等）
- **集成测试**：39 个，全部通过（含区块链-审计、P2P-组、RBAC-同步、Secret CRUD、解锁流程、渗透测试）
- **未发现**专门的 P2P 多节点端到端压力测试或长时间运行的网络分区恢复测试

---

## 三、安全与健壮性评估

### 3.1 密码学与密钥管理

| 项目 | 状态 | 说明 |
|------|------|------|
| Argon2id 参数 | ⚠️ | 首次生成使用 `calibrate_argon2_params(1000)` 动态校准，但 `reset_password` 硬编码 `Argon2Params::default()`，导致新旧密钥文件参数可能不一致 |
| 主密钥派生 | ✅ | `derive_master_key` → `derive_keyfile_key` → `derive_db_key` / `derive_secret_seed` 隔离清晰 |
| Per-secret 加密 | ✅ | `derive_per_secret_key` 基于 `secret_id` 独立派生，单条密码泄露不影响其他 |
| XChaCha20-Poly1305 nonce | ✅ | 192-bit 随机 nonce，使用 `rand::thread_rng()` |
| .key 文件格式 | ✅ | 完全符合文档 10.4 节：Magic + Version + Salt + Params + Nonce + EncData + PubKey + Fingerprint + Checksum |
| 校验和验证 | ✅ | SHA-256 校验和在 `decode_key_file` 中被验证 |

**关键安全问题：**

1. **`UnlockedSession` 安全擦除不可靠**（`src/auth/unlock.rs:33`）
   ```rust
   self.private_key = SigningKey::from_bytes(&[0u8; 32]);
   ```
   Rust 的移动语义意味着原 `SigningKey` 所占内存**不一定被覆盖**，编译器可能将原值留在栈/堆上的旧位置。应使用 `ed25519-dalek` 配合 `zeroize` feature 提供的 `Zeroize` trait，或显式调用 `zeroize()` 再丢弃。目前虽然实现了 `Drop`，但 `SigningKey` 内部字段的擦除效果依赖 `ed25519-dalek` 的实现，**建议显式验证**。

2. **`reset_password` 未重新校准 Argon2 参数**（`src/auth/keyfile.rs:115`）
   ```rust
   let argon2_params = Argon2Params::default();
   ```
   与首次生成时的 `calibrate_argon2_params(1000)` 行为不一致。如果用户在不同硬件上重置密码，参数可能不适合当前机器。

3. **`SecretStore::get_secret` 错误信息掩盖**（`src/secret/store.rs:150`）
   ```rust
   .map_err(|_| SecretEntryError::NotFound(secret_id.clone()))
   ```
   将所有 `rusqlite::Error`（包括数据库损坏、解密失败、SQL 语法错误）统一映射为 `NotFound`，掩盖了真实的故障原因，不利于安全审计和问题排查。

4. **SQLCipher 密钥以 hex 字符串驻留内存**（`src/storage/database.rs:43-47`）
   派生的 `db_key` 被转换为 `db_key_hex` 字符串传给 SQLCipher pragma，原始 `[u8; 32]` 数组虽然离开作用域但**未被 zeroize**，`db_key_hex` 字符串在堆上持续存在且 Rust 不保证其被覆写。应使用 SQLCipher 的原始密钥 pragma（`PRAGMA key = "x'...'"` 格式）或确保 hex 字符串在 Connection 建立后被安全擦除。

5. **`master_key` 全会话驻留内存**（`src/auth/unlock.rs:15-28`）
   `UnlockedSession` 持有 `master_key: [u8; 32]` 直到会话结束（可能数小时），从此密钥可派生所有子密钥（db_key、keyfile_key、secret_seed）。`Drop` 实现正确擦除了它，但会话期间密钥始终在内存中，且未使用 `mlock()` 防止换页暴露。建议使用 `zeroize::SecretBox` 或 OS 锁定内存机制。

6. **`SigningKey` 擦除使用可识别的全零模式**（`src/auth/unlock.rs:33`）
   `SigningKey::from_bytes(&[0u8; 32])` 用全零覆写，这是可识别的模式，对冷启动攻击的抵抗力不如随机覆写。应使用 `zeroize` crate 的 derive 宏或 `ed25519-dalek` 的 `zeroize` feature。

### 3.2 网络安全

| 项目 | 状态 | 说明 |
|------|------|------|
| Noise 协议加密 | ✅ | libp2p Noise + TCP/yamux + QUIC 组合 |
| gossipsub 消息认证 | ✅ | `MessageAuthenticity::Signed` 启用 |
| mesh 参数 | ❌ | 文档要求：`mesh_n_high=6`, `mesh_n_low=4`, `mesh_outbound_min=2`；实际代码为 `4`, `2`, `1`（`src/p2p/transport.rs:40-42`） |
| max_transmit_size | ✅ | 1 MiB，符合需求 |
| rate limiting | ⚠️ | 未在代码中显式配置 gossipsub 的 rate limiting，依赖 libp2p 默认行为 |
| 消息去重 / 重放防护 | ⚠️ | `P2pMessageEnvelope` 含 `nonce: u64`，但 `event_loop.rs` 中未见基于 nonce 的消息去重缓存实现；测试中的重放防护仅为文档级测试 |

7. **`seen_message_ids` 批量清空产生重放窗口**（`src/p2p/event_loop.rs:133-135`）
   当去重缓存达到 1000 条时，整个 `HashSet` 被 `clear()` 一次性清空，此时之前见过的消息可被重放。应改用 LRU 淘汰策略或基于时间的过期机制。

8. **mDNS 地址无去重累积**（`src/p2p/discovery.rs:46-49`）
   每次 `mDNS::Discovered` 事件都将地址 `push` 到 `peer_addresses[peer]`，同一 peer 的重复发现会导致地址列表无限增长，无去重或清理机制。

9. **mDNS 过期导致组丢失**（`src/p2p/discovery.rs:63-66`）
   当某个 peer 的 mDNS 记录过期时（WiFi 波动常见），整个组从 `discovered_groups` 中移除，即使该组内其他 peer 仍可达。应实现引用计数或组内多 peer 追踪。

**建议**：将 mesh 参数调整至文档要求值，或补充说明为何可降低参数；显式配置 `gossipsub` 的 rate limiting 防止 DoS；修复消息去重缓存策略。

### 3.3 访问控制与审计

| 项目 | 状态 | 说明 |
|------|------|------|
| RBAC 权限矩阵 | ✅ | 与文档 4.4 节权限矩阵一致 |
| Admin 自保护 | ✅ | `change_role` 阻止最后一个 Admin 被降级（`CannotChangeOwnRole` + `admin_count_after` 检查） |
| AuditUser 审批流程 | ✅ | `request_usage` → `approve_usage` → `UsageApproval` 含 TTL |
| 审计事件签名 | ❌ | `AuditEvent` 结构体**没有 `signature` 字段**，也未在创建时进行 ed25519 签名；文档 4.7 节明确要求 "ed25519 签名后打包入区块链 Block" |
| 区块链签名 | ✅ | Block 级别由 Admin 私钥签名 |
| 剪贴板自动清除 | ✅ | `SecureClipboard::copy_secure` 启动后台线程，30 秒后清除（仅当内容未变时） |

**关键安全问题：**

4. **审计事件缺少签名**  
   文档明确要求每次操作生成 `AuditEvent` 后需 `ed25519` 签名，但当前 `AuditEvent` 结构体（`src/audit/event.rs`）缺少 `signature: Signature` 字段，`audit::logger::log_event` 也未执行签名。这削弱了审计日志的抗抵赖性。

5. **`handle_audit_batch_sync` 伪造空字段**（`src/app.rs:544-572`）
   ```rust
   .with_secret_id(brief.target_secret_id.clone().unwrap_or_default());
   ```
   P2P 同步审计事件时，`device_fingerprint` 和 `peer_id` 被硬编码为空字符串，丢失了原始信息，且未验证 `AuditEventBrief.signature`。

### 3.4 数据存储与持久化

| 项目 | 状态 | 说明 |
|------|------|------|
| SQLCipher 加密 | ✅ | `bundled-sqlcipher-vendored-openssl` feature，密钥通过 HKDF 派生 |
| Schema 完整性 | ✅ | 7 张表 + 索引，与文档 4.8 节基本一致 |
| Schema 迁移 | ✅ | `migrate()` 支持版本升级，当前版本为 1 |
| 外键约束 | ✅ | `groups` / `members` / `secrets` / `blocks` / `audit_index` 均定义外键 |

### 3.5 CRDT 同步健壮性

| 项目 | 状态 | 说明 |
|------|------|------|
| LWW 冲突解决 | ⚠️ | Delete-vs-Update 并发场景下 Update 可能静默恢复已删除条目 |
| 待处理操作 | ⚠️ | 对不存在的 secret 执行 Update 时，数据存入 pending 但永远不会生效 |
| 版本号语义 | ⚠️ | Create-duplicate 与 Update 路径的版本号递增逻辑不一致 |
| 组成员 OR-Set | ❌ | CRDT 状态（`Orswot`）被 `#[serde(skip)]`，重启后丢失；单 actor 模式无法区分不同 Admin 操作 |

**关键问题：**

10. **Delete-vs-Update 并发导致静默恢复**（`src/sync/merge.rs:89-106`）
    当用户 A 删除一个 secret（版本 5），用户 B 同时更新同一 secret（版本 5→6），B 的 Update 因版本更高而胜出，**静默恢复了 Admin 明确删除的条目**。应在 LWW 合并中引入 tombstone 优先策略，或要求删除操作具有更高的冲突优先级。

11. **对不存在的 secret 执行 Update 丢失数据**（`src/sync/crdt_engine.rs:113-117`）
    Update 到达时若本地无对应 entry，数据被存入 `pending_ops` 但 `Create` 到达后会用自己的数据覆盖，导致先前的 Update 静默丢失。

12. **组 CRDT 状态重启后丢失**（`src/group/manager.rs:55-56`）
    `members: Orswot<MemberId, String>` 标记为 `#[serde(skip)]`，序列化时跳过。节点重启后 CRDT 操作日志为空，仅靠 `member_map` 恢复成员，可能导致合并后状态发散。

13. **CRDT 所有操作共用同一 actor**（`src/group/manager.rs:171,254,308`）
    `add` / `remove` 均以 `group_id` 作为 actor，不同 Admin 的并发操作共享同一向量时钟条目，无法区分操作来源，可能导致排序异常。

### 3.6 区块链分叉处理

| 项目 | 状态 | 说明 |
|------|------|------|
| 分叉检测 | ✅ | `resolve_fork` 实现了最长链优先 + hash 比较决胜 |
| 分叉恢复 | ❌ | 被替换链上的 `BlockchainOp` 静默丢失，无重新应用机制 |
| Validator 管理 | ⚠️ | 从 DB 加载时从历史签名者推断 validator，已被移除的 Admin 仍可能在列表中 |
| 主键设计 | ⚠️ | `blocks` 表以 `height` 为主键，多组共享 DB 时可能冲突 |

**关键问题：**

14. **分叉替换时孤立操作丢失**（`src/blockchain/chain.rs:233/244`）
    `resolve_fork` 直接替换 `self.blocks`，失败链上的 `BlockchainOp` 全部丢弃，无重新入队或合并逻辑。两个 Admin 同时出块时，必然有一方的操作被静默丢失。

15. **从 DB 加载的 validator 列表包含已移除 Admin**（`src/blockchain/chain.rs:162-169`）
    `load_from_db` 从所有历史 block 的 `signer_pubkey` 提取 validator，没有撤销机制。已被降级的 Admin 仍会出现在 validator 列表中。

16. **`blocks` 表主键缺少 `group_id`**（`src/storage/schema.rs:91`）
    `height` 是主键但 `group_id` 仅是普通列，多组共享数据库时同高度 block 会 `INSERT OR REPLACE` 互相覆盖。

### 3.7 输入验证

| 项目 | 状态 | 说明 |
|------|------|------|
| 密码最小长度 | ⚠️ | UI 要求 ≥8 字符，但 `generate_key_file` 接受空密码 |
| Secret 字段长度 | ❌ | `create_secret` / `update_secret` 所有字段无最大长度限制 |
| 组名验证 | ⚠️ | 仅 UI 层检查 ≤64 字符，API 层无验证 |
| 设备指纹 | ⚠️ | `request_join` 接受任意格式/长度的 `device_fingerprint` |

**关键问题：**

17. **`generate_key_file` 接受空密码**（`src/auth/keyfile.rs:348-352`）
    测试明确确认 `generate_key_file("")` 可成功执行。UI 要求 ≥8 字符，但 API 层无此约束。P2P 同步或程序化调用可能绕过 UI 验证，产生极弱密钥。

18. **Secret 字段无长度限制**（`src/secret/store.rs:42-110`）
    `create_secret` 的 `title`、`username`、`password`、`description` 等字段无最大长度检查，恶意或异常客户端可存入超大字符串导致内存耗尽或数据库膨胀。

19. **组名仅 UI 层验证**（`src/group/manager.rs:144-178`）
    `create_group` 函数本身不对 `name` 做长度或字符验证。P2P 同步创建的组可绕过 UI 的 64 字符限制。

### 3.8 威胁模型覆盖

| 威胁 | 缓解措施 | 评估 |
|------|---------|------|
| T1 ARP 欺骗 / MITM | Noise E2EE + 应用层加密 | ✅ 充分 |
| T2 WiFi 劫持 | mDNS 仅发现 + Admin 审批 | ✅ 充分 |
| T3 密钥文件被盗 | Argon2id + 设备指纹 | ⚠️ 设备指纹 fallback 到 `"unknown"` 时可能冲突 |
| T4 内存转储 | zeroize（部分可靠） | ⚠️ `SigningKey` 擦除方式需加固 |
| T5 恶意 Admin | 区块链 + 签名追溯 | ⚠️ 审计事件本身无签名，依赖 Block 级别签名 |
| T6 恶意节点泛洪 | gossipsub 参数 + 消息签名 | ⚠️ mesh 参数偏低，rate limit 未显式配置 |
| T7 离线暴力破解数据库 | SQLCipher AES-256 | ✅ 充分 |
| T8 剪贴板窃取 | 30 秒自动清除 | ✅ 充分 |
| T9 量子计算 | 未实现 `VaultCryptoScheme` trait | ❌ 文档 7.3 节预留的 trait 未实现 |
| T10 CRDT 并发删除恢复 | LWW 版本号决胜 | ❌ Update 可静默恢复已删除条目 |
| T11 分叉操作丢失 | 最长链优先 | ❌ 失败链操作无重新入队机制 |
| T12 输入长度无限制 | UI 层部分验证 | ❌ API 层缺少字段长度和格式校验 |
| T13 密钥换页暴露 | zeroize on Drop | ⚠️ 未使用 mlock 防止主密钥被换出到磁盘 |

---

## 四、编码规范性评估

### 4.1 代码风格与组织

- **模块划分**：清晰，与文档 4.1 节目录结构基本一致
- **错误处理**：大量使用 `thiserror` 定义结构化错误，类型安全
- **文档注释**：各模块顶部均有 `//!` 文档注释，关键函数有说明
- **命名规范**：Rust 命名规范（snake_case / PascalCase）严格遵守
- **unsafe 代码**：未发现 `unsafe` 块，符合预期

### 4.2 发现的规范性问题

1. **多处 `unused_variables` 警告**（`blockchain/chain.rs`, `blockchain/consensus.rs`, `tests/pentest.rs`）
   - 虽然不影响功能，但表明代码审查和清理工作可更细致

2. **`list_secrets` 与 `list_secrets_offset` 中 `tags` 序列化格式不一致**
   - `list_secrets`：使用 `serde_json::from_str` 解析 JSON 数组
   - `list_secrets_offset`：使用 `tags_str.split(',')` 按逗号分割
   - 这是潜在的 bug：如果 tags 包含 JSON 格式数据，分页查询会解析失败或行为异常

3. **`refresh_pending_requests` 使用占位符签名**（`src/app.rs:603`）
   ```rust
   signature: ed25519_dalek::Signature::from_bytes(&[0u8; 64]),
   ```
   为 PendingApproval 成员构造的 `JoinRequest` 使用了全零签名，若该请求被用于验证逻辑会导致误通过。

4. **`reject_join` 为空壳实现**（`src/group/manager.rs:275-283`）
   ```rust
   pub fn reject_join(...) -> Result<(), GroupError> {
       Ok(())
   }
   ```
   拒绝操作无任何状态变更或通知机制，与文档 4.3 节要求的 "签名上链" 不符。

5. **`calibrate_argon2_params` 未在 `reset_password` 中使用**
   - 文档 4.2 节强调 Argon2id 参数应记录并可展示，`reset_password` 却使用了默认参数

6. **SQL 拼接（LIMIT/OFFSET）**（`src/audit/logger.rs:105-109`）
   ```rust
   sql.push_str(&format!(" LIMIT {}", limit));
   ```
   虽然 `limit` 和 `offset` 是 `usize` 类型，但直接格式化拼接 SQL 不是最佳实践，应使用参数化查询。

### 4.3 测试规范

- 单元测试覆盖核心逻辑 ✅
- 集成测试覆盖跨模块流程 ✅
- `#[cfg(all(test, not(miri)))]` 使用得当，避免 Miri 无法运行的测试 ✅
- 渗透测试框架（`tests/pentest.rs`）存在但偏文档化，建议增加实际的异常输入模糊测试

---

## 五、与构建方案文档的关键偏差

| 偏差项 | 文档要求 | 实际实现 | 影响等级 |
|--------|---------|---------|---------|
| gossipsub mesh 参数 | `mesh_n_high=6`, `mesh_n_low=4`, `mesh_outbound_min=2` | `4`, `2`, `1` | 中 |
| AuditEvent 签名 | 含 `signature: Signature` 字段 | **缺少该字段** | **高** |
| 审计事件上链签名 | 每条操作 `ed25519` 签名后打包 | 仅 Block 级别签名 | **高** |
| `VaultCryptoScheme` trait | 预留后量子切换接口 | 未实现 | 低 |
| CRDT Delete-vs-Update 并发 | 删除应优先 / 有审计 | Update 版本更高可静默恢复已删除条目 | **高** |
| 组 CRDT 状态持久化 | 序列化应保留 Orswot 状态 | `#[serde(skip)]` 导致重启后丢失 | 中 |
| 区块链分叉操作保留 | 失败链操作应重新入队 | 直接丢弃，无恢复机制 | **高** |
| 输入验证（API 层） | 字段长度 / 格式校验 | 仅 UI 层验证，API 无约束 | 中 |
| `generate_key_file` 密码强度 | 应拒绝弱密码 | 接受空密码 | 中 |
| `reset_password` Argon2 参数 | 应与首次生成一致 | 使用 `default()` | 中 |
| `egui_extras` 版本 | ≥0.26（文档附录） | 0.34.1（与 egui 一致） | 无影响 |
| libp2p 版本 | ≥0.49.4，推荐 0.54 | **0.56** | 无影响（更新更好） |
| `bundled-sqlcipher` | 文档附录使用 | `bundled-sqlcipher-vendored-openssl` | 无影响（等价） |

---

## 六、优先修复建议

### 🔴 P0（必须修复）

1. **为 `AuditEvent` 增加 `signature` 字段并在创建时签名**  
   这是文档核心安全要求之一，缺失会导致审计日志无法抗抵赖。修改 `AuditEvent` 结构体 + `audit::event::AuditEvent::new()` 流程，使用用户私钥对 `event_hash` 签名。

2. **统一 `tags` 在数据库查询中的解析逻辑**  
   `list_secrets_offset` 应与 `list_secrets` 一致使用 `serde_json::from_str`，否则分页功能可能解析错误。

3. **移除 `get_secret` 的错误掩盖**
   区分 `NotFound`（行不存在）与真正的数据库错误，避免安全问题被隐藏。

4. **修复 CRDT Delete-vs-Update 并发导致静默恢复**（`src/sync/merge.rs:89-106`）
   在 LWW 合并中引入 tombstone 优先策略，确保 Admin 的删除操作不会被并发 Update 静默覆盖。

5. **修复区块链分叉替换时操作丢失**（`src/blockchain/chain.rs:233/244`）
   `resolve_fork` 替换链时应将失败链上的 `BlockchainOp` 重新入队或合并到待处理队列，而非静默丢弃。

### 🟡 P1（强烈建议）

6. **修复 `UnlockedSession::zeroize` 中 `SigningKey` 的可靠擦除**
   验证 `ed25519-dalek` 的 `SigningKey` 是否在赋值时安全擦除原内存；若不可靠，考虑使用 `secrecy` crate 或手动覆盖原内存后再丢弃。同时修复全零覆写模式，改用 `zeroize` derive 宏。

7. **对齐 gossipsub mesh 参数或补充设计说明**
   将 `mesh_n_high=6`, `mesh_n_low=4`, `mesh_outbound_min=2` 设为默认值，或编写设计决策文档说明为何降低参数。

8. **实现 `reject_join` 的完整逻辑**
   至少记录拒绝审计日志，或向请求者发送拒绝通知。

9. **`reset_password` 使用 `calibrate_argon2_params`**
   保证密钥文件参数行为一致。

10. **修复组 CRDT 状态序列化丢失**
    移除 `Orswot<MemberId, String>` 上的 `#[serde(skip)]`，或将 CRDT 操作日志独立持久化，确保重启后合并不发散。同时为不同 Admin 使用不同 actor 标识。

11. **为 API 层增加输入验证**
    `generate_key_file` 应拒绝空/弱密码；`create_secret` 应限制字段最大长度；`create_group` 应在 API 层校验组名长度和字符。

12. **修复 `seen_message_ids` 批量清空策略**
    改用 LRU 缓存或基于时间的过期淘汰，避免清空瞬间产生重放窗口。

### 🟢 P2（建议优化）

13. **`handle_audit_batch_sync` 验证远程审计事件签名**
    不应对同步事件盲目信任，至少验证 `AuditEventBrief.signature`。

14. **减少 SQL 格式化拼接**
    `audit/logger.rs` 中的 `LIMIT` / `OFFSET` 应改为 `params!` 参数化。

15. **清理编译器警告**
    修复 `unused_variables` 和 `unused_mut` 警告，保持代码整洁。

16. **SQLCipher 密钥 hex 字符串安全擦除**
    `db_key_hex` 在 Connection 建立后应被安全擦除，或改用原始密钥 pragma 格式。

17. **区块链 validator 列表增加撤销机制**
    `load_from_db` 应结合当前 RBAC 角色过滤 validator 列表，排除已降级的 Admin。

18. **`blocks` 表主键加入 `group_id`**
    避免多组共享数据库时同高度 block 互相覆盖。

---

## 七、总结

SynapseVault 是一个架构设计良好、密码学基础扎实、测试覆盖充分的去中心化密码管理项目。代码在**功能实现层面**基本对标了构建方案文档的 Phase 0~5 目标，但在以下方面存在需要改进的项：

- **安全细节**：审计事件签名缺失、gossipsub 参数不符、安全擦除可靠性、密钥内存驻留
- **编码一致性**：tags 解析不一致、错误处理掩盖
- **数据一致性**：CRDT Delete-vs-Update 静默恢复已删除条目、区块链分叉操作丢失、组 CRDT 重启后状态丢失
- **输入验证**：API 层缺少字段长度和格式校验，弱密码可绕过 UI 限制
- **网络健壮性**：消息去重缓存策略缺陷、mDNS 发现机制边界问题

如果团队能优先修复 P0 级别的 5 项问题（审计签名、tags 解析、错误掩盖、CRDT 并发删除恢复、分叉操作丢失），并加固 P1 级别的安全擦除、网络参数和输入验证，项目可达到 **A 级** 代码质量水准，具备发布 v1.0 的技术基础。
