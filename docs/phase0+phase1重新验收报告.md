# Phase 0 + Phase 1 重新验收报告

> **项目**：SynapseVault
> **阶段**：Phase 0 & Phase 1 重新验收
> **验收日期**：2026-04-20
> **结论**：✅ **双阶段均通过，允许开始 Phase 2**

---

## 一、Phase 0 重新验收

### 1.1 交付物逐项审查

| # | 交付项 | 状态 | 说明 |
|---|--------|------|------|
| 1 | 初始化 Cargo 项目 + 目录结构 | ✅ 通过 | 11 个模块及全部子模块文件与方案§4.1一致 |
| 2 | 配置 Cargo.toml 所有依赖 | ✅ 通过 | 全部核心依赖已配置（含 SQLCipher，见§1.2） |
| 3 | 搭建 CI（GitHub Actions） | ✅ 通过 | fmt/check/clippy/audit 四项 + 三平台测试矩阵 |
| 4 | 实现 main.rs 入口 + 空壳 SynapseVaultApp | ✅ 通过 | 完整状态机 + eframe::App trait |
| 5 | egui 空界面渲染通过 | ✅ 通过 | cargo check + cargo test 均通过 |
| 6 | 确认跨平台编译 | ✅ 通过 | CI 矩阵覆盖三平台；本地 Windows cargo build 通过 |

**6/6 通过。**

### 1.2 原延期项 TODO-P2-001 状态

| 属性 | 值 |
|------|-----|
| **问题** | rusqlite 需从 `bundled` 切换为 `bundled-sqlcipher-vendored-openssl` |
| **当前配置** | `rusqlite = { version = "0.39", features = ["bundled-sqlcipher-vendored-openssl"] }` |
| **位置** | Cargo.toml:34 |
| **状态** | ✅ **已修复** — Windows 本地 `cargo build` 通过 |

---

## 二、Phase 1 重新验收

### 2.1 交付物逐项审查

| # | 交付项 | 状态 | 说明 |
|---|--------|------|------|
| 1 | `crypto/kdf.rs`：Argon2id 密钥派生 | ✅ 通过 | 参数默认值与方案一致（m=65536,t=3,p=4）；HKDF 三路隔离（db:key / keyfile:enc / secret:seed）互异 |
| 2 | `crypto/symmetric.rs`：XChaCha20-Poly1305 | ✅ 通过 | 加解密循环、错误密钥、错误 nonce、篡改密文、空明文、1MiB 大数据均通过 |
| 3 | `crypto/signing.rs`：ed25519 签名与验签 | ✅ 通过 | 密钥对生成、签名验证、错误消息/错误密钥、字节恢复均通过 |
| 4 | `crypto/key_derivation.rs`：per-secret 密钥派生 | ✅ 通过 | 确定性派生、不同 secret_id 隔离、不同 seed 隔离均通过 |
| 5 | `auth/keyfile.rs`：.key 文件生成与读写 | ✅ 通过 | `generate_key_file` 返回三元组含 master_key；编解码循环、校验和、重置密码含 zeroize 均通过 |
| 6 | `auth/unlock.rs`：双认证解锁流程 | ✅ 通过 | 解锁/错误密码/错误指纹/无效文件/公钥一致性验证均通过；`UnlockedSession` 含 `public_key` 字段 |
| 7 | `auth/device_fingerprint.rs`：设备指纹 | ✅ 通过 | 确定性、不同公钥隔离、格式校验、重构匹配均通过 |
| 8 | `ui/unlock_window.rs`：解锁窗口 UI | ✅ 通过 | 首次设置/解锁双模式、密码显示切换、文件浏览按钮、Spinner 加载中状态 |
| 9 | zeroize 安全擦除 | ✅ 通过 | UnlockedSession Drop 擦除；reset_password 中 private_key_bytes 已 zeroize |
| 10 | 单元测试 | ✅ 通过 | 44 测试全部通过（36 单元 + 8 集成）；clippy 零警告 |

**10/10 通过。**

### 2.2 原致命 Bug 和高优先级问题修复验证

#### BUG-P1-001（致命）：首次设置后永远无法解锁 — 设备指纹与公钥不一致

| 属性 | 值 |
|------|-----|
| **修复状态** | ✅ **已修复** |
| **验证方式** | 代码审查 + 集成测试 `test_full_unlock_flow_from_disk` |

**修复验证**：

- `generate_key_file` 签名改为 `fn(master_password: &str) -> Result<(KeyFile, SigningKey, [u8; 32])>` — 内部先生成密钥对再用同一公钥生成指纹（keyfile.rs:67-103）
- `handle_first_setup` 不再额外调用 `generate_keypair()` 或 `generate_device_fingerprint()`，直接调用 `generate_key_file(&password)`，再从 `key_file.public_key` 生成指纹（app.rs:193-218）
- `handle_unlock` 从解码后的 `key_file.public_key` 重新生成指纹（app.rs:269-270）
- 集成测试 `test_full_unlock_flow_from_disk` 模拟完整磁盘读写路径，验证生成→保存→读取→用公钥重建指纹→解锁 的端到端流程

**数据流现在一致**：`generate_key_file` 内部的 keypair → fingerprint 绑定到同一密钥对，解锁时从 `key_file.public_key` 重建的指纹必然匹配。

---

#### ISS-P1-002（高）：首次设置时 Argon2id 在主线程执行导致 UI 卡死

| 属性 | 值 |
|------|-----|
| **修复状态** | ✅ **已修复** |
| **验证方式** | 代码审查 |

`handle_first_setup` 的整个密钥文件生成和 Argon2id 计算流程已移入 `std::thread::spawn`（app.rs:191-229），复用 `self.unlock_result` 的 `Arc<Mutex>` 机制。UI 线程在 `UnlockState::Unlocking` 期间持续重绘并显示 Spinner，不会卡死。

---

#### ISS-P1-003（高）：UnlockedSession 缺少 public_key 字段

| 属性 | 值 |
|------|-----|
| **修复状态** | ✅ **已修复** |
| **验证方式** | 代码审查 + 测试断言 |

`UnlockedSession` 现包含 `pub public_key: ed25519_dalek::VerifyingKey`（unlock.rs:19），在 `unlock_key_file`（unlock.rs:137）和 `handle_first_setup`（app.rs:221）中均正确赋值。测试 `test_unlock_success` 验证 `session.public_key == key_file.public_key`（unlock.rs:164）。

---

#### ISS-P1-004（中高）：Argon2id 重复计算

| 属性 | 值 |
|------|-----|
| **修复状态** | ✅ **已修复** |
| **验证方式** | 代码审查 |

`generate_key_file` 返回三元组 `(KeyFile, SigningKey, [u8; 32])`，第三个元素为 master_key（keyfile.rs:103）。`handle_first_setup` 直接使用返回的 master_key 创建 UnlockedSession，无需二次调用 `derive_master_key`。

---

#### ISS-P1-005（中）：reset_password 中 private_key_bytes 未 zeroize

| 属性 | 值 |
|------|-----|
| **修复状态** | ✅ **已修复** |
| **验证方式** | 代码审查 |

`private_key_bytes` 声明为 `let mut`（keyfile.rs:122），函数末尾调用 `private_key_bytes.zeroize()`（keyfile.rs:135）。

---

#### ISS-P1-006（中）：密钥文件默认路径不规范

| 属性 | 值 |
|------|-----|
| **修复状态** | ✅ **已修复** |
| **验证方式** | 代码审查 |

使用 `dirs::data_dir().join("synapsevault").join("synapsevault.key")`（app.rs:63-68），`dirs = "6.0"` 已在 Cargo.toml 中配置。

---

#### ISS-P1-007（中）：密钥文件路径无文件选择器

| 属性 | 值 |
|------|-----|
| **修复状态** | ✅ **已修复** |
| **验证方式** | 代码审查 |

UI 层添加"浏览..."按钮（unlock_window.rs:87-89），触发 `UnlockAction::BrowseKeyFile`。App 层使用 `rfd::FileDialog` 弹出原生文件对话框（app.rs:150-159），首次设置模式用 `save_file()`，解锁模式用 `pick_file()`。`rfd = "0.15"` 已在 Cargo.toml 中配置。

---

### 2.3 原低优先级观察项状态

| # | 观察 | 当前状态 |
|---|------|---------|
| O-001 | `UnlockState` 枚举设计偏离方案 | 保持现状 — 当前 `UnlockState + session: Option` 分离方案可行，BUG-P1-001 修复后不存在状态不一致风险 |
| O-002 | 主密码强度校验过弱 | 保持现状 — `len() < 8` 为最低标准，可在后续阶段增强 |
| O-003 | `reset_password` 签名偏离方案 | 保持现状 — 当前实现更安全（要求先解锁再重置） |
| O-004 | `verify_device_fingerprint` 函数缺失 | 保持现状 — 逻辑内联在 `unlock_key_file` 中，无重复代码 |
| O-005 | 测试名称误导 | 已修正 — 原 `test_empty_password_fails_argon2` 已更名为 `test_empty_password_allowed_by_argon2`（keyfile.rs:345） |
| O-006 | eframe::App trait 使用新 API | ✅ 正确 — 使用 `fn ui()` 而非已废弃的 `fn update()` |

---

## 三、验证结果汇总

| 检查项 | 结果 |
|--------|------|
| `cargo check` | ✅ 通过 |
| `cargo build`（含 SQLCipher） | ✅ 通过 |
| `cargo test --lib` | ✅ 36 tests passed |
| `cargo test`（含集成测试） | ✅ 44 tests passed（36 单元 + 8 集成） |
| `cargo clippy -- -W clippy::all -W clippy::unwrap_used` | ✅ 零警告 |
| 首次设置 → 保存 → 读取 → 解锁 完整流程 | ✅ 通过（集成测试 `test_full_unlock_flow_from_disk`） |
| 首次设置 UI 响应性 | ✅ 通过（Argon2id 在独立线程执行） |

---

## 四、Phase 2 准入评估

### 4.1 Phase 2 前置条件检查

| # | 前置条件 | 状态 |
|---|---------|------|
| 1 | Phase 0 所有交付物通过 | ✅ |
| 2 | Phase 1 所有交付物通过 | ✅ |
| 3 | BUG-P1-001 已修复 | ✅ |
| 4 | TODO-P2-001 已修复（SQLCipher 可编译） | ✅ |
| 5 | `cargo test` 全部通过 | ✅ |
| 6 | `cargo clippy` 零警告 | ✅ |

### 4.2 Phase 2 交付物清单（来自方案文档§8）

| # | 交付项 | 说明 |
|---|--------|------|
| 1 | `storage/database.rs`：SQLCipher 连接管理 | 依赖 TODO-P2-001 已修复 |
| 2 | `storage/schema.rs`：数据库 Schema | — |
| 3 | `secret/entry.rs`：密码条目数据结构 | — |
| 4 | `secret/store.rs`：密码 CRUD 操作 | — |
| 5 | `crypto/key_derivation.rs`：per-secret 密钥派生 | ⚡ 已在 Phase 1 提前完成 |
| 6 | `secret/clipboard.rs`：安全剪贴板 | — |
| 7 | `ui/secret_panel.rs`：密码库面板 UI | — |
| 8 | `ui/dialogs/view_secret.rs`：查看密码弹窗 | — |
| 9 | 集成测试：密码增删改查完整流程 | — |

**注意**：`crypto/key_derivation.rs` 已在 Phase 1 提前实现并通过测试，Phase 2 实际仅需完成 8 项交付物。

---

> **验收结论**：Phase 0 和 Phase 1 重新验收均**通过**。原致命 Bug BUG-P1-001 及全部 6 个高/中优先级问题均已修复验证。Phase 0 延期项 TODO-P2-001（SQLCipher）已修复且编译通过。**允许开始 Phase 2 开发。**
