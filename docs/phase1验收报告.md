# Phase 1 验收报告

> **项目**：SynapseVault
> **阶段**：Phase 1 — 双认证 + 加密核心
> **验收日期**：2026-04-20
> **结论**：❌ **不通过，存在 1 个致命 Bug 和多个高优先级问题，必须修复后重新验收**

---

## 一、Phase 1 交付物逐项审查

| # | 交付项 | 状态 | 说明 |
|---|--------|------|------|
| 1 | `crypto/kdf.rs`：Argon2id 密钥派生 | ✅ 通过 | 参数默认值与方案一致（m=65536,t=3,p=4）；HKDF-SHA256 派生隔离正确（db:key / keyfile:enc / secret:seed 三路互异） |
| 2 | `crypto/symmetric.rs`：XChaCha20-Poly1305 | ✅ 通过 | 加解密循环、错误密钥、错误 nonce、篡改密文、空明文、1MiB 大数据均通过 |
| 3 | `crypto/signing.rs`：ed25519 签名与验签 | ✅ 通过 | 密钥对生成、签名验证、错误消息/错误密钥、字节恢复均通过 |
| 4 | `crypto/key_derivation.rs`：per-secret 密钥派生 | ✅ 通过 | 确定性派生、不同 secret_id 隔离、不同 seed 隔离均通过 |
| 5 | `auth/keyfile.rs`：.key 文件生成与读写 | ⚠️ 有条件通过 | 编解码循环、校验和、重置密码通过；**但与 app.rs 集成存在致命 Bug**（见 BUG-P1-001） |
| 6 | `auth/unlock.rs`：双认证解锁流程 | ⚠️ 有条件通过 | 解锁/错误密码/错误指纹/无效文件通过；**UnlockedSession 缺少 public_key 字段**（见 ISS-P1-003） |
| 7 | `auth/device_fingerprint.rs`：设备指纹 | ✅ 通过 | 确定性、不同公钥隔离、格式校验、重构匹配均通过 |
| 8 | `ui/unlock_window.rs`：解锁窗口 UI | ✅ 通过 | 首次设置/解锁双模式渲染正确，密码显示切换、错误提示、Spinner 加载中状态均已实现 |
| 9 | zeroize 安全擦除 | ⚠️ 有条件通过 | UnlockedSession Drop 擦除通过；**reset_password 中 private_key_bytes 未擦除**（见 ISS-P1-005） |
| 10 | 单元测试 | ✅ 通过 | 36 个单元测试全部通过；clippy 零警告 |

---

## 二、致命 Bug（必须立即修复）

### BUG-P1-001：首次设置后永远无法解锁 — 设备指纹与公钥不一致

| 属性 | 值 |
|------|-----|
| **严重程度** | 🔴 **致命** |
| **位置** | `src/app.rs:174-176`（handle_first_setup） |
| **影响** | 用户完成首次设置后，再次启动应用输入正确密码也无法解锁，永远被 FingerprintMismatch 拦截 |

**根因分析**：

`handle_first_setup` 的执行流程：

```
1. let (_sk, vk) = generate_keypair();          ← 生成密钥对 A
2. let fp = generate_device_fingerprint(&vk);   ← 用 A 的公钥生成指纹
3. let (key_file, signing_key) = generate_key_file("密码", &fp);
   └── 内部: let (signing_key, verifying_key) = generate_keypair(); ← 生成密钥对 B
   └── key_file.public_key = B 的公钥
   └── key_file.device_fingerprint = fp.combined ← 包含 SHA256(A 的公钥)
```

密钥文件中存储了**密钥对 B 的公钥**，但设备指纹包含的是**密钥对 A 的公钥哈希**。

当用户下次启动尝试解锁时（`handle_unlock`）：

```
1. decode_key_file → key_file.public_key = B 的公钥
2. let fp = generate_device_fingerprint(&key_file.public_key) ← 用 B 的公钥生成指纹
3. unlock_key_file → 比对 key_file.device_fingerprint 与 fp.combined
4. "SHA256(A_pubkey)" ≠ "SHA256(B_pubkey)" → FingerprintMismatch ❌
```

**为什么单元测试没有发现**：测试直接传入同一个 `fp` 给 `generate_key_file` 和 `unlock_key_file`，两侧比对一致。但真实 App 中，`unlock_key_file` 的 `expected_fingerprint` 是从 `key_file.public_key` 重新生成的，与存储的指纹不一致。

**修复方案**：

修改 `generate_key_file` 函数签名，移除 `device_fingerprint` 参数，改为内部先生成密钥对再生成指纹：

```rust
// 修改前
pub fn generate_key_file(
    master_password: &str,
    device_fingerprint: &DeviceFingerprint,
) -> Result<(KeyFile, SigningKey), KeyFileError>

// 修改后
pub fn generate_key_file(
    master_password: &str,
) -> Result<(KeyFile, SigningKey), KeyFileError> {
    let salt = generate_salt();
    let argon2_params = Argon2Params::default();
    let master_key = derive_master_key(master_password, &salt, &argon2_params)?;

    let (signing_key, verifying_key) = generate_keypair();  // 先生成密钥对
    let fp = generate_device_fingerprint(&verifying_key);    // 再用同一公钥生成指纹
    // ... 加密私钥 ...
    let key_file = KeyFile {
        device_fingerprint: fp.combined,  // 指纹与公钥一致
        public_key: verifying_key,
        // ...
    };
    Ok((key_file, signing_key))
}
```

`handle_first_setup` 中相应移除多余 keypair 生成和指纹生成代码。

---

## 三、高优先级问题

### ISS-P1-002：首次设置时 Argon2id 在主线程执行导致 UI 卡死

| 属性 | 值 |
|------|-----|
| **严重程度** | 🟠 **高** |
| **位置** | `src/app.rs:152-222`（handle_first_setup） |
| **方案文档引用** | §10.5 第 2 条："必须在独立线程执行，通过 Arc<Mutex<UnlockState>> 传递状态" |

`handle_unlock` 正确地在 `std::thread::spawn` 中执行 Argon2id，但 `handle_first_setup` 直接在 egui 主线程中执行 `generate_key_file`（内部含 Argon2id）和第二次 `derive_master_key`。两次 Argon2id 合计耗时 **2-6 秒**，期间 UI 完全无响应。

**修复方案**：将 `handle_first_setup` 的密钥文件生成和 Argon2id 计算移入 `std::thread::spawn`，复用 `self.unlock_result` 的 Arc<Mutex> 机制。

---

### ISS-P1-003：UnlockedSession 缺少 public_key 字段

| 属性 | 值 |
|------|-----|
| **严重程度** | 🟠 **高** |
| **位置** | `src/auth/unlock.rs:14-24` |
| **方案文档引用** | §4.2 UnlockedSession 定义包含 `pub public_key: VerifyingKey` |

方案文档明确要求 `UnlockedSession` 包含 `public_key` 字段，用于节点身份标识。当前实现仅通过 `private_key.verifying_key()` 间接获取，违反了接口设计。

**修复方案**：在 `UnlockedSession` 中添加 `pub public_key: VerifyingKey` 字段，并在 `unlock_key_file` 和 `handle_first_setup` 中赋值。

---

### ISS-P1-004：Argon2id 重复计算（首次设置执行两次）

| 属性 | 值 |
|------|-----|
| **严重程度** | 🟡 **中高** |
| **位置** | `src/app.rs:176 + 199-209` |
| **性能影响** | 白白增加 1-3 秒延迟 |

`generate_key_file` 内部调用 `derive_master_key` 后将 master_key zeroize 且不返回。`handle_first_setup` 随后又调用 `derive_master_key` 获取 master_key 给 UnlockedSession。

**修复方案**：`generate_key_file` 返回 `(KeyFile, SigningKey, [u8; 32])` 三元组，第三个元素为 master_key（由调用方负责 zeroize）。或新增 `generate_key_file_with_master_key` 函数接受外部传入的 master_key。

---

### ISS-P1-005：reset_password 中 private_key_bytes 未 zeroize

| 属性 | 值 |
|------|-----|
| **严重程度** | 🟡 **中** |
| **位置** | `src/auth/keyfile.rs:125` |
| **对比** | 同函数中 master_key_copy 和 keyfile_key_copy 正确 zeroize |

```rust
// 当前代码（第125行）
let private_key_bytes = signing_key.to_bytes();
// ... 使用 private_key_bytes ...
// ⚠️ 没有 private_key_bytes.zeroize()
```

**修复方案**：添加 `let mut private_key_bytes = signing_key.to_bytes();` 并在函数末尾调用 `private_key_bytes.zeroize();`。

---

### ISS-P1-006：密钥文件默认路径不规范

| 属性 | 值 |
|------|-----|
| **严重程度** | 🟡 **中** |
| **位置** | `src/app.rs:63-66` |
| **方案文档引用** | §4.8："数据库文件默认存储在 {用户数据目录}/synapsevault/" |

当前默认路径为 `std::env::current_dir()/synapsevault.key`，密钥文件将保存在工作目录（可能为任意位置），而非用户数据目录。

**修复方案**：

```rust
let default_key_path = dirs::data_dir()  // 需要添加 dirs crate 依赖
    .unwrap_or_else(|| std::path::PathBuf::from("."))
    .join("synapsevault")
    .join("synapsevault.key");
```

---

### ISS-P1-007：密钥文件路径无文件选择器

| 属性 | 值 |
|------|-----|
| **严重程度** | 🟡 **中** |
| **位置** | `src/ui/unlock_window.rs:81-85` |
| **用户体验影响** | 用户必须手动输入完整路径，极易出错 |

当前 UI 只有一个 TextEdit 输入框，没有"浏览"按钮和文件选择对话框。

**修复方案**：添加 `egui::Button::new("浏览...")` 按钮，使用 `rfd` (Rust File Dialog) crate 弹出原生文件选择对话框。

---

## 四、低优先级 / 观察项

| # | 观察 | 优先级 | 说明 |
|---|------|--------|------|
| O-001 | `UnlockState` 枚举设计偏离方案 | 信息 | 方案定义 `UnlockState::Unlocked(UnlockedSession)`，实现为 `UnlockState::Unlocked + session: Option<UnlockedSession>` 分离存储。当前方案可行但存在状态不一致风险；如修复 BUG-P1-001 时重构为方案设计更好 |
| O-002 | 主密码强度校验过弱 | 低 | 仅检查 `len() < 8`，建议增加字符集多样性检查或 zxcvbn 评分 |
| O-003 | `reset_password` 签名偏离方案 | 信息 | 方案要求 `reset_password(key_file_path, old_password, new_password)`，实现为 `reset_password(key_file, signing_key, new_password)`。当前实现更安全（要求先解锁再重置），但签名不一致 |
| O-004 | `verify_device_fingerprint` 函数缺失 | 低 | 方案§4.2定义了独立函数，当前逻辑内联在 `unlock_key_file` 中 |
| O-005 | 测试 `test_empty_password_fails_argon2` 名称误导 | 信息 | 函数名暗示空密码会导致 Argon2 失败，但测试断言 `result.is_ok()`（Argon2 确实接受空密码）。应重命名或改为验证空密码被 UI 层拦截 |
| O-006 | eframe::App trait 使用新 API `fn ui()` | ✅ 正确 | eframe 0.34.1 中 `fn update()` 已标记 `#[deprecated]`，`fn ui()` 是推荐 API。方案文档中的 `fn update()` 示例已过时 |

---

## 五、Phase 0 延期项状态

### TODO-P2-001：rusqlite 切换为 bundled-sqlcipher-vendored-openssl

| 属性 | 值 |
|------|-----|
| **严重程度** | 🟡 **高**（Phase 2 前必须修复） |
| **当前配置** | `rusqlite = { version = "0.39", features = ["bundled"] }` |
| **目标配置** | `rusqlite = { version = "0.39", features = ["bundled-sqlcipher-vendored-openssl"] }` |
| **位置** | `Cargo.toml:34` |
| **原始延期原因** | Windows 本地开发环境缺少 Strawberry Perl，vendored OpenSSL 无法编译 |
| **当前状态** | 🔴 **待修复** — Phase 1 修复周期内必须完成，否则 Phase 2 无法使用加密数据库 |

**修复前置条件**：
- 安装 Strawberry Perl（Windows 本地编译 OpenSSL 所需）
- 或使用预编译 OpenSSL 并设置 `OPENSSL_DIR` 环境变量
- CI 需确认 `cargo install cargo-audit` 与 SQLCipher 编译兼容

**背景**：方案文档§3.1要求使用 SQLCipher 加密数据库。`bundled` 仅为标准 SQLite，不具备加密能力。Phase 0/1 骨架阶段不涉及实际数据库操作，暂不影响功能；但进入 Phase 2 实现存储层时**必须**切换为 `bundled-sqlcipher-vendored-openssl`，因此须在 Phase 1 修复周期内一并解决。

现有Strawberry Perl安装路径：C:\Users\ikrx2\Desktop\project\strawberry-perl

---

## 六、验证结果

| 检查项 | 结果 |
|--------|------|
| `cargo test --lib` | ✅ 36 tests passed |
| `cargo test`（集成） | ✅ 5 tests passed |
| `cargo clippy -- -W clippy::all -W clippy::unwrap_used` | ✅ 零警告 |
| 首次设置 → 锁定 → 解锁 流程 | ❌ **解锁永远失败**（BUG-P1-001） |
| 首次设置 UI 响应性 | ❌ **UI 卡死 2-6 秒**（ISS-P1-002） |

---

## 七、给 AI Coding Agent 的具体修正指南

### 核心问题诊断

当前 AI Agent 在 Phase 1 编码中暴露了以下思维缺陷，导致上述 Bug 和问题：

**1. 数据流未端到端推演**

Agent 在编写 `handle_first_setup` 时，调用了 `generate_keypair()` 生成指纹，却未意识到 `generate_key_file` 内部会生成**另一个不同的**密钥对。Agent 缺乏"追踪数据从产生到消费的完整路径"的意识。

**具体做法**：每写一个函数调用，必须追踪其内部产生的数据是否与调用方的预期一致。对于涉及密钥/ID/指纹等身份绑定的场景，必须验证"谁生成了什么、谁消费了什么"的完整链条。

**2. 未对照方案文档的显式约束**

方案文档§10.5第2条明确写了"必须在独立线程执行"，但 Agent 只对 `handle_unlock` 遵守了此约束，`handle_first_setup` 却遗漏了。Agent 存在"部分遵守、部分遗漏"的模式。

**具体做法**：在开始编码前，将方案文档中所有"必须"/"禁止"/"注意"等约束性语句提取为 checklist，编码完成后逐条对照。不要依赖"我记得要这样做"，而是强制用 checklist 验证。

**3. 测试未模拟真实调用路径**

`test_unlock_success` 测试直接构造了 `fp` 并传给两处，但真实 App 的调用路径是从 `key_file.public_key` 重新生成 `fp`。测试通过了，但真实场景失败了。

**具体做法**：每个单元测试必须至少有一个变体模拟**真实的集成调用路径**，而非仅测试函数在理想输入下的行为。对于涉及多模块协作的功能，必须编写集成级别的端到端测试。

**4. 重复计算未感知**

Agent 在 `generate_key_file` 内部 zeroize 了 master_key 但未返回，然后在 `handle_first_setup` 中又重新计算一次。Agent 没有意识到两次 Argon2id 调用的性能代价。

**具体做法**：对耗时操作（Argon2id、网络 I/O、磁盘 I/O）的调用次数必须显式审计。如果同一数据需要多处使用，应在设计函数签名时就规划好返回值，避免"用完即丢、之后重算"。

---

### 修复优先级和具体步骤

按以下顺序修复，每步修复后运行 `cargo test --lib` 和 `cargo clippy` 验证：

**Step 1 — 修复 BUG-P1-001（致命）**：

1. 修改 `src/auth/keyfile.rs`：`generate_key_file` 移除 `device_fingerprint` 参数，内部先生成密钥对再生成指纹
2. 修改 `src/app.rs`：`handle_first_setup` 移除多余的 `generate_keypair()` 和 `generate_device_fingerprint()` 调用
3. 更新 `src/auth/keyfile.rs` 和 `src/auth/unlock.rs` 中的测试用例
4. 新增集成测试：`tests/integration_tests/unlock_flow_test.rs`，验证 "生成密钥文件 → 保存 → 读取 → 解锁" 的完整路径

**Step 2 — 修复 ISS-P1-002 + ISS-P1-004（高 + 中高）**：

1. 修改 `generate_key_file` 返回 `(KeyFile, SigningKey, [u8; 32])`，第三个为 master_key
2. 修改 `handle_first_setup`：将整个流程移入 `std::thread::spawn`，复用 `unlock_result` 机制
3. 在 UnlockedSession Drop 时 master_key 自然被 zeroize

**Step 3 — 修复 ISS-P1-003（高）**：

1. 在 `UnlockedSession` 中添加 `pub public_key: VerifyingKey`
2. 在 `unlock_key_file` 中赋值 `public_key: private_key.verifying_key()`
3. 在 `handle_first_setup` 中赋值 `public_key: signing_key.verifying_key()`（如果 Step 2 改为线程后，需从 unlock 结果获取）

**Step 4 — 修复 ISS-P1-005 + ISS-P1-006 + ISS-P1-007 + TODO-P2-001（中 + Phase 0 延迟项）**：

1. `reset_password` 中 `private_key_bytes` 添加 zeroize
2. 添加 `dirs` crate 依赖，修改默认密钥文件路径
3. 添加 `rfd` crate 依赖，在解锁窗口添加"浏览"按钮
4. 安装 Strawberry Perl（Windows 本地环境），修改 `Cargo.toml` 中 rusqlite feature 从 `bundled` 切换为 `bundled-sqlcipher-vendored-openssl`，验证 `cargo build` 全平台通过

---

> **验收结论**：Phase 1 因致命 Bug BUG-P1-001 不通过。修复上述 Step 1-4 后可重新申请验收。其中 Step 1-3 为核心修复，Step 4（含 Phase 0 延迟项 TODO-P2-001）须在 Phase 2 开始前完成，与 Step 1-3 一同作为重新验收的前提。TODO-P2-001 为进入 Phase 2 的硬性前置条件——不切换 SQLCipher，存储层无法使用加密数据库。
