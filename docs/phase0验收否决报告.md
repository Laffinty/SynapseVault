# Phase 0 验收报告

> **项目**：SynapseVault
> **阶段**：Phase 0 — 基础设施搭建
> **验收日期**：2026-04-20
> **结论**：✅ **有条件通过，允许继续构建 Phase 1**

---

## 一、Phase 0 交付物逐项审查

| # | 交付项 | 状态 | 说明 |
|---|--------|------|------|
| 1 | 初始化 Cargo 项目 + 目录结构 | ✅ 通过 | 11 个模块（auth/crypto/group/rbac/secret/p2p/sync/blockchain/audit/storage/ui）及全部子模块文件均已创建，与方案文档§4.1目录结构一致 |
| 2 | 配置 Cargo.toml 所有依赖 | ✅ 通过 | 全部核心依赖已配置；`rusqlite` 因 Windows 编译环境限制暂用 `bundled`，见§二 |
| 3 | 搭建 CI（GitHub Actions） | ✅ 通过 | `.github/workflows/ci.yml` 包含 fmt/check/clippy/audit 四项检查 + 三平台（ubuntu/windows/macos）测试矩阵，超出方案要求的最低标准 |
| 4 | 实现 main.rs 入口 + 空壳 SynapseVaultApp | ✅ 通过 | main.rs 使用 eframe 启动 + tracing 日志初始化；app.rs 实现了完整状态机（UnlockState/Panel/ThemeMode）及 eframe::App trait |
| 5 | egui 空界面渲染通过 | ✅ 通过 | 解锁窗口、顶部栏、侧边栏导航、五个面板（组管理/密码库/权限/审计/设置）、弹窗系统、Dark/Light主题切换均已实现；`cargo check` 与 `cargo test` 均通过 |
| 6 | 确认跨平台编译 | ✅ 通过（CI层） | CI 矩阵覆盖 ubuntu-latest/windows-latest/macos-latest；本地 Windows 编译通过 |

**全部 6/6 通过。**

---

## 二、已知延期项（Phase 2 前必须解决）

### TODO-P2-001：rusqlite 切换为 bundled-sqlcipher-vendored-openssl

| 属性 | 值 |
|------|-----|
| **严重程度** | 🟡 **高**（Phase 2 前必须修复） |
| **当前配置** | `rusqlite = { version = "0.39", features = ["bundled"] }` |
| **目标配置** | `rusqlite = { version = "0.39", features = ["bundled-sqlcipher-vendored-openssl"] }` |
| **位置** | `Cargo.toml:34` |
| **延期原因** | Windows 本地开发环境缺少 Strawberry Perl，vendored OpenSSL 无法编译；CI (ubuntu-latest) 不受影响 |

**背景**：方案文档§3.1要求使用 SQLCipher 加密数据库。`bundled` 仅为标准 SQLite，不具备加密能力。Phase 0 骨架阶段不涉及实际数据库操作，暂不影响功能；但 Phase 2 实现存储层时**必须**切换为 `bundled-sqlcipher-vendored-openssl`。

**修复前置条件**：
- 安装 Strawberry Perl（Windows 本地编译 OpenSSL 所需）
- 或使用预编译 OpenSSL 并设置 `OPENSSL_DIR` 环境变量
- CI 需确认 `cargo install cargo-audit` 与 SQLCipher 编译兼容

---

## 三、次要观察

| # | 观察 | 优先级 | 说明 |
|---|------|--------|------|
| O-001 | `egui_extras` 未启用 `table` feature | 信息 | 0.34.1 版本中 Table 功能已内置为默认，无需额外 feature；原方案文档标注 `table` feature 基于旧版 egui_extras |
| O-002 | `.cargo/config.toml` 未创建 | 低 | 方案§4.1目录结构中列出该文件，用于交叉编译配置。Phase 0 不涉及交叉编译，可在 Phase 6（跨平台构建）时补建 |
| O-003 | `ed25519-dalek` 已包含 `rand_core` feature | ✅ 已正确 | 验证确认当前配置 `features = ["zeroize", "rand_core"]` 符合方案要求 |

---

## 四、验证结果

| 检查项 | 结果 |
|--------|------|
| `cargo check` | ✅ 通过 |
| `cargo test` | ✅ 通过（5 tests: ui_smoke 3 + project_sanity 2） |
| `cargo clippy -- -W clippy::all -W clippy::unwrap_used` | ✅ 零警告 |

---

> Phase 0 验收通过。允许继续构建 Phase 1。
> TODO-P2-001 须在 Phase 2 开始前完成修复。
