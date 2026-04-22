# Phase 6 剩余任务清单

**最后更新**：2026-04-22
**当前状态**：201 测试通过，0 clippy 警告，Batch 1-4 大部分完成

---

## Batch 3 遗留：UI 打磨

### 3.2 提取布局到独立模块 [M]

**问题**：`main_layout.rs`/`side_panel.rs`/`top_bar.rs` 为骨架，布局内联在 app.rs

**修改文件**：
- `src/ui/side_panel.rs` — 提取侧边栏渲染（app.rs:585-621），宽度响应式（140-200px），支持折叠
- `src/ui/top_bar.rs` — 提取顶栏渲染（app.rs:558-582），动态绑定组名和在线数
- `src/ui/main_layout.rs` — 组合三者，替换 app.rs 中的内联布局
- `src/app.rs` — 用 `render_main_layout()` 替换内联面板代码

**验证**：不同窗口尺寸下布局正常，导航功能不变

---

### 3.4 审计面板状态重构 [M]

**问题**：审计面板仍部分使用 `active_dialog` 管理筛选/导出状态，`AuditPanelState` 结构体已定义但未添加到 app

**修改文件**：
- `src/app.rs` — 添加 `audit_panel_state: AuditPanelState` 字段
- `src/ui/audit_panel.rs` — 替换所有通过 `active_dialog` 管理面板状态的用法，改用 `app.audit_panel_state` 管理筛选条件、刷新、导出格式
- `src/app.rs` — 从 `DialogState` 中移除 `AuditFilterType`/`AuditRefresh`/`AuditExport` 变体（这些不是弹窗而是面板状态）

**验证**：审计面板筛选、刷新、导出功能正常

---

### 3.5 Settings 面板完善 [M]

**问题**：Settings 面板目前仅有 TTL + 主题 + 版本

**修改文件**：
- `src/app.rs` — 添加 `auto_lock_minutes: u64`（默认 30，0=禁用）字段
- `src/app.rs` — 实现 Settings 渲染中：
  - 自动锁定超时滑块（0-120 分钟）
  - Argon2 参数展示（只读，从 session 中读取）
  - 数据库路径展示
  - 密钥文件路径展示与修改
  - 关于区域（版本、许可证、GitHub 链接）

**验证**：Settings 面板所有控件可交互，TTL/自动锁定设置生效

---

## Batch 4 遗留：性能优化

### 4.2 Argon2id 参数校准 [M]

**问题**：默认参数（64 MiB, 3 轮, 4 线程）在低配设备上可能过慢，高配设备上可能过快

**修改文件**：
- `src/crypto/kdf.rs` — 添加 `calibrate_argon2_params(target_ms: u64) -> Argon2Params`
  - 从最低参数开始（8192/1/1），逐步增加 memory_cost 和 time_cost
  - 直到 KDF 耗时接近 target_ms（推荐 1000ms）
  - 返回最接近目标的参数
- `src/auth/keyfile.rs` — 首次设置时调用 `calibrate_argon2_params(1000)`，将校准结果存入 key 文件
- `src/ui/unlock_window.rs` — 显示"正在校准加密参数..."提示

**验证**：`calibrate_argon2_params` 返回合法参数，首次生成 key 文件时自动校准

---

## Batch 5：发布准备

### 5.1 安全审计工具 [M]

**执行步骤**：
1. 运行 `cargo audit` — 修复所有报告的漏洞（可能需要更新 Cargo.toml 依赖版本）
2. 运行 `cargo clippy -- -W clippy::all -W clippy::unwrap_used` — 修复所有 warning
3. 运行 `cargo +nightly miri test` — 对 `crypto`、`blockchain`、`rbac` 模块运行 Miri
4. 对 I/O 相关测试添加 `#[cfg_attr(miri, ignore)]`

**修改文件**：
- `Cargo.toml` — 如有漏洞则更新依赖版本
- 各测试文件 — 添加 `#[cfg_attr(miri, ignore)]` 标注

**验证**：`cargo audit` 0 漏洞，`cargo clippy` 0 警告，`miri` 通过

---

### 5.2 渗透测试框架 [L]

**修改文件**：
- 新建 `tests/pentest.rs`：
  - **重放攻击测试**：序列化 `P2pMessage`，发送两次，验证 CRDT 去重阻止重复应用
  - **泛洪测试**：快速发送 1000 条消息，验证 gossipsub 背压不崩溃，`max_transmit_size` 拒绝超大消息
  - **ARP 欺骗缓解文档**：记录 Noise 协议提供认证加密，ARP 欺骗无法解密/篡改，但可 DoS（丢包）
- `src/p2p/protocol.rs` — 添加消息 nonce 字段（`nonce: u64`，单调递增）用于重放检测
- `src/p2p/event_loop.rs` — 添加 `seen_message_ids: HashSet<[u8; 32]>`（LRU 缓存，容量 1000）检测并丢弃重放消息

**验证**：重放攻击测试通过（重复消息被丢弃），泛洪测试通过（不崩溃）

---

### 5.3 跨平台测试 [M]

**修改文件**：
- `.github/workflows/ci.yml`：
  - 三平台矩阵：`ubuntu-latest`、`windows-latest`、`macos-latest`
  - 每个平台运行 `cargo test` + `cargo build --release`
  - 添加 `cargo clippy` 步骤（当前仅在 Ubuntu 运行）
  - 添加 `cargo audit` 步骤
- 平台特定修复：
  - Windows：`arboard` 剪贴板行为差异，添加 `#[cfg_attr(ci, ignore)]`
  - macOS：验证 `include_bytes!` 内嵌字体在 macOS 上的渲染
  - Linux：验证 `libssl` 静态链接（vendored-openssl）

**验证**：CI 三平台全部通过

---

### 5.4 文档 [M]

**新建文件**：
- `docs/user_manual.md`：
  - 安装与首次设置（密钥文件、主密码）
  - 创建组 / 发现并加入组
  - 管理密码（创建、查看、复制、搜索）
  - 角色管理（Admin/FreeUser/AuditUser）
  - 审计日志查看与导出
  - 使用审批流程（AuditUser 申请 / Admin 审批）
  - 导入/导出密码
  - 设置（TTL、自动锁定、主题）
  - 安全最佳实践
  - 故障排除（忘记密码、设备指纹不匹配）
- `docs/developer_guide.md`：
  - 架构概览（分层图：GUI → App → 模块 → P2P/存储）
  - 模块描述与文件映射表
  - 数据流：unlock → group → secret → audit → blockchain
  - P2P 协议规范（topic 命名 `synapsevault/{group_id}/{category}`、消息类型）
  - 如何添加新 UI 面板
  - 如何添加新 P2P 消息类型
  - 测试策略（单元/集成/渗透）
  - 构建与发布流程（`cargo build --release`）
  - CRDT 冲突解决策略（LWW + 版本号）
  - 区块链出块机制（双阈值：50 ops / 60s）

**验证**：文档内容与当前实现一致，无过时信息

---

### 5.5 发布构建 [M]

**修改文件**：
- `Cargo.toml` — 将 `version` 从 `"0.1.0"` 更新为 `"1.0.0"`
- `.github/workflows/ci.yml` — 添加 `release` job：
  - 构建目标：`x86_64-unknown-linux-gnu`、`x86_64-pc-windows-msvc`、`aarch64-apple-darwin`
  - 产物命名：`synapse-vault-v1.0.0-{target}.zip` / `.tar.gz`
  - 字体已通过 `include_bytes!` 内嵌，无需额外打包 font 目录
- 验证 `Cargo.toml` 的 `[profile.release]` 配置：`opt-level = 3, lto = true, strip = true, codegen-units = 1`（已正确）

**验证**：在各平台下载并运行 release 二进制，验证：解锁、创建组、添加密码、查看审计日志、导出数据

---

### 5.6 CRDT 冲突测试注释修正 [S]

**问题**：`src/sync/crdt_engine.rs` 中测试注释与实际验证行为不符

**修改文件**：
- `src/sync/crdt_engine.rs` — 审查所有测试注释，修正与实际行为不一致的描述
- `src/sync/merge.rs` — 确保 `merge_secret_entries` 注释准确描述 LWW 策略及确定性决胜逻辑

**验证**：现有测试行为不变，仅注释更准确

---

## 任务统计

| 分类 | 任务数 | 复杂度 |
|------|--------|--------|
| Batch 3 遗留 | 3 | M+M+M |
| Batch 4 遗留 | 1 | M |
| Batch 5 | 6 | M+L+M+M+M+S |
| **合计** | **10** | 约 20 工作单位 |

建议执行顺序：3.4 → 3.5 → 3.2 → 4.2 → 5.6 → 5.1 → 5.2 → 5.3 → 5.4 → 5.5
