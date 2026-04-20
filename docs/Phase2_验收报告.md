# SynapseVault Phase 2 阶段性验收报告

**验收日期**：2026-04-21  
**验收工程师**：代码审计 Agent  
**验收阶段**：Phase 2 — 存储层 + 密码管理  
**目标交付物**：单机版密码管理器（无 P2P）

---

## 一、审计范围与方法

依据《SynapseVault构建方案文档》第 8 章「开发路线图」中 Phase 2 的 9 项交付目标，对以下维度进行审计：

1. **模块存在性**：目标文件是否已创建并包含有效实现
2. **功能正确性**：核心逻辑是否符合设计文档中的数据结构、算法与接口签名
3. **测试覆盖**：单元测试与集成测试是否通过
4. **UI 集成度**：前端面板是否与后端数据层完成实际对接
5. **依赖合规性**：Cargo.toml 依赖版本与 feature 配置是否符合设计约束
6. **编译质量**：`cargo test` 与 `cargo clippy` 结果

---

## 二、目标清单逐项核查

| # | 目标项 | 文件路径 | 状态 | 备注 |
|---|--------|----------|------|------|
| 1 | SQLCipher 连接管理 | `src/storage/database.rs` | ✅ 通过 | `open_database`/`close_database` 完整，HKDF 派生 db:key，含单元测试 |
| 2 | 数据库 Schema | `src/storage/schema.rs` | ✅ 通过 | 7 张表 + 索引 + 版本迁移，测试覆盖 |
| 3 | 密码条目数据结构 | `src/secret/entry.rs` | ✅ 通过 | `SecretEntry`/`SecretMeta`/`SecretOp` 与文档一致，含 `From` 转换 |
| 4 | 密码 CRUD 操作 | `src/secret/store.rs` | ✅ 通过 | 创建/读取/列表/更新/删除/解密/搜索齐全，per-secret 密钥派生已接入 |
| 5 | per-secret 密钥派生 | `src/crypto/key_derivation.rs` | ✅ 通过 | HKDF-SHA256 两层派生路径与文档一致 |
| 6 | 安全剪贴板 | `src/secret/clipboard.rs` | ⚠️ 部分通过 | 模块实现完整，但 UI 层未真正调用 `SecureClipboard::copy_secure` |
| 7 | 密码库面板 UI | `src/ui/secret_panel.rs` | ❌ 不通过 | 未使用 `egui_extras::Table`，以 `ui.horizontal` 模拟表格；过期高亮逻辑存在但 `_row_color` 未实际应用 |
| 8 | 查看密码弹窗 | `src/ui/dialogs/view_secret.rs` | ❌ 不通过 | 组件已实现，但 `app.rs` 中仅为占位文本，未真正渲染 `render_view_secret_dialog` |
| 9 | 集成测试：密码增删改查 | `tests/secret_crud_test.rs` | ✅ 通过 | 5 项测试全部通过，覆盖完整 CRUD 流程 |

**测试汇总**：`cargo test` 共 69 项测试，全部通过（0 failed）。

---

## 三、缺陷清单（Blockers）

### 🔴 缺陷 1：查看密码弹窗未真正集成（功能级阻断）

**位置**：`src/app.rs` 第 463–469 行  
**现象**：用户点击密码列表的「👁 查看」或「📋 复制」按钮后，弹窗仅显示：

> "查看密码详情功能需要在数据库连接后使用。当前为演示模式，密码库数据尚未持久化到 UI 层。"

**影响**：Phase 2 交付物为「单机版密码管理器」，但终端用户**无法真正查看或复制已保存的密码明文**。后端 `SecretStore::decrypt_password` 与前端 `render_view_secret_dialog` 均已实现，但两者未在 `app.rs` 中桥接。  
**根因**：`app.rs` 的弹窗路由代码仍使用 Phase 1 的占位逻辑，未将 `show_dialog = Some("view_secret:{id}")` 映射到 `render_view_secret_dialog` 调用，也未调用 `SecureClipboard::copy_secure`。

---

### 🟡 缺陷 2：密码列表未使用设计要求的 `egui_extras::Table`（设计合规性）

**位置**：`src/ui/secret_panel.rs` 第 59–146 行  
**现象**：密码列表使用 `ui.group` + `ui.horizontal` 手动拼接，而非 `egui_extras::Table`。  
**影响**：
- 列宽无法固定，表头与数据行可能错位；
- 缺少 `egui_extras::Table` 提供的虚拟滚动、排序、选中行高亮等原生能力；
- 与《构建方案文档》第 4.5 节明确要求的 "`egui_extras::Table` 密码列表" 不符。  
**根因**：未引入 `egui_extras` 的 `table` feature（见缺陷 3）。

---

### 🟡 缺陷 3：Cargo.toml 中 `egui_extras` 缺少 `table` feature

**位置**：`Cargo.toml` 第 15 行  
**当前值**：
```toml
egui_extras = { version = "0.34.1", features = ["image"] }
```
**设计值**（文档第 3.1 节 / 第 10.1 节附录）：
```toml
egui_extras = { version = "0.26", features = ["table", "image"] }
```
**影响**：即使开发者后续想使用 `egui_extras::Table`，也会因 feature 未启用而编译失败。

---

### 🟡 缺陷 4：过期高亮背景色未生效（UI  polish）

**位置**：`src/ui/secret_panel.rs` 第 91 行  
**现象**：
```rust
let _row_color = if expired { ... } else { ... };
```
变量名前加 `_`，且后续未调用 `ui.visuals_mut().widgets.inactive.bg_fill = _row_color` 或任何等效操作。  
**影响**：已过期（暗红）和即将过期（暗黄）的背景色高亮**实际上不生效**，仅标题文字颜色变化（`⚠️` / `⏳` 前缀 + `LIGHT_RED`）。

---

## 四、非阻塞性观察（Observations）

1. **剪贴板测试环境敏感性**：`secret::clipboard::tests::test_copy_secure_basic` 在首次运行Headless环境时可能因剪贴板竞争失败，但重试可通过。建议增加 `#[cfg(not(ci))]` 或环境检测。
2. **Schema 前瞻性良好**：`sync_state`、`blocks`、`audit_index` 等 Phase 4/5 所需表已在 Phase 2 提前创建，利于后续迭代。
3. **per-secret 密钥隔离**：`derive_per_secret_key` 严格遵循文档中的 HKDF 派生路径（`secret:seed` → `secret:{uuid}`），加密边界清晰。

---

## 五、验收结论

### ❌ 不通过阶段性验收

虽然后端存储层（`storage`、`secret`、`crypto`）实现质量高、测试全部通过，但 **Phase 2 的核心交付物是「单机版密码管理器」**。当前终端用户无法通过 GUI 真正查看或复制已保存的密码，密码库面板仅处于「演示占位」状态，`egui_extras::Table` 也未按设计要求启用。上述缺陷 1 属于**功能级阻断**，必须在整改完成后重新验收。

---

## 六、整改建议（优先级排序）

| 优先级 | 整改项 | 预估工时 | 说明 |
|--------|--------|----------|------|
| P0 | 在 `app.rs` 中真正集成 `render_view_secret_dialog` | 0.5 d | 将 `show_dialog` 的 `view_secret:{id}` 分支替换为调用 `render_view_secret_dialog`，传入 `SecretEntry` 与解密后的密码；同时集成 `SecureClipboard::copy_secure` 到复制按钮 |
| P0 | 密码列表改用 `egui_extras::Table` | 1 d | 先补全 Cargo.toml 的 `table` feature，再重写 `render_secret_table`；参考 egui_extras 0.34 API |
| P1 | 修复过期背景色高亮 | 0.25 d | 使用 `ui.with_layout` 或 `Frame::fill` 将 `_row_color` 实际应用到行背景 |
| P1 | 补充 Cargo.toml `egui_extras` feature | 5 min | `features = ["table", "image"]` |
| P2 | 剪贴板测试增加 CI 环境跳过逻辑 | 0.25 d | 避免无头环境偶发失败 |

---

**验收工程师签章**：Kimi Code CLI（自动化审计）  
**报告生成时间**：2026-04-21T05:35:00+08:00
