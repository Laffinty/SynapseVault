# Phase 4 验收 / 优化 / 构建报告

> **审查日期**：2026-04-22
> **审查范围**：CRDT 同步 + RBAC + 中文字体
> **变更文件**：7 个修改 + 3 个新增，共 +1060 / -14 行

---

## 一、验收结论

### 1.1 交付物核对

| # | 交付物 | 状态 | 备注 |
|---|--------|------|------|
| 1 | `sync/crdt_engine.rs` | ✅ 已存在（Phase 3 完成） | 本期无改动 |
| 2 | `sync/merge.rs` | ✅ 已存在（Phase 3 完成） | 本期无改动 |
| 3 | `rbac/role.rs` | ✅ 已存在（Phase 0 完成） | 本期无改动 |
| 4 | `rbac/policy.rs` | ✅ 从占位符重写为 561 行完整实现 | **有问题，见下** |
| 5 | `ui/rbac_panel.rs` | ✅ 从占位符重写为 175 行 | **有问题，见下** |
| 6 | `ui/dialogs/approve_member.rs` | ✅ 从占位符重写为 178 行 | **有问题，见下** |
| 7 | 中文字体内嵌 `font/wqy.ttf` | ❌ **未按文档要求内嵌** | **严重问题，见下** |
| 8 | 集成测试 `rbac_sync_integration_test.rs` | ✅ 5 个测试全部通过 | 测试逻辑有问题，见下 |

**验收结论**：**有条件通过** — 7/8 交付物完成，字体内嵌为硬性不合规项，需修复后方可正式验收。

### 1.2 测试结果

```
单元测试：108 passed / 0 failed
集成测试： 23 passed / 0 failed（其中 Phase 4 新增 5 个）
Clippy：   0 warnings / 0 errors
总计：    131 tests all passed
```

---

## 二、严重问题（必须修复）

### 2.1 🔴 字体未按文档要求内嵌 — 运行时文件依赖

**文档明确要求**（构建方案第 1759 行）：

> 字体采用**内嵌**的方式使用 `font/wqy.ttf`

**实际实现**（`src/main.rs:28-34`）：

```rust
let font_path = std::path::Path::new("font/wqy.ttf");
if !font_path.exists() {
    tracing::warn!("中文字体文件不存在: {:?}", font_path);
    return;
}
match std::fs::read(font_path) { ... }
```

这是 **运行时从相对路径读取文件**，不是内嵌。存在以下问题：

1. **部署即崩溃**：分发二进制时必须同时分发 `font/` 目录，且必须从正确工作目录启动，否则中文显示为方块
2. **静默失败**：字体找不到只打一条 warn 日志，用户看到乱码完全不知道原因
3. **违背文档**：构建方案明确写"内嵌"，代码没有遵守

#### ✅ 正确做法：使用 `include_bytes!()` 编译时内嵌

修改 `src/main.rs`，将 `load_chinese_font` 函数替换为：

```rust
/// 从编译时内嵌的二进制数据加载中文字体（WenQuanYi Micro Hei）
fn load_chinese_font(ctx: &egui::Context) {
    // 编译时内嵌，零运行时文件依赖
    let font_data = include_bytes!("../font/wqy.ttf");

    let mut fonts = egui::FontDefinitions::default();

    fonts.font_data.insert(
        "wqy".to_owned(),
        egui::FontData::from_owned(font_data.to_vec()).into(),
    );

    // 将中文字体加入 Proportional 和 Monospace 的 fallback 列表
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .push("wqy".to_owned());
    fonts
        .families
        .entry(egui::FontFamily::Monospace)
        .or_default()
        .push("wqy".to_owned());

    ctx.set_fonts(fonts);
    tracing::info!("中文字体加载成功（内嵌模式）");
}
```

**关键变更说明**：

| 项目 | 修改前 | 修改后 |
|------|--------|--------|
| 加载方式 | `std::fs::read("font/wqy.ttf")` | `include_bytes!("../font/wqy.ttf")` |
| 编译时行为 | 无 | 4.4 MB 字体数据编入二进制 |
| 运行时依赖 | 必须有 `font/wqy.ttf` 文件 | 无，单文件即可运行 |
| 失败模式 | 静默 warn + 中文乱码 | 编译时保证成功，不可能失败 |
| 二进制体积增加 | 无 | ~4.4 MB（可接受） |

> **注意**：`include_bytes!()` 路径相对于当前源文件。`main.rs` 在 `src/` 目录，`wqy.ttf` 在 `font/` 目录，所以路径是 `"../font/wqy.ttf"`。

---

## 三、中等问题（建议修复）

### 3.1 `check_permission` 在纯查询函数中产生副作用

**位置**：`src/rbac/policy.rs:133-136`

```rust
Action::ViewSecretPlaintext => PermissionCheck::RequiresApproval {
    approval_id: format!("usage_req_{}", uuid::Uuid::new_v4()),
    requested_at: Utc::now(),
},
```

**问题**：`check_permission` 是权限查询函数，应无副作用。但每次调用都生成新 UUID + 获取当前时间，且生成的 `approval_id` 从未被使用（真正的 ID 在 `request_usage` 中重新生成）。在 `rbac_panel.rs` 的权限矩阵渲染中，这意味着每帧都分配 UUID。

**修复方案**：移除 `approval_id` 字段，`RequiresApproval` 仅表示"需要审批"这个语义：

```rust
pub enum PermissionCheck {
    Allowed,
    Denied(String),
    RequiresApproval,  // 不再附带无用的 approval_id
}
```

### 3.2 `request_usage` 未校验调用者角色

**位置**：`src/rbac/policy.rs:213-239`

`request_usage` 接受任意 `SigningKey`，不验证调用者是否为 AuditUser。FreeUser 或 Admin 也能调用成功。与 `change_role` 和 `approve_usage` 内部强制角色校验的做法不一致。

**修复方案**：增加 `members` 参数，内部校验角色：

```rust
pub fn request_usage(
    secret_id: &SecretId,
    reason: &str,
    requester_signing_key: &SigningKey,
    members: &HashMap<MemberId, Member>,  // 新增
) -> Result<UsageRequest, RbacError> {
    let requester_id = hex::encode(requester_signing_key.verifying_key().as_bytes());
    let requester = members.get(&requester_id)
        .ok_or_else(|| RbacError::PermissionDenied("请求者不在成员列表中".to_string()))?;
    if requester.role != Role::AuditUser {
        return Err(RbacError::PermissionDenied("仅 AuditUser 可发起使用请求".to_string()));
    }
    // ... 其余不变
}
```

### 3.3 签名数据拼接缺少长度前缀

**位置**：`src/rbac/policy.rs:222-228` 和 `274-278`

```rust
// request_usage 签名
sign_data = request_id || secret_id || timestamp || reason
// approve_usage 签名
approval_data = request_id || "APPROVED" || timestamp
```

没有分隔符或长度前缀，理论上存在碰撞风险（例如 `secret_id = "abcDE"` + `timestamp = "FGH"` 和 `secret_id = "abcDEFGH"` + `timestamp = ""` 的签名数据相同）。

**修复方案**：使用长度前缀或结构化序列化：

```rust
let mut sign_data = Vec::new();
sign_data.extend_from_slice(&(request_id.len() as u64).to_le_bytes());
sign_data.extend_from_slice(request_id.as_bytes());
sign_data.extend_from_slice(&(secret_id.len() as u64).to_le_bytes());
sign_data.extend_from_slice(secret_id.as_bytes());
// ... 同理处理 timestamp 和 reason
```

### 3.4 使用审批过期时间硬编码

**位置**：`src/rbac/policy.rs:285`

```rust
expires_at: Utc::now() + chrono::Duration::minutes(5),
```

构建方案要求"可配置，默认 5 分钟"，但实际硬编码无配置机制。

**修复方案**：添加常量或函数参数：

```rust
const DEFAULT_USAGE_APPROVAL_TTL_MINUTES: i64 = 5;

// 或作为参数
pub fn approve_usage(
    request: &UsageRequest,
    admin_signing_key: &SigningKey,
    admin_members: &HashMap<MemberId, Member>,
    ttl: Option<chrono::Duration>,  // 新增
) -> Result<UsageApproval, RbacError> {
    // ...
    let ttl = ttl.unwrap_or(chrono::Duration::minutes(DEFAULT_USAGE_APPROVAL_TTL_MINUTES));
    Ok(UsageApproval {
        expires_at: Utc::now() + ttl,
        // ...
    })
}
```

### 3.5 Admin 身份检查逻辑重复 3 次

**位置**：
- `src/app.rs:670-675`
- `src/ui/group_panel.rs:99-110`
- `src/ui/rbac_panel.rs:23-34`

三处都使用完全相同的模式：

```rust
let admin_id = hex::encode(session.public_key.as_bytes());
let is_admin = group.member_map.get(&admin_id)
    .map(|m| m.role == Role::Admin && m.is_active())
    .unwrap_or(false);
```

**修复方案**：在 `SynapseVaultApp` 上添加辅助方法：

```rust
impl SynapseVaultApp {
    pub fn is_current_user_admin(&self) -> bool {
        let Some(ref session) = self.session else { return false };
        let Some(ref group) = self.current_group else { return false };
        let my_id = hex::encode(session.public_key.as_bytes());
        group.member_map.get(&my_id)
            .map(|m| m.role == Role::Admin && m.is_active())
            .unwrap_or(false)
    }
}
```

### 3.6 审批弹窗每帧做排序去重分配

**位置**：`src/app.rs:679-689`

```rust
let mut pending = self.received_join_requests.clone();
pending.extend(pending_join_requests_from_group(group));
pending.sort_by(|a, b| {
    hex::encode(a.requester_public_key.as_bytes())
        .cmp(&hex::encode(b.requester_public_key.as_bytes()))
});
pending.dedup_by(|a, b| { ... });
```

每帧执行 `clone()` + `extend()` + `sort()` + `dedup()` + 2× `hex::encode()`。应在数据变更时维护去重列表，而非每帧重算。

### 3.7 `pending_join_requests_from_group` 使用全零签名

**位置**：`src/ui/dialogs/approve_member.rs:142`

```rust
signature: ed25519_dalek::Signature::from_bytes(&[0u8; 64]),
```

伪造签名意味着这些 `JoinRequest` 对象不能通过任何签名验证流程。如果有代码尝试验证，将静默失败或产生错误行为。

**修复方案**：将 `JoinRequest.signature` 改为 `Option<Signature>`，或在函数文档中明确标注"此构造仅用于 UI 展示，签名无效，不可用于 P2P 传输或验证"。

### 3.8 角色变更无确认弹窗

**位置**：`src/ui/rbac_panel.rs:165-169`

点击"设为 AuditUser"或"设为 FreeUser"立即执行角色变更，无二次确认。误触即永久生效（且角色变更不持久化，重启后丢失——双重问题）。

---

## 四、轻微问题

| # | 问题 | 位置 | 说明 |
|---|------|------|------|
| 1 | `show_dialog: Option<String>` 用字符串匹配分发 | `app.rs` | 应使用 enum 替代，防止拼写错误 |
| 2 | `ApproveMemberDialog` 为空单元结构体 | `approve_member.rs:10` | 无任何状态，`Option<ApproveMemberDialog>` 仅做类型标记 |
| 3 | 权限矩阵每帧调用 `permissions_for_role` | `rbac_panel.rs:98` | 10 次 `check_permission` + UUID 分配/帧，应缓存 |
| 4 | CRDT 冲突测试逻辑与注释不符 | `rbac_sync_integration_test.rs:143-146` | 注释说"版本较低应被删除"，但 node-a 刚更新过版本更高；实际测试验证的是"删除总是胜出"，与构建方案"高版本修改可覆盖删除"矛盾 |
| 5 | `change_role` 签名偏离构建方案 | `policy.rs:157` | 文档写 `group: &mut Group`，实际用 `members: &mut HashMap` |
| 6 | `approve_usage` 返回类型偏离构建方案 | `policy.rs:242` | 文档写返回 `BlockchainOp`，实际返回 `UsageApproval` |
| 7 | 无 AuditUser 晋升 Admin 的 UI | `rbac_panel.rs` | 只有降级按钮，无升级 Admin 入口（可能有意为之） |

---

## 五、构建质量评价

### 5.1 正面评价

1. **`change_role` 的两阶段借用模式**正确避免了 NLL 冲突，Rust 惯用法
2. **RBAC 策略引擎的权限矩阵**完整覆盖 10 动作 × 3 角色，边界测试充分
3. **角色变更的延迟执行模式**（`role_changes` Vec 收集后统一执行）正确处理了 egui 即时模式的借用约束
4. **最后一个 Admin 保护逻辑**正确实现，不会导致组失去管理员
5. **集成测试覆盖**了 RBAC + CRDT 的交叉场景

### 5.2 负面评价（AI Agent 编码质量问题）

本次负责 coding 的 AI agent 存在以下"不够聪明"的表现：

1. **未遵循文档明确的内嵌要求**：文档白纸黑字写"内嵌"，agent 却实现了运行时文件读取。这不是理解偏差，是直接无视了需求
2. **纯查询函数混入副作用**：`check_permission` 生成 UUID 是设计错误——查询函数就应该是查询函数
3. **角色校验不一致**：`change_role` 和 `approve_usage` 内部强制校验角色，`request_usage` 却不校验。同一个策略引擎里三处逻辑应统一
4. **签名数据拼接缺少分隔**：密码学协议设计的基本功，长度前缀是常识
5. **空结构体 + Option 包装**：`ApproveMemberDialog` 完全没有状态，整个设计多余
6. **每帧重复计算**：排序、去重、UUID 生成、权限矩阵查询——全在渲染循环里做，缺乏基本性能意识

---

## 六、修复优先级

| 优先级 | 项目 | 工作量 |
|--------|------|--------|
| P0 | 字体内嵌：`include_bytes!()` 替换 `std::fs::read` | 15 分钟 |
| P1 | `check_permission` 移除副作用 UUID | 30 分钟 |
| P1 | `request_usage` 添加角色校验 | 20 分钟 |
| P1 | 签名数据添加长度前缀 | 30 分钟 |
| P2 | Admin 检查提取为公共方法 | 15 分钟 |
| P2 | 审批过期时间可配置 | 15 分钟 |
| P2 | 角色变更添加确认弹窗 | 30 分钟 |
| P3 | 其余轻微问题 | 1-2 小时 |

---

## 七、总结

Phase 4 的**功能覆盖完整**，8 个交付物中 7 个已实现，131 个测试全部通过，Clippy 无警告。但存在一个**硬性不合规项**（字体未内嵌）和若干**设计一致性问题**（策略引擎内部校验不统一、签名拼接不规范、纯函数副作用）。

字体内嵌修复为 P0 优先级，建议立即处理。其余 P1 项建议在 Phase 5 开始前完成。
