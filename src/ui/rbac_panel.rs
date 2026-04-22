//! 权限管理面板
//!
//! 展示当前组成员列表、角色分配，以及权限矩阵。
//! Admin 可在此变更成员角色（带二次确认）。

use crate::app::SynapseVaultApp;
use crate::group::member::{Member, MemberStatus};
use crate::rbac::policy::{permissions_for_role, PermissionCheck};
use crate::rbac::role::Role;
use egui::{Color32, Context, Ui};

/// 渲染权限管理面板
pub fn render_rbac_panel(app: &mut SynapseVaultApp, ctx: &Context, ui: &mut Ui) {
    ui.heading("权限管理");
    ui.add_space(8.0);

    // 先判断当前用户是否为 Admin（在获取 group 可变引用之前）
    let is_admin = app.is_current_user_admin();
    let has_pending_change = app.pending_role_change.is_some();

    let Some(ref mut group) = app.current_group else {
        ui.label("您尚未加入任何组。请先创建或加入一个组。");
        return;
    };

    // 克隆成员列表以避免同时借用
    let members: Vec<Member> = group.member_map.values().cloned().collect();

    // 收集角色变更指令（在渲染后统一执行，避免借用冲突）
    let mut role_changes: Vec<(String, Role)> = Vec::new();

    // ===== 成员列表 =====
    ui.group(|ui| {
        ui.label(egui::RichText::new("成员列表").size(16.0).strong());
        ui.add_space(4.0);

        egui::ScrollArea::vertical().max_height(250.0).show(ui, |ui| {
            for member in &members {
                ui.push_id(&member.member_id, |ui| {
                    render_member_row(
                        ui,
                        member,
                        is_admin,
                        has_pending_change,
                        &mut role_changes,
                    );
                });
            }
        });
    });

    // 执行收集到的角色变更（非确认型，直接执行）
    // 注意：点击按钮后不会立即执行，而是先设置 pending_role_change，弹窗确认后才执行
    if !role_changes.is_empty() && app.pending_role_change.is_none() {
        // 只取第一个变更请求进入确认流程
        app.pending_role_change = Some(role_changes.remove(0));
    }

    // Admin 使用审批入口
    if is_admin {
        ui.add_space(8.0);
        ui.group(|ui| {
            ui.label(egui::RichText::new("使用审批").size(16.0).strong());
            let pending_count = app.pending_usage_requests.len();
            if pending_count > 0 {
                ui.label(format!("待审批请求: {} 条", pending_count));
                if ui.button("查看待审批请求").clicked() {
                    app.show_usage_approve = true;
                }
            } else {
                ui.label("暂无待审批的使用请求。");
            }
        });
    }

    // 渲染角色变更确认弹窗
    if let Some((target_id, new_role)) = app.pending_role_change.clone() {
        let mut confirmed = false;
        let mut cancelled = false;

        egui::Window::new("确认角色变更")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(ctx, |ui| {
                let target = group.member_map.get(&target_id);
                let target_short = if target_id.len() > 16 {
                    format!("{}...", &target_id[..16])
                } else {
                    target_id.clone()
                };
                ui.label(format!("您确定要变更成员 {} 的角色吗？", target_short));
                if let Some(t) = target {
                    ui.label(format!("当前角色: {}", t.role));
                }
                ui.label(format!("新角色: {}", new_role));
                ui.add_space(8.0);
                ui.colored_label(Color32::YELLOW, "此操作将立即生效并同步到所有节点。");
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    if ui.button("取消").clicked() {
                        cancelled = true;
                    }
                    if ui.button("确认变更").clicked() {
                        confirmed = true;
                    }
                });
            });

        if cancelled {
            app.pending_role_change = None;
        } else if confirmed {
            if let Some(ref session) = app.session {
                match crate::rbac::policy::change_role(
                    &mut group.member_map,
                    &target_id,
                    new_role,
                    &session.private_key,
                ) {
                    Ok(op) => {
                        tracing::info!(
                            "角色变更成功: {} {} -> {}",
                            op.target_member,
                            op.old_role,
                            op.new_role
                        );
                        // Phase 5: 持久化角色变更到数据库
                        if let Some(ref conn) = app.db_conn {
                            if let Err(e) = persist_role_change(conn, &target_id, new_role) {
                                tracing::warn!("角色变更持久化失败: {}", e);
                            } else {
                                tracing::info!("角色变更已持久化到数据库");
                            }
                        }
                        // 记录审计日志
                        if let Some(ref conn) = app.db_conn {
                            let event = crate::audit::event::AuditEvent::new(
                                format!("role_change_{}", uuid::Uuid::new_v4()),
                                crate::audit::event::OperationType::RoleChange,
                                hex::encode(session.public_key.as_bytes()),
                                session.device_fingerprint.clone(),
                                "local".to_string(),
                            )
                            .with_summary(format!(
                                "将 {} 从 {} 变更为 {}",
                                target_id, op.old_role, op.new_role
                            ));
                            let _ = crate::audit::logger::log_event(conn, &event, None);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("角色变更失败: {}", e);
                    }
                }
            }
            app.pending_role_change = None;
        }
    }

    ui.add_space(12.0);

    // ===== 权限矩阵 =====
    ui.group(|ui| {
        ui.label(egui::RichText::new("权限矩阵").size(16.0).strong());
        ui.add_space(4.0);

        egui::ScrollArea::horizontal().show(ui, |ui| {
            ui.horizontal(|ui| {
                for role in [Role::Admin, Role::FreeUser, Role::AuditUser] {
                    ui.vertical(|ui| {
                        ui.label(
                            egui::RichText::new(role.to_string())
                                .strong()
                                .size(14.0),
                        );
                        ui.separator();

                        for (action, check) in permissions_for_role(&role) {
                            let (icon, color) = match check {
                                PermissionCheck::Allowed => ("[允许]", Color32::GREEN),
                                PermissionCheck::Denied(_) => ("[拒绝]", Color32::RED),
                                PermissionCheck::RequiresApproval => ("[需审批]", Color32::YELLOW),
                            };
                            ui.label(
                                egui::RichText::new(format!("{} {}", icon, action))
                                    .color(color)
                                    .size(12.0),
                            );
                        }
                    });
                    ui.add_space(16.0);
                }
            });
        });
    });
}

/// 将角色变更持久化到数据库
fn persist_role_change(
    conn: &rusqlite::Connection,
    member_id: &str,
    new_role: Role,
) -> Result<(), rusqlite::Error> {
    conn.execute(
        "UPDATE members SET role = ?1 WHERE member_id = ?2",
        rusqlite::params![new_role.to_string(), member_id],
    )?;
    Ok(())
}

fn render_member_row(
    ui: &mut Ui,
    member: &Member,
    is_admin: bool,
    has_pending_change: bool,
    role_changes: &mut Vec<(String, Role)>,
) {
    let (status_icon, status_color) = match member.status {
        MemberStatus::Active => ("[在线]", Color32::GREEN),
        MemberStatus::PendingApproval => ("[待审批]", Color32::YELLOW),
        MemberStatus::Revoked => ("[已撤销]", Color32::RED),
    };

    let id_short = if member.member_id.len() > 12 {
        format!("{}...", &member.member_id[..12])
    } else {
        member.member_id.clone()
    };

    ui.horizontal(|ui| {
        ui.label(format!("{} ", status_icon));
        ui.monospace(id_short);
        ui.label(format!("({})", member.device_fingerprint));

        // 角色徽章
        let role_color = match member.role {
            Role::Admin => Color32::from_rgb(100, 200, 100),
            Role::FreeUser => Color32::from_rgb(100, 150, 255),
            Role::AuditUser => Color32::from_rgb(255, 200, 100),
        };
        ui.label(
            egui::RichText::new(member.role.to_string())
                .color(role_color)
                .strong(),
        );

        ui.label(
            egui::RichText::new(format!("{:?}", member.status))
                .color(status_color)
                .size(12.0),
        );

        // Admin 可操作：变更角色（仅在无待确认变更时显示）
        if is_admin
            && member.status == MemberStatus::Active
            && member.role != Role::Admin
            && !has_pending_change
        {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("设为 AuditUser").clicked() {
                    role_changes.push((member.member_id.clone(), Role::AuditUser));
                }
                if ui.button("设为 FreeUser").clicked() {
                    role_changes.push((member.member_id.clone(), Role::FreeUser));
                }
            });
        }
    });
    ui.separator();
}
