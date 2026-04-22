//! 组管理面板
//!
//! 展示当前已加入的群组信息、成员列表，并提供创建/发现组的操作入口。

use crate::app::SynapseVaultApp;
use egui::{Color32, Context, Ui};

/// 渲染组管理面板
pub fn render_group_panel(app: &mut SynapseVaultApp, _ctx: &Context, ui: &mut Ui) {
    ui.heading("组管理");
    ui.add_space(8.0);

    if let Some(ref group) = app.current_group {
        // ===== 当前已加入组的信息 =====
        ui.group(|ui| {
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new("当前组").size(18.0).strong());
                ui.label(
                    egui::RichText::new("(Admin)")
                        .color(Color32::from_rgb(100, 200, 100))
                        .size(14.0),
                );
            });
            ui.add_space(4.0);

            ui.horizontal(|ui| {
                ui.label("组名:");
                ui.label(egui::RichText::new(&group.name).strong());
            });

            let short_id = if group.group_id.len() > 16 {
                format!("{}...", &group.group_id[..16])
            } else {
                group.group_id.clone()
            };
            ui.horizontal(|ui| {
                ui.label("组 ID:");
                ui.monospace(short_id);
            });

            ui.horizontal(|ui| {
                ui.label("成员:");
                let active_count = group
                    .member_map
                    .values()
                    .filter(|m| m.is_active())
                    .count();
                ui.label(format!("{} / {} 人", active_count, group.config.max_members));
            });

            ui.horizontal(|ui| {
                ui.label("Gossip 端口:");
                ui.label(group.config.gossip_port.to_string());
            });

            ui.horizontal(|ui| {
                ui.label("需审批加入:");
                ui.label(if group.config.require_approval {
                    "是"
                } else {
                    "否"
                });
            });

            ui.separator();
            ui.label("成员列表:");

            egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                for member in group.member_map.values() {
                    let (icon, color) = match member.status {
                        crate::group::member::MemberStatus::Active => ("[在线]", Color32::GREEN),
                        crate::group::member::MemberStatus::PendingApproval => {
                            ("[待审批]", Color32::YELLOW)
                        }
                        crate::group::member::MemberStatus::Revoked => ("[已撤销]", Color32::RED),
                    };
                    ui.push_id(&member.member_id, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(format!("{} ", icon));
                            let id_short = if member.member_id.len() > 12 {
                                format!("{}...", &member.member_id[..12])
                            } else {
                                member.member_id.clone()
                            };
                            ui.monospace(id_short);
                            ui.label(format!("({:?})", member.role));
                            ui.label(
                                egui::RichText::new(format!("{:?}", member.status))
                                    .color(color)
                                    .size(12.0),
                            );
                        });
                    });
                }
            });
        });

        ui.add_space(12.0);

        // Admin 可打开审批弹窗
        let is_admin = app.is_current_user_admin();

        if is_admin {
            let pending_count = group
                .member_map
                .values()
                .filter(|m| m.status == crate::group::member::MemberStatus::PendingApproval)
                .count();
            let btn_text = if pending_count > 0 {
                format!("审批加入请求 ({})", pending_count)
            } else {
                "审批加入请求".to_string()
            };
            if ui.button(btn_text).clicked() {
                app.approve_member_dialog =
                    Some(crate::ui::dialogs::approve_member::ApproveMemberDialog::new());
            }
            ui.add_space(8.0);
        }

        if ui.button("离开当前组").clicked() {
            app.current_group = None;
            app.group_signing_key = None;
        }
    } else {
        // ===== 未加入任何组 =====
        ui.label("您当前尚未加入任何组。");
        ui.add_space(8.0);
        ui.label("您可以创建一个新组并邀请同事加入，或发现局域网中已有的组。");
        ui.add_space(16.0);

        ui.group(|ui| {
            ui.label(egui::RichText::new("操作").strong());
            ui.add_space(8.0);

            if ui.button("创建新组").clicked() {
                app.create_group_dialog = Some(crate::ui::dialogs::create_group::CreateGroupDialog::new());
            }
            ui.add_space(4.0);
            if ui.button("发现组").clicked() {
                app.join_group_dialog = Some(crate::ui::dialogs::join_group::JoinGroupDialog::new());
            }
        });

        ui.add_space(12.0);

        // 显示发现状态摘要
        if !app.discovery_state.discovered_groups.is_empty() {
            ui.group(|ui| {
                ui.label(egui::RichText::new("已发现的组").strong());
                ui.add_space(4.0);
                for (gid, dg) in &app.discovery_state.discovered_groups {
                    ui.horizontal(|ui| {
                        ui.label("[组]");
                        ui.label(format!("{} ({})", dg.name, &gid[..8.min(gid.len())]));
                    });
                }
            });
        }
    }
}
