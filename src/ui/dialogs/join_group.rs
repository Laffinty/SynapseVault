//! 加入组弹窗
//!
//! 展示已发现的群组列表，允许用户选择并发送加入请求。

use crate::auth::device_fingerprint::generate_device_fingerprint;
use crate::auth::unlock::UnlockedSession;
use crate::group::manager::{request_join, JoinRequest};
use crate::p2p::discovery::DiscoveryState;
use egui::{Context, Window};

/// 加入组弹窗状态
#[derive(Default)]
pub struct JoinGroupDialog {
    pub selected_group_id: Option<String>,
    pub error: Option<String>,
}

impl JoinGroupDialog {
    pub fn new() -> Self {
        Self::default()
    }
}

/// 弹窗操作结果
#[allow(clippy::large_enum_variant)]
pub enum JoinGroupResult {
    /// 用户取消
    Cancelled,
    /// 已发送加入请求
    Requested(JoinRequest),
}

/// 渲染加入组弹窗
///
/// 返回 `Some(JoinGroupResult)` 表示用户已做出选择。
pub fn render_join_group_dialog(
    ctx: &Context,
    dialog: &mut JoinGroupDialog,
    discovery_state: &DiscoveryState,
    session: &UnlockedSession,
) -> Option<JoinGroupResult> {
    let mut result = None;
    let mut open = true;

    Window::new("发现组")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .open(&mut open)
        .show(ctx, |ui| {
            ui.label("局域网中可加入的组:");
            ui.add_space(8.0);

            if discovery_state.discovered_groups.is_empty() {
                ui.label("当前未发现任何组。");
                ui.add_space(4.0);
                ui.label("提示：确保同网段有其他 SynapseVault 节点正在运行，并已创建组。");
            } else {
                egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                    for (group_id, group) in &discovery_state.discovered_groups {
                        let is_selected = dialog.selected_group_id.as_ref() == Some(group_id);
                        let response = ui.selectable_label(
                            is_selected,
                            format!("[组] {} (ID: {}...)", group.name, &group_id[..8.min(group_id.len())]),
                        );
                        if response.clicked() {
                            dialog.selected_group_id = Some(group_id.clone());
                        }
                        ui.horizontal(|ui| {
                            ui.add_space(20.0);
                            ui.label(format!(
                                "Admin: {}... | 端口: {} | Peer: {}...",
                                &group.admin_pubkey_hash[..8.min(group.admin_pubkey_hash.len())],
                                group.port,
                                &group.peer_id[..12.min(group.peer_id.len())]
                            ));
                        });
                        ui.separator();
                    }
                });
            }

            ui.add_space(8.0);

            if let Some(ref err) = dialog.error {
                ui.colored_label(egui::Color32::RED, format!("[错误] {}", err));
                ui.add_space(8.0);
            }

            ui.horizontal(|ui| {
                if ui.button("取消").clicked() {
                    result = Some(JoinGroupResult::Cancelled);
                }
                if ui.button("申请加入").clicked() {
                    if let Some(ref gid) = dialog.selected_group_id {
                        if let Some(group) = discovery_state.discovered_groups.get(gid) {
                            let fp = generate_device_fingerprint(&session.public_key);
                            match request_join(group, &session.private_key, &fp) {
                                Ok(req) => {
                                    result = Some(JoinGroupResult::Requested(req));
                                }
                                Err(e) => {
                                    dialog.error = Some(format!("加入请求失败: {}", e));
                                }
                            }
                        } else {
                            dialog.error = Some("所选组已不可用".to_string());
                        }
                    } else {
                        dialog.error = Some("请先选择一个组".to_string());
                    }
                }
            });
        });

    if !open {
        result = Some(JoinGroupResult::Cancelled);
    }

    result
}
