//! 成员审批弹窗
//!
//! Admin 通过此弹窗查看待审批的加入请求，并执行批准或拒绝操作。

use crate::group::manager::{approve_join, reject_join, Group, JoinRequest};
use crate::group::member::MemberStatus;
use egui::{Context, Window};

/// 审批弹窗状态
#[derive(Default)]
pub struct ApproveMemberDialog;

impl ApproveMemberDialog {
    pub fn new() -> Self {
        Self
    }
}

/// 审批结果
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApproveMemberResult {
    /// 用户关闭弹窗
    Closed,
    /// 批准了某个请求
    Approved {
        requester_id: String,
    },
    /// 拒绝了某个请求
    Rejected {
        requester_id: String,
    },
}

/// 渲染成员审批弹窗
///
/// 返回 `Some(ApproveMemberResult)` 表示用户已完成操作或关闭弹窗。
pub fn render_approve_member_dialog(
    ctx: &Context,
    _dialog: &mut ApproveMemberDialog,
    pending_requests: &[JoinRequest],
    group: &mut Group,
    admin_signing_key: &ed25519_dalek::SigningKey,
) -> Option<ApproveMemberResult> {
    let mut result = None;
    let mut open = true;

    Window::new("⏳ 审批加入请求")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .open(&mut open)
        .show(ctx, |ui| {
            ui.label("以下用户请求加入本组，请审批：");
            ui.add_space(8.0);

            if pending_requests.is_empty() {
                ui.label("当前没有待审批的加入请求。");
            } else {
                egui::ScrollArea::vertical().max_height(250.0).show(ui, |ui| {
                    for request in pending_requests {
                        let requester_id = hex::encode(request.requester_public_key.as_bytes());
                        let id_short = if requester_id.len() > 16 {
                            format!("{}...", &requester_id[..16])
                        } else {
                            requester_id.clone()
                        };

                        ui.group(|ui| {
                            ui.horizontal(|ui| {
                                ui.label("👤");
                                ui.monospace(&id_short);
                            });
                            ui.horizontal(|ui| {
                                ui.label("设备指纹:");
                                ui.label(&request.device_fingerprint);
                            });
                            ui.horizontal(|ui| {
                                ui.label("申请时间:");
                                ui.label(request.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string());
                            });

                            ui.add_space(4.0);
                            ui.horizontal(|ui| {
                                if ui.button("✅ 批准").clicked() {
                                    match approve_join(group, request, admin_signing_key) {
                                        Ok(_approval) => {
                                            result = Some(ApproveMemberResult::Approved {
                                                requester_id: requester_id.clone(),
                                            });
                                        }
                                        Err(e) => {
                                            ui.colored_label(
                                                egui::Color32::RED,
                                                format!("批准失败: {}", e),
                                            );
                                        }
                                    }
                                }
                                if ui.button("❌ 拒绝").clicked() {
                                    if let Err(e) = reject_join(group, request, admin_signing_key) {
                                        ui.colored_label(
                                            egui::Color32::RED,
                                            format!("拒绝失败: {}", e),
                                        );
                                    } else {
                                        result = Some(ApproveMemberResult::Rejected {
                                            requester_id: requester_id.clone(),
                                        });
                                    }
                                }
                            });
                        });
                        ui.add_space(8.0);
                    }
                });
            }

            ui.add_space(8.0);
            if ui.button("关闭").clicked() {
                result = Some(ApproveMemberResult::Closed);
            }
        });

    if !open {
        result = Some(ApproveMemberResult::Closed);
    }

    result
}

/// 从组成员中提取待审批的加入请求（基于 PendingApproval 状态）
///
/// ⚠️ 注意：本函数构造的 `JoinRequest` 中 `signature` 字段为全零填充，
/// 仅用于 UI 展示和 Admin 审批流程。这些对象**不可**用于 P2P 传输或签名验证。
/// 实际网络传输的 `JoinRequest` 必须由请求者使用真实私钥签名。
pub fn pending_join_requests_from_group(group: &Group) -> Vec<JoinRequest> {
    group
        .member_map
        .values()
        .filter(|m| m.status == MemberStatus::PendingApproval)
        .map(|m| JoinRequest {
            group_id: group.group_id.clone(),
            requester_public_key: m.public_key,
            device_fingerprint: m.device_fingerprint.clone(),
            timestamp: m.joined_at,
            signature: ed25519_dalek::Signature::from_bytes(&[0u8; 64]),
        })
        .collect()
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;
    use crate::crypto::signing::generate_keypair;
    use crate::group::manager::{create_group, GroupConfig};
    use crate::group::member::Member;

    #[test]
    fn test_pending_members_empty_for_new_group() {
        let (admin_sk, _admin_vk) = generate_keypair();
        let (group, _gsk) = create_group("Test", &admin_sk, GroupConfig::default()).unwrap();
        let pending = pending_join_requests_from_group(&group);
        // Admin 在创建时直接激活，没有 PendingApproval
        assert!(pending.is_empty());
    }

    #[test]
    fn test_pending_members_detects_pending() {
        use crate::rbac::role::Role;
        let (admin_sk, _admin_vk) = generate_keypair();
        let (_user_sk, user_vk) = generate_keypair();
        let (mut group, _gsk) = create_group("Test", &admin_sk, GroupConfig::default()).unwrap();

        // 手动添加一个 PendingApproval 成员
        let member = Member::from_public_key(user_vk, Role::FreeUser, "fp".to_string());
        group.member_map.insert(member.member_id.clone(), member);

        let pending = pending_join_requests_from_group(&group);
        assert_eq!(pending.len(), 1);
    }
}
