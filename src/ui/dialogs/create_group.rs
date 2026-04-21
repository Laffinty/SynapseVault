//! 创建组弹窗
//!
//! 提供输入组名、选择配置并创建新群组的 UI。

use crate::auth::unlock::UnlockedSession;
use crate::group::group_key::GroupSigningKey;
use crate::group::manager::{create_group, Group, GroupConfig, GroupError};
use egui::{Context, Window};

/// 创建组弹窗状态
#[derive(Default)]
pub struct CreateGroupDialog {
    pub group_name: String,
    pub error: Option<String>,
}

impl CreateGroupDialog {
    pub fn new() -> Self {
        Self::default()
    }
}

/// 弹窗操作结果
#[allow(clippy::large_enum_variant)]
pub enum CreateGroupResult {
    /// 用户取消
    Cancelled,
    /// 成功创建
    Created(Group, GroupSigningKey),
}

/// 渲染创建组弹窗
///
/// 返回 `Some(CreateGroupResult)` 表示用户已做出选择（创建成功或取消）。
pub fn render_create_group_dialog(
    ctx: &Context,
    dialog: &mut CreateGroupDialog,
    session: &UnlockedSession,
) -> Option<CreateGroupResult> {
    let mut result = None;
    let mut open = true;

    Window::new("➕ 创建新组")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .open(&mut open)
        .show(ctx, |ui| {
            ui.label("请输入新组的名称：");
            ui.text_edit_singleline(&mut dialog.group_name);
            ui.add_space(8.0);

            ui.label("配置：");
            ui.label("• 端口: 42424 (默认)");
            ui.label("• 最大成员: 50 (默认)");
            ui.label("• 加入需审批: 是 (默认)");
            ui.add_space(8.0);

            if let Some(ref err) = dialog.error {
                ui.colored_label(egui::Color32::RED, format!("❌ {}", err));
                ui.add_space(8.0);
            }

            ui.horizontal(|ui| {
                if ui.button("取消").clicked() {
                    result = Some(CreateGroupResult::Cancelled);
                }
                if ui.button("创建").clicked() {
                    let name = dialog.group_name.trim();
                    if name.is_empty() {
                        dialog.error = Some("组名不能为空".to_string());
                    } else if name.len() > 64 {
                        dialog.error = Some("组名长度不能超过 64 个字符".to_string());
                    } else {
                        match create_group(name, &session.private_key, GroupConfig::default()) {
                            Ok((group, gsk)) => {
                                result = Some(CreateGroupResult::Created(group, gsk));
                            }
                            Err(GroupError::Serialization(e)) => {
                                dialog.error = Some(format!("序列化错误: {}", e));
                            }
                            Err(e) => {
                                dialog.error = Some(format!("创建失败: {}", e));
                            }
                        }
                    }
                }
            });
        });

    if !open {
        result = Some(CreateGroupResult::Cancelled);
    }

    result
}
