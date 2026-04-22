//! 审计详情弹窗
//!
//! 展示单条审计事件的完整信息。

use crate::audit::event::AuditEvent;
use egui::{Context, Window};

/// 审计详情弹窗状态
#[derive(Clone, Debug)]
pub struct AuditDetailDialog {
    pub event: AuditEvent,
}

impl AuditDetailDialog {
    pub fn new(event: AuditEvent) -> Self {
        Self { event }
    }
}

/// 渲染审计详情弹窗
///
/// 返回 `true` 表示用户已关闭弹窗。
pub fn render_audit_detail_dialog(ctx: &Context, dialog: &mut AuditDetailDialog) -> bool {
    let mut closed = false;

    Window::new("审计详情")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .show(ctx, |ui| {
            ui.heading("📋 事件详情");
            ui.add_space(12.0);

            egui::Grid::new("audit_detail_grid")
                .num_columns(2)
                .spacing([16.0, 8.0])
                .show(ui, |ui| {
                    ui.label("事件 ID:");
                    ui.label(&dialog.event.event_id);
                    ui.end_row();

                    ui.label("操作类型:");
                    ui.label(dialog.event.operation_type.to_string());
                    ui.end_row();

                    ui.label("执行者:");
                    ui.label(&dialog.event.actor_member_id);
                    ui.end_row();

                    ui.label("目标密码:");
                    ui.label(dialog.event.target_secret_id.as_deref().unwrap_or("无"));
                    ui.end_row();

                    ui.label("设备指纹:");
                    ui.label(&dialog.event.device_fingerprint);
                    ui.end_row();

                    ui.label("节点标识:");
                    ui.label(&dialog.event.peer_id);
                    ui.end_row();

                    ui.label("客户端 IP:");
                    ui.label(dialog.event.client_ip.as_deref().unwrap_or("未记录"));
                    ui.end_row();

                    ui.label("时间戳:");
                    ui.label(dialog.event.timestamp.to_rfc3339());
                    ui.end_row();

                    if !dialog.event.summary.is_empty() {
                        ui.label("摘要:");
                        ui.label(&dialog.event.summary);
                        ui.end_row();
                    }

                    ui.label("事件哈希:");
                    ui.monospace(hex::encode(dialog.event.event_hash));
                    ui.end_row();
                });

            ui.add_space(16.0);
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("关闭").clicked() {
                        closed = true;
                    }
                });
            });
        });

    closed
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::event::{AuditEvent, OperationType};

    #[test]
    fn test_audit_detail_dialog_creation() {
        let event = AuditEvent::new(
            "evt-test".to_string(),
            OperationType::ViewSecret,
            "member-1".to_string(),
            "fp-1".to_string(),
            "peer-1".to_string(),
        )
        .with_secret_id("secret-1".to_string())
        .with_summary("测试摘要".to_string());

        let dialog = AuditDetailDialog::new(event.clone());
        assert_eq!(dialog.event.event_id, "evt-test");
        assert_eq!(dialog.event.operation_type, OperationType::ViewSecret);
    }
}
