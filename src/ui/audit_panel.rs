//! 审计面板
//!
//! 在 egui 中展示审计日志列表、筛选与导出入口。

use crate::app::{DialogState, SynapseVaultApp};
use crate::audit::event::OperationType;
use crate::audit::export::{export_events, ExportFormat};
use crate::audit::logger::{query_events, AuditQuery};
use chrono::Utc;
use egui::{Context, Ui};

/// 审计面板状态
#[derive(Clone, Debug, Default)]
pub struct AuditPanelState {
    pub filter_type: Option<OperationType>,
    pub filter_actor: String,
    pub filter_secret: String,
    pub show_export_dialog: bool,
    pub export_format: ExportFormat,
    pub events: Vec<crate::audit::event::AuditEvent>,
    pub last_refresh: Option<chrono::DateTime<Utc>>,
}

/// 渲染审计面板
pub fn render_audit_panel(app: &mut SynapseVaultApp, ctx: &Context, ui: &mut Ui) {
    ui.heading("📋 审计日志");
    ui.add_space(8.0);

    // 从 active_dialog 解析当前筛选条件
    let filter_type = app
        .active_dialog
        .as_ref()
        .and_then(|d| match d {
            DialogState::AuditFilterType { operation_type } => *operation_type,
            _ => None,
        });

    // 处理一次性触发动作
    if let Some(ref dialog) = app.active_dialog {
        match dialog {
            DialogState::AuditRefresh => {
                app.active_dialog = Some(DialogState::AuditFilterType { operation_type: filter_type });
            }
            DialogState::AuditExport { format } => {
                handle_audit_export(app, ctx, *format);
                // 导出弹窗自行管理关闭
                return;
            }
            _ => {}
        }
    }

    // 筛选栏
    ui.horizontal(|ui| {
        ui.label("操作类型:");

        let types = [
            ("全部", None),
            ("查看密码", Some(OperationType::ViewSecret)),
            ("复制密码", Some(OperationType::CopySecret)),
            ("创建密码", Some(OperationType::CreateSecret)),
            ("更新密码", Some(OperationType::UpdateSecret)),
            ("删除密码", Some(OperationType::DeleteSecret)),
            ("成员审批", Some(OperationType::MemberApprove)),
            ("角色变更", Some(OperationType::RoleChange)),
            ("使用审批", Some(OperationType::UsageApprove)),
            ("生成区块", Some(OperationType::BlockProduced)),
        ];

        let selected_label = types
            .iter()
            .find(|(_, op)| *op == filter_type)
            .map(|(label, _)| *label)
            .unwrap_or("全部");

        egui::ComboBox::from_id_salt("audit_type_filter")
            .width(120.0)
            .selected_text(selected_label)
            .show_ui(ui, |ui| {
                for (label, op) in &types {
                    if ui.selectable_label(*op == filter_type, *label).clicked() {
                        app.active_dialog = Some(DialogState::AuditFilterType { operation_type: *op });
                    }
                }
            });

        ui.separator();

        if ui.button("🔄 刷新").clicked() {
            app.active_dialog = Some(DialogState::AuditRefresh);
        }

        if ui.button("📤 导出 JSON").clicked() {
            app.active_dialog = Some(DialogState::AuditExport { format: ExportFormat::Json });
        }

        if ui.button("📤 导出 CSV").clicked() {
            app.active_dialog = Some(DialogState::AuditExport { format: ExportFormat::Csv });
        }
    });

    ui.separator();

    // 加载事件
    let events = if let Some(ref conn) = app.db_conn {
        let query = AuditQuery {
            operation_type: filter_type,
            limit: Some(100),
            ..Default::default()
        };
        match query_events(conn, &query) {
            Ok(evts) => evts,
            Err(e) => {
                ui.colored_label(egui::Color32::RED, format!("查询失败: {}", e));
                return;
            }
        }
    } else {
        Vec::new()
    };

    if events.is_empty() {
        ui.label("暂无审计记录。");
        return;
    }

    // 事件列表
    egui::ScrollArea::vertical().show(ui, |ui| {
        egui::Grid::new("audit_grid")
            .num_columns(5)
            .spacing([12.0, 8.0])
            .striped(true)
            .show(ui, |ui| {
                ui.label("时间");
                ui.label("操作");
                ui.label("执行者");
                ui.label("目标");
                ui.label("设备指纹");
                ui.end_row();

                for event in &events {
                    ui.label(event.timestamp.format("%Y-%m-%d %H:%M:%S").to_string());
                    ui.label(event.operation_type.to_string());
                    ui.label(&event.actor_member_id);
                    ui.label(event.target_secret_id.as_deref().unwrap_or("-"));
                    ui.label(&event.device_fingerprint);
                    ui.end_row();
                }
            });
    });
}

/// 处理审计导出弹窗
fn handle_audit_export(
    app: &mut SynapseVaultApp,
    ctx: &Context,
    format: ExportFormat,
) {
    let mut close = false;
    egui::Window::new("导出审计日志")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .show(ctx, |ui| {
            if let Some(ref conn) = app.db_conn {
                let query = AuditQuery::default();
                let count = query_events(conn, &query).map(|e| e.len()).unwrap_or(0);
                ui.label(format!("即将导出 {} 条记录", count));
            } else {
                ui.label("数据库未连接");
            }
            ui.add_space(10.0);

            if ui.button("选择保存路径").clicked() {
                let ext = match format {
                    ExportFormat::Json => "json",
                    ExportFormat::Csv => "csv",
                };
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter(ext.to_uppercase().as_str(), &[ext])
                    .save_file()
                {
                    if let Some(ref conn) = app.db_conn {
                        let query = AuditQuery::default();
                        match std::fs::File::create(&path) {
                            Ok(mut file) => {
                                match export_events(conn, &query, format, &mut file) {
                                    Ok(count) => {
                                        ui.label(format!("✅ 成功导出 {} 条记录", count));
                                    }
                                    Err(e) => {
                                        ui.colored_label(
                                            egui::Color32::RED,
                                            format!("导出失败: {}", e),
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                ui.colored_label(
                                    egui::Color32::RED,
                                    format!("创建文件失败: {}", e),
                                );
                            }
                        }
                    }
                }
                close = true;
            }

            ui.add_space(10.0);
            if ui.button("取消").clicked() {
                close = true;
            }
        });

    if close {
        app.active_dialog = None;
    }
}
