//! AuditUser 使用申请弹窗

use egui::Context;

/// 使用申请弹窗状态
#[derive(Clone, Debug)]
pub struct UsageRequestDialog {
    pub target_secret_id: String,
    pub reason: String,
    pub submitted: bool,
    pub error: Option<String>,
}

impl UsageRequestDialog {
    pub fn new(target_secret_id: String) -> Self {
        Self {
            target_secret_id,
            reason: String::new(),
            submitted: false,
            error: None,
        }
    }
}

/// 渲染使用申请弹窗
///
/// 返回 Some(request) 当用户提交，None 当关闭
pub fn render_usage_request_dialog(
    ctx: &Context,
    dialog: &mut UsageRequestDialog,
) -> Option<crate::rbac::policy::UsageRequest> {
    let mut result = None;
    let mut close = false;

    egui::Window::new("申请查看密码")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .show(ctx, |ui| {
            ui.label(format!("目标密码 ID: {}", dialog.target_secret_id));
            ui.add_space(8.0);

            ui.label("申请原因:");
            ui.add(
                egui::TextEdit::multiline(&mut dialog.reason)
                    .desired_width(300.0)
                    .desired_rows(3),
            );

            if let Some(ref err) = dialog.error {
                ui.colored_label(egui::Color32::RED, err);
            }

            if dialog.submitted {
                ui.colored_label(egui::Color32::GREEN, "申请已提交，等待 Admin 审批");
            }

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if !dialog.submitted && ui.button("提交申请").clicked() && !dialog.reason.trim().is_empty() {
                    result = Some(());
                }
                if ui.button("关闭").clicked() {
                    close = true;
                }
            });
        });

    if close {
        return None;
    }
    // The actual request creation is handled by the caller using app state
    result.map(|_| {
        // Placeholder - actual creation happens in app.rs
        unreachable!("Request creation handled externally")
    })
}

/// 渲染简化版使用申请弹窗（直接在 app 层处理请求创建）
///
/// 返回 true 表示用户点击了提交
pub fn render_usage_request_simple(
    ctx: &Context,
    reason: &mut String,
    target_secret_id: &str,
    error: &Option<String>,
) -> (bool, bool) {
    let mut submitted = false;
    let mut close = false;

    egui::Window::new("申请查看密码")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .show(ctx, |ui| {
            ui.label(format!("目标密码 ID: {}", target_secret_id));
            ui.add_space(8.0);

            ui.label("申请原因:");
            ui.add(
                egui::TextEdit::multiline(reason)
                    .desired_width(300.0)
                    .desired_rows(3),
            );

            if let Some(err) = error {
                ui.colored_label(egui::Color32::RED, err);
            }

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("提交申请").clicked() && !reason.trim().is_empty() {
                    submitted = true;
                }
                if ui.button("关闭").clicked() {
                    close = true;
                }
            });
        });

    (submitted, close)
}
