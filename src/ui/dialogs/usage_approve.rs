//! Admin 审批使用请求弹窗

use egui::Context;

/// 渲染使用审批弹窗
///
/// 返回 (approved_request_id, closed) 当用户操作时
pub fn render_usage_approve_dialog(
    ctx: &Context,
    requests: &[crate::rbac::policy::UsageRequest],
) -> (Option<String>, bool) {
    let mut approved = None;
    let mut close = false;

    egui::Window::new("审批使用请求")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .show(ctx, |ui| {
            if requests.is_empty() {
                ui.label("暂无待审批的使用请求。");
            } else {
                ui.label(format!("待审批请求: {} 条", requests.len()));
                ui.add_space(8.0);

                egui::ScrollArea::vertical()
                    .max_height(300.0)
                    .show(ui, |ui| {
                        for req in requests {
                            ui.group(|ui| {
                                ui.label(format!("请求 ID: {}", req.request_id));
                                ui.label(format!("请求者: {}", req.requester));
                                ui.label(format!("目标密码: {}", req.target_secret_id));
                                ui.label(format!("原因: {}", req.reason));
                                ui.label(format!("时间: {}", req.timestamp.format("%Y-%m-%d %H:%M")));

                                ui.horizontal(|ui| {
                                    if ui.button("✓ 批准").clicked() {
                                        approved = Some(req.request_id.clone());
                                    }
                                    // 拒绝仅关闭该请求的显示
                                });
                            });
                            ui.add_space(4.0);
                        }
                    });
            }

            ui.add_space(8.0);
            if ui.button("关闭").clicked() {
                close = true;
            }
        });

    (approved, close)
}
