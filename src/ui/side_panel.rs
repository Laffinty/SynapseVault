//! 侧边栏组件
//!
//! 提供导航按钮和锁定入口，支持响应式宽度（140–200px）和折叠。

use crate::app::{Panel, SynapseVaultApp};
use egui::Ui;

/// 渲染侧边栏
pub fn render_side_panel(app: &mut SynapseVaultApp, ui: &mut Ui) {
    let panel_width = if app.side_panel_collapsed {
        48.0
    } else {
        160.0f32
            .clamp(140.0, ui.available_width().min(200.0))
    };

    egui::Panel::left("side_panel")
        .exact_size(panel_width)
        .show_inside(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(10.0);
                if app.side_panel_collapsed {
                    if ui.button("▶").clicked() {
                        app.side_panel_collapsed = false;
                    }
                } else {
                    ui.label("导航");
                    if ui.button("◀").clicked() {
                        app.side_panel_collapsed = true;
                    }
                }
                ui.separator();
            });

            if !app.side_panel_collapsed {
                let buttons = [
                    ("组管理", Panel::GroupManagement),
                    ("密码库", Panel::SecretVault),
                    ("权限", Panel::RbacManagement),
                    ("审计", Panel::AuditLog),
                ];

                for (label, panel) in &buttons {
                    let is_active = app.current_panel == *panel;
                    let btn = egui::Button::new(*label)
                        .fill(if is_active {
                            ui.visuals().selection.bg_fill
                        } else {
                            ui.visuals().widgets.inactive.bg_fill
                        })
                        .min_size(egui::vec2(140.0, 32.0));
                    if ui.add(btn).clicked() {
                        app.current_panel = *panel;
                    }
                    ui.add_space(4.0);
                }

                ui.add_space(20.0);
                ui.separator();
            }

            ui.vertical_centered(|ui| {
                if ui.button("锁定").clicked() {
                    app.lock_app();
                }
            });
        });
}
