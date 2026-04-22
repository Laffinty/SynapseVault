//! 顶部栏组件
//!
//! 显示应用标题、解锁状态、当前组名、在线人数、主题切换和设置入口。

use crate::app::{SynapseVaultApp, ThemeMode};
use egui::{Context, Ui};

/// 渲染顶部栏
pub fn render_top_bar(app: &mut SynapseVaultApp, ctx: &Context, ui: &mut Ui) {
    egui::Panel::top("top_bar").show_inside(ui, |ui| {
        ui.horizontal(|ui| {
            ui.heading("SynapseVault");
            ui.separator();

            ui.label("已解锁");
            ui.separator();

            let group_name = app
                .current_group
                .as_ref()
                .map(|g| g.name.as_str())
                .unwrap_or("未加入");
            ui.label(format!("组: {}", group_name));
            ui.separator();

            // 在线人数（基于 discovery_state 中的已知 peer 数）
            let online_count = app.discovery_state.peer_to_group.len();
            ui.label(format!("在线: {}/{}", online_count, online_count.max(1)));

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let theme_icon = match app.theme {
                    ThemeMode::Dark => "浅色",
                    ThemeMode::Light => "深色",
                };
                if ui.button(theme_icon).clicked() {
                    app.toggle_theme(ctx);
                }
                if ui.button("设置").clicked() {
                    app.current_panel = crate::app::Panel::Settings;
                }
            });
        });
    });
}
