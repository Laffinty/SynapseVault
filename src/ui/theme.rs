//! 主题系统
//!
//! 定义语义化颜色令牌，支持深色/浅色主题切换。

use egui::{Color32, Visuals};

/// SynapseVault 语义化主题
#[derive(Clone, Debug)]
pub struct SynapseVaultTheme {
    pub primary: Color32,
    pub danger: Color32,
    pub warning: Color32,
    pub success: Color32,
    pub surface: Color32,
    pub on_surface: Color32,
    pub sidebar_bg: Color32,
    pub topbar_bg: Color32,
    pub expired_row: Color32,
    pub expiring_row: Color32,
}

/// 根据 is_dark 选择主题
pub fn theme_for_mode(is_dark: bool) -> SynapseVaultTheme {
    if is_dark {
        SynapseVaultTheme::dark()
    } else {
        SynapseVaultTheme::light()
    }
}

impl SynapseVaultTheme {
    pub fn dark() -> Self {
        Self {
            primary: Color32::from_rgb(100, 149, 237),
            danger: Color32::from_rgb(220, 80, 80),
            warning: Color32::from_rgb(220, 180, 50),
            success: Color32::from_rgb(80, 180, 80),
            surface: Color32::from_rgb(35, 35, 40),
            on_surface: Color32::from_rgb(230, 230, 235),
            sidebar_bg: Color32::from_rgb(28, 28, 32),
            topbar_bg: Color32::from_rgb(30, 30, 35),
            expired_row: Color32::from_rgb(80, 25, 25),
            expiring_row: Color32::from_rgb(80, 70, 20),
        }
    }

    pub fn light() -> Self {
        Self {
            primary: Color32::from_rgb(60, 100, 200),
            danger: Color32::from_rgb(200, 50, 50),
            warning: Color32::from_rgb(200, 160, 30),
            success: Color32::from_rgb(50, 150, 50),
            surface: Color32::from_rgb(245, 245, 250),
            on_surface: Color32::from_rgb(30, 30, 35),
            sidebar_bg: Color32::from_rgb(235, 235, 240),
            topbar_bg: Color32::from_rgb(240, 240, 245),
            expired_row: Color32::from_rgb(255, 220, 220),
            expiring_row: Color32::from_rgb(255, 245, 200),
        }
    }

    /// 应用主题到 egui Visuals
    pub fn apply_to_visuals(&self, visuals: &mut Visuals) {
        visuals.widgets.inactive.bg_fill = self.surface;
        visuals.widgets.inactive.fg_stroke.color = self.on_surface;
        visuals.widgets.active.bg_fill = self.primary;
        visuals.widgets.active.fg_stroke.color = Color32::WHITE;
        visuals.widgets.hovered.bg_fill = self.primary.linear_multiply(0.6);
        visuals.widgets.hovered.fg_stroke.color = Color32::WHITE;
        visuals.selection.bg_fill = self.primary.linear_multiply(0.4);
        visuals.selection.stroke.color = self.primary;
    }
}
