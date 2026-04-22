//! 主布局组件
//!
//! 组合顶部栏、侧边栏和中央内容区。

use crate::app::{Panel, SynapseVaultApp};
use crate::ui::audit_panel::render_audit_panel;
use crate::ui::group_panel::render_group_panel;
use crate::ui::rbac_panel::render_rbac_panel;
use crate::ui::secret_panel::render_secret_panel;
use crate::ui::side_panel::render_side_panel;
use crate::ui::top_bar::render_top_bar;
use egui::{Context, Ui};

/// 渲染主布局（顶部栏 + 侧边栏 + 中央面板）
pub fn render_main_layout(app: &mut SynapseVaultApp, ctx: &Context, ui: &mut Ui) {
    render_top_bar(app, ctx, ui);
    render_side_panel(app, ui);

    egui::CentralPanel::default().show_inside(ui, |ui| match app.current_panel {
        Panel::GroupManagement => {
            render_group_panel(app, ctx, ui);
        }
        Panel::SecretVault => {
            render_secret_panel(app, ctx, ui);
        }
        Panel::RbacManagement => {
            render_rbac_panel(app, ctx, ui);
        }
        Panel::AuditLog => {
            render_audit_panel(app, ctx, ui);
        }
        Panel::Settings => {
            render_settings_panel(app, ctx, ui);
        }
    });
}

/// 渲染设置面板
fn render_settings_panel(app: &mut SynapseVaultApp, ctx: &Context, ui: &mut Ui) {
    ui.heading("⚙️ 设置");
    ui.add_space(8.0);

    // 使用审批 TTL
    ui.group(|ui| {
        ui.label("使用审批有效期（分钟）:");
        ui.add(
            egui::DragValue::new(&mut app.approval_ttl_minutes)
                .range(1..=60)
                .speed(0.1),
        );
        ui.label(format!("当前: {} 分钟", app.approval_ttl_minutes));
    });

    ui.add_space(8.0);

    // 自动锁定超时
    ui.group(|ui| {
        ui.label("自动锁定超时（分钟，0=禁用）:");
        ui.add(egui::Slider::new(&mut app.auto_lock_minutes, 0..=120).text("分钟"));
        if app.auto_lock_minutes == 0 {
            ui.label("自动锁定已禁用");
        } else {
            ui.label(format!("当前: {} 分钟后自动锁定", app.auto_lock_minutes));
        }
    });

    ui.add_space(8.0);

    // 主题切换
    ui.group(|ui| {
        ui.label("主题:");
        ui.horizontal(|ui| {
            if ui
                .selectable_label(app.theme == crate::app::ThemeMode::Dark, "深色")
                .clicked()
            {
                app.theme = crate::app::ThemeMode::Dark;
                app.apply_theme(ctx);
            }
            if ui
                .selectable_label(app.theme == crate::app::ThemeMode::Light, "浅色")
                .clicked()
            {
                app.theme = crate::app::ThemeMode::Light;
                app.apply_theme(ctx);
            }
        });
    });

    ui.add_space(8.0);

    // Argon2 参数展示
    ui.group(|ui| {
        ui.label("Argon2id 参数:");
        if let Some(ref session) = app.session {
            ui.label(format!("内存: {} KiB", session.argon2_params.memory_cost));
            ui.label(format!("迭代次数: {}", session.argon2_params.time_cost));
            ui.label(format!("并行度: {}", session.argon2_params.parallelism));
        } else {
            ui.label("未解锁");
        }
    });

    ui.add_space(8.0);

    // 数据库路径
    ui.group(|ui| {
        ui.label("数据库路径:");
        let db_path = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("synapsevault")
            .join("vault.db");
        ui.label(db_path.to_string_lossy().to_string());
    });

    ui.add_space(8.0);

    // 密钥文件路径
    ui.group(|ui| {
        ui.label("密钥文件路径:");
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut app.key_file_path)
                    .hint_text("输入 .key 文件路径..."),
            );
            if ui.button("浏览...").clicked() {
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("Key File", &["key"])
                    .pick_file()
                {
                    app.key_file_path = path.to_string_lossy().to_string();
                }
            }
        });
    });

    ui.add_space(16.0);
    ui.separator();

    // 关于区域
    ui.heading("关于");
    ui.label(format!("SynapseVault v{}", env!("CARGO_PKG_VERSION")));
    ui.label("MIT License");
    ui.hyperlink_to(
        "GitHub 仓库",
        "https://github.com/SynapseVault/synapse-vault",
    );
}
