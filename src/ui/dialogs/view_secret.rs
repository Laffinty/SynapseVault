//! 查看密码弹窗
//!
//! 显示密码条目的详细信息，支持显示/隐藏密码明文、复制到剪贴板。

use crate::secret::entry::{SecretEntry, SecretId};
use egui::{Color32, Context, Window};
use zeroize::Zeroize;

/// 查看密码弹窗状态
#[derive(Clone, Debug)]
pub struct ViewSecretDialog {
    pub secret_id: SecretId,
    pub title: String,
    pub username: String,
    pub password_plaintext: String,
    pub environment: String,
    pub tags: Vec<String>,
    pub description: String,
    pub show_password: bool,
    pub copied: bool,
    pub copy_timer: f32,
}

impl ViewSecretDialog {
    pub fn new(secret_id: SecretId, entry: &SecretEntry, password_plaintext: String) -> Self {
        Self {
            secret_id,
            title: entry.title.clone(),
            username: entry.username.clone(),
            password_plaintext,
            environment: entry.environment.clone(),
            tags: entry.tags.clone(),
            description: entry.description.clone(),
            show_password: false,
            copied: false,
            copy_timer: 0.0,
        }
    }
}

impl Drop for ViewSecretDialog {
    fn drop(&mut self) {
        self.password_plaintext.zeroize();
    }
}

/// 渲染查看密码弹窗
///
/// # 返回
/// - `true` 表示用户点击了关闭
pub fn render_view_secret_dialog(
    ctx: &Context,
    dialog: &mut ViewSecretDialog,
    on_copy: &mut dyn FnMut(&str),
) -> bool {
    let mut close = false;

    Window::new("查看密码")
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .show(ctx, |ui| {
            ui.set_min_width(400.0);

            ui.horizontal(|ui| {
                ui.label("标题:");
                ui.strong(&dialog.title);
            });
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                ui.label("用户名:");
                ui.strong(&dialog.username);
                if ui.button("复制用户名").clicked() {
                    on_copy(&dialog.username);
                    dialog.copied = true;
                    dialog.copy_timer = 2.0;
                }
            });
            ui.add_space(8.0);

            // 密码显示区域
            ui.group(|ui| {
                ui.label("密码:");
                ui.horizontal(|ui| {
                    let password_display = if dialog.show_password {
                        dialog.password_plaintext.clone()
                    } else {
                        "•".repeat(dialog.password_plaintext.len().max(8))
                    };

                    ui.add(
                        egui::TextEdit::singleline(&mut password_display.clone())
                            .password(!dialog.show_password)
                            .desired_width(280.0),
                    );

                    if ui
                        .button(if dialog.show_password {
                            "隐藏"
                        } else {
                            "显示"
                        })
                        .clicked()
                    {
                        dialog.show_password = !dialog.show_password;
                    }
                });

                ui.horizontal(|ui| {
                    if ui.button("复制密码").clicked() {
                        on_copy(&dialog.password_plaintext);
                        dialog.copied = true;
                        dialog.copy_timer = 2.0;
                    }
                    if dialog.copied {
                        ui.colored_label(Color32::GREEN, "已复制");
                    }
                });
            });
            ui.add_space(8.0);

            ui.horizontal(|ui| {
                ui.label("环境:");
                ui.label(&dialog.environment);
            });

            if !dialog.tags.is_empty() {
                ui.horizontal(|ui| {
                    ui.label("标签:");
                    for tag in &dialog.tags {
                        ui.label(
                            egui::RichText::new(format!("[标签] {}", tag))
                                .background_color(ui.visuals().widgets.inactive.bg_fill),
                        );
                    }
                });
            }

            if !dialog.description.is_empty() {
                ui.add_space(4.0);
                ui.label("描述:");
                ui.label(&dialog.description);
            }

            ui.add_space(16.0);
            ui.separator();
            ui.horizontal(|ui| {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("关闭").clicked() {
                        close = true;
                    }
                });
            });
        });

    // 复制提示计时器衰减
    if dialog.copied {
        dialog.copy_timer -= ctx.input(|i| i.stable_dt);
        if dialog.copy_timer <= 0.0 {
            dialog.copied = false;
        }
    }

    close
}
