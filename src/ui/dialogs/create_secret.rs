//! 创建/编辑密码弹窗
//!
//! 提供输入密码各字段的 UI，支持新建和编辑两种模式。

use chrono::{DateTime, NaiveDate, Utc};
use egui::{Context, Window};

/// 密码弹窗状态
#[derive(Default)]
pub struct CreateSecretDialog {
    /// 是否为编辑模式
    pub is_edit: bool,
    /// 编辑时的 secret_id
    pub secret_id: Option<String>,
    pub title: String,
    pub username: String,
    pub password: String,
    pub environment: String,
    pub tags_input: String,
    pub description: String,
    pub expires_at_str: String,
    pub show_password: bool,
    pub error: Option<String>,
}

impl CreateSecretDialog {
    pub fn new() -> Self {
        Self::default()
    }

    /// 从现有条目创建编辑对话框
    pub fn for_edit(
        secret_id: &str,
        title: &str,
        username: &str,
        environment: &str,
        tags: &[String],
        description: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> Self {
        Self {
            is_edit: true,
            secret_id: Some(secret_id.to_string()),
            title: title.to_string(),
            username: username.to_string(),
            password: String::new(), // 编辑时不预填充密码（需要重新输入或留空表示不改）
            environment: environment.to_string(),
            tags_input: tags.join(", "),
            description: description.to_string(),
            expires_at_str: expires_at.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default(),
            show_password: false,
            error: None,
        }
    }
}

/// 弹窗操作结果
pub enum CreateSecretResult {
    /// 用户取消
    Cancelled,
    /// 提交创建/编辑
    Submit {
        secret_id: Option<String>,
        title: String,
        username: String,
        password: String,
        environment: String,
        tags: Vec<String>,
        description: String,
        expires_at: Option<DateTime<Utc>>,
    },
}

/// 渲染创建/编辑密码弹窗
pub fn render_create_secret_dialog(
    ctx: &Context,
    dialog: &mut CreateSecretDialog,
) -> Option<CreateSecretResult> {
    let mut result = None;
    let mut open = true;

    let window_title = if dialog.is_edit {
        "编辑密码"
    } else {
        "添加新密码"
    };

    Window::new(window_title)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
        .open(&mut open)
        .show(ctx, |ui| {
            ui.label("标题:");
            ui.text_edit_singleline(&mut dialog.title);
            ui.add_space(4.0);

            ui.label("用户名:");
            ui.text_edit_singleline(&mut dialog.username);
            ui.add_space(4.0);

            ui.label("密码:");
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut dialog.password)
                        .password(!dialog.show_password),
                );
                if ui.button(if dialog.show_password { "隐藏" } else { "显示" }).clicked() {
                    dialog.show_password = !dialog.show_password;
                }
            });
            if dialog.is_edit {
                ui.colored_label(egui::Color32::GRAY, "留空表示不修改密码");
            }
            ui.add_space(4.0);

            ui.label("环境:");
            ui.text_edit_singleline(&mut dialog.environment);
            ui.add_space(4.0);

            ui.label("标签（逗号分隔）:");
            ui.text_edit_singleline(&mut dialog.tags_input);
            ui.add_space(4.0);

            ui.label("描述:");
            ui.add(
                egui::TextEdit::multiline(&mut dialog.description)
                    .desired_rows(3),
            );
            ui.add_space(4.0);

            ui.label("过期日期 (YYYY-MM-DD，留空=不过期):");
            ui.text_edit_singleline(&mut dialog.expires_at_str);
            ui.add_space(8.0);

            if let Some(ref err) = dialog.error {
                ui.colored_label(egui::Color32::RED, format!("[错误] {}", err));
                ui.add_space(8.0);
            }

            ui.horizontal(|ui| {
                if ui.button("取消").clicked() {
                    result = Some(CreateSecretResult::Cancelled);
                }
                if ui.button(if dialog.is_edit { "保存" } else { "创建" }).clicked() {
                    let title = dialog.title.trim();
                    if title.is_empty() {
                        dialog.error = Some("标题不能为空".to_string());
                        return;
                    }

                    let expires_at = if dialog.expires_at_str.trim().is_empty() {
                        None
                    } else {
                        match NaiveDate::parse_from_str(dialog.expires_at_str.trim(), "%Y-%m-%d") {
                            Ok(date) => {
                                Some(date.and_hms_opt(0, 0, 0).unwrap().and_utc())
                            }
                            Err(_) => {
                                dialog.error = Some("过期日期格式错误，请使用 YYYY-MM-DD".to_string());
                                return;
                            }
                        }
                    };

                    let tags: Vec<String> = dialog
                        .tags_input
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();

                    result = Some(CreateSecretResult::Submit {
                        secret_id: dialog.secret_id.clone(),
                        title: title.to_string(),
                        username: dialog.username.trim().to_string(),
                        password: dialog.password.clone(),
                        environment: dialog.environment.trim().to_string(),
                        tags,
                        description: dialog.description.trim().to_string(),
                        expires_at,
                    });
                }
            });
        });

    if !open {
        result = Some(CreateSecretResult::Cancelled);
    }

    result
}
