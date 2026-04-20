//! 解锁窗口 UI 组件
//!
//! 提供首次设置和解锁两种模式的渲染逻辑。

use egui::{Context, Vec2};

/// 解锁窗口模式
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum UnlockWindowMode {
    /// 首次使用，需要创建密钥文件
    FirstSetup,
    /// 已有密钥文件，输入密码解锁
    Unlock,
}

/// 解锁窗口用户动作
#[derive(Clone, Debug, PartialEq)]
pub enum UnlockAction {
    /// 用户点击了主按钮（创建/解锁）
    Submit,
    /// 用户点击了忘记密码
    ForgotPassword,
}

/// 渲染解锁窗口
#[allow(clippy::too_many_arguments)]
///
/// # 参数
/// - `ctx`: egui 上下文
/// - `mode`: 窗口模式（首次设置 / 解锁）
/// - `key_file_path`: 密钥文件路径输入
/// - `password`: 密码输入
/// - `confirm_password`: 确认密码输入（仅首次设置使用）
/// - `show_password`: 是否明文显示密码
/// - `error`: 错误信息（渲染后由调用方清除）
/// - `is_unlocking`: 是否正在解锁中（显示 spinner）
///
/// # 返回
/// 用户触发的动作（如果有）
pub fn render_unlock_window(
    ctx: &Context,
    mode: UnlockWindowMode,
    key_file_path: &mut String,
    password: &mut String,
    confirm_password: &mut String,
    show_password: &mut bool,
    error: &mut Option<String>,
    is_unlocking: bool,
) -> Option<UnlockAction> {
    let screen_rect = ctx.viewport_rect();
    let window_size = match mode {
        UnlockWindowMode::FirstSetup => Vec2::new(420.0, 380.0),
        UnlockWindowMode::Unlock => Vec2::new(420.0, 340.0),
    };
    let pos = screen_rect.center() - window_size * 0.5;

    let mut action = None;

    let title = match mode {
        UnlockWindowMode::FirstSetup => "🔐 首次设置 SynapseVault",
        UnlockWindowMode::Unlock => "🔐 解锁 SynapseVault",
    };

    egui::Window::new(title)
        .fixed_pos(pos)
        .fixed_size(window_size)
        .resizable(false)
        .collapsible(false)
        .movable(false)
        .title_bar(true)
        .show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(16.0);
                ui.heading("SynapseVault");
                ui.label("局域网团队密码库");
                ui.add_space(16.0);

                // 密钥文件路径
                ui.horizontal(|ui| {
                    ui.label("密钥文件:");
                    ui.add(
                        egui::TextEdit::singleline(key_file_path)
                            .hint_text("输入 .key 文件路径..."),
                    );
                });
                if key_file_path.is_empty() {
                    ui.colored_label(
                        egui::Color32::GRAY,
                        "提示: 输入 .key 文件的保存/加载路径",
                    );
                }

                ui.add_space(8.0);

                // 密码输入
                ui.horizontal(|ui| {
                    ui.label("主密码:  ");
                    if *show_password {
                        ui.add(
                            egui::TextEdit::singleline(password)
                                .password(false)
                                .hint_text("输入主密码..."),
                        );
                    } else {
                        ui.add(
                            egui::TextEdit::singleline(password)
                                .password(true)
                                .hint_text("输入主密码..."),
                        );
                    }
                    if ui
                        .button(if *show_password { "🙈" } else { "👁" })
                        .clicked()
                    {
                        *show_password = !*show_password;
                    }
                });

                // 首次设置：确认密码
                if mode == UnlockWindowMode::FirstSetup {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label("确认密码:");
                        if *show_password {
                            ui.add(
                                egui::TextEdit::singleline(confirm_password)
                                    .password(false)
                                    .hint_text("再次输入主密码..."),
                            );
                        } else {
                            ui.add(
                                egui::TextEdit::singleline(confirm_password)
                                    .password(true)
                                    .hint_text("再次输入主密码..."),
                            );
                        }
                    });
                }

                ui.add_space(8.0);

                // 错误信息
                if let Some(ref err) = *error {
                    ui.colored_label(egui::Color32::RED, format!("错误: {}", err));
                }

                ui.add_space(12.0);

                // 操作按钮
                if is_unlocking {
                    ui.add(egui::Spinner::new());
                    ui.label("正在解锁，请稍候...");
                } else {
                    let btn_text = match mode {
                        UnlockWindowMode::FirstSetup => "创建密钥并进入",
                        UnlockWindowMode::Unlock => "解锁",
                    };
                    let btn_size = [140.0, 36.0];
                    if ui.add_sized(btn_size, egui::Button::new(btn_text)).clicked() {
                        action = Some(UnlockAction::Submit);
                    }

                    if mode == UnlockWindowMode::Unlock {
                        ui.add_space(8.0);
                        if ui.button("忘记密码？").clicked() {
                            action = Some(UnlockAction::ForgotPassword);
                        }
                    }
                }
            });
        });

    action
}
