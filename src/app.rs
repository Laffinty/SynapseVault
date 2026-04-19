use egui::{CentralPanel, Context, Ui, Visuals};

/// 应用面板枚举
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Panel {
    GroupManagement,
    SecretVault,
    RbacManagement,
    AuditLog,
    Settings,
}

/// 主题模式
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum ThemeMode {
    Dark,
    Light,
}

/// 解锁状态
#[derive(Clone, PartialEq, Debug)]
pub enum UnlockState {
    Locked,
    Unlocking,
    Unlocked,
}

/// 主应用状态机
pub struct SynapseVaultApp {
    pub unlock_state: UnlockState,
    pub current_panel: Panel,
    pub theme: ThemeMode,

    // 解锁窗口状态
    pub password_input: String,
    pub show_password: bool,
    pub unlock_error: Option<String>,

    // 搜索与过滤
    pub secret_search_query: String,

    // 弹窗状态
    pub show_dialog: Option<String>,
}

impl Default for SynapseVaultApp {
    fn default() -> Self {
        Self {
            unlock_state: UnlockState::Locked,
            current_panel: Panel::SecretVault,
            theme: ThemeMode::Dark,
            password_input: String::new(),
            show_password: false,
            unlock_error: None,
            secret_search_query: String::new(),
            show_dialog: None,
        }
    }
}

impl SynapseVaultApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let app = Self::default();
        app.apply_theme(&_cc.egui_ctx);
        app
    }

    fn apply_theme(&self, ctx: &Context) {
        match self.theme {
            ThemeMode::Dark => ctx.set_visuals(Visuals::dark()),
            ThemeMode::Light => ctx.set_visuals(Visuals::light()),
        }
    }

    fn toggle_theme(&mut self, ctx: &Context) {
        self.theme = match self.theme {
            ThemeMode::Dark => ThemeMode::Light,
            ThemeMode::Light => ThemeMode::Dark,
        };
        self.apply_theme(ctx);
    }

    /// 渲染解锁窗口
    fn render_unlock_window(&mut self, ctx: &Context) {
        let screen_rect = ctx.viewport_rect();
        let window_size = egui::vec2(400.0, 280.0);
        let pos = screen_rect.center() - window_size * 0.5;

        egui::Window::new("🔐 解锁 SynapseVault")
            .fixed_pos(pos)
            .fixed_size(window_size)
            .resizable(false)
            .collapsible(false)
            .movable(false)
            .title_bar(true)
            .show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(20.0);
                    ui.heading("SynapseVault");
                    ui.label("局域网团队密码库");
                    ui.add_space(20.0);

                    ui.horizontal(|ui| {
                        ui.label("主密码:");
                        if self.show_password {
                            ui.text_edit_singleline(&mut self.password_input);
                        } else {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.password_input).password(true),
                            );
                        }
                        if ui
                            .button(if self.show_password { "🙈" } else { "👁" })
                            .clicked()
                        {
                            self.show_password = !self.show_password;
                        }
                    });

                    ui.add_space(10.0);

                    if let Some(ref err) = self.unlock_error {
                        ui.colored_label(egui::Color32::RED, format!("错误: {}", err));
                    }

                    ui.add_space(10.0);

                    let can_unlock = !self.password_input.is_empty();
                    if ui
                        .add_sized([120.0, 36.0], egui::Button::new("解锁"))
                        .clicked()
                        && can_unlock
                    {
                        // FIXME(Phase 1): 接入 auth::unlock::unlock_key_file 真实解锁逻辑。
                        // 当前为 Phase 0 骨架占位，任何非空密码均通过。
                        self.unlock_state = UnlockState::Unlocked;
                        self.unlock_error = None;
                    }

                    ui.add_space(10.0);
                    if ui.button("忘记密码？").clicked() {
                        self.show_dialog = Some("forget_password".to_string());
                    }
                });
            });
    }

    /// 渲染顶部栏
    fn render_top_bar(&mut self, ui: &mut Ui) {
        egui::Panel::top("top_bar").show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading("SynapseVault");
                ui.separator();

                let status_text = match self.unlock_state {
                    UnlockState::Locked => "🔒 已锁定",
                    UnlockState::Unlocking => "⏳ 解锁中...",
                    UnlockState::Unlocked => "🔓 已解锁",
                };
                ui.label(status_text);

                ui.separator();
                ui.label("组: 未加入");
                ui.separator();
                ui.label("在线: 0/0");

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let theme_icon = match self.theme {
                        ThemeMode::Dark => "☀️",
                        ThemeMode::Light => "🌙",
                    };
                    if ui.button(theme_icon).clicked() {
                        self.toggle_theme(ui.ctx());
                    }
                    if ui.button("⚙️").clicked() {
                        self.current_panel = Panel::Settings;
                    }
                });
            });
        });
    }

    /// 渲染侧边栏
    fn render_side_panel(&mut self, ui: &mut Ui) {
        egui::Panel::left("side_panel")
            .exact_size(160.0)
            .show_inside(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(10.0);
                    ui.label("导航");
                    ui.separator();
                });

                let buttons = [
                    ("📁 组管理", Panel::GroupManagement),
                    ("🔑 密码库", Panel::SecretVault),
                    ("🛡️ 权限", Panel::RbacManagement),
                    ("📋 审计", Panel::AuditLog),
                ];

                for (label, panel) in &buttons {
                    let is_active = self.current_panel == *panel;
                    let btn = egui::Button::new(*label)
                        .fill(if is_active {
                            ui.visuals().selection.bg_fill
                        } else {
                            ui.visuals().widgets.inactive.bg_fill
                        })
                        .min_size(egui::vec2(140.0, 32.0));
                    if ui.add(btn).clicked() {
                        self.current_panel = *panel;
                    }
                    ui.add_space(4.0);
                }

                ui.add_space(20.0);
                ui.separator();
                if ui.button("🔒 锁定").clicked() {
                    self.unlock_state = UnlockState::Locked;
                    self.password_input.clear();
                }
            });
    }

    /// 渲染中央面板
    fn render_central_panel(&mut self, ui: &mut Ui) {
        CentralPanel::default().show_inside(ui, |ui| match self.current_panel {
            Panel::GroupManagement => {
                ui.heading("📁 组管理");
                ui.label("此面板用于创建组、发现组和管理成员。");
                ui.add_space(20.0);
                ui.group(|ui| {
                    ui.label("操作:");
                    if ui.button("➕ 创建新组").clicked() {
                        self.show_dialog = Some("create_group".to_string());
                    }
                    if ui.button("🔍 发现组").clicked() {
                        self.show_dialog = Some("discover_groups".to_string());
                    }
                });
            }
            Panel::SecretVault => {
                ui.heading("🔑 密码库");
                ui.horizontal(|ui| {
                    ui.label("搜索:");
                    ui.text_edit_singleline(&mut self.secret_search_query);
                });
                ui.add_space(10.0);
                ui.label("密码列表将在此显示。");
            }
            Panel::RbacManagement => {
                ui.heading("🛡️ 权限管理");
                ui.label("角色与权限配置面板。");
            }
            Panel::AuditLog => {
                ui.heading("📋 审计日志");
                ui.label("区块链审计记录将在此显示。");
            }
            Panel::Settings => {
                ui.heading("⚙️ 设置");
                ui.label("应用设置与配置。");
            }
        });
    }

    /// 渲染弹窗
    fn render_dialogs(&mut self, ctx: &Context) {
        if let Some(ref dialog) = self.show_dialog.clone() {
            let mut close = false;
            egui::Window::new("提示")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .show(ctx, |ui| {
                    match dialog.as_str() {
                        "forget_password" => {
                            ui.label("忘记密码将重置本地身份，需要重新申请加入组。");
                            ui.colored_label(egui::Color32::RED, "警告：本地数据将无法恢复！");
                        }
                        "create_group" => {
                            ui.label("创建新组功能将在后续阶段实现。");
                        }
                        "discover_groups" => {
                            ui.label("组发现功能将在后续阶段实现。");
                        }
                        _ => {
                            ui.label(format!("未知弹窗: {}", dialog));
                        }
                    }
                    ui.add_space(10.0);
                    if ui.button("关闭").clicked() {
                        close = true;
                    }
                });
            if close {
                self.show_dialog = None;
            }
        }
    }
}

impl eframe::App for SynapseVaultApp {
    fn ui(&mut self, ui: &mut Ui, _frame: &mut eframe::Frame) {
        match self.unlock_state {
            UnlockState::Locked | UnlockState::Unlocking => {
                self.render_unlock_window(ui.ctx());
            }
            UnlockState::Unlocked => {
                self.render_top_bar(ui);
                self.render_side_panel(ui);
                self.render_central_panel(ui);
            }
        }

        self.render_dialogs(ui.ctx());

        // 请求持续重绘，保证 UI 响应性
        ui.ctx().request_repaint();
    }
}
