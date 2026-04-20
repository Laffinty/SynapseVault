use crate::auth::device_fingerprint::generate_device_fingerprint;
use crate::auth::keyfile::{encode_key_file, generate_key_file};
use crate::auth::unlock::{unlock_key_file, UnlockedSession};
use crate::secret::clipboard::SecureClipboard;
use crate::secret::entry::SecretMeta;
use crate::secret::store::SecretStore;
use crate::storage::database::open_database;
use crate::ui::dialogs::view_secret::{render_view_secret_dialog, ViewSecretDialog};
use crate::ui::secret_panel::render_secret_panel;
use crate::ui::unlock_window::{render_unlock_window, UnlockAction, UnlockWindowMode};
use egui::{Context, Visuals};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

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
#[derive(Clone, Copy, PartialEq, Debug)]
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
    pub key_file_path: String,
    pub is_first_setup: bool,
    pub password_input: String,
    pub confirm_password: String,
    pub show_password: bool,
    pub unlock_error: Option<String>,

    // 解锁线程通信
    pub unlock_result: Arc<Mutex<Option<Result<UnlockedSession, String>>>>,

    // 当前会话（解锁后存在）
    pub session: Option<UnlockedSession>,

    // 搜索与过滤
    pub secret_search_query: String,

    // 密码数据
    pub secret_metas: HashMap<String, Vec<SecretMeta>>,

    // 剪贴板管理器
    pub clipboard: SecureClipboard,

    // 弹窗状态
    pub show_dialog: Option<String>,

    // 数据库连接
    pub db_conn: Option<rusqlite::Connection>,

    // 查看密码弹窗状态
    pub view_secret_dialog: Option<ViewSecretDialog>,
}

impl Default for SynapseVaultApp {
    fn default() -> Self {
        let default_key_path = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("synapsevault")
            .join("synapsevault.key")
            .to_string_lossy()
            .to_string();

        let is_first_setup = !Path::new(&default_key_path).exists();

        Self {
            unlock_state: UnlockState::Locked,
            current_panel: Panel::SecretVault,
            theme: ThemeMode::Dark,
            key_file_path: default_key_path,
            is_first_setup,
            password_input: String::new(),
            confirm_password: String::new(),
            show_password: false,
            unlock_error: None,
            unlock_result: Arc::new(Mutex::new(None)),
            session: None,
            secret_search_query: String::new(),
            secret_metas: HashMap::new(),
            clipboard: SecureClipboard::new(),
            show_dialog: None,
            db_conn: None,
            view_secret_dialog: None,
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

    /// 轮询解锁线程结果
    fn poll_unlock_result(&mut self) {
        if self.unlock_state != UnlockState::Unlocking {
            return;
        }

        let result = {
            let mut guard = self
                .unlock_result
                .lock()
                .expect("unlock result mutex poisoned");
            guard.take()
        };

        if let Some(result) = result {
            match result {
                Ok(session) => {
                    self.session = Some(session);
                    self.unlock_state = UnlockState::Unlocked;
                    self.is_first_setup = false;
                    self.unlock_error = None;
                    self.password_input.clear();
                    self.confirm_password.clear();
                    self.open_database_and_load_secrets();
                }
                Err(err) => {
                    self.unlock_state = UnlockState::Locked;
                    self.unlock_error = Some(err);
                }
            }
        }
    }

    /// 处理解锁窗口用户动作
    fn handle_unlock_action(&mut self, action: UnlockAction) {
        match action {
            UnlockAction::Submit => {
                if self.is_first_setup {
                    self.handle_first_setup();
                } else {
                    self.handle_unlock();
                }
            }
            UnlockAction::ForgotPassword => {
                self.show_dialog = Some("forget_password".to_string());
            }
            UnlockAction::BrowseKeyFile => {
                let picked = if self.is_first_setup {
                    rfd::FileDialog::new()
                        .add_filter("Key File", &["key"])
                        .save_file()
                } else {
                    rfd::FileDialog::new()
                        .add_filter("Key File", &["key"])
                        .pick_file()
                };
                if let Some(path) = picked {
                    self.key_file_path = path.to_string_lossy().to_string();
                }
            }
        }
    }

    /// 首次设置：在独立线程中生成密钥文件并解锁
    fn handle_first_setup(&mut self) {
        self.unlock_error = None;

        // 输入验证
        if self.key_file_path.is_empty() {
            self.unlock_error = Some("请输入密钥文件保存路径".to_string());
            return;
        }
        if self.password_input.is_empty() {
            self.unlock_error = Some("请输入主密码".to_string());
            return;
        }
        if self.password_input != self.confirm_password {
            self.unlock_error = Some("两次输入的密码不一致".to_string());
            return;
        }
        if self.password_input.len() < 8 {
            self.unlock_error = Some("主密码长度至少为 8 位".to_string());
            return;
        }

        let password = self.password_input.clone();
        let key_file_path = self.key_file_path.clone();
        let result_arc = Arc::clone(&self.unlock_result);

        self.unlock_state = UnlockState::Unlocking;

        std::thread::spawn(move || {
            // 生成密钥文件（内部包含 Argon2id）
            let (key_file, signing_key, master_key) = match generate_key_file(&password) {
                Ok(v) => v,
                Err(e) => {
                    let mut guard = result_arc.lock().expect("unlock result mutex poisoned");
                    *guard = Some(Err(format!("生成密钥文件失败: {}", e)));
                    return;
                }
            };

            // 编码并保存
            let encoded = match encode_key_file(&key_file) {
                Ok(v) => v,
                Err(e) => {
                    let mut guard = result_arc.lock().expect("unlock result mutex poisoned");
                    *guard = Some(Err(format!("编码密钥文件失败: {}", e)));
                    return;
                }
            };

            if let Err(e) = std::fs::write(&key_file_path, &encoded) {
                let mut guard = result_arc.lock().expect("unlock result mutex poisoned");
                *guard = Some(Err(format!("保存密钥文件失败: {}", e)));
                return;
            }

            let fp = generate_device_fingerprint(&key_file.public_key);
            let session = UnlockedSession {
                private_key: signing_key,
                public_key: key_file.public_key,
                master_key,
                device_fingerprint: fp.combined,
                unlocked_at: chrono::Utc::now(),
            };

            let mut guard = result_arc.lock().expect("unlock result mutex poisoned");
            *guard = Some(Ok(session));
        });
    }

    /// 正常解锁：在线程中执行 Argon2id
    fn handle_unlock(&mut self) {
        self.unlock_error = None;

        if self.key_file_path.is_empty() {
            self.unlock_error = Some("请输入密钥文件路径".to_string());
            return;
        }
        if self.password_input.is_empty() {
            self.unlock_error = Some("请输入主密码".to_string());
            return;
        }

        let key_file_data = match std::fs::read(&self.key_file_path) {
            Ok(v) => v,
            Err(e) => {
                self.unlock_error = Some(format!("读取密钥文件失败: {}", e));
                return;
            }
        };

        let password = self.password_input.clone();
        let result_arc = Arc::clone(&self.unlock_result);

        self.unlock_state = UnlockState::Unlocking;

        std::thread::spawn(move || {
            // 先解码获取公钥以生成设备指纹
            let key_file = match crate::auth::keyfile::decode_key_file(&key_file_data) {
                Ok(kf) => kf,
                Err(e) => {
                    let mut guard = result_arc.lock().expect("unlock result mutex poisoned");
                    *guard = Some(Err(format!("无效的密钥文件: {}", e)));
                    return;
                }
            };

            let fp = generate_device_fingerprint(&key_file.public_key);
            let result = unlock_key_file(&key_file_data, &password, &fp);

            let mut guard = result_arc.lock().expect("unlock result mutex poisoned");
            *guard = Some(result.map_err(|e| e.to_string()));
        });
    }

    /// 打开数据库并加载密码列表
    fn open_database_and_load_secrets(&mut self) {
        let Some(session) = &self.session else { return };

        let db_path = dirs::data_dir()
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .join("synapsevault")
            .join("vault.db");

        match open_database(&db_path, &session.master_key) {
            Ok(conn) => {
                let store = SecretStore::new(&conn);
                match store.list_secrets(None) {
                    Ok(metas) => {
                        self.secret_metas.insert("default".to_string(), metas);
                    }
                    Err(e) => {
                        tracing::warn!("加载密码列表失败: {}", e);
                    }
                }
                self.db_conn = Some(conn);
            }
            Err(e) => {
                tracing::warn!("打开数据库失败: {}", e);
            }
        }
    }

    /// 锁定应用
    fn lock_app(&mut self) {
        self.unlock_state = UnlockState::Locked;
        self.session = None;
        self.password_input.clear();
        self.confirm_password.clear();
        self.unlock_error = None;
        self.db_conn = None;
        self.secret_metas.clear();
        self.view_secret_dialog = None;
    }
}

impl eframe::App for SynapseVaultApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        // 1. 轮询解锁线程结果
        self.poll_unlock_result();

        // 2. 根据解锁状态渲染界面
        match self.unlock_state {
            UnlockState::Locked | UnlockState::Unlocking => {
                let mode = if self.is_first_setup {
                    UnlockWindowMode::FirstSetup
                } else {
                    UnlockWindowMode::Unlock
                };

                let action = render_unlock_window(
                    &ctx,
                    mode,
                    &mut self.key_file_path,
                    &mut self.password_input,
                    &mut self.confirm_password,
                    &mut self.show_password,
                    &mut self.unlock_error,
                    self.unlock_state == UnlockState::Unlocking,
                );

                if let Some(action) = action {
                    self.handle_unlock_action(action);
                }
            }
            UnlockState::Unlocked => {
                // 顶部栏
                egui::Panel::top("top_bar").show_inside(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading("SynapseVault");
                        ui.separator();

                        ui.label("🔓 已解锁");
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
                                self.toggle_theme(&ctx);
                            }
                            if ui.button("⚙️").clicked() {
                                self.current_panel = Panel::Settings;
                            }
                        });
                    });
                });

                // 侧边栏
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
                            self.lock_app();
                        }
                    });

                // 中央面板
                egui::CentralPanel::default().show_inside(ui, |ui| match self.current_panel {
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
                        render_secret_panel(self, &ctx, ui);
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
        }

        // 3. 渲染弹窗
        if let Some(ref dialog) = self.show_dialog.clone() {
            let mut close = false;
            egui::Window::new("提示")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                .show(&ctx, |ui| {
                    match dialog.as_str() {
                        "forget_password" => {
                            ui.label("忘记密码将重置本地身份，需要重新申请加入组。");
                            ui.colored_label(egui::Color32::RED, "警告：本地数据将无法恢复！");
                            ui.add_space(10.0);
                            if ui.button("重置密钥文件").clicked() {
                                let _ = std::fs::remove_file(&self.key_file_path);
                                self.is_first_setup = true;
                                self.lock_app();
                                close = true;
                            }
                        }
                        "create_group" => {
                            ui.label("创建新组功能将在后续阶段实现。");
                        }
                        "discover_groups" => {
                            ui.label("组发现功能将在后续阶段实现。");
                        }
                        dialog_str if dialog_str.starts_with("view_secret:") => {
                            if let Some(secret_id) = dialog_str.strip_prefix("view_secret:") {
                                if let Some(ref conn) = self.db_conn {
                                    if let Some(ref session) = self.session {
                                        let store = SecretStore::new(conn);
                                        match store.get_secret(&secret_id.to_string()) {
                                            Ok(entry) => {
                                                match store.decrypt_password(
                                                    &secret_id.to_string(),
                                                    &session.master_key,
                                                ) {
                                                    Ok(password) => {
                                                        self.view_secret_dialog =
                                                            Some(ViewSecretDialog::new(
                                                                secret_id.to_string(),
                                                                &entry,
                                                                password,
                                                            ));
                                                    }
                                                    Err(e) => {
                                                        ui.label(format!("解密失败: {}", e));
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                ui.label(format!("获取密码条目失败: {}", e));
                                            }
                                        }
                                    } else {
                                        ui.label("会话未建立，无法查看密码。");
                                    }
                                } else {
                                    ui.label("数据库未连接，无法查看密码。");
                                }
                            }
                            close = true;
                        }
                        dialog_str if dialog_str.starts_with("copy_secret:") => {
                            if let Some(secret_id) = dialog_str.strip_prefix("copy_secret:") {
                                if let Some(ref conn) = self.db_conn {
                                    if let Some(ref session) = self.session {
                                        let store = SecretStore::new(conn);
                                        match store.decrypt_password(
                                            &secret_id.to_string(),
                                            &session.master_key,
                                        ) {
                                            Ok(password) => {
                                                let _ = self.clipboard.copy_secure(&password, 30);
                                                ui.label("密码已复制到剪贴板（30秒后自动清除）。");
                                            }
                                            Err(e) => {
                                                ui.label(format!("解密失败: {}", e));
                                            }
                                        }
                                    } else {
                                        ui.label("会话未建立，无法复制密码。");
                                    }
                                } else {
                                    ui.label("数据库未连接，无法复制密码。");
                                }
                            }
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

        // 4. 渲染查看密码弹窗
        if let Some(mut dialog) = self.view_secret_dialog.take() {
            let clipboard = &self.clipboard;
            let mut on_copy = |text: &str| {
                let _ = clipboard.copy_secure(text, 30);
            };
            if !render_view_secret_dialog(&ctx, &mut dialog, &mut on_copy) {
                self.view_secret_dialog = Some(dialog);
            }
        }

        // 5. 请求持续重绘
        ctx.request_repaint();
    }
}
