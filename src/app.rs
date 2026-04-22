use crate::auth::device_fingerprint::generate_device_fingerprint;
use crate::auth::keyfile::{encode_key_file, generate_key_file};
use crate::auth::unlock::{unlock_key_file, UnlockedSession};
use crate::group::manager::JoinRequest;
use crate::p2p::discovery::DiscoveryState;
use crate::rbac::role::Role;
use crate::secret::clipboard::SecureClipboard;
use crate::secret::entry::SecretMeta;
use crate::secret::store::SecretStore;
use crate::storage::database::open_database;
use crate::ui::dialogs::approve_member::{
    render_approve_member_dialog, ApproveMemberDialog, ApproveMemberResult,
};
use crate::ui::dialogs::create_group::{render_create_group_dialog, CreateGroupDialog, CreateGroupResult};
use crate::ui::dialogs::create_secret::{render_create_secret_dialog, CreateSecretDialog, CreateSecretResult};
use crate::ui::dialogs::join_group::{render_join_group_dialog, JoinGroupDialog, JoinGroupResult};
use crate::ui::dialogs::audit_detail::{render_audit_detail_dialog, AuditDetailDialog};
use crate::ui::dialogs::view_secret::{render_view_secret_dialog, ViewSecretDialog};
use crate::ui::main_layout::render_main_layout;
use crate::ui::unlock_window::{render_unlock_window, UnlockAction, UnlockWindowMode};
use egui::{Context, Visuals};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use zeroize::Zeroize;

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

/// 弹窗状态枚举（替换原有的 show_dialog: Option<String>）
#[derive(Clone, Debug, PartialEq)]
pub enum DialogState {
    /// 忘记密码确认
    ForgetPassword,
    /// 查看密码
    ViewSecret { secret_id: String },
    /// 复制密码
    CopySecret { secret_id: String },
    /// 申请查看密码（AuditUser）
    RequestUsage { secret_id: String },
    /// 创建新密码
    CreateSecret,
    /// 编辑密码
    EditSecret { secret_id: String },
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
    pub active_dialog: Option<DialogState>,

    // 数据库连接
    pub db_conn: Option<rusqlite::Connection>,

    // 查看密码弹窗状态
    pub view_secret_dialog: Option<ViewSecretDialog>,

    // ===== Phase 3: 组管理状态 =====
    /// 当前已加入的组
    pub current_group: Option<crate::group::manager::Group>,
    /// 群组签名密钥（仅 Admin 持有）
    pub group_signing_key: Option<crate::group::group_key::GroupSigningKey>,
    /// P2P 发现状态
    pub discovery_state: DiscoveryState,
    /// 待处理的加入请求（已发送但未收到响应）
    pub pending_join_requests: Vec<JoinRequest>,

    // 组管理弹窗状态
    pub create_group_dialog: Option<CreateGroupDialog>,
    pub join_group_dialog: Option<JoinGroupDialog>,
    /// 创建/编辑密码弹窗
    pub create_secret_dialog: Option<CreateSecretDialog>,

    // ===== Phase 4: RBAC 审批弹窗状态 =====
    pub approve_member_dialog: Option<ApproveMemberDialog>,
    /// 收到的待审批加入请求（P2P 事件会推入此处）
    pub received_join_requests: Vec<JoinRequest>,
    /// 去重后的待审批请求缓存（避免每帧重算）
    pub pending_requests_cache: Vec<JoinRequest>,
    /// 待确认的角色变更操作（目标成员 ID, 新角色）
    pub pending_role_change: Option<(String, Role)>,

    // ===== Phase 5: 审计与区块链 =====
    /// 审计面板状态
    pub audit_panel_state: crate::ui::audit_panel::AuditPanelState,
    /// 审计详情弹窗
    pub audit_detail_dialog: Option<AuditDetailDialog>,
    /// 当前使用审批（AuditUser 查看密码前需要）
    pub usage_approval: Option<crate::rbac::policy::UsageApproval>,
    /// 使用审批 TTL（分钟）
    pub approval_ttl_minutes: u64,
    /// 自动锁定超时（分钟，0=禁用）
    pub auto_lock_minutes: u64,
    /// 区块生产者
    pub block_producer: Option<crate::blockchain::chain::BlockProducer>,
    /// 本地区块链
    pub local_chain: Option<crate::blockchain::chain::Blockchain>,
    /// 使用申请弹窗
    pub usage_request_dialog: Option<crate::ui::dialogs::usage_request::UsageRequestDialog>,
    /// 使用审批弹窗
    pub show_usage_approve: bool,
    /// 待审批的使用请求列表
    pub pending_usage_requests: Vec<crate::rbac::policy::UsageRequest>,
    /// 密码列表分页
    pub secret_page: usize,
    pub secrets_per_page: usize,
    pub total_secrets_count: usize,
    /// 侧边栏折叠状态
    pub side_panel_collapsed: bool,
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
            active_dialog: None,
            db_conn: None,
            view_secret_dialog: None,
            current_group: None,
            group_signing_key: None,
            discovery_state: DiscoveryState::new(),
            pending_join_requests: Vec::new(),
            create_group_dialog: None,
            join_group_dialog: None,
            create_secret_dialog: None,
            approve_member_dialog: None,
            received_join_requests: Vec::new(),
            pending_requests_cache: Vec::new(),
            pending_role_change: None,
            audit_panel_state: crate::ui::audit_panel::AuditPanelState::default(),
            audit_detail_dialog: None,
            usage_approval: None,
            approval_ttl_minutes: 5,
            auto_lock_minutes: 30,
            block_producer: None,
            local_chain: None,
            usage_request_dialog: None,
            show_usage_approve: false,
            pending_usage_requests: Vec::new(),
            secret_page: 0,
            secrets_per_page: 50,
            total_secrets_count: 0,
            side_panel_collapsed: false,
        }
    }
}

impl SynapseVaultApp {
    pub fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let app = Self::default();
        app.apply_theme(&_cc.egui_ctx);
        app
    }

    pub(crate) fn apply_theme(&self, ctx: &Context) {
        let is_dark = self.theme == ThemeMode::Dark;
        let theme = crate::ui::theme::theme_for_mode(is_dark);
        match self.theme {
            ThemeMode::Dark => {
                let mut v = Visuals::dark();
                theme.apply_to_visuals(&mut v);
                ctx.set_visuals(v);
            }
            ThemeMode::Light => {
                let mut v = Visuals::light();
                theme.apply_to_visuals(&mut v);
                ctx.set_visuals(v);
            }
        }
    }

    pub(crate) fn toggle_theme(&mut self, ctx: &Context) {
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
                    self.password_input.zeroize();
                    self.confirm_password.zeroize();
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
                self.active_dialog = Some(DialogState::ForgetPassword);
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
                    self.update_first_setup();
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

            if let Some(parent) = std::path::Path::new(&key_file_path).parent() {
                if let Err(e) = std::fs::create_dir_all(parent) {
                    let mut guard = result_arc.lock().expect("unlock result mutex poisoned");
                    *guard = Some(Err(format!("创建目录失败: {}", e)));
                    return;
                }
            }

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
                argon2_params: key_file.argon2_params,
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

    /// 刷新密码列表（从数据库重新加载）
    fn refresh_secret_metas(&mut self) {
        if let (Some(ref conn), Some(ref group)) = (&self.db_conn, &self.current_group) {
            let store = SecretStore::new(conn);
            match store.list_secrets(Some(&group.group_id)) {
                Ok(metas) => {
                    self.secret_metas.insert(group.group_id.clone(), metas);
                }
                Err(e) => {
                    tracing::warn!("刷新密码列表失败: {}", e);
                }
            }
        }
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

    /// 判断当前用户是否为 Admin
    pub fn is_current_user_admin(&self) -> bool {
        let Some(ref session) = self.session else { return false };
        let Some(ref group) = self.current_group else { return false };
        let my_id = hex::encode(session.public_key.as_bytes());
        group
            .member_map
            .get(&my_id)
            .map(|m| m.is_admin())
            .unwrap_or(false)
    }

    /// 获取当前用户角色
    fn current_user_role(&self) -> Option<crate::rbac::role::Role> {
        let session = self.session.as_ref()?;
        let group = self.current_group.as_ref()?;
        let my_id = hex::encode(session.public_key.as_bytes());
        group.member_map.get(&my_id).map(|m| m.role)
    }

    /// Phase 5: 检查使用审批（AuditUser 需要有效的 UsageApproval）
    fn check_usage_approval(&self, _secret_id: &str) -> Result<(), String> {
        let role = self.current_user_role();
        match role {
            Some(crate::rbac::role::Role::Admin) | Some(crate::rbac::role::Role::FreeUser) => Ok(()),
            Some(crate::rbac::role::Role::AuditUser) => {
                if let Some(ref approval) = self.usage_approval {
                    if approval.expires_at > chrono::Utc::now() {
                        Ok(())
                    } else {
                        Err("使用审批已过期，请重新申请。".to_string())
                    }
                } else {
                    Err("AuditUser 查看/复制密码需要 Admin 审批。请在使用请求面板申请。".to_string())
                }
            }
            None => Err("无法确定用户角色。".to_string()),
        }
    }

    /// Phase 5: 记录查看密码审计日志
    fn log_audit_view_secret(&self, secret_id: &str) {
        if let (Some(ref session), Some(ref conn)) = (&self.session, &self.db_conn) {
            let mut event = crate::audit::event::AuditEvent::new(
                format!("view_{}", uuid::Uuid::new_v4()),
                crate::audit::event::OperationType::ViewSecret,
                hex::encode(session.public_key.as_bytes()),
                session.device_fingerprint.clone(),
                "local".to_string(),
            )
            .with_secret_id(secret_id.to_string());
            event.sign(&session.private_key);
            let _ = crate::audit::logger::log_event(conn, &event, None);
        }
    }

    /// Phase 5: 记录复制密码审计日志
    fn log_audit_copy_secret(&self, secret_id: &str) {
        if let (Some(ref session), Some(ref conn)) = (&self.session, &self.db_conn) {
            let mut event = crate::audit::event::AuditEvent::new(
                format!("copy_{}", uuid::Uuid::new_v4()),
                crate::audit::event::OperationType::CopySecret,
                hex::encode(session.public_key.as_bytes()),
                session.device_fingerprint.clone(),
                "local".to_string(),
            )
            .with_secret_id(secret_id.to_string());
            event.sign(&session.private_key);
            let _ = crate::audit::logger::log_event(conn, &event, None);
        }
    }

    /// 尝试生产新区块（双阈值触发：操作数或时间间隔）
    fn try_produce_block(&mut self) {
        let Some(ref mut producer) = self.block_producer else { return };
        if !producer.should_produce_block() {
            return;
        }
        let Some(ref mut chain) = self.local_chain else { return };
        let Some(ref _session) = self.session else { return };
        let Some(ref signing_key) = self.group_signing_key else { return };

        match producer.produce_block(chain, &signing_key.private_key) {
            Ok(Some(_block)) => {
                if let Some(ref conn) = self.db_conn {
                    let _ = chain.save_to_db(conn);
                }
                tracing::info!("新区块已生成，当前高度: {}", chain.height());
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!("区块生产失败: {}", e);
            }
        }
    }

    /// 处理 P2P 审计事件批次（远程同步）
    pub fn handle_audit_batch_sync(
        &mut self,
        _from_peer: &str,
        group_id: &str,
        events: &[crate::p2p::protocol::AuditEventBrief],
    ) {
        let Some(ref conn) = self.db_conn else { return };
        let current_group = self.current_group.as_ref().map(|g| g.group_id.as_str()).unwrap_or("");
        if group_id != current_group {
            return; // 不属于当前组，忽略
        }

        for brief in events {
            let mut event = crate::audit::event::AuditEvent::new(
                brief.event_id.clone(),
                crate::audit::logger::parse_operation_type(&brief.operation_type),
                brief.actor_member_id.clone(),
                String::new(), // device_fingerprint not in brief
                String::new(), // peer_id not in brief
            )
            .with_secret_id(brief.target_secret_id.clone().unwrap_or_default());
            event.signature = brief.signature.clone();

            match crate::audit::logger::sync_event(conn, &event, None) {
                Ok(true) => tracing::debug!("同步审计事件: {}", brief.event_id),
                Ok(false) => {} // 已存在
                Err(e) => tracing::warn!("同步审计事件失败: {}", e),
            }
        }
    }

    /// 刷新待审批请求缓存（去重）
    fn refresh_pending_requests(&mut self) {
        let Some(ref group) = self.current_group else {
            self.pending_requests_cache.clear();
            return;
        };

        use std::collections::HashSet;
        let mut seen = HashSet::new();
        let mut result = Vec::new();

        // 优先使用外部收到的请求
        for req in &self.received_join_requests {
            let id = hex::encode(req.requester_public_key.as_bytes());
            if seen.insert(id.clone()) {
                result.push(req.clone());
            }
        }

        // 补充 group.member_map 中的 PendingApproval 成员
        for member in group.member_map.values() {
            if member.status == crate::group::member::MemberStatus::PendingApproval {
                let id = member.member_id.clone();
                if seen.insert(id.clone()) {
                    result.push(crate::group::manager::JoinRequest {
                        group_id: group.group_id.clone(),
                        requester_public_key: member.public_key,
                        device_fingerprint: member.device_fingerprint.clone(),
                        timestamp: member.joined_at,
                        signature: ed25519_dalek::Signature::from_bytes(&[0u8; 64]),
                    });
                }
            }
        }

        self.pending_requests_cache = result;
    }

    /// 根据当前 key_file_path 更新 is_first_setup 状态
    fn update_first_setup(&mut self) {
        self.is_first_setup = !Path::new(&self.key_file_path).exists();
    }

    /// 锁定应用
    pub(crate) fn lock_app(&mut self) {
        self.unlock_state = UnlockState::Locked;
        self.session = None;
        self.password_input.zeroize();
        self.confirm_password.zeroize();
        self.unlock_error = None;
        self.db_conn = None;
        self.secret_metas.clear();
        self.view_secret_dialog = None;
        self.current_group = None;
        self.group_signing_key = None;
        self.discovery_state = DiscoveryState::new();
        self.pending_join_requests.clear();
        self.create_group_dialog = None;
        self.join_group_dialog = None;
        self.create_secret_dialog = None;
        self.approve_member_dialog = None;
        self.received_join_requests.clear();
        self.pending_requests_cache.clear();
        self.pending_role_change = None;
        self.audit_detail_dialog = None;
        self.usage_approval = None;
        self.block_producer = None;
        self.local_chain = None;
        self.usage_request_dialog = None;
        self.show_usage_approve = false;
        self.pending_usage_requests.clear();
    }
}

impl eframe::App for SynapseVaultApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        // 1. 轮询解锁线程结果
        self.poll_unlock_result();

        // 1.5 尝试生产新区块
        self.try_produce_block();

        // 2. 根据解锁状态渲染界面
        if self.unlock_state == UnlockState::Locked {
            self.update_first_setup();
        }
        match self.unlock_state {
            UnlockState::Locked | UnlockState::Unlocking => {
                let mode = if self.is_first_setup {
                    UnlockWindowMode::FirstSetup
                } else {
                    UnlockWindowMode::Unlock
                };

                let is_calibrating = self.is_first_setup && self.unlock_state == UnlockState::Unlocking;
                let action = render_unlock_window(
                    &ctx,
                    mode,
                    &mut self.key_file_path,
                    &mut self.password_input,
                    &mut self.confirm_password,
                    &mut self.show_password,
                    &mut self.unlock_error,
                    self.unlock_state == UnlockState::Unlocking,
                    is_calibrating,
                );

                if let Some(action) = action {
                    self.handle_unlock_action(action);
                }
            }
            UnlockState::Unlocked => {
                render_main_layout(self, &ctx, ui);
            }
        }

        // 3. 渲染弹窗
        if let Some(ref dialog) = self.active_dialog.clone() {
            let mut close = false;
            match dialog {
                DialogState::ForgetPassword => {
                    egui::Window::new("忘记密码")
                        .collapsible(false)
                        .resizable(false)
                        .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                        .show(&ctx, |ui| {
                            ui.label("忘记密码将重置本地身份，需要重新申请加入组。");
                            ui.colored_label(egui::Color32::RED, "警告：本地数据将无法恢复！");
                            ui.add_space(10.0);
                            ui.horizontal(|ui| {
                                if ui.button("重置密钥文件").clicked() {
                                    let _ = std::fs::remove_file(&self.key_file_path);
                                    self.is_first_setup = true;
                                    self.lock_app();
                                    close = true;
                                }
                                if ui.button("取消").clicked() {
                                    close = true;
                                }
                            });
                        });
                }
                DialogState::ViewSecret { secret_id } => {
                    if let Some(ref conn) = self.db_conn {
                        if let Some(ref session) = self.session {
                            if let Err(msg) = self.check_usage_approval(secret_id) {
                                let sid = secret_id.clone();
                                egui::Window::new("权限不足")
                                    .collapsible(false)
                                    .resizable(false)
                                    .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                                    .show(&ctx, |ui| {
                                        ui.colored_label(egui::Color32::YELLOW, msg);
                                        ui.add_space(8.0);
                                        if ui.button("📋 申请查看权限").clicked() {
                                            self.active_dialog = Some(DialogState::RequestUsage { secret_id: sid });
                                            return;
                                        }
                                        if ui.button("关闭").clicked() {
                                            close = true;
                                        }
                                    });
                            } else {
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
                                                self.log_audit_view_secret(secret_id);
                                            }
                                            Err(e) => {
                                                egui::Window::new("错误")
                                                    .collapsible(false)
                                                    .resizable(false)
                                                    .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                                                    .show(&ctx, |ui| {
                                                        ui.label(format!("解密失败: {}", e));
                                                        if ui.button("关闭").clicked() {
                                                            close = true;
                                                        }
                                                    });
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        egui::Window::new("错误")
                                            .collapsible(false)
                                            .resizable(false)
                                            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                                            .show(&ctx, |ui| {
                                                ui.label(format!("获取密码条目失败: {}", e));
                                                if ui.button("关闭").clicked() {
                                                    close = true;
                                                }
                                            });
                                    }
                                }
                                close = true; // view_secret 弹窗一次性触发
                            }
                        }
                    }
                }
                DialogState::CopySecret { secret_id } => {
                    if let Some(ref conn) = self.db_conn {
                        if let Some(ref session) = self.session {
                            if let Err(msg) = self.check_usage_approval(secret_id) {
                                let sid = secret_id.clone();
                                egui::Window::new("权限不足")
                                    .collapsible(false)
                                    .resizable(false)
                                    .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                                    .show(&ctx, |ui| {
                                        ui.colored_label(egui::Color32::YELLOW, msg);
                                        ui.add_space(8.0);
                                        if ui.button("📋 申请复制权限").clicked() {
                                            self.active_dialog = Some(DialogState::RequestUsage { secret_id: sid });
                                            return;
                                        }
                                        if ui.button("关闭").clicked() {
                                            close = true;
                                        }
                                    });
                            } else {
                                let store = SecretStore::new(conn);
                                match store.decrypt_password(
                                    &secret_id.to_string(),
                                    &session.master_key,
                                ) {
                                    Ok(mut password) => {
                                        let _ = self.clipboard.copy_secure(&password, 30);
                                        self.log_audit_copy_secret(secret_id);
                                        password.zeroize();
                                    }
                                    Err(e) => {
                                        egui::Window::new("错误")
                                            .collapsible(false)
                                            .resizable(false)
                                            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
                                            .show(&ctx, |ui| {
                                                ui.label(format!("解密失败: {}", e));
                                                if ui.button("关闭").clicked() {
                                                    close = true;
                                                }
                                            });
                                    }
                                }
                                close = true; // copy_secret 一次性触发
                            }
                        }
                    }
                }
                DialogState::RequestUsage { secret_id } => {
                    // 打开使用申请弹窗
                    self.usage_request_dialog = Some(
                        crate::ui::dialogs::usage_request::UsageRequestDialog::new(secret_id.clone())
                    );
                    close = true; // 清除 active_dialog，弹窗由 usage_request_dialog 管理
                }
                DialogState::CreateSecret => {
                    self.create_secret_dialog = Some(CreateSecretDialog::new());
                    close = true;
                }
                DialogState::EditSecret { secret_id } => {
                    if let Some(ref conn) = self.db_conn {
                        match SecretStore::new(conn).get_secret(secret_id) {
                            Ok(entry) => {
                                self.create_secret_dialog = Some(CreateSecretDialog::for_edit(
                                    &entry.secret_id,
                                    &entry.title,
                                    &entry.username,
                                    &entry.environment,
                                    &entry.tags,
                                    &entry.description,
                                    entry.expires_at,
                                ));
                            }
                            Err(e) => {
                                tracing::warn!("加载密码条目失败: {}", e);
                            }
                        }
                    }
                    close = true;
                }
            }
            if close {
                self.active_dialog = None;
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

        // 4.5 渲染审计详情弹窗
        if let Some(mut dialog) = self.audit_detail_dialog.take() {
            if !render_audit_detail_dialog(&ctx, &mut dialog) {
                self.audit_detail_dialog = Some(dialog);
            }
        }

        // 4.6 渲染使用申请弹窗
        if let Some(mut dialog) = self.usage_request_dialog.take() {
            let (submitted, closed) =
                crate::ui::dialogs::usage_request::render_usage_request_simple(
                    &ctx,
                    &mut dialog.reason,
                    &dialog.target_secret_id,
                    &dialog.error,
                );

            if submitted {
                // 创建使用请求
                if let (Some(ref session), Some(ref group)) = (&self.session, &self.current_group) {
                    let result = crate::rbac::policy::request_usage(
                        &dialog.target_secret_id,
                        &dialog.reason,
                        &session.private_key,
                        &group.member_map,
                    );
                    match result {
                        Ok(req) => {
                            // 本地暂存，等待 Admin 审批
                            // 实际场景中应通过 P2P 发送给 Admin
                            dialog.submitted = true;
                            tracing::info!("使用请求已创建: {}", req.request_id);
                        }
                        Err(e) => {
                            dialog.error = Some(e.to_string());
                        }
                    }
                }
                self.usage_request_dialog = Some(dialog);
            } else if closed {
                // 弹窗关闭
            } else {
                self.usage_request_dialog = Some(dialog);
            }
        }

        // 4.7 渲染使用审批弹窗
        if self.show_usage_approve {
            let (approved_id, closed) =
                crate::ui::dialogs::usage_approve::render_usage_approve_dialog(
                    &ctx,
                    &self.pending_usage_requests,
                );

            if let Some(request_id) = approved_id {
                // 找到对应请求并审批
                if let Some(req) = self.pending_usage_requests.iter().find(|r| r.request_id == request_id) {
                    if let (Some(ref session), Some(ref group)) = (&self.session, &self.current_group) {
                        let ttl = chrono::Duration::minutes(self.approval_ttl_minutes as i64);
                        let result = crate::rbac::policy::approve_usage(
                            req,
                            &session.private_key,
                            &group.member_map,
                            Some(ttl),
                        );
                        match result {
                            Ok(approval) => {
                                tracing::info!("使用审批已通过: {}", approval.request_id);
                                self.pending_usage_requests.retain(|r| r.request_id != request_id);
                            }
                            Err(e) => {
                                tracing::warn!("审批失败: {}", e);
                            }
                        }
                    }
                }
            }
            if closed {
                self.show_usage_approve = false;
            }
        }

        // 5. 渲染创建组弹窗
        if let Some(mut dialog) = self.create_group_dialog.take() {
            if let Some(ref session) = self.session {
                match render_create_group_dialog(&ctx, &mut dialog, session) {
                    Some(CreateGroupResult::Created(group, gsk)) => {
                        self.current_group = Some(group);
                        self.group_signing_key = Some(gsk);
                    }
                    Some(CreateGroupResult::Cancelled) => {}
                    None => {
                        self.create_group_dialog = Some(dialog);
                    }
                }
            } else {
                // 无会话时直接丢弃弹窗
            }
        }

        // 5.5 渲染创建/编辑密码弹窗
        if let Some(mut dialog) = self.create_secret_dialog.take() {
            match render_create_secret_dialog(&ctx, &mut dialog) {
                Some(CreateSecretResult::Submit {
                    secret_id,
                    title,
                    username,
                    password,
                    environment,
                    tags,
                    description,
                    expires_at,
                }) => {
                    if let (Some(ref conn), Some(ref session), Some(ref group)) =
                        (&self.db_conn, &self.session, &self.current_group)
                    {
                        let store = SecretStore::new(conn);
                        if let Some(sid) = secret_id {
                            // 编辑模式
                            let new_pw = if password.is_empty() { None } else { Some(password.as_str()) };
                            match store.update_secret(
                                &sid,
                                new_pw,
                                Some(&title),
                                Some(&username),
                                Some(&environment),
                                Some(tags),
                                Some(&description),
                                Some(expires_at),
                                &session.master_key,
                            ) {
                                Ok(_) => {
                                    tracing::info!("密码已更新: {}", sid);
                                    self.refresh_secret_metas();
                                }
                                Err(e) => {
                                    tracing::warn!("更新密码失败: {}", e);
                                    dialog.error = Some(e.to_string());
                                    self.create_secret_dialog = Some(dialog);
                                }
                            }
                        } else {
                            // 新建模式
                            let created_by = hex::encode(session.public_key.as_bytes());
                            match store.create_secret(
                                &group.group_id,
                                &title,
                                &username,
                                &password,
                                &environment,
                                tags,
                                &description,
                                expires_at,
                                &created_by,
                                &session.master_key,
                            ) {
                                Ok(_) => {
                                    tracing::info!("新密码已创建: {}", title);
                                    self.refresh_secret_metas();
                                }
                                Err(e) => {
                                    tracing::warn!("创建密码失败: {}", e);
                                    dialog.error = Some(e.to_string());
                                    self.create_secret_dialog = Some(dialog);
                                }
                            }
                        }
                    }
                }
                Some(CreateSecretResult::Cancelled) => {}
                None => {
                    self.create_secret_dialog = Some(dialog);
                }
            }
        }

        // 6. 渲染加入组弹窗
        if let Some(mut dialog) = self.join_group_dialog.take() {
            if let Some(ref session) = self.session {
                match render_join_group_dialog(&ctx, &mut dialog, &self.discovery_state, session) {
                    Some(JoinGroupResult::Requested(req)) => {
                        self.pending_join_requests.push(req);
                    }
                    Some(JoinGroupResult::Cancelled) => {}
                    None => {
                        self.join_group_dialog = Some(dialog);
                    }
                }
            } else {
                // 无会话时直接丢弃弹窗
            }
        }

        // 7. 渲染成员审批弹窗
        if let Some(mut dialog) = self.approve_member_dialog.take() {
            let is_admin = self.is_current_user_admin();
            if is_admin {
                // 使用预计算的缓存列表，避免每帧 clone/sort/dedup
                if self.pending_requests_cache.is_empty() {
                    self.refresh_pending_requests();
                }
                if let Some(ref session) = self.session {
                    if let Some(ref mut group) = self.current_group {
                        match render_approve_member_dialog(
                            &ctx,
                            &mut dialog,
                            &self.pending_requests_cache,
                            group,
                            &session.private_key,
                        ) {
                            Some(ApproveMemberResult::Approved { requester_id }) => {
                                tracing::info!("已批准成员加入: {}", requester_id);
                                self.pending_requests_cache.clear();
                            }
                            Some(ApproveMemberResult::Rejected { requester_id }) => {
                                tracing::info!("已拒绝成员加入: {}", requester_id);
                                self.pending_requests_cache.clear();
                            }
                            Some(ApproveMemberResult::Closed) => {
                                self.approve_member_dialog = None;
                            }
                            None => {
                                self.approve_member_dialog = Some(dialog);
                            }
                        }
                    } else {
                        self.approve_member_dialog = None;
                    }
                } else {
                    self.approve_member_dialog = None;
                }
            } else {
                // 非 Admin 无法打开审批弹窗
                self.approve_member_dialog = None;
            }
        }

        // 8. 请求持续重绘
        ctx.request_repaint();
    }
}
