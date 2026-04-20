//! 安全剪贴板操作
//!
//! 提供密码复制到剪贴板的能力，并在指定时间后自动清除。
//! 使用后台线程计时，不依赖 UI 帧循环。

use std::thread;
use std::time::Duration;

/// 剪贴板错误
#[derive(Debug, thiserror::Error)]
pub enum ClipboardError {
    #[error("Clipboard access failed: {0}")]
    AccessFailed(String),
    #[error("Clipboard content was not text")]
    NotText,
}

/// 安全剪贴板管理器
///
/// 在后台线程中管理剪贴板内容的自动清除。
pub struct SecureClipboard;

impl SecureClipboard {
    /// 创建新的安全剪贴板管理器
    pub fn new() -> Self {
        Self
    }

    /// 将密码复制到剪贴板，并在指定时间后自动清除
    ///
    /// # 参数
    /// - `password`: 要复制的密码明文
    /// - `clear_after_secs`: 自动清除时间（秒），默认 30 秒
    ///
    /// # 注意
    /// - 此操作会启动一个后台线程，在超时后将剪贴板内容替换为空字符串
    /// - 如果剪贴板在超时前已被用户修改，不会覆盖用户新内容
    pub fn copy_secure(&self, password: &str, clear_after_secs: u64) -> Result<(), ClipboardError> {
        let mut clipboard =
            arboard::Clipboard::new().map_err(|e| ClipboardError::AccessFailed(e.to_string()))?;

        clipboard
            .set_text(password.to_string())
            .map_err(|e| ClipboardError::AccessFailed(e.to_string()))?;

        // 记录当前内容，用于判断剪贴板是否被修改
        let original_content = password.to_string();
        let timeout = Duration::from_secs(clear_after_secs.max(1));

        // 启动清除线程
        thread::spawn(move || {
            thread::sleep(timeout);

            // 尝试读取当前剪贴板内容
            if let Ok(mut cb) = arboard::Clipboard::new() {
                if let Ok(current) = cb.get_text() {
                    // 仅当内容未被用户修改时才清除
                    if current == original_content {
                        let _ = cb.set_text("");
                    }
                }
            }
        });

        Ok(())
    }

    /// 立即清除剪贴板内容
    pub fn clear(&self) -> Result<(), ClipboardError> {
        let mut clipboard =
            arboard::Clipboard::new().map_err(|e| ClipboardError::AccessFailed(e.to_string()))?;
        clipboard
            .set_text("")
            .map_err(|e| ClipboardError::AccessFailed(e.to_string()))?;
        Ok(())
    }
}

impl Default for SecureClipboard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(ci, ignore = "clipboard tests are flaky in headless CI environments")]
    fn test_copy_secure_basic() {
        let clipboard = SecureClipboard::new();
        let result = clipboard.copy_secure("test_password", 1);
        // 在非 GUI 环境中剪贴板操作可能失败，所以允许 Err
        // 但通常应该成功
        if result.is_ok() {
            // 验证剪贴板内容
            let mut cb = arboard::Clipboard::new().unwrap();
            let text = cb.get_text().unwrap();
            assert_eq!(text, "test_password");
        }
    }

    #[test]
    fn test_clear_clipboard() {
        let clipboard = SecureClipboard::new();
        clipboard.copy_secure("temp", 60).ok();
        clipboard.clear().ok();

        if let Ok(mut cb) = arboard::Clipboard::new() {
            let text = cb.get_text().unwrap_or_default();
            assert_eq!(text, "");
        }
    }
}
