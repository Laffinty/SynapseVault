//! Phase 0 UI 结构体 smoke test

use synapse_vault::app::{Panel, ThemeMode, UnlockState};

#[test]
fn test_panel_enum() {
    assert_eq!(Panel::GroupManagement, Panel::GroupManagement);
    assert_ne!(Panel::SecretVault, Panel::AuditLog);
}

#[test]
fn test_theme_mode_enum() {
    assert_eq!(ThemeMode::Dark, ThemeMode::Dark);
    assert_eq!(ThemeMode::Light, ThemeMode::Light);
}

#[test]
fn test_unlock_state_enum() {
    assert_eq!(UnlockState::Locked, UnlockState::Locked);
    assert_eq!(UnlockState::Unlocked, UnlockState::Unlocked);
    assert_ne!(UnlockState::Locked, UnlockState::Unlocked);
}
