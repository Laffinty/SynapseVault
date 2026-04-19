//! Phase 0 项目骨架完整性测试

/// 验证 synapse_vault crate 能正常导入并编译
#[test]
fn test_crate_imports() {
    // 验证 synapse_vault crate 能正常导入并编译
    // 只要本测试能编译通过即表示所有模块声明正确
    let _ = ();
}

/// 验证基本工具依赖可用
#[test]
fn test_core_dependencies() {
    // serde
    let _ = serde_json::json!({"ok": true});

    // chrono
    let _ = chrono::Utc::now();

    // uuid
    let _ = uuid::Uuid::new_v4();

    // anyhow
    let _result: anyhow::Result<()> = Ok(());
}
