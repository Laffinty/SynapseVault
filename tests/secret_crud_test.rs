#![cfg(not(miri))]
//! PHASE2 集成测试：密码增删改查完整流程
//!
//! 验证密码管理模块的核心功能：
//! - 创建密码条目
//! - 列表查询
//! - 搜索过滤
//! - 更新密码
//! - 删除密码
//! - 解密验证
//! - 错误密钥解密失败

use rusqlite::Connection;
use synapse_vault::secret::entry::SecretEntryError;
use synapse_vault::secret::store::SecretStore;
use synapse_vault::storage::schema::init_schema;

fn setup_test_db() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    init_schema(&conn).unwrap();
    // 插入测试组，满足外键约束
    conn.execute(
        "INSERT INTO groups (group_id, name, group_public_key, admin_public_key, config, created_at, updated_at)
         VALUES ('group-1', 'Test Group', X'00', X'00', X'00', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')",
        [],
    ).unwrap();
    conn
}

#[test]
fn test_secret_full_crud_flow() {
    let conn = setup_test_db();
    let store = SecretStore::new(&conn);
    let master_key = [0x42u8; 32];

    // 1. 创建密码
    let entry = store
        .create_secret(
            &"group-1".to_string(),
            "核心交换机-SSH",
            "admin",
            "SecurePass123!",
            "生产环境",
            vec!["ssh".to_string(), "network".to_string()],
            "核心网络设备SSH密码",
            None,
            &"member-1".to_string(),
            &master_key,
        )
        .unwrap();

    assert_eq!(entry.title, "核心交换机-SSH");
    assert_eq!(entry.username, "admin");
    assert_eq!(entry.environment, "生产环境");
    assert_eq!(entry.tags, vec!["ssh".to_string(), "network".to_string()]);
    assert_eq!(entry.version, 1);

    // 2. 获取密码
    let fetched = store.get_secret(&entry.secret_id).unwrap();
    assert_eq!(fetched.secret_id, entry.secret_id);
    assert_eq!(fetched.title, entry.title);

    // 3. 解密验证
    let plaintext = store
        .decrypt_password(&entry.secret_id, &master_key)
        .unwrap();
    assert_eq!(plaintext, "SecurePass123!");

    // 4. 列表查询
    let list = store.list_secrets(Some(&"group-1".to_string())).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].title, "核心交换机-SSH");

    // 5. 更新密码
    let updated = store
        .update_secret(
            &entry.secret_id,
            Some("NewPass456!"),
            Some("核心交换机-SSH-已更新"),
            Some("root"),
            Some("测试环境"),
            Some(vec!["telnet".to_string()]),
            Some("更新后的描述"),
            None,
            &master_key,
        )
        .unwrap();

    assert_eq!(updated.title, "核心交换机-SSH-已更新");
    assert_eq!(updated.username, "root");
    assert_eq!(updated.environment, "测试环境");
    assert_eq!(updated.tags, vec!["telnet".to_string()]);
    assert_eq!(updated.version, 2);

    // 验证更新后的密码可解密
    let new_plaintext = store
        .decrypt_password(&entry.secret_id, &master_key)
        .unwrap();
    assert_eq!(new_plaintext, "NewPass456!");

    // 6. 搜索
    let results = store
        .search_secrets(Some(&"group-1".to_string()), "核心交换机", None)
        .unwrap();
    assert_eq!(results.len(), 1);

    let results = store
        .search_secrets(Some(&"group-1".to_string()), "不存在", None)
        .unwrap();
    assert!(results.is_empty());

    // 7. 删除密码
    store.delete_secret(&entry.secret_id).unwrap();

    // 验证删除后无法获取
    let result = store.get_secret(&entry.secret_id);
    assert!(matches!(result, Err(SecretEntryError::NotFound(_))));

    // 验证列表为空
    let list = store.list_secrets(Some(&"group-1".to_string())).unwrap();
    assert!(list.is_empty());
}

#[test]
fn test_decrypt_with_wrong_master_key_fails() {
    let conn = setup_test_db();
    let store = SecretStore::new(&conn);
    let master_key = [0xABu8; 32];
    let wrong_key = [0xBAu8; 32];

    let entry = store
        .create_secret(
            &"group-1".to_string(),
            "Secret",
            "user",
            "password123",
            "dev",
            vec![],
            "",
            None,
            &"member-1".to_string(),
            &master_key,
        )
        .unwrap();

    let result = store.decrypt_password(&entry.secret_id, &wrong_key);
    assert!(result.is_err());
}

#[test]
fn test_search_by_environment() {
    let conn = setup_test_db();
    let store = SecretStore::new(&conn);
    let master_key = [0x42u8; 32];

    store
        .create_secret(
            &"group-1".to_string(),
            "Prod DB",
            "dbadmin",
            "pass1",
            "production",
            vec!["database".to_string()],
            "",
            None,
            &"member-1".to_string(),
            &master_key,
        )
        .unwrap();

    store
        .create_secret(
            &"group-1".to_string(),
            "Dev Server",
            "devuser",
            "pass2",
            "development",
            vec!["server".to_string()],
            "",
            None,
            &"member-1".to_string(),
            &master_key,
        )
        .unwrap();

    let results = store
        .search_secrets(Some(&"group-1".to_string()), "", Some("production"))
        .unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].title, "Prod DB");
}

#[test]
fn test_secret_expiration() {
    let conn = setup_test_db();
    let store = SecretStore::new(&conn);
    let master_key = [0x42u8; 32];
    let expires = chrono::Utc::now() + chrono::Duration::days(30);

    let entry = store
        .create_secret(
            &"group-1".to_string(),
            "Temp Password",
            "temp",
            "temppass",
            "staging",
            vec![],
            "",
            Some(expires),
            &"member-1".to_string(),
            &master_key,
        )
        .unwrap();

    assert!(entry.expires_at.is_some());
    let fetched = store.get_secret(&entry.secret_id).unwrap();
    assert_eq!(
        fetched.expires_at.map(|dt| dt.timestamp()),
        Some(expires.timestamp())
    );
}

#[test]
fn test_multiple_secrets_list_ordering() {
    let conn = setup_test_db();
    let store = SecretStore::new(&conn);
    let master_key = [0x42u8; 32];

    for i in 0..5 {
        store
            .create_secret(
                &"group-1".to_string(),
                &format!("Secret {}", i),
                &format!("user{}", i),
                &format!("pass{}", i),
                "prod",
                vec![],
                "",
                None,
                &"member-1".to_string(),
                &master_key,
            )
            .unwrap();
    }

    let list = store.list_secrets(Some(&"group-1".to_string())).unwrap();
    assert_eq!(list.len(), 5);

    // 验证按 updated_at DESC 排序
    for i in 1..list.len() {
        assert!(
            list[i - 1].updated_at >= list[i].updated_at,
            "List should be sorted by updated_at DESC"
        );
    }
}
