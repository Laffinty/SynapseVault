//! 角色定义
//!
//! 三角色体系：Admin / FreeUser / AuditUser。

use serde::{Deserialize, Serialize};

/// 角色枚举
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Role {
    /// 管理员：拥有完全权限，可管理群组、成员、审核日志
    Admin,
    /// 普通用户：可自由使用密码（查看/复制）
    FreeUser,
    /// 审计用户：使用密码前需经 Admin 授权，可查看审计日志
    AuditUser,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::Admin => write!(f, "Admin"),
            Role::FreeUser => write!(f, "FreeUser"),
            Role::AuditUser => write!(f, "AuditUser"),
        }
    }
}

impl std::str::FromStr for Role {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Admin" => Ok(Role::Admin),
            "FreeUser" => Ok(Role::FreeUser),
            "AuditUser" => Ok(Role::AuditUser),
            _ => Err(format!("Unknown role: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_role_roundtrip() {
        for role in [Role::Admin, Role::FreeUser, Role::AuditUser] {
            let s = role.to_string();
            let parsed: Role = s.parse().unwrap();
            assert_eq!(role, parsed);
        }
    }

    #[test]
    fn test_role_serde() {
        let role = Role::Admin;
        let json = serde_json::to_string(&role).unwrap();
        assert_eq!(json, "\"Admin\"");
        let de: Role = serde_json::from_str(&json).unwrap();
        assert_eq!(role, de);
    }
}
