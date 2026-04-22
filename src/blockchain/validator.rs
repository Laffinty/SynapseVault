//! 验证者逻辑
//!
//! 管理验证者集合、出块权轮换、投票。

use crate::group::member::{Member, MemberId};
#[cfg(test)]
use crate::rbac::role::Role;
use ed25519_dalek::VerifyingKey;
use std::collections::HashMap;

/// 验证者信息
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Validator {
    pub member_id: MemberId,
    pub public_key: VerifyingKey,
    /// 连续出块次数（用于轮换）
    pub blocks_mined: u64,
}

/// 验证者集合
#[derive(Clone, Debug)]
pub struct ValidatorSet {
    validators: Vec<Validator>,
    /// 当前轮次索引
    current_round: usize,
}

impl ValidatorSet {
    /// 从成员列表中提取 Admin 作为验证者
    pub fn from_members(members: &HashMap<MemberId, Member>) -> Self {
        let validators: Vec<Validator> = members
            .values()
            .filter(|m| m.is_admin())
            .map(|m| Validator {
                member_id: m.member_id.clone(),
                public_key: m.public_key,
                blocks_mined: 0,
            })
            .collect();

        Self {
            validators,
            current_round: 0,
        }
    }

    /// 是否为空
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// 验证者数量
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// 获取当前轮次的验证者
    pub fn current_validator(&self) -> Option<&Validator> {
        if self.validators.is_empty() {
            return None;
        }
        Some(&self.validators[self.current_round % self.validators.len()])
    }

    /// 轮换到下一个验证者
    pub fn rotate(&mut self) {
        if !self.validators.is_empty() {
            self.current_round = (self.current_round + 1) % self.validators.len();
        }
    }

    /// 记录某验证者出块
    pub fn record_mined(&mut self, member_id: &MemberId) {
        if let Some(v) = self.validators.iter_mut().find(|v| &v.member_id == member_id) {
            v.blocks_mined += 1;
        }
    }

    /// 检查公钥是否为验证者
    pub fn contains(&self, pubkey: &VerifyingKey) -> bool {
        self.validators.iter().any(|v| v.public_key == *pubkey)
    }

    /// 获取所有验证者公钥
    pub fn pubkeys(&self) -> Vec<VerifyingKey> {
        self.validators.iter().map(|v| v.public_key).collect()
    }

    /// 添加验证者（仅限动态扩展场景）
    pub fn add_validator(&mut self, validator: Validator) {
        if !self.contains(&validator.public_key) {
            self.validators.push(validator);
        }
    }

    /// 移除验证者
    pub fn remove_validator(&mut self, member_id: &MemberId) {
        self.validators.retain(|v| &v.member_id != member_id);
        // 调整 current_round 避免越界
        if !self.validators.is_empty() {
            self.current_round %= self.validators.len();
        } else {
            self.current_round = 0;
        }
    }
}

/// 判断成员是否为验证者（活跃 Admin）
pub fn is_validator_member(member: &Member) -> bool {
    member.is_admin()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signing::generate_keypair;
    use crate::group::member::{Member, MemberStatus};

    fn make_member(role: Role, status: MemberStatus) -> (Member, VerifyingKey) {
        let (_sk, vk) = generate_keypair();
        let mut member = Member::from_public_key(vk, role, "fp".to_string());
        member.status = status;
        (member, vk)
    }

    #[test]
    fn test_validator_set_from_members() {
        let mut members = HashMap::new();
        let (admin1, _vk1) = make_member(Role::Admin, MemberStatus::Active);
        let (admin2, _vk2) = make_member(Role::Admin, MemberStatus::Active);
        let (user, _vk3) = make_member(Role::FreeUser, MemberStatus::Active);
        let (revoked_admin, _vk4) = make_member(Role::Admin, MemberStatus::Revoked);

        members.insert(admin1.member_id.clone(), admin1);
        members.insert(admin2.member_id.clone(), admin2.clone());
        members.insert(user.member_id.clone(), user);
        members.insert(revoked_admin.member_id.clone(), revoked_admin);

        let set = ValidatorSet::from_members(&members);
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_validator_rotation() {
        let mut members = HashMap::new();
        let (admin1, vk1) = make_member(Role::Admin, MemberStatus::Active);
        let (admin2, vk2) = make_member(Role::Admin, MemberStatus::Active);
        members.insert(admin1.member_id.clone(), admin1);
        members.insert(admin2.member_id.clone(), admin2.clone());

        let mut set = ValidatorSet::from_members(&members);
        let first = set.current_validator().unwrap().public_key;
        set.rotate();
        let second = set.current_validator().unwrap().public_key;
        set.rotate();
        let third = set.current_validator().unwrap().public_key;

        assert_ne!(first, second);
        assert_eq!(first, third); // 两个验证者，轮转两次回到第一个
        assert!(set.contains(&vk1));
        assert!(set.contains(&vk2));
    }

    #[test]
    fn test_record_mined() {
        let mut members = HashMap::new();
        let (admin1, _vk1) = make_member(Role::Admin, MemberStatus::Active);
        let id = admin1.member_id.clone();
        members.insert(id.clone(), admin1);

        let mut set = ValidatorSet::from_members(&members);
        set.record_mined(&id);
        assert_eq!(set.current_validator().unwrap().blocks_mined, 1);
    }

    #[test]
    fn test_remove_validator_adjusts_round() {
        let mut members = HashMap::new();
        let (admin1, _vk1) = make_member(Role::Admin, MemberStatus::Active);
        let (admin2, _vk2) = make_member(Role::Admin, MemberStatus::Active);
        members.insert(admin1.member_id.clone(), admin1);
        members.insert(admin2.member_id.clone(), admin2.clone());

        let mut set = ValidatorSet::from_members(&members);
        set.rotate(); // current_round = 1
        set.remove_validator(&admin2.member_id);
        assert_eq!(set.len(), 1);
        assert_eq!(set.current_round, 0);
    }

    #[test]
    fn test_empty_validator_set() {
        let members = HashMap::new();
        let set = ValidatorSet::from_members(&members);
        assert!(set.is_empty());
        assert!(set.current_validator().is_none());
    }

    #[test]
    fn test_is_validator_member() {
        let (admin, _vk) = make_member(Role::Admin, MemberStatus::Active);
        let (user, _vk2) = make_member(Role::FreeUser, MemberStatus::Active);
        let (revoked, _vk3) = make_member(Role::Admin, MemberStatus::Revoked);

        assert!(is_validator_member(&admin));
        assert!(!is_validator_member(&user));
        assert!(!is_validator_member(&revoked));
    }
}
