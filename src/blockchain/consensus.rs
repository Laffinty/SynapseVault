//! PoA 共识
//!
//! 轻量 Proof-of-Authority：只有 Admin 可作为 Validator 出块。

use crate::blockchain::block::Block;
use crate::blockchain::merkle::compute_merkle_root;
use crate::crypto::signing;
use chrono::Utc;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};

/// 可序列化的区块链操作
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum BlockchainOp {
    /// 成员加入
    MemberJoin {
        member_id: String,
        public_key: Vec<u8>,
        role: String,
        device_fingerprint: String,
    },
    /// 成员移除/撤销
    MemberRevoke {
        member_id: String,
        revoked_by: String,
    },
    /// 角色变更
    RoleChange {
        target_member: String,
        old_role: String,
        new_role: String,
        changed_by: String,
    },
    /// 密码创建
    SecretCreate {
        secret_id: String,
        created_by: String,
    },
    /// 密码更新
    SecretUpdate {
        secret_id: String,
        updated_by: String,
    },
    /// 密码删除
    SecretDelete {
        secret_id: String,
        deleted_by: String,
    },
    /// 使用审批
    UsageApprove {
        request_id: String,
        secret_id: String,
        approved_by: String,
    },
    /// 审计事件锚定
    AuditAnchor {
        event_id: String,
        event_hash: [u8; 32],
    },
}

/// PoA 共识错误
#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("Not a validator: {0}")]
    NotValidator(String),
    #[error("Invalid previous hash")]
    InvalidPrevHash,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// 检查公钥是否为指定群组的验证者（Admin）
///
/// 简化实现：任何 Admin 公钥都是验证者。
pub fn is_validator(_group_id: &str, pubkey: &VerifyingKey, admin_pubkeys: &[VerifyingKey]) -> bool {
    admin_pubkeys.iter().any(|pk| pk == pubkey)
}

/// 创建新区块
///
/// # 参数
/// - `group_id`: 群组 ID
/// - `prev_block`: 前一区块
/// - `ops`: 要打包的操作列表
/// - `signing_key`: 签名者私钥（必须是 Admin）
/// - `admin_pubkeys`: 允许的验证者公钥列表
pub fn create_block(
    group_id: &str,
    prev_block: &Block,
    ops: &[BlockchainOp],
    signing_key: &SigningKey,
    admin_pubkeys: &[VerifyingKey],
) -> Result<Block, ConsensusError> {
    let signer_pubkey = signing_key.verifying_key();

    if !is_validator(group_id, &signer_pubkey, admin_pubkeys) {
        return Err(ConsensusError::NotValidator(hex::encode(signer_pubkey.as_bytes())));
    }

    let height = prev_block.height + 1;
    let prev_hash = prev_block.block_hash;
    let timestamp = Utc::now();

    // 序列化操作列表
    let ops_data = bincode::serialize(ops)
        .map_err(|e| ConsensusError::Serialization(e.to_string()))?;

    // 计算 Merkle 根
    let leaves: Vec<Vec<u8>> = ops
        .iter()
        .map(|op| bincode::serialize(op).map_err(|e| ConsensusError::Serialization(e.to_string())))
        .collect::<Result<Vec<_>, _>>()?;
    let merkle_root = compute_merkle_root(&leaves);

    let mut block = Block {
        height,
        group_id: group_id.to_string(),
        prev_hash,
        timestamp,
        signer_pubkey,
        signature: Signature::from_bytes(&[0u8; 64]),
        merkle_root,
        nonce: 0,
        ops_data,
        block_hash: [0u8; 32],
    };

    // 计算哈希并签名
    block.update_hash();
    block.signature = signing::sign(signing_key, &block.block_hash);

    Ok(block)
}

/// 验证区块签名
pub fn verify_block_signature(block: &Block, admin_pubkeys: &[VerifyingKey]) -> Result<(), ConsensusError> {
    if !is_validator(&block.group_id, &block.signer_pubkey, admin_pubkeys) {
        return Err(ConsensusError::NotValidator(hex::encode(block.signer_pubkey.as_bytes())));
    }

    signing::verify(&block.signer_pubkey, &block.block_hash, &block.signature)
        .map_err(|_| ConsensusError::InvalidSignature)
}

/// 验证区块链接性
pub fn verify_block_link(new_block: &Block, prev_block: &Block) -> Result<(), ConsensusError> {
    if new_block.prev_hash != prev_block.block_hash {
        return Err(ConsensusError::InvalidPrevHash);
    }
    if new_block.height != prev_block.height + 1 {
        return Err(ConsensusError::InvalidPrevHash);
    }
    Ok(())
}

/// 验证区块的 Merkle 根
pub fn verify_merkle_root(block: &Block) -> Result<(), ConsensusError> {
    let ops: Vec<BlockchainOp> = bincode::deserialize(&block.ops_data)
        .map_err(|e| ConsensusError::Serialization(e.to_string()))?;
    let leaves: Vec<Vec<u8>> = ops
        .iter()
        .map(|op| bincode::serialize(op).map_err(|e| ConsensusError::Serialization(e.to_string())))
        .collect::<Result<Vec<_>, _>>()?;
    let expected_root = compute_merkle_root(&leaves);
    if expected_root != block.merkle_root {
        return Err(ConsensusError::InvalidPrevHash);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::signing::generate_keypair;
    use crate::blockchain::block::Block;

    #[test]
    fn test_is_validator() {
        let (admin_sk, admin_vk) = generate_keypair();
        let (_other_sk, other_vk) = generate_keypair();

        assert!(is_validator("g1", &admin_vk, &[admin_vk]));
        assert!(!is_validator("g1", &other_vk, &[admin_vk]));
    }

    #[test]
    fn test_create_and_verify_block() {
        let (admin_sk, admin_vk) = generate_keypair();
        let genesis = Block::genesis("g1", admin_vk);

        let ops = vec![BlockchainOp::MemberJoin {
            member_id: "user1".to_string(),
            public_key: vec![1, 2, 3],
            role: "FreeUser".to_string(),
            device_fingerprint: "fp1".to_string(),
        }];

        let block = create_block("g1", &genesis, &ops, &admin_sk, &[admin_vk]).unwrap();
        assert_eq!(block.height, 1);
        assert_eq!(block.prev_hash, genesis.block_hash);

        verify_block_signature(&block, &[admin_vk]).unwrap();
        verify_block_link(&block, &genesis).unwrap();
        verify_merkle_root(&block).unwrap();
    }

    #[test]
    fn test_non_validator_cannot_create_block() {
        let (admin_sk, admin_vk) = generate_keypair();
        let (user_sk, _user_vk) = generate_keypair();
        let genesis = Block::genesis("g1", admin_vk);

        let ops = vec![];
        let result = create_block("g1", &genesis, &ops, &user_sk, &[admin_vk]);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_block_link_fails_with_wrong_prev() {
        let (admin_sk, admin_vk) = generate_keypair();
        let genesis = Block::genesis("g1", admin_vk);
        let mut wrong_genesis = genesis.clone();
        wrong_genesis.nonce = 999;
        wrong_genesis.update_hash();

        let ops = vec![];
        let block = create_block("g1", &genesis, &ops, &admin_sk, &[admin_vk]).unwrap();
        let result = verify_block_link(&block, &wrong_genesis);
        assert!(result.is_err());
    }

    #[test]
    fn test_verify_merkle_root_fails_when_tampered() {
        let (admin_sk, admin_vk) = generate_keypair();
        let genesis = Block::genesis("g1", admin_vk);

        let ops = vec![BlockchainOp::MemberJoin {
            member_id: "user1".to_string(),
            public_key: vec![1, 2, 3],
            role: "FreeUser".to_string(),
            device_fingerprint: "fp1".to_string(),
        }];

        let mut block = create_block("g1", &genesis, &ops, &admin_sk, &[admin_vk]).unwrap();
        block.merkle_root = [0xFFu8; 32];
        let result = verify_merkle_root(&block);
        assert!(result.is_err());
    }
}
