//! 链式存储
//!
//! 提供内存中的区块链管理、持久化读写、链验证。

use crate::blockchain::block::{Block, BlockHeight};
use crate::blockchain::consensus::{create_block, verify_block_link, verify_block_signature, verify_merkle_root, BlockchainOp, ConsensusError};
use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rusqlite::{params, Connection};

/// 区块链存储错误
#[derive(Debug, thiserror::Error)]
pub enum ChainError {
    #[error("Consensus error: {0}")]
    Consensus(#[from] ConsensusError),
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("Block not found at height {0}")]
    BlockNotFound(BlockHeight),
    #[error("Chain is empty")]
    EmptyChain,
    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// 内存中的区块链
#[derive(Clone, Debug)]
pub struct Blockchain {
    pub group_id: String,
    pub blocks: Vec<Block>,
    /// 允许的验证者公钥（Admin）
    pub validators: Vec<VerifyingKey>,
}

impl Blockchain {
    /// 创建新区块链（自动创建创世区块）
    pub fn new(group_id: &str, genesis_signer: VerifyingKey, validators: Vec<VerifyingKey>) -> Self {
        let genesis = Block::genesis(group_id, genesis_signer);
        Self {
            group_id: group_id.to_string(),
            blocks: vec![genesis],
            validators,
        }
    }

    /// 获取最新区块
    pub fn latest_block(&self) -> Option<&Block> {
        self.blocks.last()
    }

    /// 获取当前链高度
    pub fn height(&self) -> BlockHeight {
        self.blocks.len() as BlockHeight - 1
    }

    /// 追加新区块（执行验证）
    pub fn append_block(&mut self, block: Block) -> Result<(), ChainError> {
        let latest = self.latest_block().ok_or(ChainError::EmptyChain)?;

        verify_block_link(&block, latest)?;
        verify_block_signature(&block, &self.validators)?;
        verify_merkle_root(&block)?;
        // 额外验证哈希
        if !block.verify_hash() {
            return Err(ChainError::Consensus(ConsensusError::InvalidPrevHash));
        }

        self.blocks.push(block);
        Ok(())
    }

    /// 获取指定高度的区块
    pub fn get_block(&self, height: BlockHeight) -> Option<&Block> {
        self.blocks.get(height as usize)
    }

    /// 验证整条链
    pub fn validate_chain(&self) -> Result<(), ChainError> {
        if self.blocks.is_empty() {
            return Err(ChainError::EmptyChain);
        }

        // 验证创世区块
        let genesis = &self.blocks[0];
        if genesis.height != 0 {
            return Err(ChainError::Consensus(ConsensusError::InvalidPrevHash));
        }
        if !genesis.verify_hash() {
            return Err(ChainError::Consensus(ConsensusError::InvalidPrevHash));
        }

        // 验证后续链接
        for i in 1..self.blocks.len() {
            let prev = &self.blocks[i - 1];
            let curr = &self.blocks[i];
            verify_block_link(curr, prev)?;
            verify_block_signature(curr, &self.validators)?;
            verify_merkle_root(curr)?;
            if !curr.verify_hash() {
                return Err(ChainError::Consensus(ConsensusError::InvalidPrevHash));
            }
        }

        Ok(())
    }

    /// 从数据库加载区块链
    pub fn load_from_db(conn: &Connection, group_id: &str) -> Result<Option<Self>, ChainError> {
        let mut stmt = conn.prepare(
            "SELECT height, prev_hash, timestamp, signer_pubkey, signature, merkle_root, nonce, ops_data, block_hash
             FROM blocks WHERE group_id = ?1 ORDER BY height"
        )?;

        let rows = stmt.query_map([group_id], |row| {
            let height: i64 = row.get(0)?;
            let height = height as u64;
            let prev_hash: Vec<u8> = row.get(1)?;
            let timestamp: String = row.get(2)?;
            let signer_pubkey: Vec<u8> = row.get(3)?;
            let signature: Vec<u8> = row.get(4)?;
            let merkle_root: Vec<u8> = row.get(5)?;
            let nonce: i64 = row.get(6)?;
            let nonce = nonce as u64;
            let ops_data: Vec<u8> = row.get(7)?;
            let block_hash: Vec<u8> = row.get(8)?;

            Ok((height, prev_hash, timestamp, signer_pubkey, signature, merkle_root, nonce, ops_data, block_hash))
        })?;

        let mut blocks = Vec::new();
        for row in rows {
            let (height, prev_hash, timestamp, signer_pubkey, signature, merkle_root, nonce, ops_data, block_hash) = row?;

            let prev_hash: [u8; 32] = prev_hash.try_into().map_err(|_| ChainError::Serialization("prev_hash length".to_string()))?;
            let signer_pubkey: [u8; 32] = signer_pubkey.try_into().map_err(|_| ChainError::Serialization("signer_pubkey length".to_string()))?;
            let signer_pubkey = VerifyingKey::from_bytes(&signer_pubkey).map_err(|e| ChainError::Serialization(e.to_string()))?;
            let signature: [u8; 64] = signature.try_into().map_err(|_| ChainError::Serialization("signature length".to_string()))?;
            let signature = Signature::from_bytes(&signature);
            let merkle_root: [u8; 32] = merkle_root.try_into().map_err(|_| ChainError::Serialization("merkle_root length".to_string()))?;
            let block_hash: [u8; 32] = block_hash.try_into().map_err(|_| ChainError::Serialization("block_hash length".to_string()))?;

            let timestamp = timestamp.parse().map_err(|e: chrono::ParseError| ChainError::Serialization(e.to_string()))?;

            blocks.push(Block {
                height,
                group_id: group_id.to_string(),
                prev_hash,
                timestamp,
                signer_pubkey,
                signature,
                merkle_root,
                nonce,
                ops_data,
                block_hash,
            });
        }

        if blocks.is_empty() {
            return Ok(None);
        }

        // 提取验证者（所有签名过区块的 Admin 公钥，去重）
        let mut validators = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for block in &blocks {
            let pk_bytes = block.signer_pubkey.as_bytes();
            if seen.insert(*pk_bytes) {
                validators.push(block.signer_pubkey);
            }
        }

        Ok(Some(Blockchain {
            group_id: group_id.to_string(),
            blocks,
            validators,
        }))
    }

    /// 保存区块链到数据库
    pub fn save_to_db(&self, conn: &Connection) -> Result<(), ChainError> {
        for block in &self.blocks {
            conn.execute(
                "INSERT OR REPLACE INTO blocks (
                    height, group_id, prev_hash, timestamp, signer_pubkey, signature, merkle_root, nonce, ops_data, block_hash
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                params![
                    block.height as i64,
                    &block.group_id,
                    &block.prev_hash.as_slice(),
                    block.timestamp.to_rfc3339(),
                    &block.signer_pubkey.as_bytes().as_slice(),
                    &block.signature.to_bytes().as_slice(),
                    &block.merkle_root.as_slice(),
                    block.nonce as i64,
                    &block.ops_data.as_slice(),
                    &block.block_hash.as_slice(),
                ],
            )?;
        }
        Ok(())
    }

    /// 获取所有操作（按区块高度顺序）
    pub fn all_ops(&self) -> Vec<(BlockHeight, BlockchainOp)> {
        let mut result = Vec::new();
        for block in &self.blocks {
            if let Ok(ops) = bincode::deserialize::<Vec<BlockchainOp>>(&block.ops_data) {
                for op in ops {
                    result.push((block.height, op));
                }
            }
        }
        result
    }

    /// 解决分叉：最长链胜出，等长时用累计哈希决胜
    ///
    /// 如果远程链更长或等长但累计哈希更大，替换本地链。
    /// 返回 true 表示本地链被替换。
    pub fn resolve_fork(&mut self, remote: &Blockchain) -> bool {
        if remote.group_id != self.group_id {
            return false;
        }
        // 验证远程链
        if remote.validate_chain().is_err() {
            return false;
        }

        let local_len = self.blocks.len();
        let remote_len = remote.blocks.len();

        if remote_len > local_len {
            self.blocks = remote.blocks.clone();
            self.validators = remote.validators.clone();
            return true;
        }

        if remote_len == local_len {
            // 等长：用最后一个区块哈希作为决胜条件
            let local_tip = self.blocks.last().map(|b| b.block_hash).unwrap_or([0u8; 32]);
            let remote_tip = remote.blocks.last().map(|b| b.block_hash).unwrap_or([0u8; 32]);
            if remote_tip > local_tip {
                self.blocks = remote.blocks.clone();
                self.validators = remote.validators.clone();
                return true;
            }
        }

        false
    }
}

use ed25519_dalek::Signature;

/// 区块生产者：双阈值触发出块
///
/// 当待打包操作数达到 `max_ops_per_block` 或距上次出块超过 `max_block_interval_secs` 时，
/// 自动触发区块生产。
pub struct BlockProducer {
    pub group_id: String,
    pub pending_ops: Vec<BlockchainOp>,
    pub last_block_time: DateTime<Utc>,
    pub max_ops_per_block: usize,
    pub max_block_interval_secs: i64,
}

impl BlockProducer {
    pub fn new(group_id: &str) -> Self {
        Self {
            group_id: group_id.to_string(),
            pending_ops: Vec::new(),
            last_block_time: Utc::now(),
            max_ops_per_block: 50,
            max_block_interval_secs: 60,
        }
    }

    /// 添加待打包操作
    pub fn add_op(&mut self, op: BlockchainOp) {
        self.pending_ops.push(op);
    }

    /// 检查是否应触发出块
    pub fn should_produce_block(&self) -> bool {
        if self.pending_ops.is_empty() {
            return false;
        }
        let ops_threshold = self.pending_ops.len() >= self.max_ops_per_block;
        let time_threshold = (Utc::now() - self.last_block_time).num_seconds() >= self.max_block_interval_secs;
        ops_threshold || time_threshold
    }

    /// 生产新区块并追加到链上
    ///
    /// 返回生产的区块（如果触发了出块），或 None。
    pub fn produce_block(
        &mut self,
        chain: &mut Blockchain,
        signing_key: &SigningKey,
    ) -> Result<Option<Block>, ChainError> {
        if !self.should_produce_block() {
            return Ok(None);
        }

        let ops = std::mem::take(&mut self.pending_ops);
        let prev_block = chain.latest_block().ok_or(ChainError::EmptyChain)?;

        let block = create_block(
            &self.group_id,
            prev_block,
            &ops,
            signing_key,
            &chain.validators,
        )
        .map_err(ChainError::Consensus)?;

        chain.append_block(block.clone())?;
        self.last_block_time = Utc::now();

        Ok(Some(block))
    }
}

#[cfg(all(test, not(miri)))]
mod tests {
    use super::*;
    use crate::crypto::signing::generate_keypair;
    use crate::blockchain::consensus::create_block;

    #[test]
    fn test_blockchain_creation() {
        let (_sk, vk) = generate_keypair();
        let chain = Blockchain::new("g1", vk, vec![vk]);
        assert_eq!(chain.height(), 0);
        assert!(chain.latest_block().is_some());
        assert_eq!(chain.latest_block().unwrap().height, 0);
    }

    #[test]
    fn test_append_valid_block() {
        let (admin_sk, admin_vk) = generate_keypair();
        let mut chain = Blockchain::new("g1", admin_vk, vec![admin_vk]);

        let ops = vec![BlockchainOp::MemberJoin {
            member_id: "u1".to_string(),
            public_key: vec![1],
            role: "FreeUser".to_string(),
            device_fingerprint: "fp".to_string(),
        }];
        let block = create_block("g1", chain.latest_block().unwrap(), &ops, &admin_sk, &[admin_vk]).unwrap();

        chain.append_block(block).unwrap();
        assert_eq!(chain.height(), 1);
    }

    #[test]
    fn test_append_invalid_signature_fails() {
        let (admin_sk, admin_vk) = generate_keypair();
        let (other_sk, other_vk) = generate_keypair();
        let mut chain = Blockchain::new("g1", admin_vk, vec![admin_vk]);

        let ops = vec![];
        // 用非 validator 的 key 创建 block（但 validators 列表仍只有 admin_vk）
        let block = create_block("g1", chain.latest_block().unwrap(), &ops, &other_sk, &[other_vk]).unwrap();
        // 手动修改签名者为 other_vk 但 validators 是 [admin_vk]
        // 上面的 create_block 已经签名了，我们需要让签名者是 other_vk 但链只认 admin_vk
        // 直接测试 append 应该失败
        let result = chain.append_block(block);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_chain() {
        let (admin_sk, admin_vk) = generate_keypair();
        let mut chain = Blockchain::new("g1", admin_vk, vec![admin_vk]);

        for i in 0..3 {
            let ops = vec![BlockchainOp::AuditAnchor {
                event_id: format!("evt-{}", i),
                event_hash: [i as u8; 32],
            }];
            let block = create_block("g1", chain.latest_block().unwrap(), &ops, &admin_sk, &[admin_vk]).unwrap();
            chain.append_block(block).unwrap();
        }

        chain.validate_chain().unwrap();
        assert_eq!(chain.height(), 3);
    }

    #[test]
    fn test_validate_chain_fails_when_tampered() {
        let (admin_sk, admin_vk) = generate_keypair();
        let mut chain = Blockchain::new("g1", admin_vk, vec![admin_vk]);

        let ops = vec![BlockchainOp::AuditAnchor {
            event_id: "evt-1".to_string(),
            event_hash: [1u8; 32],
        }];
        let block = create_block("g1", chain.latest_block().unwrap(), &ops, &admin_sk, &[admin_vk]).unwrap();
        chain.append_block(block).unwrap();

        // 篡改区块
        chain.blocks[1].nonce = 999;
        assert!(chain.validate_chain().is_err());
    }

    #[test]
    fn test_save_and_load_from_db() {
        let (admin_sk, admin_vk) = generate_keypair();
        let mut chain = Blockchain::new("g1", admin_vk, vec![admin_vk]);

        let ops = vec![BlockchainOp::MemberJoin {
            member_id: "u1".to_string(),
            public_key: vec![1],
            role: "FreeUser".to_string(),
            device_fingerprint: "fp".to_string(),
        }];
        let block = create_block("g1", chain.latest_block().unwrap(), &ops, &admin_sk, &[admin_vk]).unwrap();
        chain.append_block(block).unwrap();

        let conn = rusqlite::Connection::open_in_memory().unwrap();
        crate::storage::schema::init_schema(&conn).unwrap();
        // 插入测试组以避免外键约束失败
        conn.execute(
            "INSERT INTO groups (group_id, name, group_public_key, admin_public_key, config, created_at, updated_at)
             VALUES ('g1', 'Test', X'00', X'00', X'00', '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z')",
            [],
        ).unwrap();
        chain.save_to_db(&conn).unwrap();

        let loaded = Blockchain::load_from_db(&conn, "g1").unwrap().unwrap();
        assert_eq!(loaded.height(), chain.height());
        assert_eq!(loaded.blocks[0].block_hash, chain.blocks[0].block_hash);
        assert_eq!(loaded.blocks[1].block_hash, chain.blocks[1].block_hash);
    }

    #[test]
    fn test_all_ops() {
        let (admin_sk, admin_vk) = generate_keypair();
        let mut chain = Blockchain::new("g1", admin_vk, vec![admin_vk]);

        let ops1 = vec![
            BlockchainOp::MemberJoin {
                member_id: "u1".to_string(),
                public_key: vec![1],
                role: "FreeUser".to_string(),
                device_fingerprint: "fp1".to_string(),
            },
        ];
        let block1 = create_block("g1", chain.latest_block().unwrap(), &ops1, &admin_sk, &[admin_vk]).unwrap();
        chain.append_block(block1).unwrap();

        let all = chain.all_ops();
        assert_eq!(all.len(), 1);
        assert!(matches!(all[0].1, BlockchainOp::MemberJoin { .. }));
    }

    #[test]
    fn test_block_producer_ops_threshold() {
        let (admin_sk, admin_vk) = generate_keypair();
        let mut chain = Blockchain::new("g1", admin_vk, vec![admin_vk]);
        let mut producer = BlockProducer::new("g1");
        producer.max_ops_per_block = 3;

        // 不到阈值不应出块
        producer.add_op(BlockchainOp::AuditAnchor { event_id: "e1".to_string(), event_hash: [1u8; 32] });
        producer.add_op(BlockchainOp::AuditAnchor { event_id: "e2".to_string(), event_hash: [2u8; 32] });
        assert!(!producer.should_produce_block());

        // 达到阈值应出块
        producer.add_op(BlockchainOp::AuditAnchor { event_id: "e3".to_string(), event_hash: [3u8; 32] });
        assert!(producer.should_produce_block());

        let result = producer.produce_block(&mut chain, &admin_sk).unwrap();
        assert!(result.is_some());
        assert_eq!(chain.height(), 1);
        assert!(producer.pending_ops.is_empty());
    }

    #[test]
    fn test_block_producer_empty_ops_no_block() {
        let (admin_sk, admin_vk) = generate_keypair();
        let chain = Blockchain::new("g1", admin_vk, vec![admin_vk]);
        let mut producer = BlockProducer::new("g1");
        assert!(!producer.should_produce_block());
    }

    #[test]
    fn test_resolve_fork_longer_chain_wins() {
        let (admin_sk, admin_vk) = generate_keypair();

        // 本地链：1 个区块
        let mut local = Blockchain::new("g1", admin_vk, vec![admin_vk]);
        let ops = vec![BlockchainOp::AuditAnchor { event_id: "e1".to_string(), event_hash: [1u8; 32] }];
        let block = create_block("g1", local.latest_block().unwrap(), &ops, &admin_sk, &[admin_vk]).unwrap();
        local.append_block(block).unwrap();

        // 远程链：2 个区块（更长）
        let mut remote = Blockchain::new("g1", admin_vk, vec![admin_vk]);
        let ops1 = vec![BlockchainOp::AuditAnchor { event_id: "e1".to_string(), event_hash: [1u8; 32] }];
        let block1 = create_block("g1", remote.latest_block().unwrap(), &ops1, &admin_sk, &[admin_vk]).unwrap();
        remote.append_block(block1).unwrap();
        let ops2 = vec![BlockchainOp::AuditAnchor { event_id: "e2".to_string(), event_hash: [2u8; 32] }];
        let block2 = create_block("g1", remote.latest_block().unwrap(), &ops2, &admin_sk, &[admin_vk]).unwrap();
        remote.append_block(block2).unwrap();

        assert!(local.resolve_fork(&remote));
        assert_eq!(local.height(), 2);
    }

    #[test]
    fn test_resolve_fork_shorter_chain_ignored() {
        let (admin_sk, admin_vk) = generate_keypair();

        // 本地链：2 个区块
        let mut local = Blockchain::new("g1", admin_vk, vec![admin_vk]);
        let ops1 = vec![BlockchainOp::AuditAnchor { event_id: "e1".to_string(), event_hash: [1u8; 32] }];
        let block1 = create_block("g1", local.latest_block().unwrap(), &ops1, &admin_sk, &[admin_vk]).unwrap();
        local.append_block(block1).unwrap();

        // 远程链：1 个区块（更短）
        let remote = Blockchain::new("g1", admin_vk, vec![admin_vk]);

        assert!(!local.resolve_fork(&remote));
        assert_eq!(local.height(), 1);
    }

    #[test]
    fn test_resolve_fork_different_group_ignored() {
        let (admin_sk, admin_vk) = generate_keypair();
        let mut local = Blockchain::new("g1", admin_vk, vec![admin_vk]);
        let remote = Blockchain::new("g2", admin_vk, vec![admin_vk]);
        assert!(!local.resolve_fork(&remote));
    }
}
