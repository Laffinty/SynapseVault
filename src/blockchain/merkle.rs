//! Merkle 树
//!
//! 提供 Merkle 根计算、证明生成与验证。

use sha2::{Digest, Sha256};

/// 计算叶子节点哈希
fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0u8]); // 叶子前缀
    hasher.update(data);
    hasher.finalize().into()
}

/// 计算内部节点哈希
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([1u8]); // 内部节点前缀
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// 计算 Merkle 根
///
/// 空列表返回全零哈希。
pub fn compute_merkle_root(leaves: &[Vec<u8>]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }

    let mut level: Vec<[u8; 32]> = leaves.iter().map(|d| leaf_hash(d)).collect();

    while level.len() > 1 {
        let mut next_level = Vec::new();
        for chunk in level.chunks(2) {
            if chunk.len() == 2 {
                next_level.push(node_hash(&chunk[0], &chunk[1]));
            } else {
                // 奇数个节点，复制最后一个
                next_level.push(node_hash(&chunk[0], &chunk[0]));
            }
        }
        level = next_level;
    }

    level[0]
}

/// Merkle 证明路径
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    pub indices: Vec<usize>, // 0 = left, 1 = right
    pub hashes: Vec<[u8; 32]>,
}

/// 生成 Merkle 证明
///
/// `leaf_index` 为要证明的叶子在原始列表中的索引。
pub fn generate_proof(leaves: &[Vec<u8>], leaf_index: usize) -> Option<MerkleProof> {
    if leaves.is_empty() || leaf_index >= leaves.len() {
        return None;
    }

    let mut level: Vec<[u8; 32]> = leaves.iter().map(|d| leaf_hash(d)).collect();
    let mut current_index = leaf_index;
    let mut indices = Vec::new();
    let mut hashes = Vec::new();

    while level.len() > 1 {
        let mut next_level = Vec::new();
        for (i, chunk) in level.chunks(2).enumerate() {
            if chunk.len() == 2 {
                next_level.push(node_hash(&chunk[0], &chunk[1]));
                if i * 2 == current_index || i * 2 + 1 == current_index {
                    let sibling = if current_index % 2 == 0 {
                        indices.push(1); // sibling is right
                        chunk[1]
                    } else {
                        indices.push(0); // sibling is left
                        chunk[0]
                    };
                    hashes.push(sibling);
                }
            } else {
                next_level.push(node_hash(&chunk[0], &chunk[0]));
                if i * 2 == current_index {
                    indices.push(1);
                    hashes.push(chunk[0]);
                }
            }
        }
        level = next_level;
        current_index /= 2;
    }

    Some(MerkleProof { indices, hashes })
}

/// 验证 Merkle 证明
pub fn verify_proof(leaf: &[u8], root: &[u8; 32], proof: &MerkleProof) -> bool {
    let mut current = leaf_hash(leaf);
    for (side, hash) in proof.indices.iter().zip(proof.hashes.iter()) {
        current = if *side == 0 {
            node_hash(hash, &current)
        } else {
            node_hash(&current, hash)
        };
    }
    &current == root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_merkle_root() {
        let root = compute_merkle_root(&[]);
        assert_eq!(root, [0u8; 32]);
    }

    #[test]
    fn test_single_leaf() {
        let leaves = vec![b"hello".to_vec()];
        let root = compute_merkle_root(&leaves);
        let expected = leaf_hash(b"hello");
        assert_eq!(root, expected);
    }

    #[test]
    fn test_two_leaves() {
        let leaves = vec![b"a".to_vec(), b"b".to_vec()];
        let root = compute_merkle_root(&leaves);
        let expected = node_hash(&leaf_hash(b"a"), &leaf_hash(b"b"));
        assert_eq!(root, expected);
    }

    #[test]
    fn test_odd_leaves() {
        let leaves = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let root = compute_merkle_root(&leaves);
        let l1 = node_hash(&leaf_hash(b"a"), &leaf_hash(b"b"));
        let l2 = node_hash(&leaf_hash(b"c"), &leaf_hash(b"c"));
        let expected = node_hash(&l1, &l2);
        assert_eq!(root, expected);
    }

    #[test]
    fn test_proof_generation_and_verification() {
        let leaves = vec![
            b"a".to_vec(),
            b"b".to_vec(),
            b"c".to_vec(),
            b"d".to_vec(),
        ];
        let root = compute_merkle_root(&leaves);

        for (i, leaf) in leaves.iter().enumerate() {
            let proof = generate_proof(&leaves, i).unwrap();
            assert!(verify_proof(leaf, &root, &proof));
        }
    }

    #[test]
    fn test_proof_fails_for_tampered_leaf() {
        let leaves = vec![b"a".to_vec(), b"b".to_vec()];
        let root = compute_merkle_root(&leaves);
        let proof = generate_proof(&leaves, 0).unwrap();
        assert!(!verify_proof(b"x", &root, &proof));
    }

    #[test]
    fn test_proof_deterministic() {
        let leaves = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let proof1 = generate_proof(&leaves, 1).unwrap();
        let proof2 = generate_proof(&leaves, 1).unwrap();
        assert_eq!(proof1, proof2);
    }
}
