use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use synapse_vault::crypto::signing::generate_keypair;
use synapse_vault::crypto::symmetric::{decrypt, encrypt, generate_nonce};
use synapse_vault::blockchain::merkle::compute_merkle_root;
use synapse_vault::blockchain::block::Block;

fn bench_argon2id(c: &mut Criterion) {
    let mut group = c.benchmark_group("argon2id");
    group.sample_size(10);

    let params = synapse_vault::crypto::kdf::Argon2Params::default();
    let salt = [0u8; 32];
    let password = "benchmark_password_123";

    group.bench_function("default_params", |b| {
        b.iter(|| {
            synapse_vault::crypto::kdf::derive_master_key(password, &salt, &params)
        })
    });

    let fast_params = synapse_vault::crypto::kdf::Argon2Params {
        memory_cost: 8192,
        time_cost: 1,
        parallelism: 1,
    };
    group.bench_function("fast_params", |b| {
        b.iter(|| {
            synapse_vault::crypto::kdf::derive_master_key(password, &salt, &fast_params)
        })
    });

    group.finish();
}

fn bench_xchacha20_poly1305(c: &mut Criterion) {
    let mut group = c.benchmark_group("xchacha20_poly1305");
    let key = [42u8; 32];
    let nonce = generate_nonce();

    for size in [16, 256, 1024, 16384].iter() {
        let plaintext = vec![0u8; *size];
        group.bench_with_input(BenchmarkId::new("encrypt", size), size, |b, _| {
            b.iter(|| encrypt(black_box(&plaintext), black_box(&key), black_box(&nonce)))
        });
    }

    let ciphertext = encrypt(&vec![0u8; 1024], &key, &nonce).unwrap();
    group.bench_function("decrypt_1kb", |b| {
        b.iter(|| decrypt(black_box(&ciphertext), black_box(&key), black_box(&nonce)))
    });

    group.finish();
}

fn bench_ed25519(c: &mut Criterion) {
    let mut group = c.benchmark_group("ed25519");
    let (sk, _vk) = generate_keypair();
    let message = b"benchmark message for ed25519 signing";

    group.bench_function("sign", |b| {
        b.iter(|| synapse_vault::crypto::signing::sign(black_box(&sk), black_box(message)))
    });

    let signature = synapse_vault::crypto::signing::sign(&sk, message);
    let vk = sk.verifying_key();
    group.bench_function("verify", |b| {
        b.iter(|| synapse_vault::crypto::signing::verify(black_box(&vk), black_box(message), black_box(&signature)))
    });

    group.finish();
}

fn bench_merkle(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle");

    for count in [1, 10, 50, 100].iter() {
        let leaves: Vec<Vec<u8>> = (0..*count)
            .map(|i| format!("leaf_{}", i).into_bytes())
            .collect();
        group.bench_with_input(BenchmarkId::new("compute_root", count), count, |b, _| {
            b.iter(|| compute_merkle_root(black_box(&leaves)))
        });
    }

    group.finish();
}

fn bench_block_hash(c: &mut Criterion) {
    let (_sk, vk) = generate_keypair();
    let genesis = Block::genesis("bench_group", vk);

    c.bench_function("block_compute_hash", |b| {
        b.iter(|| {
            let mut block = genesis.clone();
            block.height = 1;
            block.update_hash();
            black_box(block.block_hash)
        })
    });
}

fn bench_bincode_serialize(c: &mut Criterion) {
    let msg = synapse_vault::p2p::protocol::P2pMessage::Heartbeat {
        group_id: "bench_group".to_string(),
        peer_id: "bench_peer".to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    c.bench_function("bincode_serialize_p2p_message", |b| {
        b.iter(|| bincode::serialize(black_box(&msg)))
    });

    let data = bincode::serialize(&msg).unwrap();
    c.bench_function("bincode_deserialize_p2p_message", |b| {
        b.iter(|| bincode::deserialize::<synapse_vault::p2p::protocol::P2pMessage>(black_box(&data)))
    });
}

criterion_group!(
    benches,
    bench_argon2id,
    bench_xchacha20_poly1305,
    bench_ed25519,
    bench_merkle,
    bench_block_hash,
    bench_bincode_serialize,
);
criterion_main!(benches);
