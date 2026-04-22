# SynapseVault

纯分布式局域网团队密码库，基于 Rust + egui 构建，无需中心服务器即可在局域网内实现安全的团队密码共享与同步。

> **⚠️ 项目状态：早期开发中，暂不可用**
>
> 本项目尚处于开发阶段，存在多项已知关键问题尚未修复，**不建议在实际生产环境中使用**。主要未解决问题包括：
> - 审计事件缺少 ed25519 签名，无法保证抗抵赖性
> - CRDT 同步在并发删除/更新场景下可能静默恢复已删除条目
> - 区块链分叉时操作可能丢失
> - P2P 网络事件循环为骨架级实现，尚未完成端到端集成
> - API 层缺少输入验证，弱密码可绕过 UI 限制
>
> 详细问题清单参见 [Code Review 报告](docs/CODE_REVIEW_REPORT.md)。

## 特性

- **纯 P2P 分布式架构**：基于 libp2p 实现局域网内节点发现与数据同步，无需依赖任何中心服务器。
- **端到端加密**：使用 XChaCha20-Poly1305、Argon2id、Ed25519 等现代密码学算法保护数据安全。
- **本地安全存储**：采用 SQLCipher（SQLite 加密版）在本地加密存储所有密码与审计日志。
- **CRDT 无冲突同步**：基于 CRDT 数据结构实现离线编辑与自动冲突解决。
- **RBAC 权限管理**：支持管理员、成员、审计员等多角色精细权限控制。
- **区块链审计日志**：关键操作写入本地区块链结构，确保审计日志不可篡改。
- **跨平台 GUI**：基于 egui/eframe 构建的现代化桌面界面，支持 Windows、macOS 与 Linux。

## 技术栈

| 领域 | 技术 |
|------|------|
| GUI | egui / eframe (wgpu) |
| P2P 网络 | libp2p (gossipsub, mDNS, Noise, QUIC) |
| 加密 | Argon2id, XChaCha20-Poly1305, Ed25519, HKDF-SHA256 |
| 存储 | SQLCipher (rusqlite) |
| 同步 | CRDT (crdts) |
| 异步运行时 | Tokio |

## 构建

```bash
cargo build --release
```

## 项目结构

```
src/
├── audit/      # 区块链审计日志
├── auth/       # 身份认证与 Argon2id 密钥派生
├── blockchain/ # 本地区块链实现
├── crypto/     # 加密封装（XChaCha20-Poly1305 等）
├── group/      # 群组生命周期管理
├── p2p/        # libp2p 网络与协议处理
├── rbac/       # 基于角色的访问控制
├── secret/     # 密码/密钥的 CRUD 与同步
├── storage/    # SQLCipher 数据库访问层
├── sync/       # CRDT 同步引擎
└── ui/         # egui 界面实现
```

## 许可证

本项目采用 [Apache License 2.0](LICENSE) 许可。
