# Navegação do código

O repositório reúne vários crates Rust em um workspace. A lista de membros e
dependências compartilhadas está em [Cargo.toml](../../Cargo.toml). O diretório
`apps/` contém aplicações, `platforms/` contém integrações de plataforma e
`scripts/` reúne demonstrações e ferramentas de operação.

## Por onde começar

| Objetivo | Código de entrada |
|---|---|
| Comandos e argumentos da CLI `mycelium` | [cli/mycelium-cli/src/main.rs](../../cli/mycelium-cli/src/main.rs) |
| Tipos compartilhados, identidades e recursos | [crates/mycelium-core/src/lib.rs](../../crates/mycelium-core/src/lib.rs) |
| Daemon, controle local e estado do nó | [crates/mycelium-node/src/lib.rs](../../crates/mycelium-node/src/lib.rs) |
| Transporte, descoberta, gossip e DHT | [crates/mycelium-hyphae/src/lib.rs](../../crates/mycelium-hyphae/src/lib.rs) |
| Armazenamento local de Plots e chaves DHT | [crates/mycelium-sporebank/src/lib.rs](../../crates/mycelium-sporebank/src/lib.rs) |
| Construção e representação de Plots | [crates/giggs/src/lib.rs](../../crates/giggs/src/lib.rs) |

No crate do nó, `control.rs` define o plano de controle local, `organism.rs`
reúne o estado e as operações do organismo, e `store.rs` trata da persistência.
Os módulos com sufixo `_ion` contêm integrações HTTP específicas. Para uma visão
mais ampla, consulte a [referência de crates](CRATES_REFERENCE.md) e confira o
workspace para a lista atual de membros.

## Identificadores e dados

`NodeId::derive` calcula BLAKE3 sobre os bytes recebidos. `PeerBinding::is_valid`
verifica a correspondência da chave com o `NodeId`, a expiração e a assinatura;
o chamador deve conferir o `peer_id` com a identidade do transporte em uso.

`ContentId` contém um hash BLAKE3 de 32 bytes. Sua representação textual usa
`Qm` seguido de 64 dígitos hexadecimais; esse formato próprio não deve ser
interpretado automaticamente como um CID IPFS. Nas chaves DHT do Spore Bank,
o prefixo `spore/` é seguido dos bytes binários do hash, não do texto em hex.

## Verificação de alterações

Execute os testes do componente alterado, por exemplo:

```bash
cargo test -p mycelium-core
cargo test -p mycelium-sporebank
```

Mudanças que atravessam componentes também precisam de testes de integração;
consulte as demonstrações e instruções no [README principal](../../README.md).
