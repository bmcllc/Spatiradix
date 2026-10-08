# 🪐 `cosmic-cli` — COSMIC Sovereign Compute & Storage CLI

Interface de linha de comando para o ecossistema de computação distribuída e armazenamento particionado pós-quântico **COSMIC**.

---

## 🎯 Visão Geral

O `cosmic-cli` é a ferramenta de ponta para operadores de nós e desenvolvedores interagirem com o plano de computação e armazenamento do Mycelium. Ele orquestra sharding QEL pós-quântico, emissão de licenças criptográficas VOID-00 (ML-DSA-87 / Dilithium5), e verificação de integridade sem intermediários centrais.

### Funcionalidades:
- **`cosmic put <arquivo> [--k 3 --n 7]`**:
  - Divide e codifica um arquivo local em $N$ fragmentos (*shards*) criptográficos usando o esquema QEL (Quantum Entanglement Layer) e codificação de apagamento Cauchy/Reed-Solomon.
  - Qualquer subconjunto de $K$ fragmentos é suficiente para reconstruir o arquivo original sem vazar as chaves de sessão.
- **`cosmic get <cid> [--out <destino>]`**:
  - Consulta a DHT e nós de armazenamento do Mycelium, coleta ao menos $K$ fragmentos válidos e restaura os bytes originais com verificação estrita de hash BLAKE3.
- **`cosmic license issue --holder <pubkey> --scope <perm>`**:
  - Emite uma licença de computação/armazenamento soberana VOID-00 assinada com o algoritmo pós-quântico ML-DSA-87.
- **`cosmic license verify --cert <path>`**:
  - Valida a autenticidade e validade temporal de uma licença VOID-00.

---

## 🚀 Instalação e Execução

```bash
# Compilar e instalar binário
cargo install --path crates/cosmic-cli

# Obter ajuda
cosmic --help
```
