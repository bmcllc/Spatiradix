# 📦 `mycelium-sporebank` — Armazenamento Distribuído de Esporos

Banco de esporos imutáveis e particionados (*SporeBank*), gerindo armazenamento content-addressed (BLAKE3), indexação em banco de chave-valor e integridade de blocos.

---

## 🎯 Funcionalidades

- **Content-Addressing Nativo**:
  - Armazenamento de dados fragmentados indexados diretamente pelo `ContentId` (hash BLAKE3).
- **Backend Pluggável**:
  - Implementações sobre filesystem local e bancos embarcados de alto desempenho (Sled / RocksDB).
- **Replicação Biológica**:
  - Troca autônoma de esporos entre nós vizinhos baseada na demanda e disponibilidade de nutrientes.
- **Validação de Integridade**:
  - Verificação de somas de verificação em cada leitura de bloco, prevenindo corrupção silenciosa de dados (*bit rot*).
