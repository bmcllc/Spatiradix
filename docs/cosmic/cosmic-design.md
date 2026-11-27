# COSMIC: computação e armazenamento sobre o Mycelium

O COSMIC propõe usar fragmentação, identidades criptográficas e verificação de
resultados para distribuir armazenamento e computação entre nós. A segurança
e a disponibilidade dependem da implementação, da distribuição dos fragmentos
e dos nós acessíveis. Algumas etapas deste desenho ainda são propostas;
consulte [Validação](../VALIDACAO.md) para os resultados registrados.

Guia espelho conceptual: ET-COSMIC `void_core` · marcador vivo:
[`status.md`](../reports/status.md) Fase 9+.

---

## Componentes do desenho

O desenho distribui as capacidades que uma VPS pode reunir em uma única
máquina. Redundância de shards e verificação de resultados ajudam a avaliar o
sistema, mas não substituem a medição de disponibilidade ou uma auditoria.

| Tríplice legado | Remodelagem COSMIC | Mecanismo existente |
|---|---|---|
| Storage = um disco confiável | **Shards pós-quânticos K/N** multicanal | `mycelium-qel::fragment` + `reconstruct` + `assign_hybrid_transports` |
| Compute = rodar numa VM | **Compute verificável** (recipe → proof) | `lattice build` (B.A.S.E. prova por SMT), Signal/Inertia |
| Identity = IP / SSH key / root | **GhostID portátil + VOID-00** | `mycelium-ghostid`, `mycelium-zkp::license` (ML-DSA-87) |
| Uptime = 1 máquina 24/7 | **K/N partes + transporte híbrido** | `TransportHint` lista opções; nem todos os transportes estão implementados |
| Quota/billing | **Ledger de nutrientes** | `mycelium-nutrients::Ledger`, `isotope` |

---

## Camadas

```
┌───────────────────────────────────────────────────────────────┐
│ COSMIC · CONTRATO  (o “ser”)                                   │
│   GhostID (quem) · VOID-00 license (o que pode) · QEL (como)   │
└───────────────────────────────────────────────────────────────┘
                      │
                      ▼
┌───────────────────────────────────────────────────────────────┐
│ COSMIC · SEMÂNTICA  (o “quê” — a API)                          │
│   cosmic put/get   → QEL storage (shards pós-quânticos K/N)    │
│   cosmic run       → vértice executável + proof verificável    │
│   cosmic auth      → identidade portátil (qualquer os/arch)    │
└───────────────────────────────────────────────────────────────┘
                      │
                      ▼
┌───────────────────────────────────────────────────────────────┐
│ SUBSTRATO Mycelium  (o “onde”)                                 │
│   DHT + gossipsub + RelayMesh + Nostr + LoRa/SMS/proximidade   │
│   transporte PQC (ML-KEM/ML-DSA) · qualquer os/arch             │
└───────────────────────────────────────────────────────────────┘
```

---

## 1 · `cosmic put` / `cosmic get` — Storage QEL

### Modelo de ameaça
O limiar de reconstrução é `K`: um conjunto com `K` partes suficientes pode
reconstruir o segredo. A perda de até `N-K` partes pode ser tolerada para
disponibilidade, enquanto a confidencialidade depende de o adversário não obter
`K` partes. Distribuir partes a nós distintos não garante, por si só, que eles
sejam independentes.

### Fluxo (usa `mycelium-qel` real)
1. **Cliente** com GhostID chama `QelConfig { threshold: K, total: N }`.
2. `fragment(data, config, seed)` → `Vec<QelShard>` (Shamir shares + blake3
   hash do conteúdo → `HashMismatch` protege integridade na reconstrução).
3. `assign_hybrid_transports` associa um `TransportHint` a cada shard. Um hint
   é uma indicação, não prova que o transporte foi usado ou que as partes
   estejam em locais independentes.
4. A CLI mantém shards localmente. Com `--home`, ela também tenta publicá-los
   pela rede usando `isotope-put` e a chave `cosmic/<content_id>/<i>`.
5. **`get`**: o cliente reúne shards disponíveis e, com `K` partes válidas,
   `reconstruct` devolve os bytes e verifica o hash.

### Propriedades e limites
- **Integridade**: `reconstruct` verifica o hash do conteúdo reconstruído e
  retorna `HashMismatch` quando ele não confere.
- **Confidencialidade**: o desenho usa partes Shamir; a proteção também depende
  da custódia das partes e dos metadados expostos.
- **Disponibilidade**: são necessárias `K` partes válidas e acessíveis. O
  parâmetro `K/N` não é, por si só, uma garantia de disponibilidade ou SLA.

---

## 2 · `cosmic run` — Compute verificável

### Modelo de ameaça
Um vértice pode **maliciosamente** (ou por falha) executar errado. Não basta
"rodou na minha VM".

### Fluxo
1. **Recipe** é um blob content-addressed: `(input_blob, flags, tool, salt)`
   — imutável, publicado na rede.
2. Qualquer vértice contribuidor executa e devolve `result` **assinado** com
   GhostID num `VectorOffer`/`MomentumReport` (Inertia) → converge no maior
   clock (Isotope/ledger).
3. **Proof de corretude**: B.A.S.E. (`lattice build`) já **prova contratos por
   SMT**. Para computação, o proof é um **re-provm** — segundo vértice
   independente re-executa o recipe e compara hash do result; cada result é
   content-addressed, então "este binário veio deste source+flags" é
   verificável a qualquer momento, sem confiar em quem executou.
4. Quota de execução debita no **ledger de nutrientes** do requisitante.

### Verificação e limites
- Uma reexecução independente pode comparar o resultado com a prova registrada;
  sua utilidade depende da receita, do ambiente e da independência do verificador.
- A execução em máquinas e arquiteturas diferentes precisa ser testada para
  cada receita; o desenho não garante portabilidade universal.

---

## 3 · `cosmic auth` — Identidade portátil

### Modelo de ameaça
A identidade deve poder ser restaurada em outra máquina a partir da seed. A
proteção contra roubo depende de como essa seed é guardada.

### Fluxo
1. `EntropyCollector` (keystroke timing, gyro, touch pressure, system entropy)
   → `GhostId::spawn(ttl)` — identidade efêmera com TTL (`is_expired`).
2. Para portabilidade entre qualquer OS/arch: `GhostId::from_secret_bytes(seed,
   ttl)` — o **seed** é o "pendrive criptográfico": você o carrega num QR /
   célula / arquivo protegido; em qualquer Linux/Android/macOS/Windows/
   RISC-V/ARM/x86, `spawn` da mesma identidade (`nostr_pubkey_hex`, `peer_id_bytes`).
3. **VOID-00 device binding** (`mycelium-zkp::license::license_verify_handshake`)
   amarra a licença ML-DSA-87 ao `device_entropy` do aparelho atual + GhostID.
4. `verify_nostr_event` / `sign` autenticam cada ação.

### Portabilidade e limites
- A identidade pode ser derivada novamente a partir da mesma seed em uma
  implementação compatível. A seed precisa de backup e proteção contra roubo.
- GhostID e licenças VOID-00 têm funções e algoritmos próprios; consulte os
  crates correspondentes antes de atribuir propriedades a uma integração.

---

## Por que isto "substitui VPS" (quando estiver pronto)

| Capacidade da VPS | COSMIC | Maturidade* |
|---|---|---|
| Storage durável | `put/get` QEL K/N multicanal | QEL ✅ · API ❌ |
| Compute num host | `run` com proof | B.A.S.E. 🟡 · recipe ❌ |
| Acesso de qualquer OS | `auth` GhostID+VOID-00 | GhostID/VOID ✅ · UX ❌ |
| Uptime/HA | redundância de shards + proof | parcial |

\* ✅ = primitiva existe e testada · 🟡 = proto · ❌ = falta a camada semântica.

> Este quadro registra a maturidade estimada quando o plano foi escrito.
> Consulte a CLI e os testes atuais para verificar quais operações estão
> disponíveis; o desenho, por si só, não garante disponibilidade de serviço.

---

## Roteiro de implementação (ordem de ataque)

1. **`cosmic put/get`** (storage QEL) — cerca a crate `mycelium-qel` com uma
   CLI `cosmic` + endpoint no daemon; o primeiro caso utilizável (ex.: QA
   descendente de "dropbox pós-quântico").
2. **`cosmic run`** (compute verificável) — recipe content-addressed + re-provm.
3. **`cosmic auth`** (identidade portátil) — CLI para spawn/verificar GhostID
   + VOID-00 binding "qualquer OS".

Histórico de status em [`status.md`](../reports/status.md).
