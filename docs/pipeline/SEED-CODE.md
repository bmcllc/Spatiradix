# Seed Code — Distribuição de Código via Mycelium Network

Este guia mostra como publicar e baixar código-fonte pela rede P2P usando
`seed-code` e `recall-code`.

---

## O que é

O Mycelium Network é capaz de distribuir código-fonte entre nós usando
seu próprio protocolo P2P. O conteúdo é identificado por hash BLAKE3,
armazenado no Spore Bank local e propagado via gossipsub.

```
┌──────────────────────┐          ┌──────────────────────┐
│   Nó A (publicador)  │          │   Nó B (receptor)    │
│                      │          │                      │
│  seed-code ──────────┼─ gossip →│  ── recall-code      │
│  (código → Plot)     │          │  (Plot → código)     │
└──────────────────────┘          └──────────────────────┘
        sem git                           sem git
        sem GitHub                        sem GitHub
        conteúdo público                 pares conectados
```

---

## Passo a passo: Publicar código

### 1. Tenha o Mycelium compilado

```bash
# Compila o daemon + CLI
cargo build -p mycelium-cli
```

### 2. Inicia um nó (se ainda não tem)

O exemplo abaixo usa `--sporocarp` para um nó que atuará como relay público.
Antes de ativá-lo, verifique a conectividade de entrada a partir de outra rede,
conforme o [guia de esporocarpo voluntário](../network/volunteer-sporocarp.md).
Para uma demonstração local sem relay público, omita essa opção.
Mantenha o daemon em execução e use outro terminal para os próximos comandos.

```bash
# Sprout (gera identidade)
./target/debug/mycelium sprout --contribute 2cpu,4gb,50gb

# Inicia o daemon neste terminal
RUST_LOG=info ./target/debug/mycelium daemon \
  --contribute 2cpu,4gb,50gb \
  --sporocarp \
  --horizon-port 7474 \
  --listen "/ip4/0.0.0.0/tcp/4001"
```

### 3. Publica o código

```bash
# Opção A: seed-code (direto, sem git)
./target/debug/mycelium seed-code \
  --path /caminho/do/seu/projeto \
  --name "meu-projeto" \
  --description "Descrição do que o projeto faz"

# Saída:
# [🍄] seed-code: 12 arquivos (4523 bytes) de '/caminho/do/seu/projeto'
# [🍄] 📦 'meu-projeto' semead na rede: plot=QmXXX..., 12 arquivos, 4523 bytes
#
# Para baixar em outro nó:
#   mycelium recall-code --plot QmXXX...
```

### 4. (Opcional) Anuncia também no gossip

```bash
# Anuncia o repo via gossip (outros nós recebem o nome + URL)
./target/debug/mycelium seed-repo \
  --name "meu-projeto" \
  --url "https://github.com/meu-usuario/meu-projeto.git" \
  --commit "$(git rev-parse --short HEAD)" \
  --description "Descrição do projeto"
```

---

## Passo a passo: Baixar código

Substitua `QmXXX...`, `PEER_ID` e os endereços de exemplo pelos valores reais
do publicador antes de executar os comandos.

### 1. Inicia um nó receptor

```bash
# Bootstrap em algum nó da rede (ou --public-bootstrap)
./target/debug/mycelium daemon \
  --bootstrap "/ip4/192.168.1.100/tcp/4001/p2p/PEER_ID" \
  --no-mdns
```

### 2. Lista repositórios anunciados

```bash
# Mostra repos que peers anunciaram via gossip
./target/debug/mycelium repos

# Saída:
# 📦 meu-projeto
#    url: mycelium://plot/QmXXX...
#    commit: 52ea21689265e033
#    desc: Descrição do projeto
#    from: 2a05114bee7f...
```

### 3. Baixa o código

```bash
# Opção A: recall-code (extrai os arquivos)
./target/debug/mycelium recall-code --plot QmXXX...

# Saída:
# 📦 12 arquivos extraídos em meu-projeto/

# Opção B: download via HTTP (Event Horizon)
curl http://127.0.0.1:7474/src/QmXXX.../main.rs
```

### 4. Verifica o conteúdo

```bash
ls meu-projeto/
# main.rs  Cargo.toml  README.md

cat meu-projeto/main.rs
# fn main() { println!("olá!"); }
```

---

## Fluxo completo (do zero)

```bash
# === NO NÓ A (publicador) ===

# 1. Compila
cargo build -p mycelium-cli

# 2. Inicia nó
./target/debug/mycelium sprout --contribute 2cpu,4gb,50gb
RUST_LOG=info ./target/debug/mycelium daemon --sporocarp --horizon-port 7474 &

# 3. Publica código
./target/debug/mycelium seed-code \
  --path ./meu-projeto \
  --name "meu-projeto" \
  --description "Meu app P2P"
# → plot=QmXXX...

# === NO NÓ B (receptor, qualquer lugar do mundo) ===

# 4. Inicia nó com bootstrap no A
./target/debug/mycelium sprout --contribute 2cpu,4gb,50gb
./target/debug/mycelium daemon \
  --bootstrap "/ip4/IP-DO-A/tcp/4001/p2p/PEER_ID_A" &

# 5. Baixa o código
./target/debug/mycelium recall-code --plot QmXXX...
# → 📦 12 arquivos extraídos em meu-projeto/
```

---

## Como funciona por baixo dos panos

### Seed Code → Plot → Spore Bank

```
1. seed-code lê os arquivos do diretório
2. Cada arquivo vira uma Leaf { path, content }
3. Cria um Plot { author, message, leaves }
4. SporeBank::deposit(plot) → ContentId (hash)
5. fruit_ion() → ion visível no Event Horizon
6. Envelope::RepoAnnounce → gossipsub → peers recebem
```

### Recall Code ← Plot ← Spore Bank

```
1. recall-code recebe um ContentId (Qm...)
2. SporeBank::recall(plot_id) → Plot
3. Para cada Leaf → extrai arquivo no disco
4. Pronto! Código fonte restaurado.
```

### Segurança

| Aspecto | Como funciona |
|---------|---------------|
| **Integridade** | O `ContentId` usa BLAKE3 para identificar o conteúdo; confira o identificador recebido. |
| **Versões** | Uma alteração produz outro conteúdo e outro identificador. |
| **Privacidade** | A visibilidade padrão é `public`. Não publique credenciais, chaves ou arquivos privados; visibilidade restrita não substitui criptografia. |
| **Distribuição** | Gossip e DHT dependem de conectividade; um anúncio não prova custódia remota ou disponibilidade. |

---

## Comparação: Git vs Mycelium

| | Git | Mycelium |
|---|-----|----------|
| **Armazenamento** | Repositórios locais e remotos opcionais | Plots locais e em nós participantes |
| **Conexão** | Transporte local ou de rede, conforme o remoto | LAN ou rede entre nós, conforme a configuração |
| **Identificador de conteúdo** | SHA-1 ou SHA-256, conforme o formato do repositório | BLAKE3 no `ContentId` |
| **Publicação** | `git push` para um remoto configurado | `seed-code` e anúncios na malha |
| **Disponibilidade** | Depende de cópias e remotos acessíveis | Depende de pares com o conteúdo e conectividade |

---

## Resumo dos comandos

```bash
# Publicar código (sem git):
mycelium seed-code --path ./projeto --name "nome" --description "descrição"

# Anunciar repo git (opcional):
mycelium seed-repo --name "repo" --url "https://..." --commit "abc123" --description "desc"

# Listar repos anunciados:
mycelium repos

# Baixar código:
mycelium recall-code --plot QmXXX...

# Download via HTTP:
curl http://127.0.0.1:7474/src/QmXXX.../arquivo.rs
```
