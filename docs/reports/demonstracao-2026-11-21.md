# Mycelium Network — demonstração local

Em 21 de novembro de 2026, o Mycelium foi recompilado a partir da árvore
de trabalho da branch `feat/mycelium-pkarr`, com base em `5f6b2df` e
alterações locais. A CLI permite demonstrar publicação de código, replicação
P2P e recuperação de arquivos com o Root.

| Demonstração | Resultado observado |
|---|---|
| Vitrine e Forja | Um nó local abriu a Vitrine, publicou um repositório por ContentId e clonou seus dois arquivos byte a byte. O README publicado também foi recuperado por HTTP. |
| Sobrevivência do conteúdo P2P | **13 de 13 verificações passaram.** Duas réplicas tinham o conteúdo no disco e continuaram servindo após derrubar o publicador. Um nó que entrou depois recuperou o conteúdo pela DHT. Outro recebeu a cópia sem fazer consulta. |
| Root | Um arquivo de 3 MB foi reconstruído com duas de três raízes representadas por pastas. Uma raiz sozinha foi recusada. A montagem FUSE permitiu ler e editar arquivos, e uma raiz perdida foi recriada. |

## Como reproduzir no Linux

Compile o nó e execute as demos na raiz do repositório:

```bash
cargo build --locked -p mycelium-cli
MYCELIUM_BIN="$PWD/target/debug/mycelium" bash scripts/showcase-demo.sh
```

Abra o endereço da Vitrine que o script imprimir. A Forja mostra os arquivos
publicados nessa execução. Encerre com Ctrl+C e rode as outras duas provas:

```bash
MYCELIUM_BIN="$PWD/target/debug/mycelium" bash scripts/prova-sobrevivencia.sh
bash scripts/prova-root.sh
```

A prova do Root usa `fusermount3` e requer acesso a `/dev/fuse`. Os processos
da prova P2P usam loopback em uma só máquina. Uma versão anterior trocou dados
via Nostr entre CGNAT e 5G em julho de 2026. [Histórico de campo](testes-realidade.md)

## Escopo do lançamento

Este estado é adequado para uma demonstração assistida e testes locais por
pessoas da comunidade. A homologação em máquinas e redes independentes com a
versão atual ainda está pendente. A Vitrine deve ficar em loopback durante a
demonstração porque a API de resumo inclui caminhos da máquina e dados de
interfaces físicas. Pagamentos e liquidação real ficaram fora destas provas.

A suíte padrão do workspace (`cargo test --offline --locked --workspace
--no-fail-fast`) terminou com **1.269 testes aprovados, 9 falhas e 1 ignorado**.
As nove falhas estão em `mycelium-economy --test discovery_cli`. A verificação
`cargo fmt --all -- --check` também apontou diferenças de formatação.
