# Portal S1 como artefato Mycelium

O portal pode ser distribuído como um `giggs::Plot` público, identificado por
`ContentId`, armazenado no SporeBank e servido pela ion SRC do Event Horizon.
Esse caminho reutiliza a rede existente: a identidade do conteúdo não depende
de registrar um domínio DNS nem de contratar um host central. Ainda exige nós
ativos que guardem e sirvam os arquivos, conectividade entre os pares e um
cliente Mycelium para resolver `src.mycelium`.

## Preparar um build público

`mycelium_s1::publication::prepare_site` empacota um diretório de build estático
já concluído. Os caminhos são ordenados e cada arquivo entra no manifesto
`mycelium-site.json`, com tamanho e digest BLAKE3. O formato é
`mycelium.static-site.v1`.

```rust
use mycelium_s1::publication::prepare_site;

let bundle = prepare_site("portal/dist", "Mycelium S1", "index.html")?;
let request = bundle.repo_publish_request(
    "mycelium-s1",
    "site",
    None,
    "[public] Mycelium S1 portal",
)?;
```

O empacotador rejeita links simbólicos, arquivos especiais, caminhos ocultos,
travessia de diretórios e nomes fora do conjunto ASCII seguro. O limite local é
1.024 assets e 8 MiB de conteúdo, mais até 512 KiB de manifesto. Esse limite
controla o empacotamento; não certifica que um bundle desse tamanho cabe nos
limites atuais do transporte Kademlia/gossipsub. O Spore Print usa arrays JSON
para os bytes, portanto seu tamanho de transporte é maior que o build.

Para funcionar abaixo de `/<CID>/`, o build deve usar links relativos aos seus
próprios arquivos: por exemplo, `./assets/main.js`. Builds Vite podem usar
`base: "./"`. Links absolutos como `/assets/main.js` apontam para a raiz do SRC,
fora do bundle. A rota existente serve arquivos; não implementa fallback de SPA.
Rotas de interface por hash evitam depender desse fallback.

O diretório publicado precisa conter somente conteúdo público. Ocultar botões
do Economy não remove dados de um bundle público. Chaves, credenciais, ledger,
administração econômica e dados privados de clientes pertencem à API
autenticada, fora desse build. Qualquer pessoa que obtenha o Plot pode ler todas
as suas folhas.

## Publicar pelo daemon existente

`SiteBundle::repo_publish_request` produz o JSON do comando real
`mycelium_node::control::Request::RepoPublish`. O código que fala com o daemon
deve converter esse valor para `Request` e usar `control::call`; esse cliente
carrega a autenticação do socket existente. O módulo S1 não depende de
`mycelium-node`, evitando um ciclo entre os crates.

O fluxo de `Organism::publish_repo_ref_expected` é:

1. Ler a referência atual de repositório/branch e usar seu CID como parent.
2. Depositar o Plot no SporeBank do daemon.
3. Assinar e atualizar a referência GiGGS por compare-and-swap.
4. Tentar armazenar/anunciar o Spore Print na DHT sob `spore/<CID>` e no gossip.
5. Retornar `Response::RepoPublished { cid, leaves, bytes }`.

Deve haver um único escritor responsável pelo SporeBank; não abra um segundo
`SporeBank::open` para publicar em paralelo ao daemon. Um CID calculado antes de
enviar o request é apenas uma prévia: o CID definitivo inclui o autor, a
mensagem e os parents que o daemon usa. O bundle e o manifesto são
determinísticos; o histórico também faz parte da identidade do Plot.

Um `expected_previous_cid` fornecido protege uma atualização contra mudança da
referência desde a leitura do cliente. `None` usa o estado atual lido pelo
daemon; não significa “criar somente se a referência estiver ausente”.

O retorno de publicação confirma a gravação e a referência local. O método
atual ignora falhas de envio DHT/gossip e não aguarda confirmação de custódia
remota. Portanto, não trate esse retorno como prova de replicação, de
disponibilidade pública ou de acesso por outro navegador. Validar publicação
entre máquinas exige buscar/importar o Plot em um segundo nó e conferir seu
CID; replicação durável e transporte de bundles grandes precisam de validação
separada.

## Abrir e conferir a identidade

`site_entry_url(cid, "index.html")` retorna:

```text
http://src.mycelium/<CID>/index.html
```

A entrada explícita importa: `http://src.mycelium/<CID>` retorna a listagem JSON
do Plot no SRC atual. O nome `src.mycelium` pertence à resolução/proxy local do
Event Horizon; ele não é um domínio público registrado e não passa a funcionar
automaticamente em navegadores sem o cliente. A ion SRC usa a porta local
7474 na configuração existente.

`verify_site_plot` verifica o CID completo do Plot, seu marcador público, a
ordenação dos caminhos e todos os tamanhos/hashes do manifesto.
`read_published_asset(home, cid, path)` aplica essas verificações antes de ler
um asset do layout atual `home/sporebank/plots/<hex-CID>.json`, sem abrir um
escritor. Caminho vazio ou `/` seleciona o entrypoint do manifesto.

A verificação estabelece integridade em relação ao CID pedido. O manifesto
não é uma assinatura; a autoria da publicação pertence à referência GiGGS
assinada, cuja verificação deve permanecer no fluxo de referências da rede.
Uma nova versão gera um novo Plot/CID; uma referência assinada permite seguir
seu histórico sem reescrever o conteúdo imutável antigo.

## O que a publicação não substitui

O bundle entrega HTML, JavaScript e assets. Checkout Economy, emissão de
licenças e controle de créditos continuam exigindo os serviços e autorizações
da arquitetura. O navegador não pode criar créditos confiáveis somente com
JavaScript estático. O runtime local continua funcionando com seus tickets e
buffer offline, mas treinamento e benchmarks executados no hardware alvo
também são processos separados da publicação do site.

Antes de anunciar disponibilidade descentralizada, a validação operacional
precisa demonstrar o carregamento em outro nó, seus assets relativos,
autenticação das APIs e confirmação do pagamento no serviço Economy. A
infraestrutura substitui um host central por pares que armazenam e servem
artefatos; ela não elimina o trabalho de armazenamento e entrega da rede.

Referências de implementação: `crates/mycelium-s1/src/publication.rs`,
`crates/mycelium-node/src/control.rs`,
`crates/mycelium-node/src/organism.rs`,
`crates/mycelium-node/src/src_ion.rs`,
`crates/mycelium-sporebank/src/lib.rs` e `crates/giggs/src/lib.rs`.
