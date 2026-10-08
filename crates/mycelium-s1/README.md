# Mycelium S1 — MVP local e PAYG

Runtime Rust compilável como `rlib`, biblioteca dinâmica e estática, com ABI C em
`include/mycelium_s1.h`. Calcula logits lineares e softmax estável, restringindo as
ações por máscara. A distribuição roda no processo do jogo, sem inferência remota.

## Executar

```sh
cargo test -p mycelium-s1
cargo build -p mycelium-s1 --release
cargo run -p mycelium-s1 -- compile crates/mycelium-s1/examples/npc.json /tmp/npc.s1.json
cargo run -p mycelium-s1 -- evaluate crates/mycelium-s1/examples/request.json
cargo run -p mycelium-s1 -- serve
```

O portal de desenvolvimento atende em http://127.0.0.1:7481, com
`POST /api/evaluate` e `GET /api/health`. O nó Mycelium também registra o serviço
como órbita `s1.mycelium` no Event Horizon. O endpoint de demonstração é gratuito
e não faz cobrança. O navegador calcula a demonstração diretamente em JavaScript.

## Créditos e reservas

```sh
cargo run -p mycelium-s1 -- credit /tmp/s1-ledger recibo-001 studio-demo 100000
cargo run -p mycelium-s1 -- reserve /tmp/s1-ledger crates/mycelium-s1/examples/allowance.json
```

`credit` é uma operação administrativa: executar somente depois de confirmar o
pagamento no provedor. Não representa um checkout ou uma confirmação bancária.
Recibos e reservas têm idempotência: repetir o mesmo identificador e conteúdo
não altera novamente o saldo; conteúdo diferente é rejeitado. Reservas debitam
o saldo antes de liberar o ticket Ed25519. O ledger usa gravação atômica e lock
exclusivo. A chave privada permanece no servidor emissor (`issuer.key`, modo
0600 em Unix); distribuir apenas a chave pública e o ticket para o jogo.

No SDK Rust, `Bucket::consume` valida assinatura, validade, modelo e dispositivo,
e limita o número de avaliações. O integrador deve consumir uma unidade por
decisão e persistir o contador em armazenamento confiável. Tickets permitem
continuar offline até esgotamento ou expiração. A ABI C de avaliação é uma
primitiva matemática sem medição; a integração de licenciamento deve envolver
essa chamada. Contadores e relógios controlados pelo cliente não protegem contra
rollback ou adulteração; produção exige reconciliação e uma política de confiança.

## Escopo e próximos passos

Este MVP não implementa processamento de cartão/transferência, autenticação de
estúdios, distribuição de chaves de API, treinamento de modelos, telemetria remota
nem carregamento real de assets de GPU. `compile` valida e compacta um esquema
JSON; não treina pesos. A latência submilissegundo é uma meta que precisa de
benchmark por plataforma. Builds de console/mobile exigem os respectivos SDKs.
Os preços e margens exibidos são simulações comerciais, não resultados medidos.

A página estática fica em `apps/mycelium-s1-portal/dist/index.html`; seu deploy é
independente do runtime nativo. Hospedagem não disponibiliza um backend de billing.
