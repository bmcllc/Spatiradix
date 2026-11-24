# SWP-Ω 1.0 · Space-Web Ω

**Status** · Proposta SW0 para a camada espacial L5 do Mycelium Network.

A Space-Web apresenta serviços e conteúdo da malha como mundos navegáveis. O
cliente gera a cartografia localmente. A identidade de um mundo, suas revisões,
os bytes publicados e suas posições em diferentes atlas têm endereços próprios.

## Perfil inicial

O primeiro mundo contém uma cena estática pública em GLB, metadados espaciais
e portais para outros mundos. Cenas podem aparecer em várias galáxias. O cliente
carrega assets por demanda e abre os portais mediante ação do usuário.

Capacidades privadas, presença, Web Bridge, WASM, execução remota e edição
colaborativa ficam para perfis posteriores. O SW0 define o contrato de dados
local, com assinatura e vetores verificáveis. A descoberta em outra máquina
depende do trabalho de integração com a malha.

## Identidade e endereço

| Conceito | Representação |
|---|---|
| Endereço canônico | `swp://<node-id>/<nome>` |
| `NodeId` | BLAKE3 de 32 bytes da chave pública Ed25519 do proprietário, em 64 dígitos hexadecimais minúsculos no endereço |
| `WorldId` | O mesmo identificador de serviço que o Habitat deriva de `NodeId` e nome |
| `WorldHead` | Par `(revision, manifest_cid)` de um manifesto assinado e verificado |
| `ContentId` | BLAKE3 de 32 bytes, apresentado como `Qm` seguido de 64 dígitos hexadecimais minúsculos |
| `SpatialAddress` | Coordenada relativa a um atlas. Cada atlas pode posicionar o mesmo `WorldId` de forma independente. |

O nome ocupa 1 a 64 bytes ASCII, usa `[a-z0-9-]` e começa e termina com letra
ou dígito. O perfil exige um único segmento. Rejeite componentes extras, escapes
percentuais, variantes em maiúsculas, query, fragmento, porta e credenciais.
Interprete a forma exata do endereço antes de qualquer normalização de URL.

```text
WorldId = BLAKE3(
  ASCII("mycelium-habitat-service-id-v1") || 0x00 ||
  NodeId[32] || u64be(len(nome)) || ASCII(nome)
)
```

Rotacionar a chave de descoberta do Pkarr ou mover um planeta preserva seu
`WorldId`. Trocar a chave do proprietário ou o nome produz outra identidade.
Transferência de propriedade requer um protocolo futuro. Uma chave Pkarr
serve para localizar candidatos. O cliente autentica cada candidato pela
chave do proprietário vinculada ao `NodeId`. Capacidades privadas `myc1…`
ficam fora dos endereços, atlas e índices públicos do SWP-Ω.

## Manifesto e assinatura

O [esquema JSON](manifest.schema.json) descreve a representação legível do
manifesto e do envelope. A fronteira de verificação é o envelope binário,
com assinatura Ed25519 pura. Use o perfil determinístico do [RFC 8949,
§4.2.1](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1). Use apenas
arrays de tamanho definido, texto UTF-8, bytes, inteiros sem sinal e `null`.
Os arrays usam exatamente a ordem e os tipos abaixo. `b32` e `b64` indicam
byte strings com 32 e 64 bytes. Em CBOR, decodifique valores hexadecimais e
`ContentId` para bytes. Cada texto mantém seus bytes UTF-8. Preserve a ordem
de LODs e portais. As galáxias são nomes distintos em ordem lexical ASCII.

```text
asset   = [plot: b32, path: text, digest: b32]
spatial = [class: text, seed: uint32, galaxies: [text, ...]]
portal  = [label: text, target: text]

payload = [
  1, owner_public_key: b32, service: text, title: text,
  revision: uint32, previous: b32 | null,
  "public", spatial, scene: asset, lod: [asset, ...], portals: [portal, ...]
]

signing_bytes = ASCII("mycelium-swp-manifest-v1") || 0x00 || CBOR(payload)
manifest_cid  = BLAKE3(signing_bytes)
envelope      = CBOR([payload, signature: b64])
```

Valide em ordem:

1. Limite o envelope a 32 KiB. Rejeite tipos ou tamanhos fora do perfil,
   bytes excedentes, codificação CBOR alternativa e campos JSON duplicados na
   importação legível. A recodificação determinística deve reproduzir os bytes.
2. Valide o manifesto e derive `NodeId` e `WorldId`. Compare chave e nome
   com o endereço solicitado. Aplique verificação Ed25519 estrita, com
   rejeição de chave e componente `R` de baixa ordem e de escalares `S`
   fora da faixa.
3. Exija `revision = 1` e `previous = null` no primeiro manifesto. Em revisões
   seguintes, `previous` identifica o manifesto anterior do mesmo mundo.
   Na primeira resolução, valide a cadeia até a revisão 1. Ao atualizar um
   mundo já conhecido, valide até a última revisão aceita. Cada elo
   incrementa a revisão em um. A resolução deve parar ao esgotar um
   orçamento local de elos e bytes. Preserve o estado local
   diante de rollback, cadeia incompleta ou cabeças diferentes na mesma
   revisão. Reporte o conflito em vez de escolher um vencedor.

A assinatura demonstra autorização do manifesto. Na primeira resolução, um
intermediário ainda pode omitir revisões mais recentes. Uma ausência em cache
ou rede também pode tornar um mundo temporariamente indisponível.

## Localização na malha e leitura de assets

O Habitat H0 tem um registro local de serviços assinados e os tipos
`data`, `compute` e `site`. A integração SW2 deve vincular o novo tipo
`spaceworld` ao mesmo `WorldId`, com descoberta pública opt-in. O envelope
da Space-Web tem domínio próprio e convive com a política Habitat existente.

1. Descubra um `ContentId` de Plot candidato a partir de `WorldId`.
   A integração posterior pode usar um catálogo assinado ou Pkarr como
   fonte de localizadores. O mapeamento de descoberta continua em aberto.
2. Recupere o Plot público pelo SporeBank e confira seu identificador segundo
   `giggs::Plot::id`. Encontre uma única folha `spaceworld.cbor` e valide
   seu envelope. O identificador do Plot cobre a embalagem Giggs. O
   `manifest_cid` cobre os bytes assinados do manifesto.
3. Para cada asset necessário, recupere o Plot indicado por `plot`, confira
   seu `ContentId`, encontre exatamente uma folha com o `path` assinado e
   calcule BLAKE3 dos bytes dessa folha. Compare com `digest` antes de entregar
   os bytes ao carregador. Cada caminho tem até 128 bytes ASCII, segmentos
   de letras, dígitos, `_`, `-` e pontos internos, termina em `.glb` e
   serve como chave do Plot.
4. O carregador estático aceita GLB autocontido. Rejeita URIs externos e
   extensões glTF fora da lista admitida pelo cliente antes de instanciar
   a cena. Aplica limites de download, geometria, texturas e memória. A
   validação de identidade do publicador é independente da validação dos
   dados recebidos.

Kademlia e SporeBank fornecem armazenamento e recuperação por Plot. O Atlas
usa a identidade validada ao indexar relações. Coordenadas, popularidade e
presença ficam fora do envelope do mundo. O próximo contrato do Atlas deve
versionar a projeção determinística e a partição dos tiles, de forma que um
cliente possa descartar setores sem perder a capacidade de resolver endereços.

## Critérios de aceitação

- **SW0** · Um validador independente reproduz os digests e assinaturas em
  [vetores de referência](test-vectors/retrolab.json) e rejeita troca de
  proprietário, alterações no manifesto, codificação alternativa e rollback.
- **SW1** · Um cliente renderiza a cena de teste a partir de um atlas local,
  com projeção estável e carregamento limitado aos setores relevantes.
- **SW2 + SW3** · Dois computadores em redes distintas. A publica e B
  parte apenas do endereço `swp://` para descobrir o mundo, validar a cadeia,
  recuperar a cena por Plot e renderizar o planeta. Registre as revisões,
  os CIDs e as condições da rede. Depois de obter uma réplica ativa, retire A
  e repita a resolução com um cache local vazio.

[Habitat H0](../../docs/architecture/HABITAT_MVP.md) ·
[Descoberta Pkarr](../../docs/network/pkarr-anonimo.md) ·
[Prova local do Mycelium](../../docs/reports/demonstracao-2026-11-21.md)
