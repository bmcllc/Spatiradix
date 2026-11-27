# mycelium-core

Este crate reúne tipos compartilhados pelo Mycelium: identificadores, recursos,
políticas de conectividade e interfaces de ciclo de vida. A implementação está
em [`src/lib.rs`](src/lib.rs).

## Tipos principais

- `NodeId`: identificador de 32 bytes calculado com BLAKE3 a partir dos bytes
  fornecidos, como uma chave pública.
- `PeerBinding`: associação assinada entre `NodeId` e `PeerId`. A validação
  confere a chave, a expiração e a assinatura; quem a usa também deve comparar
  o `peer_id` com a identidade do transporte.
- `ContentId`: hash BLAKE3 do conteúdo. A representação textual usa `Qm`
  seguido de 64 dígitos hexadecimais; não é automaticamente um CID IPFS.
- `Resources`: recursos declarados por um nó. Os campos são `cpu_cores`,
  `ram_mib`, `storage_gib` e `bandwidth_mbps`.
- `Nutrient`: os tipos `Atp`, `Enzymes`, `Mycelia`, `Spores` e `Resilience`.
- `Membrane`: papel de conectividade do nó: `Floresta`, `Raiz`, `Folha` ou
  `Esporocarp`. A classificação não prova, por si só, que o nó é acessível.
- `FruitingBody`: trait que expõe o tipo, a vitalidade, os nutrientes e a
  operação de decomposição de um componente que o implementa.

Para localizar outros componentes, consulte o [guia de navegação](../../docs/architecture/NAVEGACAO_CODIGO.md).

## Testes

```bash
cargo test -p mycelium-core
```
