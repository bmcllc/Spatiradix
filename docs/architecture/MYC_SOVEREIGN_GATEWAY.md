# MYC Sovereign Gateway — camada de privacidade H1 (2026-11-21)

## Objetivo

Esta etapa propõe integrar o MYC ao Meta-Gateway com proteção dos dados e
consentimento para divulgação externa. O motor monetário configura a referência
**1 MYC = 8 USDC**; isso não representa preço de mercado, reserva real nem
garantia de resgate.

Integrar o sistema financeiro ao substrato soberano requer distinguir
**dados**, **identidade**, **transporte**, **autorização**, **execução**
e **liquidação**. A implementação H1 inicia pela fronteira de persistência
e pelo consentimento explícito para exposição ao mundo externo.

## Implementado e testado nesta etapa

- Criptografia XChaCha20-Poly1305 (nonce aleatório 192 bits, autenticação de
  conteúdo) para cada estado de PaymentIntent no SporeBank.
- AAD liga ciphertext ao NodeId proprietário, ao ID da intenção e ao CID
  anterior da cadeia causal daquela intenção.
- O Plot persiste somente a mensagem genérica
  `[private] meta-gateway:sealed`, um arquivo `sealed-intent.bin` e seus
  pais. Não inclui em claro ID, destinatário ou estado na mensagem/nome.
- Índice `meta_gateway_index.enc` cifrado com AAD ligado ao NodeId.
  Arquivo gravado por rename + sync; ciphertext adulterado ou senha
  incorreta é recusado, não substituído por índice vazio.
- Índice legado `meta_gateway_index.json` permanece somente leitura; não
  pode registrar novos pagamentos em texto claro. A migração exige operação
  explícita e backup isolado.
- Cotação `IndicativeMycQuote` usa a taxa exata da política, aritmética
  verificada e `redemption_guaranteed = false` (sem inventar BRL/USD).
- Chave derivada por `mycelium-keyring::Keyring::derive32` sob
  `mycelium/v1/meta-gateway/intent-aead`; API alternativa `open_encrypted`
  recebe 32 bytes de segredo independente.
- `MetaGatewayEngine` recusa executar intenção, confirmar liquidação
  ou gravar falha quando a persistência cifrada está indisponível.
- Consentimento `external_disclosure_consent=true` obrigatório para
  preparar payloads de Pix, SWIFT e DCMS/BRICS; **não é uma autorização de
  débito, prova de titularidade, autenticação de pagador nem integração
  efetiva a PSPs ou bancos**.
- CLI `mycelium gateway pay` suporta `--allow-external-disclosure`.
  Payload bruto é oculto por padrão; `--show-native-payload` habilita
  a exibição voluntária. Não equivale a ocultá-lo do destino externo.

## Operação do daemon

Se `MYCELIUM_GATEWAY_VAULT_KEY` não estiver configurada, o daemon
inicializa normalmente, mas **operações financeiras do Meta-Gateway são
bloqueadas** em vez de persistirem pagamento em claro.

A variável deve conter 64 caracteres hexadecimais correspondentes a
32 bytes de segredo gerados fora do Meta-Gateway. Use um gerenciador
de segredos ou terminal seguro. A chave deve sobreviver ao reinício:
**perdê-la significa perder o acesso aos registros cifrados**. Não
publique a chave em Git, logs ou histórico de shell.

Uma alternativa para aplicações que usam `mycelium-keyring` é chamar
`SporebankIntentStore::open_with_keyring(home, node_id, &keyring)`.
O daemon ainda não liga automaticamente essa API ao desbloqueio BIP-39.

Com o daemon iniciado e a chave provida, a CLI pode preparar mensagens:

```bash
mycelium gateway pay --to 'pix:chave@provedor.com' \
  --amount-micros 10000000 --currency BRL \
  --allow-external-disclosure --local-hour 14
# Adicione --show-native-payload apenas para inspecionar a mensagem completa.
```

Uma mensagem local "prepared_not_submitted" **não** comprova transferência
Pix/Swift/BRICS. Nenhuma conversão de BRL/USD para USDC é estimada sem fonte
verificável. MYC Rail continua bloqueado até que haja lançamento real no ledger.

## Integração das camadas por responsabilidade

| Subsistema | Papel efetivo / próximo gate |
| --- | --- |
| core + pheromones + ghostid + keyring | NodeId, assinatura Ed25519, identidade efêmera, derivação de chaves isolada |
| pqc + zkp + entropy | Primitivas pós-quânticas, compromisso e partilha; self-encapsulation NÃO é proteção E2E |
| hyphae + veil + nostr + pkarr + distancebridge | Transporte e descoberta; precisa comprovar privacidade por rota, proxy e provas de dois hosts |
| qel + sporebank + giggs + ipfs + root | Fragmentos e recuperação; só ciphertext pode sair do host se for sensível |
| isotope | Estado convergente de serviços; não usar LWW para saldo financeiro |
| vacuum + inertia + plasma + singularity | Sandbox e serviços que criam demanda útil por armazenamento e computação pagos em MYC |
| tropical + cosmic-cli + cosmoplanck | Orquestração e interoperabilidade, com isolamento por capacidade |
| node + cli + thefield + sclerotium + s1 | Daemon, controle local, descoberta e mensageria; trilhos não devem burlar o cofre |
| nutrients + economy + bank + pay + mint + royalty | Medição de trabalho, pagamentos, mercado e incentivos; sem comprovação, não emitir recibos liquidados |
| media + store + bot | Serviços aos quais MYC pode dar acesso real, mediante cobrança e entrega verificadas |
| meta-gateway | Roteamento, consentimento de divulgação, armazenamento cifrado, estados sem falsa liquidação |

## Política de soberania econômica (projeto, não executada)

O fortalecimento do MYC perante o USDC deve vir de: (1) bens e serviços de
verdade precificados em MYC; (2) oferta monetária transparente e demanda
associada a trabalho útil; (3) trocas voluntárias com preços observáveis;
(4) separação entre **valor indicativo** e **reservas exigíveis**.

A taxa configurada em código não obriga contrapartes a aceitar MYC por 8 USDC.
Se for oferecido resgate fixo, isso exige contrapartes, reserva, liquidez e
verificação operacional independentes. O código desta etapa **não** promete
conversão garantida, lastro bancário, execução de Pix ou finalização bancária.

## Limitações e próximos testes

- Chaves de cofre entregues por variável de ambiente podem vazar em um host
  comprometido. Proteger com vault/OS keychain/hardware token e minimizar
  exposição; uma chave armazenada ao lado do ciphertext não defende
  contra roubo de todo o computador.
- A posição do índice criptografado e CIDs de plots ainda permite observar
  tamanho/frequência de atualização, mesmo sem ler conteúdo.
- O código de PKARR e o "PQC seal" atual não provam anonimato nem comunicação
  pós-quântica E2E. Não alegar tal garantia sem endpoint e handshake auditáveis.
- Os eventos externos ainda são representações preparadas por adaptadores.
  Webhooks e HSM precisam validação específica de provedores reais.
- O legado em claro requer ferramenta de migração e limpeza segura separada.
- Endurecer a autorização do plano de controle e a persistência transacional
  com crash-injection e recuperação de índice. Testar em duas máquinas.
- Instanciar o transporte opt-in via VEIL/QUIC/Nostr e medir ausência de DNS/IP
  leaks, incluindo falhas de relay. **Não habilitar rede anônima por suposição**.

O registro acima descreve as alterações locais e os limites observados nesta etapa.
