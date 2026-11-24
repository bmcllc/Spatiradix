# 🍄 Mycelium Machine Hub — núcleo nativo, SDK, integração, economia e compatibilidade

Data: 2026-10-22. Status: **desenho de arquitetura**. Nada daqui está
implementado. Tudo o que este documento afirma sobre o código existente foi
conferido por leitura nesta data, com `arquivo:linha`. O contrato do §2.2 foi
compilado e testado num projeto descartável (§2.7). A auditoria de segurança do
código que o Hub reutiliza está em
[`MACHINE_HUB_AUDITORIA.md`](MACHINE_HUB_AUDITORIA.md).

Entrada: o plano "Mycelium Machine Hub" (máquinas fictícias, simuladores
históricos e recriações nativas, distribuídos e vendidos pela malha, sem VM).
Este documento fixa o que o plano deixou em aberto e corrige o que ele supôs
sobre o repositório.

---

## 0. Decisões

| # | Decisão | Por quê | Descartado |
|---|---|---|---|
| D1 | Contrato por **quadro** (`run_frame`) | rewind, replay, netplay e vetores de teste precisam de uma fronteira fixa; precisão de ciclo continua possível *dentro* do quadro | `step(budget)` como contrato principal |
| D2 | ABI nativa = **perfil "mycelium-v1" da API libretro** | padrão de fato para núcleos nativos em `.so`/`.dll`/`.dylib`: ~25 funções C, cabeçalho MIT, centenas de núcleos existentes | inventar e manter uma ABI nova |
| D3 | **Código baixado nunca roda no processo do Hub** | núcleo de terceiro — ou ROM que explora bug de um núcleo honesto — é código nativo hostil | `dlopen` no Hub |
| D4 | Núcleo baixado roda no **`machine-host`**: processo isolado (receita bwrap do `vacuum`), sem rede, sem `$HOME`, sem display; fala só por pipe e memória compartilhada | isolamento de processo resolve sem VM | janela e áudio dentro da sandbox |
| D5 | Máquina 0 = **MYC-0**, CPU **RV32IM** real com orçamento fixo de instruções por quadro | simulação honesta de hardware; compiladores padrão (C, Rust, Zig); interpretador pequeno e determinístico | Lua ou WASM como "CPU" |
| D6 | Publicador e comprador = **chave Schnorr secp256k1 (GhostId/npub)**, separada da chave do nó | refs do `giggs`, eventos Nostr e NIP-44 já usam essa chave | publicador = nó; ids globais sem dono |
| D7 | Canal de versão = **`SignedRefUpdate`** do `giggs`, com assinante fixado | CAS e sequência monotônica já existem (anti-rollback) | registro central de pacotes |
| D8 | Manifesto em Plot; binários em **chunks de 2 MiB** | Plot serializa bytes como array JSON de números e vive inteiro em memória | núcleo ou ROM grande dentro de Plot |
| D9 | Dinheiro só com **liquidação reverificável**: USDC na Base pelo verificador read-only do `mycelium-economy` (já existe); Lightning por **preimagem** depois | regra herdada do economy: simulado e interno nunca viram demanda paga | nutrients como pagamento; "Settled" por assinatura |
| D10 | Licença = objeto assinado pelo vendedor, verificado com a chave do **anúncio assinado**, nunca com a chave que vem na licença | é o defeito do premium de hoje (MH-09) | lease *bearer* autoassinada |
| D11 | Conteúdo pago: **cifrar e depois publicar**; chave entregue por NIP-44 | seeder hospeda sem acesso; reaproveita `mycelium-nostr` | DRM |
| D12 | Seeding pago por **fatia declarada de cada venda**, só com recibo assinado pelo **comprador licenciado**, com teto por licença | fraudar recibos só devolve parte do próprio dinheiro | cunhar recompensa por bytes anunciados |
| D13 | `mycelium-machine` e `mycelium-machine-host` sob **MIT OR Apache-2.0** | o host carrega núcleos GPL-2.0-only, GPL-3.0, MPL-2.0; o Hub (AGPL-3.0) fica do outro lado da fronteira de processo | host AGPL no mesmo processo que núcleo GPL-2.0-only |
| D14 | Núcleo com licença **não comercial** não entra em anúncio pago | snes9x, Genesis Plus GX, PicoDrive e FinalBurn Neo proíbem venda | |
| D15 | Lançadores legados (QEMU/RetroArch/MAME externos, motor `Native`) saem do caminho padrão | QEMU é virtualização de PC; argumento vindo de manifesto é a classe de RCE da auditoria | `extra_args` livres |
| D16 | v1 sem GPU, sem WASM, sem sandbox Windows/macOS — nessas plataformas só roda núcleo **Referência** | menos superfície; honestidade sobre onde existe isolamento | |

---

## 1. O que o plano supôs e o que o código mostra

- **`mycelium-store` não é um launcher P2P.** O catálogo é local: as entradas vêm
  do seed embutido (`crates/mycelium-store/src/catalog.rs:181`) ou de publicação
  local (`StorePublish` em `crates/mycelium-node/src/organism.rs:3866`;
  `mycelium store publish` em `cli/mycelium-cli/src/main.rs:3199`). Nenhum
  caminho ingere manifesto da rede. O launcher executa binários externos
  (`qemu-system-*`, `retroarch`, `mame`, `sh`) com argumentos tirados do
  manifesto (`crates/mycelium-store/src/runner.rs:275`). Os `content_id` do seed
  são hash de um rótulo, não dos bytes (`catalog.rs:182`).
  *Reaproveita-se:* a persistência do catálogo (escrita atômica + `validate()`
  fail-closed), a regra de licença (`SporeLicense::Proprietary` nunca sai do nó —
  BYOR) e o padrão de ion no Event Horizon. *Não se reaproveita:* o caminho de
  execução.
- **`mycelium-nutrients`:** confirmado, ledger local sem consenso
  (`crates/mycelium-nutrients/src/lib.rs:3`). Além disso, voucher é IOU
  autoassinado — o emissor honesto debita a si mesmo (`organism.rs:2672`), mas
  quem recebe não tem como saber — e o campo BOLT11 só confere a sintaxe do
  invoice (`crates/mycelium-zkp/src/bolt11.rs:89`). Invoice é pedido de
  pagamento, não prova.
- **O trilho de liquidação já existe e o plano não o viu:** `mycelium-economy`
  verifica pagamento USDC na Base em modo read-only
  (`crates/mycelium-economy/src/base_usdc.rs:446`), com provedor RPC fixado,
  confirmações mínimas, bloco-âncora e "uma tx, um settlement"
  (`crates/mycelium-economy/src/lib.rs:831`).
- **Já existe venda no repo:** a assinatura premium da vitrine
  (`crates/mycelium-node/src/vitrine_ion.rs:298`). Ela aceita lease de qualquer
  chave (MH-09); o modelo de licenças do §6 evita isso por construção.
- **Roteamento dedicado:** o navegador de código & Signals usa o ion `field`
  (`/field/`, `crates/mycelium-node/src/field_ion.rs`, TheField). O Hub de
  máquinas usa o ion **`machines`**.
- **Crates:** o plano propõe sete. Bastam dois novos agora — `mycelium-machine`
  (contrato, SDK e harness) e `mycelium-machine-host` (binário da sandbox) — e
  um na etapa 4 (`mycelium-market`). Hub, player e CLI entram no `mycelium-cli`
  como `mycelium machine …`; pagamentos reaproveitam o `mycelium-economy`.

---

## 2. Núcleo nativo

### 2.1 Camadas

```text
┌───────────────────────────────────────────────────────────────────────┐
│ Hub       biblioteca · loja · compras · `mycelium machine …`          │
│           (confiável)                                                 │
├───────────────────────────────────────────────────────────────────────┤
│ Player    janela, áudio e controles (SDL3) · ritmo A/V · saves        │
│           (confiável; único dono da tela, do som e do disco)          │
├────────────────────── pipe + memória compartilhada ───────────────────┤
│ Runner    InProcess: só núcleo compilado dentro do binário            │
│           Sandboxed: processo `machine-host` sob bwrap                │
├───────────────────────────────────────────────────────────────────────┤
│ Núcleo    trait `Machine` (Rust)  ou  perfil libretro (ABI C)         │
├───────────────────────────────────────────────────────────────────────┤
│ Conteúdo  cartucho/ROM/disco por CID · arquivos de sistema por BLAKE3 │
└───────────────────────────────────────────────────────────────────────┘
```

O núcleo nunca toca tela, som, rede ou disco: recebe a entrada do quadro e
devolve imagem e amostras. Isso é o que permite isolá-lo inteiro.

### 2.2 O contrato

```rust
/// Fração exata (ex.: NTSC = 60000/1001 quadros por segundo).
pub struct Ratio { pub num: u32, pub den: u32 }

pub enum PixelFormat { Xrgb8888, Rgb565 }

/// Fixo enquanto um conteúdo estiver carregado.
pub struct AvSpec {
    pub fps: Ratio,
    /// Hz; o áudio é sempre i16 estéreo intercalado.
    pub sample_rate: u32,
    pub max_width: u32,
    pub max_height: u32,
    pub pixel_format: PixelFormat,
    pub display_aspect: Ratio,
}

/// Um controle: 16 botões (bitmask) e 4 eixos.
pub struct Pad { pub buttons: u16, pub axes: [i16; 4] }

/// Entrada amostrada UMA vez por quadro. O núcleo nunca lê entrada no meio do
/// quadro: é isso que torna replay, rewind, netplay e vetores de teste possíveis.
pub struct Input {
    pub pads: [Pad; 4],
    /// Scancodes USB HID das teclas pressionadas.
    pub keys: Vec<u16>,
    /// (x, y, botões) em coordenadas do framebuffer.
    pub pointer: Option<(i16, i16, u8)>,
}

pub struct Frame<'a> {
    pub width: u32,
    pub height: u32,
    /// Bytes por linha (pode ser maior que a parte visível).
    pub pitch: usize,
    pub pixels: &'a [u8],
}

/// Destino da saída de um quadro; quem implementa é o runner.
pub trait Sink {
    fn video(&mut self, frame: Frame<'_>);
    /// Amostras i16 estéreo intercaladas (L, R, L, R…).
    fn audio(&mut self, samples: &[i16]);
}

/// BIOS/firmware fornecidos pelo usuário. O runner só entrega arquivos cujo
/// BLAKE3 bate com o declarado no manifesto.
pub trait SystemFiles {
    fn get(&self, name: &str) -> Option<&[u8]>;
}

pub enum Region {
    /// Memória persistente do cartucho ("bateria"); o player a grava em disco.
    SaveRam,
    /// RAM principal: lida por testes, conquistas e depuradores.
    MainRam,
}

pub enum MachineError {
    BadContent(String),
    MissingSystemFile(String),
    /// Estado de outra versão do núcleo, ou corrompido.
    BadState,
    BufferTooSmall { need: usize },
}

pub trait Machine {
    fn av_spec(&self) -> AvSpec;
    fn reset(&mut self, hard: bool);
    /// Emula exatamente um quadro e entrega vídeo e áudio ao `Sink`.
    fn run_frame(&mut self, input: &Input, out: &mut dyn Sink);
    fn state_size(&self) -> usize;
    fn save_state(&self, buf: &mut [u8]) -> Result<usize, MachineError>;
    fn load_state(&mut self, buf: &[u8]) -> Result<(), MachineError>;
    fn memory(&mut self, region: Region) -> Option<&mut [u8]>;
}

/// Descrição estática de um núcleo; `load` é o construtor.
pub struct MachineInfo {
    pub id: &'static str,
    pub load: fn(content: &[u8], system: &dyn SystemFiles)
        -> Result<Box<dyn Machine>, MachineError>,
}
```

(Derives omitidos aqui; a versão compilada está descrita no §2.7.)

Três regras que o tipo não expressa e que o harness (§4.4) cobra:

1. `run_frame` só lê `self` e `input` — nada de relógio, rede, arquivo ou estado
   global.
2. `save_state` captura tudo o que influencia os quadros seguintes.
3. `av_spec` não muda enquanto o conteúdo estiver carregado. Taxas não inteiras
   do hardware real são arredondadas em `sample_rate`; o controle dinâmico de
   taxa do player (§2.6) absorve a diferença.

### 2.3 Por que quadro e não `step(budget)`

- Com `step(budget) -> StepResult` (proposta do plano), sincronizar áudio e
  vídeo vira problema de cada frontend, e "o estado depois do passo N" não é
  comparável entre núcleos: cada um para num ciclo diferente.
- Com `run_frame`, o núcleo roda internamente os ciclos que o quadro exigir —
  com precisão de ciclo, se quiser — e entrega uma imagem mais as amostras
  daquele quadro. Rewind = estado salvo por quadro; replay e netplay = lista de
  `Input`; vetor de teste = (gravação de entrada, hash esperado por quadro).
- Depuração instrução a instrução fica numa extensão opcional
  (`trait Debuggable { fn step_instruction(&mut self) … }`), usada pelo harness
  e pelo depurador, nunca pelo player.

### 2.4 ABI nativa: perfil "mycelium-v1" da API libretro

A trait é o lado Rust; o lado binário é a API libretro, que tem o mesmo formato:

| trait `Machine` | libretro |
|---|---|
| `MachineInfo::load` | `retro_init` + `retro_load_game` |
| `av_spec` | `retro_get_system_av_info` |
| `run_frame` | `retro_run` (+ callbacks de vídeo, áudio e entrada) |
| `reset` | `retro_reset` |
| `state_size` / `save_state` / `load_state` | `retro_serialize_size` / `retro_serialize` / `retro_unserialize` |
| `memory(SaveRam / MainRam)` | `retro_get_memory_data` / `_size` (`SAVE_RAM` / `SYSTEM_RAM`) |

O perfil v1 é o que o `machine-host` aceita:

- **Vídeo:** framebuffer por software em XRGB8888 ou RGB565
  (`SET_PIXEL_FORMAT`); o 0RGB1555 padrão do libretro é convertido pelo host.
- **Áudio:** `audio_sample_batch`, i16 estéreo.
- **Entrada:** joypad, analógico, teclado, mouse/ponteiro. O host responde
  `input_state` a partir do retrato do quadro, então até um núcleo que consulta
  várias vezes por quadro obedece à regra 1 do §2.2.
- **Environment aceitos:** `SET_PIXEL_FORMAT`, `GET_SYSTEM_DIRECTORY` e
  `GET_SAVE_DIRECTORY` (diretórios dentro da sandbox), `GET_LOG_INTERFACE`,
  `SET_INPUT_DESCRIPTORS`, `GET_VARIABLE`/`SET_VARIABLES` (opções do núcleo),
  `SET_MEMORY_MAPS`, `SET_SERIALIZATION_QUIRKS`, `GET_CAN_DUPE`. Todo o resto
  responde `false`, que núcleos libretro já tratam.
- **Recusados na v1:** `SET_HW_RENDER` (OpenGL/Vulkan: driver de GPU é
  superfície grande demais para entregar a código não confiável, e quebra a
  portabilidade), câmera, localização, sensores e rede.
- **Rust:** `mycelium_machine::export_libretro!(MeuNucleo)` gera os símbolos
  `retro_*` a partir da trait. O mesmo núcleo roda no Hub e no RetroArch: a
  portabilidade do conteúdo vem de graça.

Consequência estratégica: núcleos libretro existentes com renderização por
software viram máquinas instaláveis assim que o host existir. O limite passa a
ser a licença de cada núcleo (§7.6), não a ABI.

### 2.5 Runner, `machine-host` e IPC

- **Regra (D3):** `InProcess` só para núcleo compilado dentro do binário do Hub
  (primeira parte, nível Referência). Qualquer `.so`/`.dll`/`.dylib` baixado vai
  para `Sandboxed`.
- **`machine-host`** é um binário pequeno: `dlopen` do núcleo e o laço de
  quadros, nada mais. Sobe com a receita do `vacuum`
  (`crates/vacuum/src/process.rs:829`: `--die-with-parent`,
  `--unshare-pid/ipc/uts`, `--clearenv`, `--tmpfs /tmp`, binds só-leitura
  mínimos) com três mudanças: `--unshare-net` sempre; sem bind de `/bin`; binds
  apenas do `.so` do núcleo (ro), do conteúdo (ro), dos arquivos de sistema
  verificados (ro) e de um diretório de saves por (núcleo, conteúdo) (rw). Sem
  display, sem servidor de áudio, sem `$HOME`.
- **Canal:** mensagens com prefixo de tamanho no stdin/stdout do host —
  `Load`, `RunFrame{input}`, `SaveState`, `LoadState`, `Reset`, `Quit` ↔
  `FrameDone{w, h, n_amostras}`, `State{bytes}`, `Error`. Vídeo e áudio vão por
  um `memfd` mapeado dos dois lados (buffer duplo de quadro e anel de áudio). Um
  quadro 320×240 XRGB tem 300 KiB; a 60 Hz são 18 MiB/s de memória
  compartilhada, custo desprezível.
- **Limites:** `RLIMIT_AS` com a memória declarada no manifesto mais margem;
  watchdog de quadro (se `RunFrame` não volta em 10× o tempo do quadro, o player
  mata o host e oferece o último save); core dump desligado. Filtro seccomp com
  a lista de syscalls do laço de quadros fica para depois da etapa 2.
- **Falha do núcleo** derruba só o host; o Hub mostra o erro e preserva o último
  estado salvo.

### 2.6 Player, ritmo e saves

- **SDL3** (janela, áudio, gamepads com banco de mapeamentos) atrás da feature
  `player`. Builds sem cabeça — CI, harness, servidores — não dependem dele.
- **Ritmo** dirigido pelo áudio com controle dinâmico de taxa (reamostragem de
  ±0,5% para o buffer não estourar nem esvaziar) e apresentação no vsync. Quando
  a máquina e o monitor divergem muito (50 Hz PAL num monitor de 60 Hz), o player
  repete ou pula quadro.
- **SaveRam** vai para o disco ao sair e a cada poucos segundos. **Save state**
  é versionado por `(CID do núcleo, CID do conteúdo, state_version)`; o Hub
  recusa carregar estado em outro build de núcleo, salvo se o manifesto declarar
  o mesmo `state_version`.
- **Cópia de segurança** opcional da biblioteca (saves, licenças, chaves) num
  Root (`mycelium-root`, cofre K-de-N em pendrives).

### 2.7 Validação do contrato

O contrato do §2.2 e o teste de determinismo do §4.4 foram compilados e testados
num projeto descartável, fora do repo, com uma máquina de brinquedo. Resultado:
5/5 testes — a máquina correta passa; uma que esquece um campo no save state é
reprovada; uma que lê estado global entre instâncias é reprovada; padding de
linha e o byte X do XRGB não alteram o hash; a trait é *object-safe* e cabe num
registro de `MachineInfo`. O crate real nasce na etapa 1.

---

## 3. MYC-0, a primeira máquina

Proposta inicial; os números se ajustam na etapa 1 com medição.

| Item | Proposta | Por quê |
|---|---|---|
| CPU | RV32IM, 32 bits, sem MMU, sem ponto flutuante | ISA real e pequena; `clang --target=riscv32` e o alvo Rust `riscv32im-unknown-none-elf` já existem |
| Orçamento | 500 000 instruções por quadro, 60 quadros/s (~30 MIPS) | estimativa: cabe num interpretador simples num ARM de entrada (classe Raspberry Pi 4); é a limitação que dá identidade à máquina |
| Memória | 1 MiB de RAM; cartucho de até 16 MiB, só leitura; 64 KiB de SaveRam | |
| Vídeo | 320×180 (16:9), 8 bits indexados, paleta de 256 cores RGB888, interrupção de vblank | framebuffer simples: qualquer pessoa consegue escrever outro núcleo compatível |
| Som | 4 vozes (quadrada, triângulo, ruído, wavetable) + 1 canal PCM; saída 48 kHz estéreo | |
| Entrada | 4 controles, teclado, ponteiro | |
| Não tem | rede, relógio de parede, sistema de arquivos | determinismo por construção: tempo = contador de quadros; aleatoriedade = semente no estado |
| Cartucho | Plot com `cart.json`, `rom.bin` (ELF RV32 ou binário plano) e assets | |

Etapa 1 entrega templates C e Rust, o empacotador e o player. Um editor integrado
no estilo TIC-80 vem depois — de preferência como cartucho da própria MYC-0 (um
"BASIC em ROM"), o que mantém a máquina honesta.

---

## 4. SDK

### 4.1 Dois SDKs

- **SDK de máquina** (quem escreve simuladores): crate `mycelium-machine`
  (contrato, `export_libretro!`, harness), cabeçalho C = `libretro.h` mais a
  página do perfil mycelium-v1, templates Rust e C, e a CLI.
- **SDK de jogo** (por máquina): para a MYC-0, cabeçalho C, crate `no_std`,
  linker script e empacotador.

### 4.2 Pacote

JSON, como o resto dos manifestos do repo (`catalog.json`,
`payment-policy.json`):

```json
{
  "id": "<chave-do-publicador-hex>/gb-classic",
  "version": "0.3.1",
  "kind": "machine",
  "machine_type": "historical",
  "license": "MPL-2.0",
  "commercial_use": true,
  "abi": "libretro/mycelium-v1",
  "deterministic": true,
  "state_version": 2,
  "memory_mib": 64,
  "content_extensions": ["gb", "gbc"],
  "system_files": [{ "name": "dmg_boot.bin", "blake3": "…", "required": false }],
  "source": { "cid": "Qm…", "recipe": "cargo build --release --locked", "toolchain": "1.88.0" },
  "artifacts": [{ "target": "x86_64-unknown-linux-gnu", "chunks": "Qm…", "blake3": "…" }],
  "tests": { "matrix": "Qm…", "claimed_level": "funcional" }
}
```

Regras:

- `id` = `<chave do publicador>/<slug>`: o namespace é a chave. Acaba a colisão
  e o sequestro de ids globais (MH-13).
- Todo CID é derivado dos bytes.
- O manifesto não carrega assinatura: quem assina é o ref do canal (§5.2).
  Atestados (build reproduzido, relatório de testes) são objetos assinados à
  parte, que citam o CID do manifesto.
- **Só campos declarativos.** Não existe `extra_args`, caminho de executável nem
  opção de emulador externo. As classes MH-06 e MH-07 da auditoria somem por
  construção.
- Arquivos de sistema (BIOS) nunca são distribuídos: nome e BLAKE3 no manifesto,
  arquivo fornecido pelo usuário.

### 4.3 Fluxo de contribuição

```text
mycelium machine new --type historical gb-classic      # template
mycelium machine test                                  # harness local (§4.4)
mycelium machine publish --channel beta                # chunks + manifesto + ref assinado
mycelium machine attest <cid> --build | --tests        # terceiros reproduzem e assinam
mycelium machine install <publicador>/<slug>[@canal]
mycelium machine run <cartucho>
```

### 4.4 Harness de conformidade e níveis

| Verificação | Como |
|---|---|
| Carrega | `load` + 600 quadros sem pânico, crash ou estouro do watchdog |
| Determinismo | a mesma gravação de entrada roda duas vezes inteira e uma terceira salvando o estado na metade e carregando num núcleo **novo**; os três hashes (vídeo visível + áudio) têm de bater |
| Save state | coberto pela terceira corrida: um campo esquecido muda o hash |
| Ritmo | quadros/s declarado × medido no host de referência; amostras por quadro dentro de ±1% de `sample_rate/fps` |
| ROMs de teste | Tipo B: suítes públicas do hardware-alvo (ex.: Klaus Dormann para 6502, ZEXDOC/ZEXALL para Z80, blargg e mooneye para Game Boy), resultado conferido por hash de quadro |
| Matriz | lista de (conteúdo por CID, gravação de entrada, hash esperado nos quadros k) declarada no manifesto |

Os cinco níveis do plano passam a ter critério verificável:

| Nível | Critério | Quem atesta |
|---|---|---|
| Experimental | publicado; harness não rodou ou falhou | — |
| Inicializa | "Carrega" passa | o autor |
| Funcional | Carrega + Save state + Determinismo (se declarado) + ROMs de teste de CPU | o autor + 1 atestador independente |
| Compatível | Funcional + ≥ 90% da matriz declarada | ≥ 2 atestadores com chaves diferentes da do autor |
| Referência | Compatível + build reproduzido por ≥ 2 builders + revisão de código assinada por um mantenedor da lista de confiança | lista de confiança do Hub |

O Hub mostra o nível **atestado**, nunca o alegado. "Chave diferente" não impede
sock puppets; por isso Referência exige a lista de confiança, e tudo abaixo de
Referência só roda na sandbox.

Build reproduzível: toolchain fixado, `--locked`, `SOURCE_DATE_EPOCH`,
`--remap-path-prefix`. "Build verificado" = dois builders independentes chegam
ao mesmo BLAKE3 do artefato.

---

## 5. Integração com o Mycelium existente

### 5.1 Mapa

| Peça existente | Papel no Hub | Mudança necessária |
|---|---|---|
| `mycelium-core` `ContentId`/`NodeId` | identificadores | nenhuma; regra: CID sempre dos bytes |
| `giggs` `Plot` + `mycelium-sporebank` | manifestos, cartuchos pequenos (≤ 1 MiB), atestados | nenhuma |
| gossip `SporePrint` + DHT (`organism.rs:2148`) | replicação de tudo o que é público | nenhuma. Consequência: Plot público se replica sozinho, logo conteúdo pago sai cifrado (§6.5) |
| `mycelium-media` (chunks de 2 MiB + manifesto de chunks) e `mycelium-ipfs` `BlockStore` | binários de núcleo, imagens de disco, ROMs grandes | generalizar o manifesto de chunks de "vídeo" para "artefato" |
| `giggs` `SignedRefUpdate` / `RefStore` | canal (repositório = chave do publicador, nome = `<pacote>.<canal>`) → CID do manifesto, com CAS e sequência | **fixar o assinante** antes de aceitar ref vindo da rede (MH-14) |
| `mycelium-ghostid` (Schnorr secp256k1) | chave do publicador e do comprador (npub) | chave de publicador separada da do nó |
| `mycelium-nostr` (eventos, `encrypt_nip44`) | anúncio de pacotes e listagens em relays públicos; entrega da chave de conteúdo | tipos de evento do Hub |
| `mycelium-pkarr` + gateway `/myc/` | **onde** buscar (endpoints do nó do publicador) — localização, não identidade | nenhuma |
| `vacuum` (receita bwrap) | sandbox do `machine-host` | perfil "machine" (§2.5) |
| `singularity` Event Horizon | UI web do Hub como ion `machines` | origem própria, token, checagem de `Host`/`Origin` (MH-01/04/05) |
| `mycelium-store` | catálogo e regra BYOR | §5.3 |
| `mycelium-economy` | verificação de pagamento USDC/Base, política de recebimento, "uma tx, um settlement" | registrar venda como demanda paga (proposta: `JobType::Sale`) |
| `mycelium-media` `ProofOfDelivery` | recibo bilateral de entrega para o seeding | regra de elegibilidade do §6.6 |
| `mycelium-nutrients` | créditos não monetários (reputação, prioridade) | nenhuma; **nunca** liquida compra |
| `mycelium-bank` | — | fica fora até MH-12 ser corrigido |
| `mycelium-root` | backup portátil de saves, licenças e chaves | nenhuma (crate em evolução) |

### 5.2 Publicar e descobrir

```text
PUBLICADOR
 1. pack: artefatos → chunks de 2 MiB → manifesto (Plot) → CID_m
 2. ref assinado:  <pub>.<pacote>.stable = CID_m   (seq n+1, previous = CID anterior)
 3. evento Nostr { ref assinado, CID_m }  ──▶  relays públicos
    Plots e chunks públicos se espalham por gossip/DHT

HUB DE QUEM INSTALA
 4. segue o feed dos publicadores escolhidos (relays Nostr)
 5. valida o ref: assinante = chave fixada do publicador; seq maior que a local
 6. baixa manifesto e chunks por CID; confere BLAKE3 de cada chunk
 7. mostra o nível ATESTADO e instala
```

`RefStore` só aceita componentes `[A-Za-z0-9-_.]` (`crates/giggs/src/lib.rs:72`),
por isso o canal usa ponto como separador: repositório = chave do publicador em
hex, nome = `<pacote>.<canal>`.

### 5.3 O que muda no `mycelium-store`

- **Fica:** `StoreCatalog` (escrita atômica, `validate()` fail-closed),
  `SporeLicense` e `list_public_spores` (BYOR).
- **Entra:** motor `ExecutionEngineType::Machine`, executado pelo runner do §2.5
  a partir de um `PackageRef { manifest: ContentId }`. Nenhum caminho de
  executável e nenhum argumento vem do manifesto.
- **Sai do caminho padrão:** `QEMU`, `RetroArchLibretro`, `MAME` e `Native`;
  `StoreLaunch` deixa de transformar motor desconhecido em `Native`
  (`organism.rs:3850`). Quem quiser os lançadores legados os encontra atrás da
  feature `legacy-launchers`, desligada, já com as correções da auditoria.
- Ids passam a `<chave>/<slug>`. O seed atual migra com CIDs reais ou sai.

---

## 6. Modelo econômico

### 6.1 Regras

1. Nada conta como pago sem prova de liquidação que um terceiro possa
   reverificar. É a invariante do `mycelium-economy` (simulado, interno e
   recompensa nunca aumentam a demanda paga — `lib.rs:3`), estendida às vendas.
2. Nutrients não são dinheiro: são IOUs autoassinados num ledger local (§1).
   Servem para reputação e prioridade.
3. Quem verifica uma licença usa a chave do vendedor tirada do **anúncio
   assinado**, que veio do canal fixado — nunca a chave que a própria licença
   traz.
4. Divisão de receita só com termos co-assinados por todos os beneficiários
   antes da venda.
5. A compra não reduz direitos da licença do código: GPL continua GPL.

### 6.2 Objetos

```text
Listing    assina: vendedor     produto (CID do manifesto) · preço · trilhos aceitos
                                · split (CID) · termos (CID) · seeding_bps
Split      assinam: todos       [(npub, endereço de recebimento, bps)] — soma 10 000
Order      assina: comprador    listing · npub do comprador · nonce · trilho
Intent     gera: vendedor       USDC: valor exato ÚNICO + bloco-âncora + destino
                                LN:   invoice com description_hash = H(Order)
Settlement verifica: qualquer   USDC: releitura da tx no provedor fixado, N confirmações
                                LN:   sha256(preimagem) = payment_hash
License    assina: vendedor     produto · npub do comprador · order · ref do settlement
                                · emitida_em [· válida_até, só em assinatura]
```

### 6.3 Compra

```text
comprador                   vendedor (nó próprio ou delegado)          cadeia / LN
  │ Order ─────────────────────▶│ cria Intent: preço + discriminador
  │◀──────────────────── Intent │ (0–999 µUSDC, único entre pedidos abertos)
  │ paga ───────────────────────┼───────────────────────────────────────────▶│
  │ tx_hash ou preimagem ──────▶│ verifica (economy::BaseUsdcVerifier ou preimagem)
  │                             │ marca a tx como usada (uma tx, um settlement)
  │◀── License + chave (NIP-44) │
  │ Hub verifica a License com a chave do Listing → decifra → instala
```

Por que valor único: dois pedidos abertos com o mesmo preço aceitariam a mesma
transferência. Com o discriminador nos últimos micro-USDC, quem vê a tx da
vítima na cadeia não consegue usá-la no próprio pedido (o valor não bate), e o
bloco-âncora barra transferências antigas. O economy já trabalha com valor exato
e âncora (`PaymentIntent.exact_amount_raw`, `anchor_block`) e recusa prova
reaproveitada (`lib.rs:831`).

Finalidade: a Base é um rollup; confirmação de L2 é branda. Para valor baixo,
`min_confirmations` da política; para valor alto, esperar o bloco `finalized`. Se
um reorg apagar a tx, o módulo `revalidation` do economy marca
`needs_revalidation` e a licença entra na lista de revogação.

### 6.4 Trilhos

| Trilho | Estado no repo | Prova | Custo para o vendedor |
|---|---|---|---|
| USDC na Base | verificador read-only pronto (`base_usdc.rs`), provedor fixado | releitura da tx: status, bloco canônico, log `Transfer` exato para o destino | um endereço de recebimento e um provedor RPC fixado |
| Lightning | só parse de invoice (`mycelium-zkp`) | preimagem; invoice assinado pelo nó LN do vendedor, ligado à chave do publicador por declaração assinada | nó LN ou LSP próprio — etapa 4b |
| Nutrients | ledger local | nenhuma (IOU) | não é trilho de pagamento |

### 6.5 Conteúdo pago

- **Cifrar e depois publicar:** o artefato é cifrado com chave aleatória
  (XChaCha20-Poly1305, já usado em `mycelium-pkarr` e `mycelium-root`); o CID é
  do texto cifrado; seeders replicam sem acesso.
- **Entrega da chave:** pelo vendedor, ou por nós que ele delegou com
  certificado assinado, só depois do settlement, embrulhada para o npub do
  comprador com NIP-44 (`encrypt_nip44` em `mycelium-nostr`).
- **Limite honesto:** quem comprou pode vazar a chave. Não existe DRM que
  resista ao dono da máquina, e núcleo GPL não pode ser restringido. O que a
  licença garante é prova de compra (atualizações, suporte, reputação).
- **Vendedor offline:** a compra espera até algum nó delegado responder. É o
  custo de não ter servidor central; a loja mostra "entrega em até X".

### 6.6 Divisão de receita e seeding

- **v1:** o destino do pagamento é o vendedor; o `Split` co-assinado é público;
  os repasses são transferências na mesma cadeia, conferíveis pelo mesmo
  verificador. Qualquer um audita "recebeu X, repassou Y".
- **v2:** destino = contrato divisor imutável (código fixado por hash); o
  verificador confere a transferência para o divisor. Acaba a confiança no
  vendedor.
- **Seeding:** o Listing declara `seeding_bps` (ex.: 300 = 3%). Conta só o
  `ProofOfDelivery` (`crates/mycelium-media/src/receipt.rs`) assinado pelo
  seeder **e** pelo comprador cuja licença cobre aquele produto, com teto =
  tamanho do artefato por licença. O pote de cada venda é dividido pelos bytes
  entregues àquele comprador. Quem forja recibos entre as próprias chaves
  recupera no máximo a fatia de seeding da própria compra e perde o resto do
  preço. Nada é cunhado.
- **Taxa de plataforma:** nenhuma no protocolo. Um "fundo de manutenção" é só
  mais uma linha do Split, se as partes aceitarem.

### 6.7 Reembolso e revogação

Não há estorno na cadeia. Reembolso = transferência do vendedor + entrada numa
lista de revogação assinada por ele (publicada como evento). Licença de compra
não expira; a revogação só é consultada quando há rede, e jogar offline
continua. Assinatura (premium) usa `válida_até`.

Vender por USDC ou BTC tem consequências fiscais e regulatórias que variam por
país. Este desenho não é parecer jurídico.

---

## 7. Decisões de compatibilidade

### 7.1 Plataformas

| Nível | Plataformas | O que roda |
|---|---|---|
| Tier 1 | Linux x86_64 e aarch64 | tudo; núcleo baixado roda na sandbox bwrap |
| Tier 2 | Windows x86_64, macOS aarch64 | só núcleo Referência, até existir sandbox nativa (AppContainer, App Sandbox) |
| Tier 3 | Android, RISC-V, ARMv7 | portabilidade de conteúdo; núcleo se alguém mantiver o build |

Fail-closed: sem sandbox, núcleo abaixo de Referência não roda — a mesma postura
do `vacuum` (`crates/vacuum/src/lib.rs:5`). Risco aceito e declarado: no Tier 2,
um núcleo Referência roda sem isolamento, e uma ROM maliciosa que explore um bug
dele alcança o usuário.

### 7.2 Artefatos por alvo

O manifesto lista um artefato por alvo (`x86_64-unknown-linux-gnu`,
`aarch64-apple-darwin`, …). Conteúdo (cartucho, ROM) nunca depende do alvo.
Fonte e receita permitem que qualquer pessoa gere o alvo que falta e o ateste
(§4.4).

### 7.3 Desempenho medido, não adivinhado

Cada núcleo traz um cartucho de benchmark. Na instalação o Hub roda 5 s e
mostra "tempo real neste computador: sim / no limite / não". Requisito mínimo
vira medida.

### 7.4 Vídeo

v1 é framebuffer por software. Núcleos 3D com renderizador por software
funcionam, mais lentos. Render por GPU volta na v2, só para Referência.

### 7.5 Saves

SaveRam é portável entre núcleos da mesma máquina: é a memória do cartucho.
Save state só vale para o mesmo núcleo, o mesmo conteúdo e o mesmo
`state_version`.

### 7.6 Licenças

| Núcleo (exemplos) | Licença | Anúncio pago? |
|---|---|---|
| mGBA | MPL-2.0 | sim, com o fonte |
| Mesen | GPL-3.0 | sim, com o fonte; o comprador pode redistribuir |
| Gambatte, DOSBox Pure | GPL-2.0 | idem |
| snes9x, Genesis Plus GX, PicoDrive, FinalBurn Neo | não comercial | **não** — só gratuito |

Conferir a licença do commit exato antes de empacotar: licenças mudam.

- O manifesto traz `license` (SPDX) e `commercial_use`; o market recusa anúncio
  com preço > 0 quando `commercial_use` é falso.
- O desenho original do Hub partia da AGPL-3.0. A licença atual do repositório
  está no [arquivo LICENSE](../../LICENSE). No desenho original, um núcleo
  GPL-2.0-only no mesmo processo que código AGPL-3.0
  forma obra combinada incompatível. Por isso D13: contrato e host sob
  MIT OR Apache-2.0, e o Hub AGPL conversa com o host por IPC, como programas
  separados. Não é parecer jurídico.
- BIOS, firmware e ROMs comerciais nunca são distribuídos (regra BYOR que já
  existe). O manifesto declara nome e BLAKE3; o usuário fornece; o Hub confere.

### 7.7 Lançadores legados

QEMU virtualiza um PC inteiro, o que o plano exclui. RetroArch e MAME externos
são substituídos pelo host próprio. Os spores MS-DOS de hoje (shareware via
QEMU, `catalog.rs:181`) passam a precisar de uma máquina "PC/DOS" via núcleo —
DOSBox Pure, GPL-2.0, é o candidato — que é exatamente o caso de uso do Tipo B.

---

## 8. Etapas revisadas

| Etapa | Entrega mínima | Pronto quando |
|---|---|---|
| 1 | `mycelium-machine` (contrato + harness), núcleo MYC-0 in-process, player SDL3, `mycelium machine run/pack`, templates C e Rust | um cartucho em C e um em Rust rodam em duas máquinas diferentes e passam no teste de determinismo |
| 2 | `mycelium-machine-host` + sandbox, chunks de artefato, canal por `SignedRefUpdate` com assinante fixado, anúncio Nostr, `install`; correções MH-01 a MH-08, MH-13 e MH-14 | o publicador A publica; B, noutra máquina e noutra rede, descobre, instala e roda sem servidor |
| 3 | primeira máquina histórica via núcleo libretro de licença compatível (ex.: Game Boy via mGBA ou Gambatte) com suíte de ROMs de teste na matriz | nível Funcional atestado por um terceiro |
| 4a | `mycelium-market`: Listing, Split, Order, License; trilho USDC/Base; conteúdo cifrado + NIP-44; correção MH-09 | venda ponta a ponta contra o RPC de teste do economy (`rpc_test_server.rs`) e depois com valor mínimo na Base: nenhuma licença antes de N confirmações, tx reaproveitada recusada |
| 4b | trilho Lightning (preimagem); seeding por recibos | |
| 5 | render por GPU (Referência), sandbox Windows/macOS, editor integrado, divisor on-chain | |

**Fora, de propósito:** WASM, GPU na v1, DRM, token ou blockchain próprios,
nutrients como pagamento, loja central, sandbox Windows/macOS na v1, editor na
v1.
