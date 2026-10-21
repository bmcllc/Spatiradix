# Root — uma nuvem sem servidor e sem rede P2P

Data: 2026-10-21. Crate: [`crates/mycelium-root`](../../crates/mycelium-root).
CLI: `mycelium root …`.

## 0. A pergunta, levada a sério

> Onde os bytes podem morar se não for num servidor nem numa rede de pares?

Bytes precisam de um meio físico. Quem não aluga o meio (servidor) nem empresta
o meio de outros (P2P) só tem uma saída: **os meios que você já possui**,
espalhados pelo seu dia. Pendrive no chaveiro, cartão SD na carteira, o celular,
um HD velho na gaveta, uma pasta no notebook do trabalho.

Aqui a nuvem perde o servidor, mas mantém o que ela tem de bom:

| O que a nuvem dá | Como o Root dá, sem servidor e sem rede |
|---|---|
| Não perder dados se um disco morrer | dados cortados em **N pedaços com paridade** (Reed-Solomon); quaisquer **K** reconstroem |
| Ninguém lê se roubarem um disco | cada pedaço é **cifrado**; a chave também é cortada (Shamir **K de N**). Com menos de K raízes, não sobra nada legível, nem a chave |
| Sincronizar vários aparelhos | **sincronização por contato**: quando duas raízes se encontram no mesmo computador, trocam o que falta. Os dados viajam com você, como esporos |
| Histórico, desfazer | log só de acréscimo; nenhuma escrita apaga a anterior |
| Abrir como uma pasta | `mycelium root mount`: aparece como um **pendrive** (FUSE) em qualquer Linux |

Cada meio é uma **raiz**. O conjunto é o **Root**. Nenhuma raiz sozinha é a
nuvem; **qualquer K delas são**.

## 1. Por que não é servidor nem P2P

- Nenhum processo fica ligado esperando conexões. O Root só existe enquanto
  você monta.
- Nenhuma raiz conversa com outra pela rede. A sincronização acontece quando
  duas raízes estão **plugadas no mesmo computador**. É um "rizoma físico".
- O computador onde você pluga é só uma lente: monta, lê e escreve, e não
  guarda nada depois que desmonta.

## 2. Mecânica

```
arquivo ──► pedaços de 1 MiB ──► id = BLAKE3-keyed(mac_key, bytes)
         ──► XChaCha20-Poly1305 (chave e nonce derivados do id)
         ──► Reed-Solomon K+M ──► fragmento i vai para a raiz i
```

- **Chave do cofre**: 32 bytes aleatórios. HKDF deriva as chaves de pedaço, de
  MAC e de log. A chave nunca é gravada inteira em lugar nenhum: cada raiz guarda
  só a sua parte Shamir (crate `entropy`, GF(256)).
- **Raiz ausente na hora da escrita**: o fragmento dela vai para `carry/<i>/` em
  todas as raízes presentes e é entregue quando ela aparecer. É o
  store-and-forward (DTN) do Mycelium, só que por contato físico em vez de
  rede.
- **Metadados**: um log cifrado de operações (`put`, `mkdir`, `rm`) com relógio
  de Lamport. Cada raiz presente recebe o log **inteiro** (é pequeno); sem K
  partes da chave ele é ilegível.
- **Edições concorrentes** (dois computadores, cada um com raízes diferentes):
  nenhuma se perde. A segunda vira `nome (conflito <aparelho>).ext`.
- **Integridade**: cada pedaço é autenticado (AEAD) e o id é um MAC do
  conteúdo. Fragmento corrompido é tratado como ausente e reconstruído a partir
  da paridade.

## 3. Uso

```bash
# cria um Root 2-de-3 em três meios (pendrive, cartão SD, pasta no HD)
mycelium root init --k 2 /media/pendrive /media/sd ~/raiz-casa

# com quaisquer 2 deles plugados:
mycelium root put  /media/pendrive /media/sd -- foto.jpg docs/
mycelium root ls   /media/pendrive /media/sd
mycelium root get  /media/pendrive /media/sd -- foto.jpg ./foto.jpg
mycelium root rm   /media/pendrive /media/sd -- foto.jpg          # o histórico guarda
mycelium root mount /media/pendrive /media/sd -- ~/Root     # vira um "pendrive"

# encontrou a terceira raiz? sincroniza por contato:
mycelium root sync /media/pendrive ~/raiz-casa

# perdeu um meio? recria a raiz dele num meio novo:
mycelium root heal /media/pendrive /media/sd --replace 3 --into /media/novo
```

`mycelium root scan` procura raízes em `/media`, `/run/media` e `/mnt`, então
`--auto` dispensa digitar os caminhos.

## 4. Evidência (2026-10-21)

- `cargo test -p mycelium-root` → 11/11. Os 7 testes de aceitação são as
  promessas deste documento: quaisquer K abrem; menos de K não abrem e nenhuma
  raiz tem nome ou conteúdo em claro; raiz ausente recebe por contato; edição
  concorrente em raízes disjuntas vira cópia de conflito; raiz perdida
  recriada; fragmento corrompido coberto pela paridade (e erro, nunca dado
  errado, quando não há paridade); log forjado ignorado; parte Shamir
  adulterada impede abrir.
- `bash scripts/prova-root.sh` → PASSOU, com FUSE real: montado como pasta,
  `cp`/`mv`/`>>`/`mkdir`/`rm` pelo sistema de arquivos e mudanças vistas
  depois por outro par de raízes.
- Custo medido: 2,9 MB de dados → 1,5 MB em cada raiz (2-de-3: total 1,5×,
  contra 3× de três cópias inteiras).
- `entropy::Vault::shade_at` (Lagrange em x qualquer) recalcula a parte Shamir
  da raiz perdida sem reconstruir a chave em disco.

## 5. Limites (ditos)

- **Não há acesso de qualquer lugar.** Você só acessa onde tiver K raízes à
  mão. É a troca entre soberania e onipresença. Receita prática: K=2 com o
  celular e o chaveiro sempre com você, e N=3 ou 4 com raízes paradas em casa
  e no trabalho.
- **Perder N−K+1 raízes ao mesmo tempo perde o Root.** Espalhe por lugares.
- **Nenhuma senha nesta versão.** Quem juntar K raízes lê tudo. Uma senha
  opcional (fator extra sobre a parte Shamir) é o próximo passo.
- **Metadados de tamanho**: quem examinar uma raiz vê quantos fragmentos existem
  e o tamanho deles, não o conteúdo nem os nomes.
- O `mount` usa FUSE: no Linux funciona hoje. macOS e Windows precisam de
  macFUSE/WinFsp ou de uma ponte WebDAV (trabalho futuro).
- Pedaços de arquivos apagados continuam nas raízes (histórico) até um
  `root gc`, que ainda não existe.
