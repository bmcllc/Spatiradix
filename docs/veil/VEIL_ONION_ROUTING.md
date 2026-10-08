# 🧅 VEIL Ω — Rede de Roteamento Cebola Pós-Quântica

> **Crate**: [`mycelium-veil`](file:///media/bruno/SAMBOOK/Mycelium%20Network/crates/mycelium-veil)  
> **Camada**: L2 — Privacidade e Anonimato Quântico-Resistente  
> **Status**: Ativo em testes locais (nível a) — homologação WAN **pendente**  
> **Homologação WAN**: ver [`VEIL_P12_WAN_FIELD_VALIDATION.md`](VEIL_P12_WAN_FIELD_VALIDATION.md) — é um roteiro de execução, não um certificado de segurança nem um resultado de campo. Estado consolidado em [`docs/VALIDACAO.md`](../VALIDACAO.md).

---

## 1. O que é o VEIL Ω?

O **VEIL Ω** é a rede de anonimato e roteamento cebola (*onion routing*) nativa do Mycelium Network. Ele foi projetado para superar as vulnerabilidades fundamentais das redes tradicionais como Tor e I2P perante a computação pós-quântica e as técnicas modernas de inspeção profunda de pacotes (DPI):

1. **Criptografia Pós-Quântica Híbrida**: Toda camada do túnel cebola utiliza **ML-KEM-768** (FIPS 203 Kyber) combinado com **X25519** e **ChaCha20-Poly1305**. Mesmo que um computador quântico grave o tráfego hoje (*Harvest Now, Decrypt Later*), o tráfego não poderá ser quebrado no futuro.
2. **Arquitetura de 3 Saltos Estrita**: O circuito é segmentado em **Guard (Entrada)**, **Relay (Meio)** e **Exit (Saída)**, garantindo que nenhum nó conheça simultaneamente a origem e o destino do pacote.
3. **Resistência à Censura via Bridges Dinâmicas**: Em ambientes com bloqueio hostil de IP (ex.: censura estatal ou firewalls corporativos), o cliente utiliza pontes (*Bridges*) que mascaram o handshake de transporte.
4. **Isolamento Anti-SSRF Estrito**: O nó Exit possui proteções de rede para impedir que requisições cebola acessem redes locais privadas (RFC 1918), interfaces loopback ou metadados de nuvem (`169.254.169.254`).
5. **Kill-Switch de Emergência**: Se o circuito cebola cair, o tráfego é interrompido no ato, impedindo vazamentos de IP real (*IP leaks*).

---

## 2. Diagrama do Circuito Cebola VEIL Ω

```text
 ┌─────────────┐
 │ CLIENTE     │
 │ SOCKS5      │
 │ :1080       │
 └──────┬──────┘
        │
        │ [Payload cifrado 3x: ML-KEM-768 + ChaCha20-Poly1305]
        ▼
 ┌─────────────┐
 │ GUARD /     │  Descasca Camada 1
 │ BRIDGE      │  Conhece: Origem (Cliente) e Próximo (Relay)
 └──────┬──────┘  NÃO Conhece: Payload nem Destino Final
        │
        │ [Payload cifrado 2x]
        ▼
 ┌─────────────┐
 │ RELAY       │  Descasca Camada 2
 │ (Meio)      │  Conhece: Guard e Exit
 └──────┬──────┘  NÃO Conhece: Origem nem Destino Final
        │
        │ [Payload cifrado 1x]
        ▼
 ┌─────────────┐
 │ EXIT        │  Descasca Camada 3 (Payload Plano)
 │ (Saída)     │  Conhece: Relay e Destino WAN (IP/Web)
 └──────┬──────┘  NÃO Conhece: Origem do Cliente!
        │
        ▼ (Inspeção Anti-SSRF)
   Internet / WAN / Destino Soberano
```

---

## 3. Especificação Criptográfica do Circuito

### 3.1. Encasulamento Híbrido (KEM + ECDH)
Para cada salto $i \in \{1, 2, 3\}$, o cliente gera:
- Um par de chaves efêmeras X25519: $(sk_{\text{ec}}, pk_{\text{ec}})$
- Um encapsulamento **ML-KEM-768**: $(ss_{\text{pqc}}, ct_{\text{pqc}}) = \text{ML-KEM.Encaps}(pk_{\text{target\_pqc}})$
- Uma chave compartilhada clássica: $ss_{\text{ec}} = \text{X25519}(sk_{\text{ec}}, pk_{\text{target\_ec}})$

A chave simétrica da camada do nó $i$ é derivada via **BLAKE3 KDF**:
$$K_i = \text{BLAKE3-DeriveKey}("veil:onion-layer:v1",\ ss_{\text{pqc}} \parallel ss_{\text{ec}} \parallel \text{salt})$$

### 3.2. Cifragem de Camadas
O cliente encapsula o payload de dados sequencialmente de trás para frente:
$$\text{Cifra}_3 = \text{ChaCha20-Poly1305}(K_3, \text{Payload})$$
$$\text{Cifra}_2 = \text{ChaCha20-Poly1305}(K_2, \text{Cifra}_3 \parallel \text{HopInfo}_3)$$
$$\text{Cifra}_1 = \text{ChaCha20-Poly1305}(K_1, \text{Cifra}_2 \parallel \text{HopInfo}_2)$$

Cada nó intermediário apenas remove sua respectiva camada com sua chave privada, lê o próximo endereço e repassa adiante.

---

## 4. Modos de Operação do VEIL

O VEIL Ω pode ser configurado em três perfis operacionais:

1. **`veil` (Padrão de Máxima Privacidade)**:
   - Circuito completo de 3 saltos (`Guard -> Relay -> Exit`).
   - Latência moderada (~150-300ms), garantia matemática contra nós espiões isolados.
2. **`geo` (Otimizado para Desempenho / 1 Salto)**:
   - Conexão direta com um nó Exit em geografia específica.
   - Ideal para contornar geobloqueios com alta vazão (streaming e downloads pesados).
3. **`mix` (Mixnet de Alta Latência com Jitter)**:
   - Insere atrasos artificiais aleatórios e reordenação de pacotes.
   - Imune a ataques de correlação estatística de tráfego por agências de inteligência com visão global da rede.

---

## 5. Interface SOCKS5 & Comandos CLI

O VEIL expõe um proxy SOCKS5 local padrão em `127.0.0.1:1080`. Qualquer aplicativo (navegador Firefox, curl, Telegram, carteiras Bitcoin) pode ser conectado ao VEIL imediatamente.

### Comandos de Controle do VEIL:

```bash
# Inicia o serviço VEIL no nó local
mycelium veil start --mode veil --socks5-port 1080

# Inicia com pontes (bridges) para furar firewalls agressivos
mycelium veil start --mode veil --bridge 198.51.100.22:9001 --bridge 203.0.113.88:9001

# Consulta o status da sessão e métricas de bytes roteados
mycelium veil status

# Exibe o descritor criptográfico assinado deste nó
mycelium veil descriptor

# Rotaciona a identidade criptográfica efêmera (nova identidade anônima)
mycelium veil start --rotate-identity

# Encerra o serviço VEIL e fecha a porta SOCKS5
mycelium veil stop
```

---

## 6. Blindagem Anti-SSRF (Server-Side Request Forgery)

O nó de egresso (`Exit`) do VEIL implementa uma barreira inegociável de segurança contra abusos da rede interna do operador:

- **Bloqueio de Loopback**: `127.0.0.0/8`, `::1`
- **Bloqueio de Subredes Privadas**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`
- **Bloqueio de Link-Local e Metadados**: `169.254.0.0/16`, `fe80::/10`
- **Bloqueio de Broadcast / Multicast**: `224.0.0.0/4`, `ff00::/8`

Tentativas de explorar o túnel para atingir serviços internos do host são descartadas antes da abertura do socket TCP de saída.
