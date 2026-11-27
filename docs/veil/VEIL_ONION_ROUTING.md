# VEIL Ω: roteamento cebola pós-quântico

> **Crate**: [`mycelium-veil`](../../crates/mycelium-veil)
> **Camada**: L2 — Privacidade e Anonimato Quântico-Resistente  
> **Status**: Ativo em testes locais (nível a) — homologação WAN **pendente**  
> **Homologação WAN**: ver [`VEIL_P12_WAN_FIELD_VALIDATION.md`](VEIL_P12_WAN_FIELD_VALIDATION.md) — é um roteiro de execução, não um certificado de segurança nem um resultado de campo. Estado consolidado em [`docs/VALIDACAO.md`](../VALIDACAO.md).

---

## 1. O que é o VEIL Ω?

O **VEIL Ω** é o componente de roteamento cebola (*onion routing*) do
Mycelium Network. Ele usa criptografia pós-quântica e oferece opções de
transporte voltadas à privacidade. Os testes locais não demonstram anonimato
em todas as condições; veja o [modelo de ameaças](THREAT_MODEL.md).

1. **Criptografia por salto**: o código usa **ML-KEM-1024** e
   **ChaCha20-Poly1305**. A segurança futura depende dos algoritmos, da
   implementação e das chaves; ela não é uma garantia absoluta.
2. **Circuito de três saltos**: o modo `veil` usa Guard, Relay e Exit para
   separar as informações disponíveis a cada nó.
3. **Pontes**: o cliente pode usar bridges para alcançar um Guard quando o
   acesso direto estiver indisponível. Sua eficácia depende da rede.
4. **Filtro Anti-SSRF**: o Exit aplica restrições a destinos internos e de
   metadados. A política deve ser testada no ambiente de uso.
5. **Kill switch**: o fluxo VEIL pode falhar fechado quando o circuito cai.
   Isso não substitui um firewall para tráfego fora do proxy.

---

## 2. Diagrama do Circuito Cebola VEIL Ω

```text
 ┌─────────────┐
 │ CLIENTE     │
 │ SOCKS5      │
 │ :1080       │
 └──────┬──────┘
        │
        │ [Payload protegido em três camadas]
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

### 3.1. Chaves por salto

O cliente encapsula um segredo para a chave pública **ML-KEM-1024** do salto.
O módulo `crypto` usa esse segredo e um salt para derivar chaves distintas de
ida e volta com BLAKE3. Os detalhes estão em
[`crates/mycelium-veil/src/crypto/mod.rs`](../../crates/mycelium-veil/src/crypto/mod.rs).

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
   - A latência depende das rotas e dos nós. O desenho limita o conhecimento de cada salto, mas não garante anonimato contra todos os observadores.
2. **`geo` (Otimizado para Desempenho / 1 Salto)**:
   - Conexão direta com um nó Exit em geografia específica.
   - Ideal para contornar geobloqueios com alta vazão (streaming e downloads pesados).
3. **`mix` (Mixnet de Alta Latência com Jitter)**:
   - Insere atrasos artificiais aleatórios e reordenação de pacotes.
   - Busca dificultar a correlação de tráfego; não há garantia de imunidade a um observador global.

---

## 5. Interface SOCKS5 & Comandos CLI

O VEIL expõe um proxy SOCKS5 local padrão em `127.0.0.1:1080`. Aplicativos
precisam ser configurados para usá-lo; tráfego fora do proxy não está coberto.

### Comandos de Controle do VEIL:

```bash
# Inicia o serviço VEIL no nó local
mycelium veil start --mode veil --port 1080

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

## 6. Filtros Anti-SSRF (Server-Side Request Forgery)

O nó de egresso (`Exit`) aplica filtros para limitar o acesso a endereços
internos. Eles devem ser verificados na configuração usada pelo operador:

- **Bloqueio de Loopback**: `127.0.0.0/8`, `::1`
- **Bloqueio de Subredes Privadas**: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`
- **Bloqueio de Link-Local e Metadados**: `169.254.0.0/16`, `fe80::/10`
- **Bloqueio de Broadcast / Multicast**: `224.0.0.0/4`, `ff00::/8`

Tentativas de explorar o túnel para atingir serviços internos do host são descartadas antes da abertura do socket TCP de saída.
