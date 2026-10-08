# 🧅 `mycelium-veil` — Protocolo VEIL Ω

Infraestrutura P2P pós-quântica de privacidade soberana, anonimato e roteamento cebola (*onion routing*) sobre a malha Mycelium Network.

---

## 🎯 Visão Geral

O `mycelium-veil` implementa a especificação completa do **VEIL Ω**, projetado para prover comunicação anônima, resistente a grampos globais de agências de inteligência e imune a ataques de computação quântica (Store-Now, Decrypt-Later).

### Principais Pilares:
1. **Roteamento Cebola Pós-Quântico (ML-KEM-1024 + ChaCha20-Poly1305)**:
   - Circuitos multi-salto (1 a 3 nós intermediários: *Entry Guard*, *Relay*, *Exit*).
   - Encapsulamento em camadas criptográficas independentes derivadas via FIPS 203 (ML-KEM-1024) e ratchets de chave simétrica.
2. **Plano Dual de Tráfego**:
   - **Plano LIVE**: Baixa latência para navegação HTTP/SOCKS5 e streaming interativo.
   - **Plano MIX**: Mixnet estocástica baseada em distribuição de Poisson com atrasos calculados e pacotes de cobertura (*chaff traffic*) para derrotar análise de correlação temporal.
3. **As 7 Camadas Herdadas e Corrigidas do ET-COSMIC-OLD (GhostVPN)**:
   - **L0: Identidade Efêmera** (`GhostID` descartável + spoofing de MAC local administrado).
   - **L1: Fragmentação Segura** (QEL sem vazar chaves de sessão).
   - **L2: Transporte Fantasma** (`DistanceBridge` multi-canal com failover automático).
   - **L3: Consenso Causal e Anti-Replay** (`HashChronicle` + Cone de Luz relativístico).
   - **L4: Execução Invisível** (Sandbox isolada COSMIC/ANIMUS).
   - **L5: Ofuscação Temporal** (Padding estocástico + Quantized Rate Control).
   - **L6: Zero-Trace em RAM & ZKP** (Compromissos de Pedersen H independentes e limpeza de buffers via `vacuum`).
4. **Proxy Local SOCKS5 (RFC 1928)**:
   - Suporte completo a comandos `CONNECT` e resolução DNS interna (*Anti-DNS Leak*).
5. **Nó de Saída e Anti-SSRF**:
   - Bloqueio rígido de endereços privados (RFC 1918), loopback, CGNAT e metadados de nuvem (169.254.169.254).
6. **Kill-Switch Fail-Closed**:
   - Bloqueio instantâneo de pacotes não encapsulados na queda de um circuito.

---

## 🏗️ Arquitetura dos Módulos

- [`src/crypto/`](file:///media/bruno/SAMBOOK/Mycelium%20Network/crates/mycelium-veil/src/crypto): Criptografia híbrida, derivação KDF (HKDF-SHA256 / BLAKE3), encapsulamento de camadas cebola.
- [`src/planes/`](file:///media/bruno/SAMBOOK/Mycelium%20Network/crates/mycelium-veil/src/planes): Roteamento LIVE e MIX estocástico.
- [`src/socks5/`](file:///media/bruno/SAMBOOK/Mycelium%20Network/crates/mycelium-veil/src/socks5): Servidor SOCKS5 local, handshake RFC 1928, canalização de túneis.
- [`src/exit/`](file:///media/bruno/SAMBOOK/Mycelium%20Network/crates/mycelium-veil/src/exit): Exit Node com validador Anti-SSRF e política de saída.
- [`src/layers/`](file:///media/bruno/SAMBOOK/Mycelium%20Network/crates/mycelium-veil/src/layers): As 7 camadas de ofuscação e defesa em profundidade.
- [`src/tunnel/`](file:///media/bruno/SAMBOOK/Mycelium%20Network/crates/mycelium-veil/src/tunnel): Abstração de interface virtual (TUN/TAP) e controle de rotas.
- [`src/identity.rs`](file:///media/bruno/SAMBOOK/Mycelium%20Network/crates/mycelium-veil/src/identity.rs): Gestão de credenciais efêmeras do nó no circuito.
- [`src/bridge.rs`](file:///media/bruno/SAMBOOK/Mycelium%20Network/crates/mycelium-veil/src/bridge.rs): Integração com o barramento `mycelium-core` e `libp2p`.

---

## 🚀 Exemplo de Uso

```rust
use mycelium_veil::config::VeilConfig;
use mycelium_veil::bridge::VeilBridge;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = VeilConfig::default();
    let bridge = VeilBridge::spawn(config).await?;

    // Inicia proxy SOCKS5 local na porta 9050
    let listener = bridge.listen_socks5("127.0.0.1:9050").await?;
    println!("Veil SOCKS5 proxy escutando em 127.0.0.1:9050");

    Ok(())
}
```
