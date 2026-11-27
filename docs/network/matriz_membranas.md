# Matriz de membranas — direct | circuit | mailbox

Esta tabela reúne observações e hipóteses para conexões entre nós. Atualize-a
após cada experimento com um esporocarpo voluntário; as linhas sem evidência
registrada não são resultados de teste.

| Par | Direct | Circuit (esporocarpo) | Mailbox DTN | Evidência |
|-----|--------|----------------------|-------------|-----------|
| LAN ↔ LAN | ✅ | — | fallback | `vizinhos: 2` TushiBook 2026-07-20 |
| Folha Vivo ↔ Esporocarpo aberto | ⏳ | ⏳ | fallback | aguarda voluntário |
| Folha 5G ↔ Esporocarpo aberto | ⏳ | ⏳ | fallback | aguarda voluntário |
| Folha Vivo ↔ Folha 5G | ❌ sem 3º | ⏳ via relay | ✅ async | tese atual |
| Dois NAT cone | ⚠️ ICE | ✅ | ✅ | |
| Dois NAT simétricos | ❌ | ✅ | ✅ | |
| Ambos CGNAT | ❌ | ✅ se relay | ✅ | |
| Sem terceiro aberto | ❌ WAN | ❌ | ✅ | mailbox só pós-bootstrap |

## Notas

- Bootstrap **sempre** precisa de um peer já alcançável (mDNS / seed / DNS TXT).
- Circuit só depois de dial outbound ao `/esporocarp`.
- Não marque um nó como alcançável apenas por definir `MYCELIUM_REACHABLE=1`;
  registre também a prova externa em `proof.json`.
