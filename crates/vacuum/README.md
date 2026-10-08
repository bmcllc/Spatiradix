# 🧹 `vacuum` — Limpeza Segura de Memória e Zero-Trace

Biblioteca de alocação protegida e limpeza irreversível de memória sensível (*Zero-Trace memory sanitizer*).

---

## 🎯 Finalidade

Em ambientes de alta segurança e privacidade criptográfica, dados confidenciais (chaves privadas ed25519, sementes KEM, senhas e fragmentos de túneis) não devem permanecer em memória volátil após o uso:
- **`Zeroize` em Drop**: Sobrescrita garantida de buffers de memória com zeros ou ruído de alta entropia.
- **Prevenção de Otimizações de Compilador**: Uso de barreiras de memória e voláteis para impedir que o otimizador LLVM elimine operações de sobrescrita.
- **Proteção contra *Memory Dumps* e *Cold Boot Attacks***.
