#!/usr/bin/env bash
# ----------------------------------------------------------------------
# run_bootstrap.sh – bootstrap S1 usando Mycelium (sponsor = deployer)
# ----------------------------------------------------------------------
set -euo pipefail
IFS=$'\n\t'

# ----------------------------------------------------------------------
# 0️⃣  Variáveis – diretório onde realmente ficam os scripts
# ----------------------------------------------------------------------
PROJECT_ROOT="/media/bruno/SAMBOOK/Mycelium Network/S1-BPF-source-update old"
cd "$PROJECT_ROOT"

# Endereço que já está em config/s1‑mainnet‑identities.json
SPONSOR_ADDR="0x54d25371559f4ad7bBA334FFC0d009C0ba42d5d9"
SPONSOR_CFG="my_sponsor.json"

# ----------------------------------------------------------------------
# 1️⃣  Inicia o gateway (fork local) – sub‑command = start
# ----------------------------------------------------------------------
echo "🟢  Starting Mycelium gateway (fork)…"
python3 scripts/sovereign-base-gateway.py start --port 8545 &
GATEWAY_PID=$!
sleep 5   # aguarda o fork abrir a porta

# ----------------------------------------------------------------------
# 2️⃣  Cria (ou reutiliza) config mínima do sponsor / deployer
# ----------------------------------------------------------------------
if [[ ! -f "$SPONSOR_CFG" ]]; then
cat > "$SPONSOR_CFG" <<'EOCFG'
{
  "address": "0x54d25371559f4ad7bBA334FFC0d009C0ba42d5d9",
  "leaderAddress": "0x1111111111111111111111111111111111111111",
  "riskAddress":   "0x2222222222222222222222222222222222222222",
  "chainAddress":  "0x3333333333333333333333333333333333333333",
  "socketPath":    "/tmp/sponsor.sock",
  "tokenFile":     "/tmp/sponsor.token",
  "replayDb":      "/tmp/sponsor-replay.db",
  "nonceDb":       "/tmp/sponsor-nonce.db",
  "executionDb":   "/tmp/sponsor-exec.db",
  "keystore":      "/tmp/sponsor-keystore.json",
  "passwordFile": "/tmp/sponsor.pass",
  "rpcUrl":        "http://127.0.0.1:8545",
  "allowMainnetBroadcast": false
}
EOCFG
echo "✅  Sponsor config created at $SPONSOR_CFG"
fi

# ----------------------------------------------------------------------
# 3️⃣  Exporta a chave privada do sponsor / deployer
# ----------------------------------------------------------------------
# <<<--- SUBSTITUA AQUI COM SUA CHAVE PRIVADA (0x…) ---------------------------
export SPONSOR_PRIV="0x54d25371559f4ad7bBA334FFC0d009C0ba42d5d9"
# ----------------------------------------------------------------------
if [[ "$SPONSOR_PRIV" == "0x<SUA_CHAVE_PRIVADA>" ]]; then
    echo "⚠️  Você ainda não substituiu <SUA_CHAVE_PRIVADA> no script."
    kill $GATEWAY_PID
    exit 1
fi

# ----------------------------------------------------------------------
# 4️⃣  Inicia o sponsor (também o deployer) – ele anuncia a oferta ao mesh
# ----------------------------------------------------------------------
echo "🟢  Starting sponsor (also deployer)…"
# Sponsor node is optional for this bootstrap. If you need the sponsor to broadcast offers, start it with only the config file:
#   python3 scripts/sovereign_sponsor.py "$SPONSOR_CFG" &
# For a zero‑capital bootstrap we only need the sponsor's private key for the CREATE transaction, so we skip launching the sponsor process.
# (If you later want the sponsor running, uncomment the line above and provide a keystore/password in the config.)
SPONSOR_PID=$!
sleep 3   # dá tempo para a oferta aparecer no mesh

# ----------------------------------------------------------------------
# 5️⃣  Verifica saldo ETH do sponsor (precisa >= 0.00008 ETH)
# ----------------------------------------------------------------------
echo "🔎  Checking ETH balance of sponsor $SPONSOR_ADDR …"
BAL_ETH=$(cast balance "$SPONSOR_ADDR" --rpc-url http://127.0.0.1:8545 | cut -d' ' -f1)
echo "   Current balance: $BAL_ETH ETH"

if (( $(echo "$BAL_ETH < 0.00008" | bc -l) )); then
    echo "⚠️  Saldo insuficiente (< 0.00008 ETH)."
    echo "   Envie ao menos 0.0001 ETH para $SPONSOR_ADDR e reexecute o script."
    kill $GATEWAY_PID $SPONSOR_PID 2>/dev/null || true
    exit 1
else
    echo "✅  Saldo suficiente."
fi

# ----------------------------------------------------------------------
# 6️⃣  Gera o plano de deploy (necessita de um preflight JSON já existente)
# ----------------------------------------------------------------------
# Ajuste o caminho abaixo caso seu preflight esteja em outro lugar.
PREFA_PATH="out/preflight.json"
if [[ ! -f "$PREFA_PATH" ]]; then
    echo "⚠️  Preflight JSON não encontrado em $PREFA_PATH."
    kill $GATEWAY_PID $SPONSOR_PID 2>/dev/null || true
    exit 1
fi

echo "📦  Generating deployment plan..."
python3 scripts/sovereign-deploy-plan.py \
    --identities config/s1-mainnet-identities.json \
    --preflight "$PREFA_PATH" \
    --out out/deploy-plan.json

# Extrai o initCode que será usado no CREATE
INITCODE=$(jq -r '.initCode' out/deploy-plan.json)

# ----------------------------------------------------------------------
# 7️⃣  Deploy (CREATE) usando a chave do sponsor – contrato será PAUSED
# ----------------------------------------------------------------------
echo "🚀  Deploying contract (PAUSED) via sponsor..."
# O cast retornará a linha "Contract address: 0x...."
DEPLOY_OUTPUT=$(cast send --private-key "$SPONSOR_PRIV" \
    --create "$INITCODE" \
    --rpc-url http://127.0.0.1:8545 2>&1)

echo "$DEPLOY_OUTPUT"

# Extrai o endereço do contrato da saída do cast
DEPLOYED=$(echo "$DEPLOY_OUTPUT" | grep -i "Contract address:" | awk '{print $3}')
if [[ -z "$DEPLOYED" ]]; then
    echo "❌  Não foi possível extrair o endereço do contrato. Verifique a saída acima."
    kill $GATEWAY_PID $SPONSOR_PID 2>/dev/null || true
    exit 1
fi

echo "✅  Contract deployed at: $DEPLOYED"

# ----------------------------------------------------------------------
# 8️⃣  Verifica o contrato implantado
# ----------------------------------------------------------------------
echo "🔍  Verifying deployed contract..."
python3 scripts/sovereign-verify-deployed.py --address "$DEPLOYED"

# ----------------------------------------------------------------------
# 9️⃣  Limpeza (opcional) – remova se quiser deixar gateway/sponsor rodando
# ----------------------------------------------------------------------
echo "🧹  Cleaning up background processes…"
kill $GATEWAY_PID $SPONSOR_PID 2>/dev/null || true

echo "🎉  Bootstrap concluído com sucesso!"
exit 0
