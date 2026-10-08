#!/usr/bin/env bash
# Higiene do repositório Mycelium: relatório de espaço e untracking seguro
# de artefatos de build, caches de tooling e snapshots superados.
#
# ======================================================================
# NADA É APAGADO DO DISCO. Este script NUNCA deleta, move ou rm -rf
# nenhum arquivo ou diretório. Ele apenas:
#   * mede o espaço ocupado na working tree (seção A, somente leitura);
#   * tira arquivos do ÍNDICE do git com `git rm --cached`, que os
#     mantém exatamente onde estão (seção B, apenas com --apply);
#   * informa o que pode ser recuperado depois (seções C e D, apenas
#     texto — nenhum comando é executado).
#
# Um arquivo despistado continua na working tree, byte a byte igual;
# ele só deixa de aparecer em `git status` e de entrar em futuros
# commits. Qualquer arquivo "perdido" volta com
#   git checkout HEAD -- <caminho>
# ou a partir do commit que ainda o contém.
#
# Uso:
#   ./scripts/housekeeping.sh            # dry-run (padrão, seguro)
#   ./scripts/housekeeping.sh --apply    # executa a seção B
#
# O dry-run é o padrão de propósito: imprime exatamente o que o
# --apply faria, sem tocar no índice. Rodar `git diff --cached`
# depois é obrigatório — nada é commitado automaticamente.
# ======================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

usage() {
  awk 'NR>1 && /^#/ { sub(/^# ?/, ""); print; next } NR>1 { exit }' \
    "${BASH_SOURCE[0]}"
}

APPLY=0
for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "argumento desconhecido: $arg (use --apply ou --help)" >&2
      exit 2
      ;;
  esac
done

command -v git >/dev/null || {
  echo "git não encontrado; instale antes de rodar este script." >&2
  exit 1
}

if (( APPLY )); then
  MODE="APLICAR (--apply)"
else
  MODE="DRY-RUN (padrão; use --apply para despistar do índice)"
fi

echo "=========================================================="
echo "🍄 Higiene do repositório Mycelium — $MODE"
echo "=========================================================="
echo "raiz: $ROOT"
if (( APPLY )); then
  echo "⚠️  MODO --apply: o índice do git será modificado."
  echo "⚠️  NENHUM ARQUIVO SERÁ APAGADO DO DISCO."
else
  echo "ℹ️  Nenhuma escrita será feita: nem índice, nem disco."
fi
echo

# -------------------------------------------------------------------
# Seção A — espaço ocupado na working tree (somente leitura)
# -------------------------------------------------------------------
echo "----------------------------------------------------------"
echo "SEÇÃO A — espaço ocupado na working tree (leitura apenas)"
echo "----------------------------------------------------------"
for dir in \
  "target/" \
  ".git/" \
  ".git-base-backup/" \
  ".cargo-home/" \
  ".release-cargo/" \
  ".release-rustup/" \
  "dist/" \
  "graphify-out/" \
  "ET-COSMIC-OLD/" \
  "S1-BPF-source-update old/"
do
  if [[ -e "$dir" ]]; then
    du -sh "$dir" 2>/dev/null || echo "  (sem permissão de leitura)"
  else
    echo "ausente: $dir"
  fi
done
echo
echo "Referência: se .git/ for maior que a árvore de código versionada,"
echo "os blobs antigos é que estão segurando espaço."
echo

# -------------------------------------------------------------------
# Seção B — untracking dos artefatos (o ÚNICO passo que escreve)
# -------------------------------------------------------------------
echo "----------------------------------------------------------"
echo "SEÇÃO B — artefatos rastreados que NÃO deveriam estar no git"
echo "----------------------------------------------------------"
echo "Levantado com 'git ls-files' (leitura): o que está no índice hoje."
echo

# Pathspecs do git; o glob é resolvido pelo git, não pela shell, e
# *.bin/*.zip/*.tar.gz/*.patch batem em qualquer nível.
pathspecs=(
  "dist"
  "graphify-out"
  "vendor"
  "ET-COSMIC-OLD"
  "*.tar.gz"
  "*.zip"
  "*.bin"
  "*.patch"
)

tracked=()
for spec in "${pathspecs[@]}"; do
  group=()
  while IFS= read -r line; do
    [[ -n "$line" ]] && group+=("$line")
  done < <(git ls-files -- "$spec")
  if (( ${#group[@]} == 0 )); then
    continue
  fi
  tracked+=("${group[@]}")
  gsize=$(printf '%s\0' "${group[@]}" \
    | xargs -0 du -sch 2>/dev/null | tail -1 | cut -f1) || gsize="?"
  printf '  %-16s %5d arquivo(s)  %6s\n' "$spec" "${#group[@]}" "${gsize:-?}"
done

if (( ${#tracked[@]} == 0 )); then
  echo "  (nada rastreado para despistar — o índice já está limpo)"
  echo
else
  total=$(du -sch "${tracked[@]}" 2>/dev/null | tail -1 | cut -f1) || total="?"
  echo
  echo "Total a despistar: ${#tracked[@]} arquivo(s), ${total:-?}"
  echo
  echo "Arquivos avulsos (os demais estão dentro de diretórios):"
  for f in "${tracked[@]}"; do
    case "$f" in
      ET-COSMIC-OLD/*|dist/*|graphify-out/*|vendor/*) continue ;;
    esac
    printf '  %-40s %s\n' "$f" "$(du -h "$f" 2>/dev/null | cut -f1)"
  done
  echo
  cat <<'WARN'

  ╔══════════════════════════════════════════════════════════════╗
  ║ AVISO — LEIA ANTES DE RODAR COM --apply                    ║
  ╠══════════════════════════════════════════════════════════════╣
  ║ `git rm --cached` NÃO apaga nada do disco. Ele marca os     ║
  ║ arquivos como deletados no ÍNDICE (staged deletion) e eles  ║
  ║ continuam na working tree, byte a byte igual.              ║
  ║                                                              ║
  ║ Recuperável pelo commit que ainda os contém:                ║
  ║   git checkout HEAD -- dist/mycelium-android-arm64          ║
  ║                                                              ║
  ║ Nenhum commit é criado. Revise antes:                        ║
  ║   git diff --cached --stat                                  ║
  ║   git diff --cached                                         ║
  ║                                                              ║
  ║ Para desfazer o --apply (ainda sem commit):                 ║
  ║   git reset                                                  ║
  ╚══════════════════════════════════════════════════════════════╝
WARN
  echo
  if (( APPLY )); then
    echo "→ Executando git rm --cached (os arquivos permanecem no disco)..."
    git rm --cached -r --quiet -- "${tracked[@]}"
    echo "✓ Índice despistado. OS ARQUIVOS AINDA ESTÃO NO DISCO."
    echo
    echo "Próximo passo MANUAL: git diff --cached --stat, depois commite."
  else
    echo "→ dry-run: NADA FOI FEITO. Com --apply, seria o equivalente a:"
    printf "    git rm --cached -r --"
    printf " '%s'" "${pathspecs[@]}"
    printf "\n"
    echo "  (aspas são intencionais: o git resolve os globs, a shell não)"
    echo "  (só os arquivos listados acima são atingidos)"
    echo
    echo "Depois do --apply, tudo continua em disco e recuperável por"
    echo "'git checkout HEAD -- <caminho>' até o commit que os remove."
  fi
  echo
fi

# -------------------------------------------------------------------
# Seção C — git gc
# -------------------------------------------------------------------
echo "----------------------------------------------------------"
echo "SEÇÃO C — compactação do histórico (.git/)"
echo "----------------------------------------------------------"
cat <<'NOTE'

  NÃO executado. `git gc --aggressive` reescreve packs inteiros e
  pode levar horas em históricos grandes. Rode depois de commitar a
  remoção da seção B, e faça backup antes:

    cp -a .git ../.git-backup-$(date +%F)
    git gc --aggressive --prune=now

  Ganho esperado: substancial aqui — da ordem de centenas de MB a
  mais de 1 GB — porque os blobs dos artefatos despistados continuam
  no histórico. O prune é o que de fato devolve o espaço: até lá, o
  pack encolhe por dentro mas ainda ocupa o .git/.

  Contraste: `.git-base-backup/` (3,8 GB) é uma cópia sua, fora do
  git. Arquivá-la é decisão do autor e NÃO é feita por este script.

NOTE
echo

# -------------------------------------------------------------------
# Seção D — cargo clean
# -------------------------------------------------------------------
echo "----------------------------------------------------------"
echo "SEÇÃO D — caches de compilação (target/)"
echo "----------------------------------------------------------"
cat <<'NOTE'

  NÃO executado, nem no --apply. `cargo clean` é a maior economia
  possível aqui (target/ sozinho ocupa ~84 GB), mas é a única seção
  deste script que DELETA arquivos de verdade: artefatos de
  compilação, nunca fonte. Foi deixada de fora de propósito.

  Se quiser descartar tudo e reconstruir:

    cargo clean

  Para preservar o cache de dependências (economia bem maior que
  apagar o target inteiro):

    cargo clean --release        # ou --profile <perfil>

  A seção A já mediu target/ para a decisão ser informada.
NOTE
echo

echo "=========================================================="
if (( APPLY )); then
  echo "Concluído em modo --apply. Índice modificado, disco intacto."
  echo "Revise com 'git diff --cached --stat' antes de commitar."
else
  echo "Dry-run concluído. Nada escrito, nada apagado."
  echo "Para despistar de fato: $0 --apply"
fi
echo "=========================================================="
