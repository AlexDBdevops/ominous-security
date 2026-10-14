#!/usr/bin/env bash
# Construye y arranca Ominous Security en http://localhost:8080
#
#   scripts/local.sh            construye la imagen y la arranca con Docker (por defecto)
#   scripts/local.sh full       igual, con Gitleaks, Semgrep, Trivy y CodeQL (imagen más grande)
#   scripts/local.sh down       la para
#   scripts/local.sh logs       muestra los logs
#   scripts/local.sh rebuild    reconstruye desde cero (sin caché) y arranca
#   scripts/local.sh lan        la abre a tu red local con token (para usarla desde el móvil)
#   scripts/local.sh scan DIR   analiza una carpeta local con el escáner (solo lectura)
#   scripts/local.sh node       arranca sin Docker, con el Node.js de tu máquina
#
# Variables: OMINOUS_PORT (8080), OMINOUS_CLONES (~/ominous-clones), GITHUB_TOKEN, ANTHROPIC_API_KEY
set -euo pipefail
cd "$(dirname "$0")/.."

export OMINOUS_PORT="${OMINOUS_PORT:-8080}"
export OMINOUS_CLONES="${OMINOUS_CLONES:-$HOME/ominous-clones}"
export OMINOUS_UID="$(id -u)" OMINOUS_GID="$(id -g)"
URL="http://localhost:${OMINOUS_PORT}"

die() { echo "✗ $*" >&2; exit 1; }
need_docker() {
  command -v docker >/dev/null || die "No encuentro Docker. Instálalo (https://docs.docker.com/get-docker/) o usa: scripts/local.sh node"
  docker compose version >/dev/null 2>&1 || die "Falta el plugin 'docker compose' (Docker 20.10+)."
  docker info >/dev/null 2>&1 || die "Docker no está arrancado."
}
wait_ready() {
  printf 'Esperando a que arranque'
  for _ in $(seq 1 60); do
    if curl -fsS -o /dev/null "http://127.0.0.1:${OMINOUS_PORT}/api/health" -H "Host: localhost:${OMINOUS_PORT}" 2>/dev/null; then
      echo; echo "✓ Ominous Security lista en ${URL}"; echo "  Clones en ${OMINOUS_CLONES}"; return 0
    fi
    printf '.'; sleep 1
  done
  echo; docker compose logs --tail 30 app; die "No ha arrancado en 60 s."
}
open_browser() {
  if command -v xdg-open >/dev/null; then xdg-open "$URL" >/dev/null 2>&1 || true
  elif command -v open >/dev/null; then open "$URL" || true; fi
}

case "${1:-up}" in
  up)
    need_docker
    mkdir -p "$OMINOUS_CLONES"
    docker compose -f compose.yaml up -d --build --force-recreate
    wait_ready && open_browser ;;
  full)
    need_docker
    mkdir -p "$OMINOUS_CLONES"
    docker compose -f compose.yaml -f compose.full.yaml up -d --build --force-recreate
    wait_ready && open_browser ;;
  rebuild)
    need_docker
    mkdir -p "$OMINOUS_CLONES"
    docker compose build --no-cache --pull
    docker compose up -d --force-recreate
    wait_ready ;;
  down) need_docker; docker compose down ;;
  logs) need_docker; docker compose logs -f app ;;
  scan)
    need_docker
    [ -n "${2:-}" ] && [ -d "$2" ] || die "Uso: scripts/local.sh scan <carpeta> [opciones de ominous-scan]"
    dir="$(cd "$2" && pwd)"; shift 2
    docker compose build -q app
    docker run --rm --read-only --cap-drop ALL --security-opt no-new-privileges --network none \
      -e OMINOUS_OFFLINE=1 -v "$dir:/src:ro" --entrypoint ominous-scan ominous-security:local /src "$@" ;;
  node)
    command -v node >/dev/null || die "No encuentro Node.js 22 o superior (https://nodejs.org)."
    [ "$(node -p 'process.versions.node.split(".")[0]')" -ge 22 ] || die "Necesitas Node.js 22 o superior."
    command -v git >/dev/null || die "No encuentro git."
    [ -d node_modules ] || npm ci --omit=dev --ignore-scripts || echo "  (sin SDK de Anthropic: el resumen del diff será local)"
    PORT="$OMINOUS_PORT" CLONE_DIR="$OMINOUS_CLONES" exec node server.js ;;
  lan)
    need_docker
    mkdir -p "$OMINOUS_CLONES"
    ip="${OMINOUS_LAN_IP:-$( (hostname -I 2>/dev/null || ipconfig getifaddr en0 2>/dev/null || true) | awk '{print $1}')}"
    [ -n "$ip" ] || die "No he podido detectar tu IP local. Pásala así: OMINOUS_LAN_IP=192.168.1.20 scripts/local.sh lan"
    if [ -z "${OMINOUS_TOKEN:-}" ]; then
      [ -s .ominous-token ] || (umask 077; od -An -tx1 -N24 /dev/urandom | tr -d ' \n' > .ominous-token)
      OMINOUS_TOKEN="$(cat .ominous-token)"
    fi
    export OMINOUS_LAN_IP="$ip" OMINOUS_TOKEN
    docker compose -f compose.yaml -f compose.lan.yaml up -d --build
    wait_ready
    echo "  Desde otro dispositivo de tu red abre (solo la primera vez, luego basta sin token):"
    echo "  http://${ip}:${OMINOUS_PORT}/?token=${OMINOUS_TOKEN}"
    echo "  Ojo: es HTTP sin cifrar. Úsalo solo en una red de confianza y vuelve a 'scripts/local.sh up' al terminar." ;;
  *) sed -n '2,14p' "$0"; exit 1 ;;
esac
