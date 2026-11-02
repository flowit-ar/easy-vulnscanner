#!/usr/bin/env bash
#
# install_vulnscan.sh - Instala Easy VulnScanner como servicio systemd.
# Uso (desde la carpeta del repo):  sudo bash install_vulnscan.sh
# Opcional: VULNSCAN_USER y VULNSCAN_PASS (si no se pasan, la password se genera).
set -euo pipefail

INSTALL_DIR=/opt/easy-vulnscanner
DATA_DIR=/var/lib/easy-vulnscanner
ENV_FILE=/etc/easy-vulnscanner.env
UNIT=/etc/systemd/system/easy-vulnscanner.service
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log(){ echo -e "\e[32m[+]\e[0m $*"; }
err(){ echo -e "\e[31m[x]\e[0m $*" >&2; }

if [ "$(id -u)" -ne 0 ]; then
    err "Ejecutá con sudo: sudo bash $0"
    exit 1
fi
if [ ! -f "$SRC_DIR/vulnscan_app.py" ]; then
    err "No encuentro vulnscan_app.py junto al instalador ($SRC_DIR)"
    exit 1
fi

log "Instalando dependencias (flask, requests, nmap)..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3-flask python3-requests nmap openssl >/dev/null
log "Dependencias OK"

install -d -m 0755 "$INSTALL_DIR"
install -d -m 0700 "$DATA_DIR"
install -m 0644 "$SRC_DIR/vulnscan_app.py" "$INSTALL_DIR/vulnscan_app.py"
python3 -m py_compile "$INSTALL_DIR/vulnscan_app.py"
rm -rf "$INSTALL_DIR/__pycache__"
log "Aplicacion copiada a $INSTALL_DIR"

GENERATED_PASS=""
if [ -f "$ENV_FILE" ]; then
    log "Ya existe $ENV_FILE: se conserva la configuracion actual"
else
    SECRET=$(openssl rand -hex 32)
    USER_NAME="${VULNSCAN_USER:-admin}"
    if [ -n "${VULNSCAN_PASS:-}" ]; then
        PASS="$VULNSCAN_PASS"
    else
        PASS=$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)
        GENERATED_PASS="$PASS"
    fi
    umask 077
    cat > "$ENV_FILE" <<EOF
VULNSCAN_SECRET=${SECRET}
VULNSCAN_USER=${USER_NAME}
VULNSCAN_PASS=${PASS}
VULNSCAN_HOST=127.0.0.1
VULNSCAN_PORT=5000
VULNSCAN_DATA_DIR=${DATA_DIR}
EOF
    chmod 600 "$ENV_FILE"
    log "Configuracion creada en $ENV_FILE (solo root puede leerla)"
fi

cat > "$UNIT" <<EOF
[Unit]
Description=Easy VulnScanner
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${ENV_FILE}
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/vulnscan_app.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now easy-vulnscanner
sleep 2

echo
echo "=================================================================="
if systemctl is-active --quiet easy-vulnscanner; then
    log "Easy VulnScanner ACTIVO"
else
    err "El servicio NO levanto. Revisá: journalctl -u easy-vulnscanner -n 40 --no-pager"
    exit 1
fi
echo "  URL:      http://127.0.0.1:5000  (solo desde esta maquina)"
echo "  Config:   $ENV_FILE"
if [ -n "$GENERATED_PASS" ]; then
    echo "  Password: $GENERATED_PASS   <-- GENERADA, guardala ahora (no se vuelve a mostrar)"
fi
echo "  Datos:    $DATA_DIR"
echo "=================================================================="
echo
echo "Comandos utiles:"
echo "  systemctl status easy-vulnscanner"
echo "  journalctl -u easy-vulnscanner -f"
echo "  sudo grep VULNSCAN_PASS $ENV_FILE"
