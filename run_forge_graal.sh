#!/usr/bin/env bash
set -e

SCRIPT="graal_forge_cli.py"
CONFIG_MASS="config.mass"
CONFIG_CIDR="config.cidr"
CONFIG_SINGLE="config.single"

echo "=== Graal Forge Launcher ==="
echo "1) mass scan"
echo "2) cidr scan"
echo "3) scan chirurgical"
read -rp "> " CHOICE

case "$CHOICE" in
  1)
    MODE_ARG="--mass"; CFG="$CONFIG_MASS"
    echo "Plage (CIDR ou start‑end ou fichier) :"; read RANGE
    MASS_FILE="mass_targets.txt"
    if [ -f "$RANGE" ]; then
      cp "$RANGE" "$MASS_FILE"
    elif [[ "$RANGE" == *"/"* ]]; then
      python3 - <<EOF
import ipaddress
with open("$MASS_FILE","w") as f:
    for ip in ipaddress.IPv4Network("$RANGE").hosts():
        f.write(str(ip)+"\n")
EOF
    else
      IFS="-" read -r S E <<<"$RANGE"
      [[ "$E" != *.* ]] && E="${S%.*}.$E"
      python3 - <<EOF
import ipaddress
start=ipaddress.IPv4Address("$S"); end=ipaddress.IPv4Address("$E")
with open("$MASS_FILE","w") as f:
    ip=start
    while ip<=end:
        f.write(str(ip)+"\n"); ip+=1
EOF
    fi
    echo "→ 'mass_targets.txt' généré avec $(wc -l <"$MASS_FILE") IP(s)."
    sed -i -E "s|^mass_ips_file *=.*|mass_ips_file = $MASS_FILE|" "$CFG"
    EXTRA="-r $RANGE"
    ;;
  2)
    MODE_ARG="--cidr"; CFG="$CONFIG_CIDR"; EXTRA=""
    CUR=$(grep -E '^cidr' "$CFG"|cut -d'=' -f2|xargs)
    echo "CIDR à scanner [$CUR] :"; read NEW
    [ -n "$NEW" ] && sed -i -E "s|^cidr *=.*|cidr = $NEW|" "$CFG"
    ;;
  3)
    MODE_ARG="--single"; CFG="$CONFIG_SINGLE"
    echo "IP pour scan chirurgical :"; read IP
    EXTRA="$IP"
    ;;
  *)
    echo "❌ Choix invalide." >&2; exit 1
    ;;
esac

[ -f "$CFG" ] || { echo "⚠️ Config '$CFG' introuvable."; exit 1; }
echo "→ Utilisation de la config '$CFG'"

# wordlist
CURWL=$(grep -E '^wordlist_file' "$CFG"|cut -d'=' -f2|xargs)
read -rp "Wordlist [$CURWL]: " W; [ -n "$W" ] && \
  sed -i -E "s|^wordlist_file *=.*|wordlist_file = $W|" "$CFG"

# ports
CURP=$(grep -E '^ports' "$CFG"|cut -d'=' -f2|tr -d ' ')
read -rp "Ports [$CURP] (ajoute, sépare ','): " P
if [ -n "$P" ]; then
  IFS=',' read -ra A <<< "${CURP},${P}"
  U=$(printf "%s\n" "${A[@]}"|sort -n|uniq|paste -sd',' -)
  sed -i -E "s|^ports *=.*|ports = $U|" "$CFG"
fi

echo "[🚀] Lancement $MODE_ARG $EXTRA…"
python3 "$SCRIPT" $MODE_ARG $EXTRA
