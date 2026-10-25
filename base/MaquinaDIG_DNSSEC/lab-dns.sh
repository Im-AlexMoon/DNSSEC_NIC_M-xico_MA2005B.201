#!/bin/bash
# Uso: sudo bash lab-dns.sh [start|stop|restart|status]

BASE="/mnt/c/Users/ugams/MaquinaDIG_DNSSEC"
IPS="172.30.0.10 172.30.0.20 172.30.0.30 172.30.0.40 172.30.0.50 172.30.0.60 172.30.0.100 172.30.0.101"
SERVIDORES="root unsigned alpha signed beta gamma recursive1 recursive2"
LOGS="$BASE/logs"

agregar_ips() {
    for ip in $IPS; do
        ip addr show lo | grep -q "$ip/" || ip addr add "$ip/32" dev lo
    done
}

detener() {
    pkill -x named 2>/dev/null
    sleep 1
}

iniciar() {
    mkdir -p "$LOGS"
    agregar_ips
    detener
    for s in $SERVIDORES; do
        named -g -c "$BASE/$s/named.conf" > "$LOGS/$s.log" 2>&1 &
        sleep 1
    done
    estado
}

estado() {
    echo "--- IPs en lo ---"
    ip -4 addr show lo | grep 172.30
    echo "--- named escuchando ---"
    ss -lunp | grep ':53 ' | grep named
}

case "$1" in
    start|"")  iniciar ;;
    stop)      detener ;;
    restart)   iniciar ;;
    status)    estado ;;
    *) echo "Uso: sudo bash $0 [start|stop|restart|status]" ;;
esac
