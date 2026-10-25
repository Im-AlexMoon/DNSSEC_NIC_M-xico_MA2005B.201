#!/bin/bash
# Punto 3: consulta cada zona del árbol a través de los DOS recursivos (sin DNSSEC y validador)
# y resume rcode, bit AD y número de RRSIG. Guarda la salida completa de dig en un .txt.
# Uso: bash consultas_recursivos.sh [arbol.json] [salida.txt]
ARBOL="${1:-arbol.json}"
OUT="${2:-consultas_recursivos_$(date +%Y%m%d_%H%M%S).txt}"
[ -f "$ARBOL" ] || { echo "No encuentro $ARBOL (genéralo con genera_arbol.py)"; exit 1; }

read R1 R2 < <(python3 -I - "$ARBOL" <<'PY'
import json, sys
r = json.load(open(sys.argv[1], encoding="utf-8"))["recursivos"]
print(r["sin_validacion"], r["validador"])
PY
)
NOMBRES=$(python3 -I - "$ARBOL" <<'PY'
import json, sys
for z in json.load(open(sys.argv[1], encoding="utf-8"))["zonas"]:
    print(z["zone"], "SOA")
    if z.get("www"):
        print("www." + z["zone"], "A")
PY
)

resumen() {  # recursivo nombre tipo
    local salida st ad nsig
    salida=$(dig @"$1" "$2" "$3" +dnssec +time=2 +tries=1 2>&1)
    { echo "##### dig @$1 $2 $3 +dnssec"; echo "$salida"; echo; } >> "$OUT"
    st=$(grep -o 'status: [A-Z]*' <<<"$salida" | head -1 | cut -d' ' -f2)
    ad=""; grep -q '^;; flags:.* ad' <<<"$salida" && ad=" +AD"
    nsig=$(grep -cE '[[:space:]]RRSIG[[:space:]]' <<<"$salida")
    printf "%s%s rrsig=%s" "${st:-TIMEOUT}" "$ad" "$nsig"
}

: > "$OUT"
printf "%-28s %-4s | %-30s | %-30s\n" "nombre" "tipo" "recursivo $R1 (sin DNSSEC)" "recursivo $R2 (valida)"
printf '%.0s-' {1..100}; echo
while read -r n t; do
    a=$(resumen "$R1" "$n" "$t"); b=$(resumen "$R2" "$n" "$t")
    marca=""; [ "${a%% *}" != "${b%% *}" ] || [[ "$b" == *"+AD"* && "$a" != *"+AD"* ]] && marca="  <-- difieren"
    printf "%-28s %-4s | %-30s | %-30s%s\n" "$n" "$t" "$a" "$b" "$marca"
done <<< "$NOMBRES"
echo; echo "Salida completa de dig: $OUT"
