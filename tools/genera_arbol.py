#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
genera_arbol.py -- Genera (o amplía) el árbol DNS/DNSSEC del laboratorio con BIND.

Perfiles
  act3 : árbol de la Actividad 3 (raíz, unsigned, alpha, signed, beta, gamma, recursive1, recursive2)
  act4 : act3 + gTLD "test" + 3 dominios nuevos bajo unsigned + 3 bajo signed
         (2 de ellos firmados) + 3 dominios con DNSSEC mal configurado bajo test.   [por defecto]

Uso típico (sobre una COPIA de tu árbol v2, nunca sobre el respaldo):
    cp -a MaquinaDIG_v2 MaquinaDIG_v3
    python3 genera_arbol.py --base MaquinaDIG_v3

Qué respeta de un árbol existente
  * Servidores que ya tienen named.conf: no se tocan (ni sus llaves, ni sus archivos de zona).
  * En las zonas padre existentes (db.root, db.signed, db.unsigned) solo agrega un bloque
    delimitado por marcadores con las delegaciones NUEVAS; es idempotente.
  * Las llaves existentes se reutilizan, así que el DS de la raíz y el ancla de confianza de
    recursive2 siguen siendo válidos.

Orden de firmado: de las hojas hacia la raíz, copiando cada dsset-* al padre antes de firmarlo.
"""
import argparse
import glob
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone

TTL = 86400
TIMERS = "3600 900 604800 86400"          # refresh retry expire minimum (iguales a los de la Actividad 2)
P256, P384, ED25519 = "ECDSAP256SHA256", "ECDSAP384SHA384", "ED25519"
RSA256, RSA1 = "RSASHA256", "RSASHA1"

# Nombres "sensibles" que se agregan a delta y epsilon para la demostración de zone walking.
EXTRAS_WALK = ["mail", "intranet", "admin", "vpn", "zq8x41"]

# fase: 3 = Actividad 3, 4 = Actividad 4.  ip = último octeto.
ZONAS = [
    dict(zone=".", dir="root", ip=10, parent=None, fase=3, signed=True, alg=P256, nsec="NSEC",
         serial=2026081601, expect="SECURE", scenario="ok", note="raíz (ECDSA P-256, NSEC)"),
    dict(zone="unsigned", dir="unsigned", ip=20, parent=".", fase=3, signed=False,
         serial=2026082001, expect="INSECURE", scenario="ok", note="gTLD sin firmar (Actividad 2)"),
    dict(zone="signed", dir="signed", ip=40, parent=".", fase=3, signed=True, alg=P256, nsec="NSEC",
         serial=2026101301, expect="SECURE", scenario="ok", note="gTLD firmado (ECDSA P-256, NSEC)"),
    dict(zone="test", dir="test", ip=70, parent=".", fase=4, signed=True, alg=P384, nsec="NSEC3",
         nsec3_salt="-", nsec3_iter=0, serial=2026102001, expect="SECURE", scenario="ok",
         note="gTLD firmado para pruebas (ECDSA P-384, NSEC3 sin sal, 0 iteraciones)"),

    # --- bajo unsigned (todos sin firmar) ---
    dict(zone="alpha.unsigned", dir="alpha", ip=30, parent="unsigned", fase=3, signed=False, www=35,
         serial=2026100601, expect="INSECURE", scenario="ok", note="Actividad 2"),
    dict(zone="eta.unsigned", dir="eta", ip=120, parent="unsigned", fase=4, signed=False, www=121,
         serial=2026102001, expect="INSECURE", scenario="ok", note="sin firmar"),
    dict(zone="theta.unsigned", dir="theta", ip=130, parent="unsigned", fase=4, signed=False, www=131,
         serial=2026102001, expect="INSECURE", scenario="ok", note="sin firmar"),
    dict(zone="iota.unsigned", dir="iota", ip=140, parent="unsigned", fase=4, signed=False, www=141,
         serial=2026102001, expect="INSECURE", scenario="ok", note="sin firmar"),

    # --- bajo signed ---
    dict(zone="beta.signed", dir="beta", ip=50, parent="signed", fase=3, signed=True, alg=P256, nsec="NSEC",
         www=51, serial=2026101301, expect="SECURE", scenario="ok", note="firmado (ECDSA P-256, NSEC)"),
    dict(zone="gamma.signed", dir="gamma", ip=60, parent="signed", fase=3, signed=False, www=61,
         serial=2026101301, expect="INSECURE", scenario="ok", note="sin firmar (delegación insegura)"),
    dict(zone="delta.signed", dir="delta", ip=80, parent="signed", fase=4, signed=True, alg=RSA256, bits=2048,
         nsec="NSEC3", nsec3_salt="AABBCCDD", nsec3_iter=5, www=81, extras=EXTRAS_WALK,
         serial=2026102001, expect="SECURE", scenario="ok",
         note="firmado (RSA-SHA256 2048, NSEC3 con sal e iteraciones; contraste con epsilon)"),
    dict(zone="epsilon.signed", dir="epsilon", ip=90, parent="signed", fase=4, signed=True, alg=ED25519,
         nsec="NSEC", www=91, extras=EXTRAS_WALK, serial=2026102001, expect="SECURE", scenario="ok",
         note="firmado (Ed25519, NSEC; mismo contenido que delta para comparar zone walking)"),
    dict(zone="zeta.signed", dir="zeta", ip=110, parent="signed", fase=4, signed=False, www=111,
         serial=2026102001, expect="INSECURE", scenario="ok", note="sin firmar"),

    # --- bajo test: DNSSEC mal configurado a propósito ---
    dict(zone="caducada.test", dir="caducada", ip=150, parent="test", fase=4, signed=True, alg=P256, nsec="NSEC",
         www=151, serial=2026102001, expect="BOGUS", scenario="firmas_caducas",
         note="DS correcto, pero las RRSIG expiraron hace 10 dias"),
    dict(zone="sinds.test", dir="sinds", ip=160, parent="test", fase=4, signed=True, alg=P256, nsec="NSEC",
         www=161, serial=2026102001, expect="INSECURE", scenario="sin_ds",
         note="zona firmada, pero el padre (test) NO publica su DS: isla de seguridad"),
    dict(zone="algdebil.test", dir="algdebil", ip=170, parent="test", fase=4, signed=True, alg=RSA1, bits=1024,
         nsec="NSEC", www=171, serial=2026102001, expect="SECURE", scenario="alg_debil",
         note="RSA-SHA1 de 1024 bits y DS con digest SHA-1: algoritmos desaconsejados (RFC 8624)"),
]

REC1, REC2 = 100, 101
MARCA_INI = "; >>> actividad4 (generado por genera_arbol.py, no editar a mano)"
MARCA_FIN = "; <<< actividad4"


# ----------------------------------------------------------------------------------------------
def info(msg):
    print(msg, flush=True)


def run(cmd, cwd=None, ok_codes=(0,), solo_stdout=False):
    """Ejecuta un comando. Con solo_stdout=True los avisos de stderr no se mezclan con la salida."""
    r = subprocess.run(cmd, cwd=cwd, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE if solo_stdout else subprocess.STDOUT, text=True)
    if r.returncode not in ok_codes:
        sys.exit("ERROR ejecutando: %s\n(cwd=%s)\n%s%s" % (" ".join(cmd), cwd, r.stdout, r.stderr or ""))
    return r.stdout


def fq(zone):
    return "." if zone == "." else zone.rstrip(".") + "."


def fname(zone):
    return "root" if zone == "." else zone.rstrip(".")


def source_file(z):
    return "db." + fname(z["zone"])


def signed_file(z):
    return source_file(z) + ".signed"


def key_glob(zone):
    return "K%s.+*.key" % ("" if zone == "." else zone.rstrip("."))


def hijos_de(zonas, zone):
    return [z for z in zonas if z["parent"] == zone]


def profundidad(zonas, z):
    d = 0
    while z["parent"] is not None:
        z = next(x for x in zonas if x["zone"] == z["parent"])
        d += 1
    return d


def ip_de(prefix, z, n=None):
    return "%s.%d" % (prefix, z["ip"] if n is None else n)


# ---------------------------------------------------------------- archivos de zona y named.conf
def propietarios(texto, zone, tipo):
    """Devuelve el conjunto de nombres (FQDN) que tienen un registro 'tipo' en el texto de zona."""
    res = set()
    for linea in texto.splitlines():
        linea = linea.split(";")[0].rstrip()
        if not linea.strip() or linea.lstrip().startswith("$"):
            continue
        if linea[0] in " \t":
            continue                                  # hereda propietario: no lo usamos
        tok = linea.split()
        if tipo not in tok[1:5]:
            continue
        owner = tok[0]
        if owner == "@":
            fqdn = fq(zone)
        elif owner.endswith("."):
            fqdn = owner.lower()
        else:
            fqdn = (owner + "." + fq(zone)).lower() if zone != "." else (owner + ".").lower()
        res.add(fqdn)
    return res


def quitar_bloque(texto):
    pat = re.compile(r"\n?%s.*?%s\n?" % (re.escape(MARCA_INI), re.escape(MARCA_FIN)), re.S)
    return pat.sub("\n", texto)


def contenido_base(z, prefix):
    zone = z["zone"]
    ns = "ns." + fq(zone) if zone != "." else "ns.root."
    adm = "admin." + fq(zone) if zone != "." else "admin.root."
    ls = ["$TTL %d" % TTL, "",
          "@ IN SOA %s %s (" % (ns, adm),
          "    %d" % z["serial"]]
    ls += ["    %s" % t for t in TIMERS.split()]
    ls += [")", "", "@ IN NS %s" % ns, "%s IN A %s" % (ns, ip_de(prefix, z))]
    if z.get("www"):
        ls += ["", "www IN A %s" % ip_de(prefix, z, z["www"])]
        for i, nombre in enumerate(z.get("extras", []), start=1):
            ls.append("%s IN A %s" % (nombre, ip_de(prefix, z, z["www"] + i)))
    return "\n".join(ls) + "\n"


def escribir_zona_fuente(base, z, zonas, prefix, nuevo):
    ruta = os.path.join(base, z["dir"], "zones", source_file(z))
    os.makedirs(os.path.dirname(ruta), exist_ok=True)
    if os.path.exists(ruta):
        with open(ruta, encoding="utf-8") as f:
            texto = f.read()
        texto = quitar_bloque(texto).rstrip("\n") + "\n"
    else:
        texto = contenido_base(z, prefix)
    hijos = hijos_de(zonas, z["zone"])
    ns_decl = propietarios(texto, z["zone"], "NS")
    a_decl = propietarios(texto, z["zone"], "A")
    lineas = []
    for h in hijos:
        c = fq(h["zone"])
        nsn = "ns." + c
        if c.lower() not in ns_decl:
            lineas.append("%s IN NS %s" % (c, nsn))
        if nsn.lower() not in a_decl:
            lineas.append("%s IN A %s" % (nsn, ip_de(prefix, h)))
    if lineas:
        texto += "\n" + MARCA_INI + "\n" + "\n".join(lineas) + "\n" + MARCA_FIN + "\n"
    with open(ruta, "w", encoding="utf-8") as f:
        f.write(texto)
    return ruta


def escribir_named_conf(base, z, prefix):
    d = os.path.join(base, z["dir"])
    arch = signed_file(z) if z["signed"] else source_file(z)
    txt = """options {
    directory "%(d)s";
    pid-file "%(d)s/named.pid";
    listen-on { %(ip)s; };
    listen-on-v6 { none; };
    recursion no;
    allow-query { any; };
    dnssec-validation no;
    notify no;
    max-cache-size 8m;
};

controls { };

zone "%(zone)s" {
    type primary;
    file "zones/%(arch)s";
};
""" % dict(d=d, ip=ip_de(prefix, z), zone=z["zone"], arch=arch)
    with open(os.path.join(d, "named.conf"), "w", encoding="utf-8") as f:
        f.write(txt)


# ---------------------------------------------------------------------------------- firmado
def leer_flags_llaves(keys_dir, zone):
    ksk, zsk = [], []
    for k in glob.glob(os.path.join(keys_dir, key_glob(zone))):
        with open(k, encoding="utf-8") as f:
            for linea in f:
                m = re.search(r"IN\s+DNSKEY\s+(\d+)\s+3\s+(\d+)", linea)
                if m:
                    (ksk if int(m.group(1)) & 1 else zsk).append(k)
    return ksk, zsk


def asegurar_llaves(base, z):
    keys_dir = os.path.join(base, z["dir"], "keys")
    os.makedirs(keys_dir, exist_ok=True)
    ksk, zsk = leer_flags_llaves(keys_dir, z["zone"])
    nuevas = 0
    for es_ksk, lista in ((True, ksk), (False, zsk)):
        if lista:
            continue
        cmd = ["dnssec-keygen", "-q", "-K", keys_dir, "-a", z["alg"]]
        if z.get("bits"):
            cmd += ["-b", str(z["bits"])]
        cmd += ["-n", "ZONE"] + (["-f", "KSK"] if es_ksk else []) + [z["zone"]]
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if r.returncode != 0 and z["alg"] == RSA1:
            # algunas compilaciones de OpenSSL/BIND ya no generan RSASHA1: se conserva la clave débil de 1024 bits
            info("      AVISO: este BIND no genera RSASHA1; %s usará RSASHA256 con clave de 1024 bits" % z["zone"])
            z["alg"] = RSA256
            z["note"] = "RSA-SHA256 con clave de solo 1024 bits y DS con digest SHA-1 (RSASHA1 no disponible en este BIND)"
            cmd[cmd.index(RSA1)] = RSA256
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        if r.returncode != 0:
            sys.exit("ERROR ejecutando: %s\n%s" % (" ".join(cmd), r.stdout))
        nuevas += 1
    return nuevas


def fecha(dt):
    return dt.strftime("%Y%m%d%H%M%S")


def firmar(base, z):
    zdir = os.path.join(base, z["dir"], "zones")
    cmd = ["dnssec-signzone", "-S", "-g", "-d", ".", "-K", "../keys", "-N", "increment",
           "-o", z["zone"], "-f", signed_file(z)]
    if z["nsec"] == "NSEC3":
        cmd += ["-3", z.get("nsec3_salt", "-"), "-H", str(z.get("nsec3_iter", 0))]
    if z["scenario"] == "firmas_caducas":
        ahora = datetime.now(timezone.utc)
        cmd += ["-s", fecha(ahora - timedelta(days=40)), "-e", fecha(ahora - timedelta(days=10)), "-P"]
    cmd.append(source_file(z))
    run(cmd, cwd=zdir)


def preparar_ds(base, z):
    """Para el escenario alg_debil reemplaza el dsset por uno con digest SHA-1 únicamente."""
    if z["scenario"] != "alg_debil":
        return
    zdir = os.path.join(base, z["dir"], "zones")
    ds = run(["dnssec-dsfromkey", "-1", "-f", signed_file(z), z["zone"]], cwd=zdir, solo_stdout=True)
    with open(os.path.join(zdir, "dsset-%s." % fname(z["zone"])), "w", encoding="utf-8") as f:
        f.write(ds)


def copiar_ds_al_padre(base, z, zonas):
    padre = next(x for x in zonas if x["zone"] == z["parent"])
    ds_origen = os.path.join(base, z["dir"], "zones", "dsset-%s." % fname(z["zone"]))
    ds_destino = os.path.join(base, padre["dir"], "zones", "dsset-%s." % fname(z["zone"]))
    if z["scenario"] == "sin_ds":
        if os.path.exists(ds_destino):
            os.remove(ds_destino)
        return False
    shutil.copyfile(ds_origen, ds_destino)
    return True


# ----------------------------------------------------------------------- recursivos y script
def ds_ancla(base, raiz):
    keys_dir = os.path.join(base, raiz["dir"], "keys")
    ksk, _ = leer_flags_llaves(keys_dir, ".")
    lineas = []
    for k in sorted(ksk):
        out = run(["dnssec-dsfromkey", "-2", k], solo_stdout=True).strip()
        t = out.split()
        # ". IN DS tag alg digesttype HEX..."
        lineas.append('    "." static-ds %s %s %s "%s";' % (t[3], t[4], t[5], "".join(t[6:])))
    return "trust-anchors {\n" + "\n".join(lineas) + "\n};\n"


def escribir_recursivos(base, prefix, raiz, forzar):
    for nombre, ip, valida in (("recursive1", REC1, False), ("recursive2", REC2, True)):
        d = os.path.join(base, nombre)
        if os.path.exists(os.path.join(d, "named.conf")) and not forzar:
            info("  = %s ya existe: no se toca" % nombre)
            continue
        os.makedirs(os.path.join(d, "zones"), exist_ok=True)
        with open(os.path.join(d, "zones", "db.root.hints"), "w", encoding="utf-8") as f:
            f.write(". 86400 IN NS ns.root.\nns.root. 86400 IN A %s.%d\n" % (prefix, raiz["ip"]))
        extra = ""
        if valida:
            with open(os.path.join(d, "anchor.conf"), "w", encoding="utf-8") as f:
                f.write(ds_ancla(base, raiz))
        txt = """options {
    directory "%(d)s";
    pid-file "%(d)s/named.pid";
    listen-on { %(p)s.%(ip)d; };
    listen-on-v6 { none; };
    recursion yes;
    allow-recursion { %(p)s.0/24; };
    allow-query { %(p)s.0/24; };
    dnssec-validation %(val)s;
    max-cache-size 32m;
};

controls { };
%(inc)s
zone "." {
    type hint;
    file "zones/db.root.hints";
};
""" % dict(d=d, p=prefix, ip=ip, val="yes" if valida else "no",
           inc=('\ninclude "%s/anchor.conf";\n' % d) if valida else "")
        with open(os.path.join(d, "named.conf"), "w", encoding="utf-8") as f:
            f.write(txt)
        info("  + %s creado (%s)" % (nombre, "valida DNSSEC" if valida else "sin validación"))


def escribir_script(base, prefix, zonas):
    ips = [ip_de(prefix, z) for z in zonas] + ["%s.%d" % (prefix, REC1), "%s.%d" % (prefix, REC2)]
    servs = [z["dir"] for z in zonas] + ["recursive1", "recursive2"]
    ruta = os.path.join(base, "lab-dns.sh")
    if os.path.exists(ruta):
        shutil.copyfile(ruta, ruta + ".bak")
    txt = """#!/bin/bash
# Uso: sudo bash lab-dns.sh [start|stop|restart|status]
BASE="%(base)s"
IPS="%(ips)s"
SERVIDORES="%(servs)s"   # los recursivos van al final
LOGS="$BASE/logs"

agregar_ips() {
    for ip in $IPS; do
        ip addr show lo | grep -q "$ip/" || ip addr add "$ip/32" dev lo
    done
}
detener() { pkill -x named 2>/dev/null; sleep 1; }
iniciar() {
    mkdir -p "$LOGS"; agregar_ips; detener
    for s in $SERVIDORES; do
        nohup named -g -c "$BASE/$s/named.conf" > "$LOGS/$s.log" 2>&1 &
        sleep 0.3
    done
    sleep 1; estado
}
estado() {
    echo "--- named escuchando ---"
    ss -lunp 2>/dev/null | grep ':53 ' | grep named | awk '{print $4}' | sort -V
    echo "--- servidores esperados: $(echo $SERVIDORES | wc -w) | activos: $(pgrep -x named | wc -l) ---"
}
case "$1" in
    start|"") iniciar ;;
    stop) detener ;;
    restart) iniciar ;;
    status) estado ;;
    *) echo "Uso: sudo bash $0 [start|stop|restart|status]" ;;
esac
""" % dict(base=os.path.abspath(base), ips=" ".join(ips), servs=" ".join(servs))
    with open(ruta, "w", encoding="utf-8", newline="\n") as f:
        f.write(txt)


def escribir_arbol_json(base, prefix, zonas):
    data = {
        "prefijo": prefix,
        "raiz_ip": "%s.%d" % (prefix, next(z for z in zonas if z["zone"] == ".")["ip"]),
        "recursivos": {"sin_validacion": "%s.%d" % (prefix, REC1), "validador": "%s.%d" % (prefix, REC2)},
        "ttl_esperado": TTL,
        "zonas": [dict(zone=z["zone"], padre=z["parent"], ip=ip_de(prefix, z), dir=z["dir"],
                       firmada=z["signed"], alg=z.get("alg"), bits=z.get("bits"),
                       nsec=z.get("nsec") if z["signed"] else None,
                       nsec3_salt=z.get("nsec3_salt"), nsec3_iter=z.get("nsec3_iter"),
                       www=(ip_de(prefix, z, z["www"]) if z.get("www") else None),
                       esperado=z["expect"], escenario=z["scenario"], nota=z["note"],
                       ttl_esperado=TTL) for z in zonas],
    }
    with open(os.path.join(base, "arbol.json"), "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# ------------------------------------------------------------------------------- principal
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", required=True, help="carpeta del árbol (copia de trabajo)")
    ap.add_argument("--prefijo", default="172.30.0", help="prefijo IPv4 (por defecto 172.30.0)")
    ap.add_argument("--perfil", choices=["act3", "act4"], default="act4")
    ap.add_argument("--no-firmar", action="store_true", help="solo escribe archivos, no firma")
    ap.add_argument("--refirmar-todo", action="store_true",
                    help="vuelve a firmar también las hojas ya firmadas (conserva llaves)")
    ap.add_argument("--forzar-recursivos", action="store_true", help="reescribe recursive1/recursive2")
    args = ap.parse_args()

    base = os.path.abspath(args.base)
    os.makedirs(base, exist_ok=True)
    fase_max = 3 if args.perfil == "act3" else 4
    zonas = [dict(z) for z in ZONAS if z["fase"] <= fase_max]
    todas = list(zonas)
    prof = {z["zone"]: profundidad(todas, z) for z in todas}
    zonas.sort(key=lambda z: (prof[z["zone"]], z["ip"]))
    raiz = next(z for z in zonas if z["parent"] is None)

    info("== Perfil %s sobre %s (prefijo %s) ==" % (args.perfil, base, args.prefijo))
    existentes = {z["zone"]: os.path.exists(os.path.join(base, z["dir"], "named.conf")) for z in zonas}

    info("-- 1/4 Archivos de zona y named.conf")
    for z in zonas:
        os.makedirs(os.path.join(base, z["dir"], "zones"), exist_ok=True)
        escribir_zona_fuente(base, z, zonas, args.prefijo, not existentes[z["zone"]])
        if not existentes[z["zone"]]:
            escribir_named_conf(base, z, args.prefijo)
            info("  + %-16s nuevo (%s)" % (z["zone"], z["note"]))
        else:
            info("  = %-16s existente: named.conf intacto, delegaciones actualizadas" % z["zone"])

    if args.no_firmar:
        info("(--no-firmar) listo")
    else:
        info("-- 2/4 Llaves y firmado (de las hojas hacia la raíz)")
        firmadas = [z for z in zonas if z["signed"]]
        for z in sorted(firmadas, key=lambda z: -profundidad(zonas, z)):
            es_padre = bool(hijos_de(zonas, z["zone"]))
            nuevo = not existentes[z["zone"]]
            nk = asegurar_llaves(base, z)
            if nuevo or es_padre or args.refirmar_todo or nk or \
                    not os.path.exists(os.path.join(base, z["dir"], "zones", signed_file(z))):
                firmar(base, z)
                info("  * %-16s firmada (%s%s)" % (z["zone"], z["alg"],
                                                    ", llaves nuevas" if nk else ", llaves reutilizadas"))
            else:
                info("  = %-16s ya firmada: se conserva" % z["zone"])
            if z["parent"] is not None:
                preparar_ds(base, z)
                copiado = copiar_ds_al_padre(base, z, zonas)
                if not copiado:
                    info("      (DS de %s NO se publica en el padre, a propósito)" % z["zone"])

    info("-- 3/4 Recursivos y script de arranque")
    escribir_recursivos(base, args.prefijo, raiz, args.forzar_recursivos)
    escribir_script(base, args.prefijo, zonas)
    escribir_arbol_json(base, args.prefijo, zonas)

    info("-- 4/4 Verificación estática")
    errores = 0
    for z in zonas:
        zd = os.path.join(base, z["dir"], "zones")
        arch = signed_file(z) if z["signed"] else source_file(z)
        r = subprocess.run(["named-checkzone", "-q", z["zone"], os.path.join(zd, arch)],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        estado = "OK" if r.returncode == 0 else "ERROR"
        extra = ""
        if z["signed"] and not args.no_firmar:
            v = subprocess.run(["dnssec-verify", "-o", z["zone"], os.path.join(zd, arch)],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            if v.returncode != 0:
                extra = "  dnssec-verify: FALLA" + ("  (esperado: firmas caducas)" if z["scenario"] == "firmas_caducas" else "")
                if z["scenario"] != "firmas_caducas":
                    errores += 1
            else:
                extra = "  dnssec-verify: OK"
        if r.returncode != 0:
            errores += 1
            extra += "\n" + r.stdout
        info("  %-16s named-checkzone %s%s" % (z["zone"], estado, extra))
    info("")
    info("Listo. Árbol: %s" % base)
    info("  levantar:  sudo bash %s/lab-dns.sh restart" % base)
    info("  auditar:   python3 dnssec_audit.py --arbol %s/arbol.json --ancla %s/recursive2/anchor.conf" % (base, base))
    if errores:
        sys.exit("Hubo %d errores de verificación" % errores)


if __name__ == "__main__":
    main()
