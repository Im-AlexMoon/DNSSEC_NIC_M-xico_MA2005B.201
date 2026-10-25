#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dnssec_audit.py -- Auditor DNSSEC para el laboratorio del reto (BIND + dnspython).

Consulta directamente a los servidores autoritativos (sin recursión), recorre las delegaciones desde la
raíz y verifica, para cada zona:

  DNSKEY      algoritmo autorizado (RFC 8624), tipo/tamaño de clave, uso (KSK/ZSK), estado
              (válida / expirada / inválida) y, si hay carpeta de llaves, su ciclo de vida
  RRSIG       qué clave firma cada RRset, vigencia (inicio/expiración), firmante, validez criptográfica
  NSEC/NSEC3  versión usada, parámetros NSEC3 (RFC 9276) y NSEC3PARAM
  DS          cadena de confianza desde el ancla hasta cada zona (SECURE / INSECURE / BOGUS)
  Zone walking  enumeración real de la zona con NSEC y su mitigación con NSEC3 (ataque de diccionario)
  TTL         observado vs. esperado (y TTL original de cada RRSIG)

Salidas: informe en pantalla, árbol de dependencias, métricas, y opcionalmente JSON / CSV / Graphviz DOT.

Ejemplos
  python3 dnssec_audit.py --arbol arbol.json --ancla recursive2/anchor.conf
  python3 dnssec_audit.py --zonas . signed beta.signed --raiz 172.30.0.10 --ancla-ds "63705 13 2 2769..."
  python3 dnssec_audit.py --arbol arbol.json --ancla recursive2/anchor.conf --json v3.json --csv v3.csv --dot v3.dot
  python3 dnssec_audit.py --comparar v2.json dnssec.json

Dependencias:  sudo apt install python3-dnspython python3-cryptography
"""
import argparse
import base64
import csv
import hashlib
import json
import os
import random
import re
import string
import sys
import time

try:
    import dns.dnssec
    import dns.edns
    import dns.exception
    import dns.flags
    import dns.message
    import dns.name
    import dns.query
    import dns.rcode
    import dns.rdatatype as rdt
except ImportError:
    sys.exit("Falta dnspython/cryptography:  sudo apt install python3-dnspython python3-cryptography")

# ------------------------------------------------------------------------------------ tablas
ALG = {
    1: ("RSAMD5", "PROHIBIDO"), 3: ("DSA", "PROHIBIDO"), 5: ("RSASHA1", "DESACONSEJADO"),
    6: ("DSA-NSEC3-SHA1", "PROHIBIDO"), 7: ("RSASHA1-NSEC3-SHA1", "DESACONSEJADO"),
    8: ("RSASHA256", "AUTORIZADO"), 10: ("RSASHA512", "DESACONSEJADO"), 12: ("ECC-GOST", "PROHIBIDO"),
    13: ("ECDSAP256SHA256", "AUTORIZADO"), 14: ("ECDSAP384SHA384", "AUTORIZADO"),
    15: ("ED25519", "AUTORIZADO"), 16: ("ED448", "AUTORIZADO"),
}
DSDIG = {1: ("SHA-1", "DESACONSEJADO", "SHA1"), 2: ("SHA-256", "AUTORIZADO", "SHA256"),
         3: ("GOST R 34.11-94", "PROHIBIDO", None), 4: ("SHA-384", "AUTORIZADO", "SHA384")}
CURVAS = {13: ("P-256", 256), 14: ("P-384", 384), 15: ("Ed25519", 256), 16: ("Ed448", 456)}
EDE = {1: "Unsupported DNSKEY Algorithm", 2: "Unsupported DS Digest Type", 5: "DNSSEC Indeterminate",
       6: "DNSSEC Bogus", 7: "Signature Expired", 8: "Signature Not Yet Valid", 9: "DNSKEY Missing",
       10: "RRSIGs Missing", 11: "No Zone Key Bit Set", 12: "NSEC Missing"}
DICCIONARIO = ["www", "ns", "ns1", "ns2", "mail", "smtp", "imap", "pop", "ftp", "vpn", "admin", "intranet",
               "dev", "test", "staging", "api", "db", "git", "portal", "webmail", "owa", "remote", "backup",
               "proxy", "dns", "gw", "fw", "ldap", "wiki", "blog", "shop", "app", "cloud", "ssh"]
ORDEN = {"SECURE": 0, "INSECURE": 1, "BOGUS": 2, "INDETERMINATE": 3, "NO_DISPONIBLE": 4}

USAR_COLOR = False
COLORES = {"SECURE": "32", "INSECURE": "33", "BOGUS": "31", "INDETERMINATE": "35", "NO_DISPONIBLE": "90",
           "ERROR": "31", "AVISO": "33", "INFO": "36", "OK": "32"}


def color(txt, clave):
    if USAR_COLOR and clave in COLORES:
        return "\033[%sm%s\033[0m" % (COLORES[clave], txt)
    return txt


def nm(x):
    return x if isinstance(x, dns.name.Name) else dns.name.from_text(x)


def tx(n):
    return nm(n).to_text()


def fmt_ts(t):
    return time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(t))


def hexs(b):
    return b.hex().upper() if b else "-"


# ------------------------------------------------------------------------------------ red
class Cliente:
    def __init__(self, timeout=2.0):
        self.timeout = timeout
        self.cache = {}
        self.fallos = []

    def consulta(self, srv, qname, rdtype, rd=False, cache=True):
        k = (srv, tx(qname), int(rdtype), rd)
        if cache and k in self.cache:
            return self.cache[k]
        m = dns.message.make_query(nm(qname), rdtype, want_dnssec=True, flags=(dns.flags.RD if rd else 0),
                                   use_edns=0, payload=1232)
        r = None
        try:
            r = dns.query.udp(m, srv, timeout=self.timeout)
            if r.flags & dns.flags.TC:
                r = dns.query.tcp(m, srv, timeout=self.timeout)
        except (dns.exception.Timeout, OSError, dns.exception.DNSException) as e:
            self.fallos.append("%s %s %s: %s" % (srv, tx(qname), rdt.to_text(rdtype), e.__class__.__name__))
        if cache:
            self.cache[k] = r
        return r


def buscar(seccion, nombre, tipo):
    for rr in seccion:
        if rr.rdtype == tipo and rr.name == nm(nombre):
            return rr
    return None


def buscar_todos(seccion, tipo):
    return [rr for rr in seccion if rr.rdtype == tipo]


def sigs_de(seccion, nombre, cubre):
    out = []
    for rr in seccion:
        if rr.rdtype == rdt.RRSIG and rr.covers == cubre and rr.name == nm(nombre):
            out.extend(list(rr))
    return out


def tipos_bitmap(rd):
    return rd.to_text().split()[1:] if rd.rdtype == rdt.NSEC else rd.to_text().split()[5:]


def nsec3_hash(nombre, salt, iteraciones):
    h = hashlib.sha1(nm(nombre).canonicalize().to_wire() + salt).digest()
    for _ in range(iteraciones):
        h = hashlib.sha1(h + salt).digest()
    return base64.b32hexencode(h).decode().rstrip("=").upper()


def rsa_bits(key):
    try:
        if key[0] == 0:
            elen, off = int.from_bytes(key[1:3], "big"), 3
        else:
            elen, off = key[0], 1
        return int.from_bytes(key[off + elen:], "big").bit_length()
    except Exception:
        return None


def leer_ancla_archivo(ruta):
    txt = open(ruta, encoding="utf-8").read()
    res = []
    for m in re.finditer(r'(?:static-ds|initial-ds)\s+(\d+)\s+(\d+)\s+(\d+)\s+"([0-9A-Fa-f ]+)"', txt):
        res.append((int(m.group(1)), int(m.group(2)), int(m.group(3)), m.group(4).replace(" ", "").upper()))
    return res


def validar_politica():
    pol = getattr(dns.dnssec, "allow_all_policy", None)
    return {"policy": pol} if pol is not None else {}


KW_POL = validar_politica()


def crear_ds(nombre, key, algoritmo):
    """DS calculado sin la política restrictiva de dnspython (para poder auditar digests SHA-1)."""
    try:
        return dns.dnssec.make_ds(nm(nombre), key, algoritmo, **KW_POL, validating=True)
    except TypeError:
        return dns.dnssec.make_ds(nm(nombre), key, algoritmo)


# -------------------------------------------------------------------------------- auditor
class Auditor:
    def __init__(self, cfgs, raiz_ip, anclas, args, base_arbol):
        self.cfgs = cfgs                       # nombre(txt) -> cfg
        self.raiz_ip = raiz_ip
        self.anclas = anclas
        self.args = args
        self.base = base_arbol
        self.net = Cliente(args.timeout)
        self.ahora = int(time.time())
        self._ip = {}
        self._claves = {}
        self._conf = {}

    # ------------------------------------------------------------ descubrimiento de servidores
    def ip(self, zona):
        zona = nm(zona)
        k = tx(zona)
        if k in self._ip:
            return self._ip[k]
        res = None
        if zona == dns.name.root:
            res = self.raiz_ip
        else:
            padre_ip = self.ip(zona.parent())
            if padre_ip:
                r = self.net.consulta(padre_ip, zona, rdt.NS)
                if r is not None:
                    ns = buscar(r.authority, zona, rdt.NS) or buscar(r.answer, zona, rdt.NS)
                    if ns is not None and buscar(r.answer, zona, rdt.NS) is not None and not (r.flags & dns.flags.AA == 0):
                        res = padre_ip               # misma máquina sirve ambas zonas
                    elif ns is not None:
                        for rd in ns:
                            a = buscar(r.additional, rd.target, rdt.A)
                            if a is not None:
                                res = a[0].address
                                break
                    elif r.rcode() == dns.rcode.NOERROR and not ns:
                        res = padre_ip               # no hay corte de zona en este nombre
        if res is None and k in self.cfgs and self.cfgs[k].get("ip"):
            res = self.cfgs[k]["ip"]
            self._ip_nota = True
        self._ip[k] = res
        return res

    # ------------------------------------------------------------ DNSKEY y firmas
    def claves(self, zona):
        k = tx(zona)
        if k in self._claves:
            return self._claves[k]
        ip = self.ip(zona)
        d = dict(ip=ip, rrset=None, sigs=[], rcode=None)
        if ip:
            r = self.net.consulta(ip, zona, rdt.DNSKEY)
            if r is not None:
                d["rcode"] = dns.rcode.to_text(r.rcode())
                d["rrset"] = buscar(r.answer, zona, rdt.DNSKEY)
                d["sigs"] = sigs_de(r.answer, zona, rdt.DNSKEY)
        self._claves[k] = d
        return d

    def evaluar_sig(self, rrset, sig, claves_rrset, apex):
        d = dict(cubre=rdt.to_text(sig.type_covered), alg=sig.algorithm, tag=sig.key_tag,
                 firmante=tx(sig.signer), inicio=sig.inception, fin=sig.expiration, labels=sig.labels,
                 ttl_orig=sig.original_ttl)
        d["alg_nombre"] = ALG.get(sig.algorithm, ("alg%d" % sig.algorithm, "DESCONOCIDO"))[0]
        d["llave_presente"] = False
        d["uso_llave"] = None
        if claves_rrset is not None:
            for k in claves_rrset:
                if k.algorithm == sig.algorithm and dns.dnssec.key_id(k) == sig.key_tag:
                    d["llave_presente"] = True
                    d["uso_llave"] = "KSK" if k.flags & 1 else "ZSK"
        d["crypto"], d["motivo"] = None, None
        if claves_rrset is not None and d["llave_presente"]:
            try:
                dns.dnssec.validate_rrsig(rrset, sig, {sig.signer: claves_rrset},
                                          now=(sig.inception + sig.expiration) // 2, **KW_POL)
                d["crypto"] = True
            except dns.dnssec.ValidationFailure as e:
                d["crypto"], d["motivo"] = False, str(e)
            except Exception as e:                       # algoritmo no soportado por la biblioteca
                d["crypto"], d["motivo"] = None, "%s: %s" % (e.__class__.__name__, e)
        elif claves_rrset is not None:
            d["crypto"], d["motivo"] = False, "el DNSKEY que firmó no está publicado en la zona"
        d["vigencia"] = "vigente"
        if sig.expiration < self.ahora:
            d["vigencia"] = "expirada"
        elif sig.inception > self.ahora:
            d["vigencia"] = "futura"
        d["dias_restantes"] = round((sig.expiration - self.ahora) / 86400.0, 1)
        d["firmante_ok"] = (nm(sig.signer) == nm(apex))
        d["valida"] = bool(d["crypto"]) and d["vigencia"] == "vigente"
        return d

    def validar_conjunto(self, rrset, sigs, claves_rrset, apex):
        """Devuelve (ok, motivo, lista_evaluaciones)."""
        evs = [self.evaluar_sig(rrset, s, claves_rrset, apex) for s in sigs]
        if not evs:
            return False, "sin RRSIG", evs
        if any(e["valida"] for e in evs):
            return True, "ok", evs
        if any(e["crypto"] and e["vigencia"] == "expirada" for e in evs):
            return False, "RRSIG expirada", evs
        if any(e["crypto"] and e["vigencia"] == "futura" for e in evs):
            return False, "RRSIG aún no vigente", evs
        return False, "RRSIG criptográficamente inválida o sin clave", evs

    # ------------------------------------------------------------ cadena de confianza
    def coincidencias_ds(self, zona, ds_rrset, dnskeys):
        res = []
        for ds in ds_rrset:
            info = DSDIG.get(ds.digest_type)
            e = dict(tag=ds.key_tag, alg=ds.algorithm, alg_nombre=ALG.get(ds.algorithm, ("alg%d" % ds.algorithm,))[0],
                     digest_tipo=ds.digest_type, digest_nombre=info[0] if info else "desconocido",
                     digest_estado=info[1] if info else "DESCONOCIDO", digest=hexs(ds.digest),
                     coincide=False, clave_uso=None)
            for k in dnskeys or []:
                if k.algorithm == ds.algorithm and dns.dnssec.key_id(k) == ds.key_tag and info and info[2]:
                    try:
                        hecho = crear_ds(zona, k, info[2])
                        if hecho.digest == ds.digest:
                            e["coincide"] = True
                            e["clave_uso"] = "KSK" if k.flags & 1 else "ZSK"
                    except Exception:
                        pass
            res.append(e)
        return res

    def prueba_sin_ds(self, r, zona, padre, padre_claves):
        """Comprueba si la respuesta del padre demuestra que NO hay DS (NSEC / NSEC3)."""
        zona = nm(zona)
        for rr in buscar_todos(r.authority, rdt.NSEC):
            if rr.name == zona:
                t = tipos_bitmap(rr[0])
                if "NS" in t and "DS" not in t and "SOA" not in t:
                    ok, motivo, _ = self.validar_conjunto(rr, sigs_de(r.authority, rr.name, rdt.NSEC), padre_claves, padre)
                    return dict(tipo="NSEC", firmada=ok, motivo=motivo)
        n3 = buscar_todos(r.authority, rdt.NSEC3)
        if n3:
            p = n3[0][0]
            h = nsec3_hash(zona, p.salt, p.iterations)
            for rr in n3:
                if rr.name.labels[0].decode().upper() == h:
                    t = tipos_bitmap(rr[0])
                    if "NS" in t and "DS" not in t and "SOA" not in t:
                        ok, motivo, _ = self.validar_conjunto(rr, sigs_de(r.authority, rr.name, rdt.NSEC3), padre_claves, padre)
                        return dict(tipo="NSEC3", firmada=ok, motivo=motivo)
            for rr in n3:                                # opt-out: cubre el nombre con la bandera activa
                if rr[0].flags & 1:
                    ok, motivo, _ = self.validar_conjunto(rr, sigs_de(r.authority, rr.name, rdt.NSEC3), padre_claves, padre)
                    return dict(tipo="NSEC3-optout", firmada=ok, motivo=motivo)
        return None

    def confianza(self, zona):
        k = tx(zona)
        if k in self._conf:
            return self._conf[k]
        zona = nm(zona)
        c = dict(zona=k, estado="INDETERMINATE", razones=[], enlace=None, claves=None, isla=False, padre=None)
        self._conf[k] = c                                # evita ciclos
        kd = self.claves(zona)
        dnskeys = list(kd["rrset"]) if kd["rrset"] is not None else []
        if kd["ip"] is None:
            c["estado"] = "NO_DISPONIBLE"
            c["razones"].append("no se pudo localizar el servidor autoritativo de la zona")
            return c
        if zona == dns.name.root:
            return self._confianza_raiz(c, kd, dnskeys)
        padre = nm(self.cfgs.get(k, {}).get("padre") or zona.parent())
        c["padre"] = tx(padre)
        cp = self.confianza(padre)
        enlace = dict(padre=tx(padre), hijo=k, ds=[], prueba_sin_ds=None, rfc=[])
        c["enlace"] = enlace
        c["isla"] = False
        if cp["estado"] in ("NO_DISPONIBLE", "INDETERMINATE"):
            c["razones"].append("no evaluable: el padre %s está %s" % (tx(padre), cp["estado"]))
            return c
        padre_ip = self.claves(padre)["ip"]
        r = self.net.consulta(padre_ip, zona, rdt.DS)
        ds_rrset = buscar(r.answer, zona, rdt.DS) if r is not None else None
        if r is None:
            c["razones"].append("el servidor del padre no respondió a la consulta DS")
            return c
        if cp["estado"] == "BOGUS":
            c["estado"] = "INDETERMINATE"
            c["razones"].append("no evaluable: el padre %s está BOGUS" % tx(padre))
            return c
        if ds_rrset is None:
            # --- sin DS en el padre
            enlace["rfc"] = ["RFC 4035 §5.2", "RFC 5155 §8.9 (NSEC3)"]
            if kd["rrset"] is not None:
                c["isla"] = True
            if cp["estado"] == "INSECURE":
                c["estado"] = "INSECURE"
                c["razones"].append("el padre %s ya es INSECURE: la inseguridad se hereda" % tx(padre))
            else:
                prueba = self.prueba_sin_ds(r, zona, padre, cp["claves"])
                enlace["prueba_sin_ds"] = prueba
                if prueba and prueba["firmada"]:
                    c["estado"] = "INSECURE"
                    c["razones"].append("delegación insegura DEMOSTRADA: %s firmado prueba que no existe DS" % prueba["tipo"])
                else:
                    c["estado"] = "BOGUS"
                    c["razones"].append("no hay DS y la ausencia no está demostrada con %s válido (%s)" %
                                        ("NSEC/NSEC3", prueba["motivo"] if prueba else "sin prueba"))
            if c["isla"]:
                c["razones"].append("ISLA DE SEGURIDAD: la zona publica DNSKEY/RRSIG pero el padre no publica su DS; "
                                    "ningún validador confiará en ella")
            return c
        # --- hay DS
        ok_ds, motivo_ds, evs_ds = self.validar_conjunto(ds_rrset, sigs_de(r.answer, zona, rdt.DS), cp["claves"], padre)
        enlace["ds"] = self.coincidencias_ds(zona, ds_rrset, dnskeys)
        enlace["ds_ttl"] = ds_rrset.ttl
        enlace["ds_sigs"] = evs_ds
        enlace["rfc"] = ["RFC 4034 §5 (DS)", "RFC 4035 §5.2", "RFC 4509 / RFC 6605", "RFC 8624"]
        if cp["estado"] == "INSECURE":
            c["estado"] = "INSECURE"
            c["razones"].append("el padre es INSECURE: el DS se ignora")
            return c
        if not ok_ds:
            c["estado"] = "BOGUS"
            c["razones"].append("el RRset DS no valida con las claves del padre: %s" % motivo_ds)
            return c
        if not dnskeys:
            c["estado"] = "BOGUS"
            c["razones"].append("el padre publica DS pero la zona hija no sirve DNSKEY (zona sin firmar o caída)")
            return c
        coinc = [e for e in enlace["ds"] if e["coincide"]]
        if not coinc:
            c["estado"] = "BOGUS"
            c["razones"].append("ningún DNSKEY de la hija produce el digest de ningún DS del padre (DS no coincide)")
            return c
        tags = {e["tag"] for e in coinc}
        firmas = [s for s in kd["sigs"] if s.key_tag in tags]
        if not firmas:
            c["estado"] = "BOGUS"
            c["razones"].append("el DNSKEY RRset no está firmado por la clave que referencia el DS")
            return c
        ok, motivo, evs = self.validar_conjunto(kd["rrset"], firmas, kd["rrset"], zona)
        if not ok:
            c["estado"] = "BOGUS"
            c["razones"].append("la RRSIG del DNSKEY firmada por la clave del DS no es válida: %s" % motivo)
            return c
        c["estado"] = "SECURE"
        c["claves"] = kd["rrset"]
        c["razones"].append("DS %s coincide con el DNSKEY y la firma del DNSKEY RRset es válida"
                            % ",".join(str(t) for t in sorted(tags)))
        return c

    def _confianza_raiz(self, c, kd, dnskeys):
        c["enlace"] = dict(padre=None, hijo=".", ds=[], rfc=["RFC 4035 §4.4 (ancla de confianza)"])
        if not dnskeys:
            c["estado"] = "BOGUS"
            c["razones"].append("la raíz no publica DNSKEY pero se configuró un ancla de confianza")
            return c
        anclas = self.anclas
        derivada = False
        if not anclas:
            derivada = True
            anclas = []
            for k in dnskeys:
                if k.flags & 1:
                    d = crear_ds(dns.name.root, k, "SHA256")
                    anclas.append((dns.dnssec.key_id(k), k.algorithm, 2, hexs(d.digest)))
            c["razones"].append("AVISO: ancla derivada de la propia raíz (no independiente); usa --ancla")
        match = set()
        for (tag, alg, dtp, hx) in anclas:
            for k in dnskeys:
                info = DSDIG.get(dtp)
                if k.algorithm == alg and dns.dnssec.key_id(k) == tag and info and info[2]:
                    if hexs(crear_ds(dns.name.root, k, info[2]).digest) == hx:
                        match.add(tag)
        c["enlace"]["ds"] = [dict(tag=t, alg=a, alg_nombre=ALG.get(a, ("?",))[0], digest_tipo=d,
                                  digest_nombre=DSDIG.get(d, ("?",))[0], digest_estado=DSDIG.get(d, ("", "?"))[1],
                                  digest=h, coincide=(t in match), clave_uso="KSK" if t in match else None)
                             for (t, a, d, h) in anclas]
        if not match:
            c["estado"] = "BOGUS"
            c["razones"].append("ningún DNSKEY de la raíz coincide con el ancla de confianza configurada")
            return c
        firmas = [s for s in kd["sigs"] if s.key_tag in match]
        ok, motivo, _ = self.validar_conjunto(kd["rrset"], firmas, kd["rrset"], dns.name.root) if firmas else (False, "sin RRSIG del ancla", [])
        if not ok:
            c["estado"] = "BOGUS"
            c["razones"].append("DNSKEY de la raíz no valida con el ancla: %s" % motivo)
            return c
        c["estado"] = "SECURE"
        c["claves"] = kd["rrset"]
        c["razones"].insert(0, "ancla de confianza %s coincide y valida el DNSKEY de la raíz" %
                            ",".join(str(t) for t in sorted(match)))
        return c

    # ------------------------------------------------------------ análisis por zona
    def ciclo_vida(self, cfg, tag):
        if not self.args.llaves_base or not cfg.get("dir"):
            ruta_base = self.base
        else:
            ruta_base = self.args.llaves_base
        if not ruta_base or not cfg.get("dir"):
            return None
        d = os.path.join(ruta_base, cfg["dir"], "keys")
        if not os.path.isdir(d):
            return None
        for f in os.listdir(d):
            if f.endswith(".private") and f.split("+")[-1].startswith("%05d" % tag):
                meta = {}
                for linea in open(os.path.join(d, f), encoding="utf-8"):
                    m = re.match(r"(Created|Publish|Activate|Revoke|Inactive|Delete):\s+(\d{14})", linea)
                    if m:
                        meta[m.group(1)] = int(time.mktime(time.strptime(m.group(2), "%Y%m%d%H%M%S"))) - time.timezone
                estado = "publicada"
                for nombre, etq in (("Activate", "activa"), ("Inactive", "inactiva (retirada)"), ("Delete", "eliminable")):
                    if nombre in meta and meta[nombre] <= self.ahora:
                        estado = etq
                if "Revoke" in meta and meta["Revoke"] <= self.ahora:
                    estado = "revocada"
                return dict(estado=estado, **{k.lower(): fmt_ts(v) for k, v in meta.items()})
        return None

    def analizar_dnskey(self, zona, cfg, kd, evals_por_tag):
        res = []
        if kd["rrset"] is None:
            return res
        for k in kd["rrset"]:
            tag = dns.dnssec.key_id(k)
            nombre, estado_alg = ALG.get(k.algorithm, ("alg%d" % k.algorithm, "DESCONOCIDO"))
            if k.algorithm in CURVAS:
                tipo_clave = "EC %s" % CURVAS[k.algorithm][0]
                bits = CURVAS[k.algorithm][1]
            else:
                bits = rsa_bits(k.key)
                tipo_clave = "RSA %s bits" % bits
            problemas, avisos = [], []
            if estado_alg in ("PROHIBIDO", "DESCONOCIDO"):
                problemas.append("algoritmo %s %s (RFC 8624)" % (nombre, estado_alg))
            elif estado_alg == "DESACONSEJADO":
                avisos.append("algoritmo %s DESACONSEJADO (RFC 8624)" % nombre)
            if k.algorithm in (1, 3, 5, 6, 7, 8, 10) and bits:
                if bits < 1024:
                    problemas.append("clave RSA de %d bits: insegura" % bits)
                elif bits < 2048:
                    avisos.append("clave RSA de %d bits: se recomiendan >= 2048" % bits)
            if k.protocol != 3:
                problemas.append("campo protocolo = %d (debe ser 3, RFC 4034 §2.1.2)" % k.protocol)
            if not (k.flags & 0x100):
                problemas.append("bit 'Zone Key' apagado (RFC 4034 §2.1.1): no puede firmar datos de zona")
            revocada = bool(k.flags & 0x80)
            if revocada:
                problemas.append("clave REVOCADA (RFC 5011)")
            evs = evals_por_tag.get((tag, k.algorithm), [])
            firma_dnskey = any(e["cubre"] == "DNSKEY" for e in evs)
            firma_datos = any(e["cubre"] != "DNSKEY" for e in evs)
            if evs:
                if any(e["valida"] for e in evs):
                    estado = "válida"
                elif any(e["vigencia"] == "expirada" for e in evs):
                    estado = "expirada"
                else:
                    estado = "inválida"
            else:
                estado = "sin firmas observadas"
            if problemas:
                estado = "inválida"
            uso = "KSK (SEP)" if k.flags & 1 else "ZSK"
            if (k.flags & 1) and not firma_dnskey:
                avisos.append("KSK que no firma el DNSKEY RRset")
            res.append(dict(tag=tag, flags=k.flags, uso=uso, alg=k.algorithm, alg_nombre=nombre, alg_estado=estado_alg,
                            tipo_clave=tipo_clave, bits=bits, protocolo=k.protocol, revocada=revocada,
                            firma_dnskey=firma_dnskey, firma_datos=firma_datos, estado=estado,
                            ciclo_vida=self.ciclo_vida(cfg, tag), problemas=problemas, avisos=avisos))
        return res

    def revisar_rrsets(self, zona, cfg, ip, kd):
        zona_n = nm(zona)
        ttl_esp = cfg.get("ttl_esperado") or self.args.ttl
        consultas = [(zona_n, rdt.SOA), (zona_n, rdt.NS), (zona_n, rdt.DNSKEY)]
        r_ns = self.net.consulta(ip, zona_n, rdt.NS)
        if r_ns is not None:
            ns = buscar(r_ns.answer, zona_n, rdt.NS)
            if ns is not None:
                for rd in ns:
                    if rd.target.is_subdomain(zona_n):
                        consultas.append((rd.target, rdt.A))
        if cfg.get("www"):
            consultas.append((nm("www." + tx(zona_n)) if zona_n != dns.name.root else nm("www."), rdt.A))
        r_p = self.net.consulta(ip, zona_n, rdt.NSEC3PARAM)
        if r_p is not None and buscar(r_p.answer, zona_n, rdt.NSEC3PARAM) is not None:
            consultas.append((zona_n, rdt.NSEC3PARAM))
        filas, soa = [], None
        evals_por_tag = {}
        for (qn, qt) in consultas:
            r = self.net.consulta(ip, qn, qt)
            if r is None:
                continue
            rr = buscar(r.answer, qn, qt)
            if rr is None:
                continue
            if qt == rdt.SOA:
                x = rr[0]
                soa = dict(mname=tx(x.mname), rname=tx(x.rname), serial=x.serial, refresh=x.refresh, retry=x.retry,
                           expire=x.expire, minimum=x.minimum)
            sigs = sigs_de(r.answer, qn, qt)
            evs = [self.evaluar_sig(rr, s, kd["rrset"], zona_n) for s in sigs] if kd["rrset"] is not None else []
            for e in evs:
                evals_por_tag.setdefault((e["tag"], e["alg"]), []).append(e)
            esp = 0 if qt == rdt.NSEC3PARAM else ttl_esp          # BIND publica NSEC3PARAM con TTL 0
            filas.append(dict(nombre=tx(qn), tipo=rdt.to_text(qt), ttl_obs=rr.ttl, ttl_esp=esp,
                              ttl_ok=(rr.ttl == esp), datos=[x.to_text()[:70] for x in rr][:4],
                              firmas=evs, firmado=bool(evs),
                              ttl_orig_ok=all(e["ttl_orig"] == rr.ttl for e in evs) if evs else None))
        return filas, soa, evals_por_tag

    def denegacion(self, zona, ip, kd, firmada, soa):
        zona_n = nm(zona)
        d = dict(modo="ninguno", nsec3=None, nsec3param=None, avisos=[], nsec_ttl=None, nsec_ttl_ok=None, firmas_ok=None)
        rp = self.net.consulta(ip, zona_n, rdt.NSEC3PARAM)
        pa = buscar(rp.answer, zona_n, rdt.NSEC3PARAM) if rp is not None else None
        if pa is not None:
            x = pa[0]
            d["nsec3param"] = dict(alg=x.algorithm, flags=x.flags, iteraciones=x.iterations, sal=hexs(x.salt) if x.salt else "-")
        sonda = nm("nx-" + "".join(random.choice(string.ascii_lowercase) for _ in range(10)) + "." + (tx(zona_n) if zona_n != dns.name.root else ""))
        r = self.net.consulta(ip, sonda, rdt.A, cache=False)
        if r is None:
            return d
        nsecs, n3s = buscar_todos(r.authority, rdt.NSEC), buscar_todos(r.authority, rdt.NSEC3)
        if n3s:
            d["modo"] = "NSEC3"
            x = n3s[0][0]
            d["nsec3"] = dict(alg=x.algorithm, flags=x.flags, optout=bool(x.flags & 1), iteraciones=x.iterations,
                              sal=hexs(x.salt) if x.salt else "-")
            if x.algorithm != 1:
                d["avisos"].append("algoritmo de hash NSEC3 %d no definido (RFC 5155)" % x.algorithm)
            if x.iterations > 0:
                d["avisos"].append("NSEC3 con %d iteraciones: RFC 9276 exige 0 (más CPU, sin ganancia real; "
                                   "BIND/Unbound tratan >50/150 como inseguro)" % x.iterations)
            if x.salt:
                d["avisos"].append("NSEC3 con sal: RFC 9276 recomienda sal vacía (no aporta protección)")
            if x.flags & 1:
                d["avisos"].append("opt-out activo: delegaciones no firmadas quedan fuera de la cadena NSEC3")
            if pa is None:
                d["avisos"].append("NSEC3 sin NSEC3PARAM en el ápice")
            rrs = n3s
        elif nsecs:
            d["modo"] = "NSEC"
            rrs = nsecs
        else:
            rrs = []
            if firmada:
                d["avisos"].append("zona firmada pero la respuesta NXDOMAIN no trae NSEC ni NSEC3")
        if rrs and kd["rrset"] is not None:
            oks = []
            for rr in rrs:
                oks.append(self.validar_conjunto(rr, sigs_de(r.authority, rr.name, rr.rdtype), kd["rrset"], zona_n)[0])
            d["firmas_ok"] = all(oks)
            d["nsec_ttl"] = rrs[0].ttl
            if soa:
                d["nsec_ttl_ok"] = (rrs[0].ttl == min(soa["minimum"], rrs[0].ttl) and rrs[0].ttl == soa["minimum"])
        return d

    def zone_walk(self, zona, ip):
        zona_n = nm(zona)
        vistos, nombres = set(), []
        actual = zona_n
        for _ in range(self.args.max_walk):
            if actual in vistos:
                break
            vistos.add(actual)
            r = self.net.consulta(ip, actual, rdt.NSEC, cache=False)
            rr = buscar(r.answer, actual, rdt.NSEC) if r is not None else None
            if rr is None:
                break
            nombres.append(dict(nombre=tx(actual), tipos=tipos_bitmap(rr[0])))
            actual = rr[0].next
            if actual == zona_n:
                break
        return nombres

    def nsec3_enumeracion(self, zona, ip, nsec3, diccionario):
        """Reconstruye la cadena de hashes NSEC3 (sin revertirlos) y ensaya un ataque de diccionario."""
        zona_n = nm(zona)
        if not nsec3:
            return None
        sal = bytes.fromhex(nsec3["sal"]) if nsec3["sal"] != "-" else b""
        cadena = {}                                           # hash propietario -> hash siguiente
        tipos = {}
        consultas = 0

        def registrar(r):
            for rr in buscar_todos(r.authority, rdt.NSEC3):
                prop = rr.name.labels[0].decode().upper()
                cadena[prop] = base64.b32hexencode(rr[0].next).decode().rstrip("=").upper()
                tipos[prop] = tipos_bitmap(rr[0])

        def sondear(etiqueta):
            nonlocal consultas
            r = self.net.consulta(ip, nm(etiqueta + "." + tx(zona_n)), rdt.A, cache=False)
            consultas += 1
            if r is not None:
                registrar(r)

        azar = lambda n: "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(n))
        for _ in range(8):
            sondear(azar(12))
        while consultas < self.args.sondas:
            faltan = sorted(h for h in set(cadena.values()) if h not in cadena)
            if not faltan:
                break
            nx = faltan[0]
            conocidos = sorted(cadena)
            sup = next((h for h in conocidos if h > nx), None)
            for _ in range(300000):                           # busca localmente un nombre cuyo hash caiga en el hueco
                et = azar(10)
                h = nsec3_hash(et + "." + tx(zona_n), sal, nsec3["iteraciones"])
                if (sup is not None and nx < h < sup) or (sup is None and (h > nx or h < conocidos[0])):
                    sondear(et)
                    break
            else:
                break
        cerrada = bool(cadena) and all(v in cadena for v in cadena.values())
        recuperados = []
        for palabra in list(diccionario) + [""]:
            nombre = (palabra + "." if palabra else "") + tx(zona_n)
            h = nsec3_hash(nombre, sal, nsec3["iteraciones"])
            if h in cadena:
                recuperados.append(dict(nombre=nombre, hash=h, tipos=tipos[h]))
        return dict(hashes_unicos=len(cadena), cadena_cerrada=cerrada, recuperados=recuperados, sondas=consultas,
                    diccionario=len(diccionario) + 1, no_recuperados=len(cadena) - len(recuperados))

    def zona(self, nombre):
        cfg = self.cfgs[nombre]
        z = dict(zona=nombre, cfg={k: cfg.get(k) for k in ("padre", "ip", "esperado", "escenario", "nota", "alg", "nsec")},
                 hallazgos=[])
        ip = self.ip(nombre)
        z["ip"] = ip
        if ip is None:
            z["estado"] = "NO_DISPONIBLE"
            z["hallazgos"].append(("ERROR", "no se encontró servidor autoritativo (¿está levantado el laboratorio?)"))
            return z
        kd = self.claves(nombre)
        firmada = kd["rrset"] is not None
        z["firmada"] = firmada
        if kd["rcode"] is None:
            z["estado"] = "NO_DISPONIBLE"
            z["hallazgos"].append(("ERROR", "el servidor %s no responde" % ip))
            return z
        conf = self.confianza(nombre)
        z["estado"], z["razones"], z["enlace"], z["isla"] = conf["estado"], conf["razones"], conf["enlace"], conf["isla"]
        filas, soa, evals_por_tag = self.revisar_rrsets(nombre, cfg, ip, kd)
        z["rrsets"], z["soa"] = filas, soa
        z["dnskey"] = self.analizar_dnskey(nombre, cfg, kd, evals_por_tag)
        z["denegacion"] = self.denegacion(nombre, ip, kd, firmada, soa)
        if firmada and kd["rrset"] is not None:
            ok_k, motivo_k, evs_k = self.validar_conjunto(kd["rrset"], kd["sigs"], kd["rrset"], nm(nombre))
            z["dnskey_rrset_firma"] = dict(ok=ok_k, motivo=motivo_k,
                                           firmantes=sorted({(e["tag"], e["uso_llave"]) for e in evs_k if e["valida"]}))
        # zone walking
        z["walk"] = None
        if firmada and not self.args.no_walk:
            if z["denegacion"]["modo"] == "NSEC":
                nombres = self.zone_walk(nombre, ip)
                z["walk"] = dict(modo="NSEC", nombres=nombres, enumerada=bool(nombres))
            elif z["denegacion"]["modo"] == "NSEC3":
                z["walk"] = dict(modo="NSEC3", nombres=[], enumerada=False,
                                 nsec3=self.nsec3_enumeracion(nombre, ip, z["denegacion"]["nsec3"], self.args.diccionario_lista))
        self.hallazgos(z, cfg)
        return z

    # ------------------------------------------------------------ hallazgos y esperados
    def hallazgos(self, z, cfg):
        h = z["hallazgos"]
        esp = cfg.get("esperado")
        z["esperado"] = esp
        z["coincide_esperado"] = (esp is None) or (z["estado"] == esp)
        if esp and z["estado"] != esp:
            h.append(("ERROR", "estado %s distinto del diseñado (%s)" % (z["estado"], esp)))
        if z["estado"] == "BOGUS":
            h.append(("ERROR", "cadena de confianza rota: %s" % "; ".join(z["razones"])))
        if z.get("isla"):
            h.append(("AVISO", "isla de seguridad (zona firmada sin DS en el padre)"))
        for k in z["dnskey"]:
            for p in k["problemas"]:
                h.append(("ERROR", "DNSKEY %d: %s" % (k["tag"], p)))
            for a in k["avisos"]:
                h.append(("AVISO", "DNSKEY %d: %s" % (k["tag"], a)))
            if k["estado"] == "expirada":
                h.append(("ERROR", "DNSKEY %d: todas sus firmas están expiradas" % k["tag"]))
        for f in z["rrsets"]:
            if not f["ttl_ok"] and f["tipo"] != "DNSKEY":
                h.append(("AVISO", "TTL de %s %s = %d, se esperaba %d" % (f["nombre"], f["tipo"], f["ttl_obs"], f["ttl_esp"])))
            if f["ttl_orig_ok"] is False:
                h.append(("AVISO", "RRSIG de %s %s: TTL original distinto del TTL del RRset (RFC 4034 §3.1.4)" % (f["nombre"], f["tipo"])))
            for e in f["firmas"]:
                if e["vigencia"] == "expirada":
                    h.append(("ERROR", "RRSIG de %s %s expirada el %s" % (f["nombre"], f["tipo"], fmt_ts(e["fin"]))))
                elif e["vigencia"] == "futura":
                    h.append(("ERROR", "RRSIG de %s %s aún no vigente (inicia %s)" % (f["nombre"], f["tipo"], fmt_ts(e["inicio"]))))
                elif e["dias_restantes"] < self.args.umbral_dias:
                    h.append(("AVISO", "RRSIG de %s %s vence en %.1f días" % (f["nombre"], f["tipo"], e["dias_restantes"])))
                if e["crypto"] is False:
                    h.append(("ERROR", "RRSIG de %s %s inválida: %s" % (f["nombre"], f["tipo"], e["motivo"])))
                if not e["firmante_ok"]:
                    h.append(("ERROR", "RRSIG de %s %s firmada por %s, no por la zona" % (f["nombre"], f["tipo"], e["firmante"])))
        if z["firmada"] and not any(f["firmado"] for f in z["rrsets"]):
            h.append(("ERROR", "zona con DNSKEY pero sin RRSIG en sus datos"))
        for a in z["denegacion"]["avisos"]:
            h.append(("AVISO", a))
        if z["denegacion"]["nsec_ttl_ok"] is False:
            h.append(("AVISO", "TTL de NSEC/NSEC3 distinto del mínimo del SOA (RFC 4034 §4 / RFC 9077)"))
        w = z.get("walk")
        if w and w["modo"] == "NSEC" and w["enumerada"]:
            h.append(("AVISO", "zone walking posible: NSEC reveló %d nombres de la zona" % len(w["nombres"])))
        if w and w["modo"] == "NSEC3":
            n3 = w["nsec3"]
            if n3 and n3["recuperados"]:
                h.append(("INFO", "NSEC3 impide el recorrido directo, pero un diccionario recuperó %d nombres" % len(n3["recuperados"])))


# --------------------------------------------------------------------------- recursivos
def comparar_recursivos(aud, resolvers, nombres_zonas):
    filas = []
    for zn in nombres_zonas:
        cfg = aud.cfgs[zn]
        consultas = [(nm(zn), rdt.SOA)]
        if cfg.get("www"):
            consultas.append((nm("www." + zn if zn != "." else "www."), rdt.A))
        for qn, qt in consultas:
            fila = dict(zona=zn, consulta="%s %s" % (tx(qn), rdt.to_text(qt)), resultados={})
            for rip in resolvers:
                r = aud.net.consulta(rip, qn, qt, rd=True, cache=False)
                if r is None:
                    fila["resultados"][rip] = dict(rcode="TIMEOUT", ad=False, ede=[])
                    continue
                ede = []
                for o in getattr(r, "options", []) or []:
                    try:
                        if o.otype == 15:
                            ede.append("%d %s" % (o.code, EDE.get(o.code, o.text or "")))
                    except Exception:
                        pass
                fila["resultados"][rip] = dict(rcode=dns.rcode.to_text(r.rcode()), ad=bool(r.flags & dns.flags.AD),
                                               ede=ede, respuestas=sum(len(x) for x in r.answer))
            filas.append(fila)
    return filas


# ------------------------------------------------------------------------------- salida
def metricas(res, comp):
    zonas = [z for z in res.values()]
    m = dict(zonas_total=len(zonas))
    for e in ("SECURE", "INSECURE", "BOGUS", "INDETERMINATE", "NO_DISPONIBLE"):
        m["zonas_" + e.lower()] = sum(1 for z in zonas if z["estado"] == e)
    m["zonas_firmadas"] = sum(1 for z in zonas if z.get("firmada"))
    m["islas_de_seguridad"] = sum(1 for z in zonas if z.get("isla"))
    m["coinciden_con_diseno"] = sum(1 for z in zonas if z.get("coincide_esperado"))
    algs, nsec, ttl_tot, ttl_ok, dias, claves = {}, {}, 0, 0, [], 0
    for z in zonas:
        for k in z.get("dnskey", []):
            claves += 1
            key = "%s (%s)" % (k["alg_nombre"], k["alg_estado"])
            algs[key] = algs.get(key, 0) + 1
        if z.get("firmada"):
            modo = z["denegacion"]["modo"]
            nsec[modo] = nsec.get(modo, 0) + 1
        for f in z.get("rrsets", []):
            if f["tipo"] != "DNSKEY":
                ttl_tot += 1
                ttl_ok += 1 if f["ttl_ok"] else 0
            for e in f["firmas"]:
                dias.append(e["dias_restantes"])
    m.update(dnskeys_total=claves, algoritmos=algs, denegacion=nsec, rrsets_ttl_evaluados=ttl_tot,
             rrsets_ttl_consistentes=ttl_ok, rrsig_dias_min=min(dias) if dias else None,
             rrsig_dias_max=max(dias) if dias else None,
             rrsig_expiradas=sum(1 for z in zonas for f in z.get("rrsets", []) for e in f["firmas"] if e["vigencia"] == "expirada"),
             hallazgos_error=sum(1 for z in zonas for s, _ in z["hallazgos"] if s == "ERROR"),
             hallazgos_aviso=sum(1 for z in zonas for s, _ in z["hallazgos"] if s == "AVISO"),
             zone_walking_posible=sum(1 for z in zonas if z.get("walk") and z["walk"]["modo"] == "NSEC" and z["walk"]["enumerada"]),
             zonas_nsec3_diccionario=sum(1 for z in zonas if z.get("walk") and z["walk"]["modo"] == "NSEC3"
                                         and z["walk"]["nsec3"] and z["walk"]["nsec3"]["recuperados"]))
    return m


def imprimir_arbol(res, cfgs):
    hijos = {}
    for n, c in cfgs.items():
        hijos.setdefault(c.get("padre"), []).append(n)
    raices = [n for n, c in cfgs.items() if c.get("padre") is None or c.get("padre") not in cfgs]
    out = []

    def etiqueta(n):
        z = res[n]
        e = z["estado"]
        extra = ""
        en = z.get("enlace") or {}
        coinc = [d for d in en.get("ds", []) if d.get("coincide")]
        if coinc:
            extra = "  DS %s→KSK" % ",".join(str(d["tag"]) for d in coinc)
        elif z.get("isla"):
            extra = "  (firmada, SIN DS en el padre)"
        alg = ",".join(sorted({k["alg_nombre"] for k in z.get("dnskey", [])}))
        modo = z.get("denegacion", {}).get("modo", "")
        det = (" %s %s" % (alg, modo)) if alg else ""
        esp = "" if z.get("coincide_esperado", True) else "  ≠ diseño(%s)" % z.get("esperado")
        return "%s [%s]%s%s%s" % (n, color(e, e), det, extra, esp)

    def rec(n, prefijo, ultimo, raiz=False):
        out.append((prefijo + ("" if raiz else ("└── " if ultimo else "├── "))) + etiqueta(n))
        hs = sorted(hijos.get(n, []), key=lambda x: cfgs[x].get("ip") or x)
        for i, h in enumerate(hs):
            rec(h, prefijo + ("" if raiz else ("    " if ultimo else "│   ")), i == len(hs) - 1)

    for r in raices:
        rec(r, "", True, True)
    return "\n".join(out)


def informe_zona(z):
    L = []
    L.append("=" * 100)
    L.append("ZONA %s   servidor %s   estado de la cadena: %s" % (z["zona"], z.get("ip"), color(z["estado"], z["estado"])))
    if z["estado"] == "NO_DISPONIBLE":
        for s, m in z["hallazgos"]:
            L.append("  [%s] %s" % (color(s, s), m))
        return "\n".join(L)
    esp = z.get("esperado")
    if esp:
        L.append("  diseño: %s -> %s   (%s)" % (z["cfg"].get("nota") or z["cfg"].get("escenario") or "", esp,
                                               "coincide" if z["coincide_esperado"] else color("NO COINCIDE", "ERROR")))
    for r in z["razones"]:
        L.append("  · " + r)
    en = z.get("enlace") or {}
    if en.get("ds"):
        L.append("  DS publicados en %s:" % (en.get("padre") or "la configuración (ancla)"))
        for d in en["ds"]:
            L.append("     tag %-5d alg %-2d %-16s digest %-8s [%s]  %s  %s" % (
                d["tag"], d["alg"], d["alg_nombre"], d["digest_nombre"], d["digest_estado"],
                "coincide con " + d["clave_uso"] if d["coincide"] else color("NO COINCIDE con ningún DNSKEY", "ERROR"),
                d["digest"][:16] + "…"))
    if en.get("prueba_sin_ds"):
        p = en["prueba_sin_ds"]
        L.append("  Prueba de ausencia de DS: %s (firma %s)" % (p["tipo"], "válida" if p["firmada"] else "inválida: " + p["motivo"]))
    L.append("  DNSKEY:")
    if not z["dnskey"]:
        L.append("     (la zona no publica DNSKEY: sin firmar)")
    for k in z["dnskey"]:
        cv = k["ciclo_vida"]["estado"] if k["ciclo_vida"] else "-"
        L.append("     tag %-5d %-9s alg %-2d %-16s [%s] %-16s estado: %-9s firma: %s ciclo:%s" % (
            k["tag"], k["uso"], k["alg"], k["alg_nombre"], k["alg_estado"], k["tipo_clave"], k["estado"],
            ("DNSKEY " if k["firma_dnskey"] else "") + ("datos" if k["firma_datos"] else ""), cv))
        for p in k["problemas"]:
            L.append("        " + color("✗ " + p, "ERROR"))
        for a in k["avisos"]:
            L.append("        " + color("! " + a, "AVISO"))
    L.append("  RRsets (TTL observado en el autoritativo / esperado) y firmas:")
    for f in z["rrsets"]:
        marca = "ok" if f["ttl_ok"] else "≠"
        L.append("     %-26s %-10s ttl %-6d/%-6d %-2s  %s" % (f["nombre"], f["tipo"], f["ttl_obs"], f["ttl_esp"], marca,
                                                              ("; ".join(f["datos"][:2]))[:60]))
        for e in f["firmas"]:
            L.append("         RRSIG tag %-5d (%s) %-15s firmante %-14s %s → %s  [%s%s]  cripto:%s" % (
                e["tag"], e["uso_llave"] or "?", e["alg_nombre"], e["firmante"], fmt_ts(e["inicio"]), fmt_ts(e["fin"]),
                e["vigencia"], (", %.1f d" % e["dias_restantes"]) if e["vigencia"] == "vigente" else
                (", hace %.1f d" % -e["dias_restantes"]) if e["vigencia"] == "expirada" else "",
                {True: "OK", False: "FALLA", None: "?"}[e["crypto"]]))
    if z.get("soa"):
        s = z["soa"]
        L.append("  SOA: serial %d refresh %d retry %d expire %d minimum %d" % (s["serial"], s["refresh"], s["retry"], s["expire"], s["minimum"]))
    d = z["denegacion"]
    L.append("  Denegación de existencia: %s" % d["modo"])
    if d["nsec3param"]:
        p = d["nsec3param"]
        L.append("     NSEC3PARAM: hash alg %d, flags %d, iteraciones %d, sal %s" % (p["alg"], p["flags"], p["iteraciones"], p["sal"]))
    if d["nsec_ttl"] is not None:
        L.append("     TTL de NSEC/NSEC3 = %d (%s con el mínimo del SOA)" % (d["nsec_ttl"], "coincide" if d["nsec_ttl_ok"] else "NO coincide"))
    w = z.get("walk")
    if w:
        if w["modo"] == "NSEC":
            L.append("  Zone walking con NSEC: %s" % (color("POSIBLE", "AVISO") if w["enumerada"] else "no"))
            for n in w["nombres"]:
                L.append("     %-28s %s" % (n["nombre"], " ".join(n["tipos"])))
        else:
            n3 = w["nsec3"] or {}
            L.append("  Zone walking con NSEC3: recorrido directo IMPOSIBLE (la cadena solo contiene hashes). Con %d consultas se "
                     "reconstruyó %s la cadena: %d hashes (= %d nombres con datos);"
                     % (n3.get("sondas", 0), "COMPLETA" if n3.get("cadena_cerrada") else "parcialmente",
                        n3.get("hashes_unicos", 0), n3.get("hashes_unicos", 0)))
            L.append("     un diccionario de %d palabras recuperó %d nombres; %d hashes siguen sin revertir"
                     % (n3.get("diccionario", 0), len(n3.get("recuperados", [])), n3.get("no_recuperados", 0)))
            for r in n3.get("recuperados", []):
                L.append("     %-28s %s  %s" % (r["nombre"], r["hash"], " ".join(r["tipos"])))
    if z["hallazgos"]:
        L.append("  Hallazgos:")
        for s, m in z["hallazgos"]:
            L.append("     [%s] %s" % (color(s, s), m))
    return "\n".join(L)


def exportar_dot(res, cfgs, ruta):
    col = {"SECURE": "palegreen", "INSECURE": "khaki", "BOGUS": "lightcoral", "INDETERMINATE": "plum", "NO_DISPONIBLE": "gray90"}
    L = ["digraph dnssec {", "  rankdir=TB; node [shape=box, style=filled, fontname=Helvetica];"]
    for n, z in res.items():
        alg = ",".join(sorted({k["alg_nombre"] for k in z.get("dnskey", [])}))
        L.append('  "%s" [fillcolor=%s, label="%s\\n%s\\n%s %s"];' % (n, col.get(z["estado"], "white"), n, z["estado"], alg,
                                                                   z.get("denegacion", {}).get("modo", "")))
    for n, z in res.items():
        p = cfgs[n].get("padre")
        if p and p in res:
            en = z.get("enlace") or {}
            coinc = [d for d in en.get("ds", []) if d.get("coincide")]
            if coinc:
                L.append('  "%s" -> "%s" [label="DS %s", color=darkgreen];' % (p, n, coinc[0]["tag"]))
            elif en.get("ds"):
                L.append('  "%s" -> "%s" [label="DS NO COINCIDE", color=red, style=bold];' % (p, n))
            else:
                L.append('  "%s" -> "%s" [label="sin DS", style=dashed, color=%s];' % (p, n, "orange" if z.get("isla") else "gray50"))
    L.append("}")
    open(ruta, "w", encoding="utf-8").write("\n".join(L) + "\n")


def exportar_csv(res, ruta):
    with open(ruta, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["zona", "estado_cadena", "nombre", "tipo", "ttl_observado", "ttl_esperado", "ttl_ok", "rrsig_tag",
                    "rrsig_uso", "rrsig_alg", "rrsig_firmante", "rrsig_inicio", "rrsig_fin", "rrsig_vigencia",
                    "rrsig_dias_restantes", "rrsig_ttl_original", "rrsig_cripto"])
        for n, z in res.items():
            for fl in z.get("rrsets", []):
                base = [n, z["estado"], fl["nombre"], fl["tipo"], fl["ttl_obs"], fl["ttl_esp"], fl["ttl_ok"]]
                if not fl["firmas"]:
                    w.writerow(base + [""] * 10)
                for e in fl["firmas"]:
                    w.writerow(base + [e["tag"], e["uso_llave"], e["alg_nombre"], e["firmante"], fmt_ts(e["inicio"]),
                                       fmt_ts(e["fin"]), e["vigencia"], e["dias_restantes"], e["ttl_orig"], e["crypto"]])


def comparar_json(a, b):
    A, B = json.load(open(a, encoding="utf-8")), json.load(open(b, encoding="utf-8"))
    print("COMPARACIÓN  A=%s  B=%s" % (a, b))
    print("-" * 100)
    print("%-20s %-15s %-15s %s" % ("zona", "A", "B", "diferencias"))
    todas = sorted(set(A["zonas"]) | set(B["zonas"]), key=lambda n: (n.count("."), n))
    for n in todas:
        za, zb = A["zonas"].get(n), B["zonas"].get(n)
        ea = za["estado"] if za else "(no existe)"
        eb = zb["estado"] if zb else "(no existe)"
        dif = []
        if za and zb:
            ka = sorted("%s/%s" % (k["uso"][:3], k["alg_nombre"]) for k in za["dnskey"])
            kb = sorted("%s/%s" % (k["uso"][:3], k["alg_nombre"]) for k in zb["dnskey"])
            if ka != kb:
                dif.append("claves A=%s B=%s" % (",".join(ka) or "-", ",".join(kb) or "-"))
            if za["denegacion"]["modo"] != zb["denegacion"]["modo"]:
                dif.append("denegación %s→%s" % (za["denegacion"]["modo"], zb["denegacion"]["modo"]))
            ha, hb = len(za["hallazgos"]), len(zb["hallazgos"])
            if ha != hb:
                dif.append("hallazgos %d→%d" % (ha, hb))
        print("%-20s %-15s %-15s %s" % (n, ea, eb, "; ".join(dif) if (ea != eb or dif) else "="))
    print("-" * 100)
    print("MÉTRICAS")
    ma, mb = A["metricas"], B["metricas"]
    for k in sorted(set(ma) | set(mb)):
        if ma.get(k) != mb.get(k):
            print("  %-30s A=%s   B=%s" % (k, ma.get(k), mb.get(k)))


# --------------------------------------------------------------------------------- main
def cargar_arbol(args):
    cfgs, raiz_ip, recursivos, base = {}, args.raiz, {}, None
    if args.arbol:
        data = json.load(open(args.arbol, encoding="utf-8"))
        base = os.path.dirname(os.path.abspath(args.arbol))
        raiz_ip = raiz_ip or data.get("raiz_ip")
        recursivos = data.get("recursivos", {})
        for z in data["zonas"]:
            c = dict(padre=z.get("padre"), ip=z.get("ip"), dir=z.get("dir"), www=z.get("www"), esperado=z.get("esperado"),
                     escenario=z.get("escenario"), nota=z.get("nota"), ttl_esperado=z.get("ttl_esperado"),
                     alg=z.get("alg"), nsec=z.get("nsec"))
            cfgs[tx(z["zone"])] = c
    for zn in args.zonas or []:
        k = tx(zn)
        if k not in cfgs:
            cfgs[k] = dict(padre=None, ip=None)
    if not cfgs:
        sys.exit("Indica --arbol arbol.json o --zonas . signed beta.signed ...")
    for k, c in cfgs.items():
        if not c.get("padre") and k != ".":
            cand = nm(k).parent()
            while tx(cand) not in cfgs and cand != dns.name.root:
                cand = cand.parent()
            c["padre"] = tx(cand) if tx(cand) in cfgs or cand == dns.name.root else None
        if c.get("padre") and tx(c["padre"]) in cfgs:
            c["padre"] = tx(c["padre"])
    if args.solo:
        keep = {tx(s) for s in args.solo}
        for k in list(cfgs):
            if k not in keep:
                pass
    return cfgs, raiz_ip or "172.30.0.10", recursivos, base


def main():
    global USAR_COLOR
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--arbol", help="arbol.json generado por genera_arbol.py")
    ap.add_argument("--zonas", nargs="*", help="zonas a auditar (alternativa a --arbol)")
    ap.add_argument("--raiz", help="IP del servidor raíz (por defecto la de arbol.json o 172.30.0.10)")
    ap.add_argument("--ancla", help="archivo con trust-anchors (static-ds/initial-ds), p.ej. recursive2/anchor.conf")
    ap.add_argument("--ancla-ds", help='DS de la raíz: "tag alg digesttype HEX"')
    ap.add_argument("--llaves-base", help="carpeta que contiene <dir>/keys (por defecto, la de arbol.json)")
    ap.add_argument("--resolvers", nargs="*", help="recursivos a comparar (por defecto los de arbol.json)")
    ap.add_argument("--solo", nargs="*", help="solo mostrar el informe detallado de estas zonas")
    ap.add_argument("--json"), ap.add_argument("--csv"), ap.add_argument("--dot")
    ap.add_argument("--comparar", nargs=2, metavar=("A.json", "B.json"))
    ap.add_argument("--ttl", type=int, default=86400, help="TTL esperado si no hay arbol.json")
    ap.add_argument("--umbral-dias", type=float, default=7.0, help="avisar si una RRSIG vence antes (días)")
    ap.add_argument("--sondas", type=int, default=300, help="máximo de consultas NXDOMAIN para reconstruir la cadena NSEC3")
    ap.add_argument("--diccionario", help="archivo con un nombre por línea para el ataque de diccionario NSEC3")
    ap.add_argument("--max-walk", type=int, default=500)
    ap.add_argument("--no-walk", action="store_true")
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--sin-color", action="store_true")
    ap.add_argument("--resumen", action="store_true", help="solo árbol, tabla y métricas (sin informe por zona)")
    args = ap.parse_args()

    if args.comparar:
        comparar_json(*args.comparar)
        return
    USAR_COLOR = sys.stdout.isatty() and not args.sin_color
    args.diccionario_lista = DICCIONARIO
    if args.diccionario:
        args.diccionario_lista = [l.strip() for l in open(args.diccionario, encoding="utf-8") if l.strip()]

    cfgs, raiz_ip, recursivos, base = cargar_arbol(args)
    anclas = []
    if args.ancla:
        anclas = leer_ancla_archivo(args.ancla)
        if not anclas:
            sys.exit("No encontré static-ds/initial-ds en %s" % args.ancla)
    if args.ancla_ds:
        t = args.ancla_ds.split()
        anclas.append((int(t[0]), int(t[1]), int(t[2]), "".join(t[3:]).upper()))
    if not args.llaves_base:
        args.llaves_base = base

    aud = Auditor(cfgs, raiz_ip, anclas, args, base)
    orden = sorted(cfgs, key=lambda n: (0 if n == "." else n.rstrip(".").count(".") + 1, cfgs[n].get("ip") or ""))
    res = {n: aud.zona(n) for n in orden}

    comp = None
    resolvers = args.resolvers or ([recursivos.get("sin_validacion"), recursivos.get("validador")] if recursivos else [])
    resolvers = [r for r in resolvers if r]
    if resolvers:
        comp = comparar_recursivos(aud, resolvers, orden)
    met = metricas(res, comp)

    # ------------------------------------------------ impresión
    print("AUDITORÍA DNSSEC  %s   raíz=%s   ancla=%s" % (fmt_ts(aud.ahora), raiz_ip,
                                                          "configurada (%d)" % len(anclas) if anclas else "derivada de la raíz"))
    print()
    print("ÁRBOL DE DEPENDENCIAS (estado de la cadena de confianza, algoritmo, denegación, DS)")
    print(imprimir_arbol(res, cfgs))
    print()
    if not args.resumen:
        for n in orden:
            if not args.solo or n in {tx(s) for s in args.solo}:
                print(informe_zona(res[n]))
        print()
    print("=" * 100)
    print("CONSULTAS A LOS RECURSIVOS")
    if comp:
        ips = resolvers
        etiq = {i: ("valida" if any(f["resultados"][i]["ad"] for f in comp) else "sin DNSSEC") for i in ips}
        print("%-34s " % "consulta" + " ".join("%-26s" % ("%s (%s)" % (i, etiq.get(i, "?"))) for i in ips))
        for fila in comp:
            celdas = []
            for i in ips:
                x = fila["resultados"][i]
                celdas.append("%-26s" % ("%s%s%s" % (x["rcode"], " +AD" if x["ad"] else "", (" EDE:" + x["ede"][0].split()[0]) if x["ede"] else "")))
            difiere = len({(fila["resultados"][i]["rcode"], fila["resultados"][i]["ad"]) for i in ips}) > 1
            print("%-34s %s %s" % (fila["consulta"][:34], " ".join(celdas), "◄ difieren" if difiere else ""))
    else:
        print("(sin recursivos: usa --resolvers IP1 IP2)")
    print()
    print("MÉTRICAS")
    for k, v in met.items():
        print("  %-30s %s" % (k, v))
    print()
    if any(z.get("esperado") for z in res.values()):
        print("CONSISTENCIA CON EL DISEÑO: %d/%d zonas coinciden con el estado esperado" % (met["coinciden_con_diseno"], met["zonas_total"]))
    else:
        print("(sin arbol.json: no hay diseño de referencia para comparar)")
    for n, z in res.items():
        if not z.get("coincide_esperado", True):
            print("  ≠ %s: observado %s, diseñado %s" % (n, z["estado"], z.get("esperado")))

    if args.json:
        json.dump(dict(generado=fmt_ts(aud.ahora), raiz=raiz_ip, zonas=res, comparacion_recursivos=comp, metricas=met),
                  open(args.json, "w", encoding="utf-8"), indent=1, ensure_ascii=False, default=str)
        print("JSON  -> %s" % args.json)
    if args.csv:
        exportar_csv(res, args.csv)
        print("CSV   -> %s" % args.csv)
    if args.dot:
        exportar_dot(res, cfgs, args.dot)
        print("DOT   -> %s   (dot -Tpng %s -o arbol.png)" % (args.dot, args.dot))
    sys.exit(0 if met["coinciden_con_diseno"] == met["zonas_total"] else 2)


if __name__ == "__main__":
    main()
