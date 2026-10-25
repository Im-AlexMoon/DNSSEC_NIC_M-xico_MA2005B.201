# Laboratorio DNS/DNSSEC con BIND9 y auditor de cadena de confianza

Laboratorio para comparar un árbol DNS con DNSSEC **bien configurado** frente a uno con
**errores deliberados**, y una herramienta en Python que audita llaves, firmas, denegación de
existencia (NSEC/NSEC3) y la cadena de DS.

> **Solo para laboratorio.** Las zonas, llaves y direcciones son de prueba. No uses estas
> configuraciones ni estos parámetros (incluidos los débiles a propósito) en producción.

## Qué contiene

| Ruta | Descripción |
|---|---|
| `tools/genera_arbol.py` | Genera y firma el árbol extendido a partir de una configuración base, crea los DS y los recursivos, y escribe `lab-dns.sh` y `arbol.json`. |
| `tools/dnssec_audit.py` | Auditor DNSSEC: DNSKEY, RRSIG, NSEC/NSEC3, DS, cadena de confianza, zone walking, TTL y métricas. |
| `tools/consultas_recursivos.sh` | Consulta cada zona con los dos recursivos y resume rcode y bit AD. |
| `base/` | Configuración de partida (`named.conf` y archivos de zona), sin llaves. |
| `results/` | Evidencia de una corrida (JSON, CSV, Graphviz y consultas). |
| `docs/` | Informe del proyecto (LaTeX y PDF). |

## Arquitectura

Cada servidor es un proceso `named` independiente con su propia IP, creada como alias de
loopback (`ip addr add X/32 dev lo`). BIND solo escucha en direcciones asignadas a una interfaz.

| Servidor | IP | Zona | Rol |
|---|---|---|---|
| root | 172.30.0.10 | `.` | autoritativo (raíz) |
| unsigned | 172.30.0.20 | `unsigned` | TLD sin firmar |
| alpha | 172.30.0.30 | `alpha.unsigned` | autoritativo |
| signed | 172.30.0.40 | `signed` | TLD firmado |
| beta | 172.30.0.50 | `beta.signed` | autoritativo firmado |
| gamma | 172.30.0.60 | `gamma.signed` | autoritativo sin firmar |
| test | 172.30.0.70 | `test` | TLD firmado (NSEC3) |
| delta | 172.30.0.80 | `delta.signed` | firmado, RSASHA256, NSEC3 con sal e iteraciones |
| epsilon | 172.30.0.90 | `epsilon.signed` | firmado, ED25519, NSEC |
| recursive1 | 172.30.0.100 | — | recursivo **sin** validación |
| recursive2 | 172.30.0.101 | — | recursivo **con** validación (ancla de confianza en la raíz) |
| zeta, eta, theta, iota | .110, .120, .130, .140 | `zeta.signed`, `eta/theta/iota.unsigned` | sin firmar |
| caducada | 172.30.0.150 | `caducada.test` | firmas expiradas (BOGUS) |
| sinds | 172.30.0.160 | `sinds.test` | firmada, sin DS en el padre (INSECURE) |
| algdebil | 172.30.0.170 | `algdebil.test` | RSASHA1, 1024 bits, DS con SHA-1 |

### Zonas con errores deliberados (bajo `test`)

- **`caducada.test`**: firmas con ventana de validez ya vencida. El validador responde
  `SERVFAIL` (EDE 7, *Signature Expired*).
- **`sinds.test`**: zona firmada cuyo DS no se publica en el padre. Es una isla de seguridad:
  resuelve, pero sin bit AD.
- **`algdebil.test`**: algoritmo y digest desaconsejados (RFC 8624). El validador la acepta con AD,
  por lo que solo el auditor la señala.

## Requisitos

- Linux (probado en Ubuntu sobre WSL2) con BIND 9.20 (`named`, `dnssec-keygen`,
  `dnssec-signzone`, `dnssec-dsfromkey`, `named-checkzone`).
- Python 3 con `dnspython` y `cryptography`.
- Opcional: Graphviz (`dot`) para dibujar el árbol, `delv` y `dig` para pruebas manuales.

```bash
sudo apt install bind9 bind9-utils bind9-dnsutils python3-dnspython python3-cryptography graphviz
```

## Uso

1. **Copiar la base de trabajo** (para no modificar la original):

   ```bash
   cp -a base/MaquinaDIG_v2 MaquinaDIG_v3
   ```

2. **Generar y firmar el árbol extendido:**

   ```bash
   python3 tools/genera_arbol.py --base MaquinaDIG_v3
   ```

   Las llaves se crean en el momento (o se reutilizan si ya existen). El generador asume los
   archivos `db.root`, `db.signed` y `db.unsigned` y los directorios `root`, `unsigned`,
   `signed`, `alpha`, `beta`, `gamma`, `recursive1` y `recursive2`.

3. **Levantar los servidores** (crea los alias de loopback y arranca los `named`):

   ```bash
   sudo bash MaquinaDIG_v3/lab-dns.sh restart
   ```

   Para detenerlos: `sudo bash MaquinaDIG_v3/lab-dns.sh stop`.
   **Solo puede haber un árbol activo a la vez**, porque todos comparten las mismas IP.

4. **Consultar con los dos recursivos:**

   ```bash
   bash tools/consultas_recursivos.sh MaquinaDIG_v3/arbol.json consultas_v3.txt
   dig @172.30.0.101 www.beta.signed A +dnssec     # con AD
   dig @172.30.0.101 www.caducada.test A +dnssec   # SERVFAIL (EDE 7)
   ```

5. **Auditar:**

   ```bash
   python3 tools/dnssec_audit.py --arbol MaquinaDIG_v3/arbol.json \
     --ancla MaquinaDIG_v3/recursive2/anchor.conf --timeout 1 \
     --json v3.json --csv v3.csv --dot v3.dot
   dot -Tpng v3.dot -o v3.png
   ```

   Opciones útiles: `--solo <zona>`, `--resumen`, `--sin-color`, `--no-walk`,
   `--diccionario`, `--umbral-dias`. El código de salida es `2` si el estado observado difiere
   del diseño.

6. **Comparar dos árboles** (apagando uno antes de levantar el otro):

   ```bash
   python3 tools/dnssec_audit.py --comparar v3.json dnssec.json
   ```

   Para un árbol sin `arbol.json`, indica zonas, raíz y ancla:

   ```bash
   python3 tools/dnssec_audit.py --zonas . unsigned signed alpha.unsigned beta.signed gamma.signed \
     --raiz 172.30.0.10 --ancla MaquinaDIG_DNSSEC/recursive2/named.conf \
     --resolvers 172.30.0.100 172.30.0.101
   ```

## Resultados esperados

| Zona | `recursive1` (sin validación) | `recursive2` (valida) |
|---|---|---|
| Zonas firmadas con cadena válida | NOERROR | NOERROR + **AD** |
| Zonas sin firmar | NOERROR | NOERROR (sin AD) |
| `caducada.test` | NOERROR | **SERVFAIL** (EDE 7) |
| `sinds.test` | NOERROR | NOERROR (sin AD) |
| `algdebil.test` | NOERROR | NOERROR + AD |

El auditor clasifica cada zona como `SECURE`, `INSECURE`, `BOGUS` o `INDETERMINATE`
(cuando no puede evaluar porque el padre no es confiable) y contrasta el resultado con el diseño.
En el árbol extendido, las 16 zonas coinciden con lo esperado.

## Qué verifica el auditor

- **DNSKEY:** algoritmo autorizado (RFC 8624), tipo ZSK/KSK, estado y ciclo de vida de la llave.
- **RRSIG:** llave firmante, ventana de validez, firmante y validez criptográfica.
- **NSEC/NSEC3/NSEC3PARAM:** versión y parámetros (RFC 9276).
- **DS y cadena de confianza:** coincidencia DS–DNSKEY, digest y cadena desde el ancla.
- **Zone walking:** enumeración por NSEC y reconstrucción de la cadena NSEC3 con ataque de diccionario.
- **TTL** por registro, árbol de dependencias y métricas.

## Limitaciones

- Un solo árbol activo a la vez (IP compartidas).
- Las vigencias de las firmas se evalúan con la hora del equipo.
- La enumeración NSEC3 depende del diccionario empleado.
- Con zonas inalcanzables la auditoría tarda más; reduce la espera con `--timeout 1`.
- Las firmas de `caducada.test` se calculan respecto al momento de la generación.
- El comportamiento ante `algdebil.test` (RSASHA1 y SHA-1) puede variar según la versión de BIND y
  de OpenSSL.

## Referencias

RFC 4033, 4034 y 4035 (DNSSEC) · RFC 5155 (NSEC3) · RFC 8624 (algoritmos) ·
RFC 9276 (parámetros de NSEC3) · RFC 9077 (TTL de NSEC) · RFC 8914 (errores extendidos).

## Licencia

Distribuido bajo la licencia MIT (ver `LICENSE`).
