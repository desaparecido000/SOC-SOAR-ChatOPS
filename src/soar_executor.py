#!/usr/bin/env python3
"""SOAR executor 4A/4B/4C - contenedores (LIVE) + bloqueo SecOps por IP (LIVE).

Recibe webhooks de Grafana Alerting (contact point gym-alertas-webhook)
y enruta CADA elemento de alerts[] por su alertname:

  "GYM - Contenedor caido"        -> rama 4A: docker start (lista blanca)
  "GYM - SOAR Anomalia Protocolo" -> rama 4B/4C: bloqueo por src_ip con
  "GYM - SOAR Entropia URI"          CORTE DUAL SIMETRICO
  "GYM - SOAR Suricata WAF"          (tabla filter: DOCKER-USER + INPUT)

Fase 4C (2026-10-20) - PROMOCION DE CONTRATOS AL PLANO DE CORTE:
  El plano de corte (_ban_ip/_unban_ip/reconcile/G4-IP) ya estaba
  certificado en 4B.4 con UNA sola regla. La 4C conecta dos contratos
  mas del Arnes P-6 al MISMO pipeline dimensional by (src_ip):
    - T-3-ENTROPIA-01 -> "GYM - SOAR Entropia URI" (escaneo L7 por
      entropia de recursos: rutas distintas / peticiones totales [5m]).
    - T-3-WAF-01      -> "GYM - SOAR Suricata WAF" (exploits de
      aplicacion por firmas del IDS Suricata, dedup por flow_id [5m]).
  Todo lo que cambia entre reglas es QUE las dispara; el corte es el
  mismo. La auditoria de cada accion incluye "rule" (alertname).

  Ref-Counting por target (anti-desbaneo prematuro): una MISMA src_ip
  puede disparar 2 reglas con fingerprints distintos. El resolved de la
  primera purga su clave pero, si otra alerta activa sigue reteniendo la
  IP, registra STATE_CLEARED_PARTIAL y NO llama a _unban_ip. Solo el
  resolved de la ULTIMA alerta activa ejecuta el -D del corte dual.

Modos por rama (independientes; Fase 4B.3/4B.4, 2026-10-20):
  DRY_RUN    = False con --live -> 4A LIVE (docker start real, certificado
               2026-10-19 con la cadena E2E 5/5).
  IP_DRY_RUN = False            -> 4B IP_LIVE: corte REAL del trafico.

Corte dual simetrico (Fase 4B.4, 2026-10-20):
  CHAINS = ("DOCKER-USER", "INPUT"). Un atacante detectado en L7 por
  nginx-proxy se banea SIMULTANEAMENTE:
    - DOCKER-USER: la PRIMERA cadena saltada de FORWARD -> corta todo el
      trafico DNATado/reenviado hacia contenedores (p.ej. el puerto 80
      publicado). Gate 0 medido 2026-10-20: `ufw deny`/`ufw route` NO
      cortan el puerto publicado (FORWARD decide antes que INPUT), asi
      que DOCKER-USER es imprescindible.
    - INPUT: cadena de entrada LOCAL del host -> corta el trafico que
      TERMINA en servicios del host, como sshd (:22) y el docker-proxy
      en modo userland que acepta conexiones en nombre de los puertos
      publicados. Sin INPUT, un atacante podria seguir tocando :22 (y el
      propio endpoint del SOAR) aunque su trafico a contenedores caiga.
  NO se toca nat PREROUTING: solo ve paquetes NEW y no corta flujos ya
  establecidos (ademas el DNAT de Docker ocurre justo ahi).
  Reglas dinamicas etiquetadas `-m comment --comment SOAR-BAN` en AMBAS
  cadenas para distinguirlas de las fijas (p.ej. aislamiento msf3
  172.30.0.0/24) y poder barrer huerfanas con precision.

Contrato capturado el 18-Oct-2026 en /root/soar-captures/ (payloads
reales de firing y resolved, Grafana 11.2.2). Guardas:

  G1  autenticacion Bearer (hmac.compare_digest)       -> 401 AUTH_FAIL
  G2  receiver + alertname esperados (por ENVELOPE y por ITEM);
      4 alertnames validos: 1 contenedor + 3 IP (Protocolo/Entropia/WAF)
  G3  coherencia status/endsAt (sentinel 0001-01-01)
  G4  contenedores: lista blanca estricta + regex ^[a-z0-9_-]+$ + argv
  G4-IP (orden estricto, fallos primero):
      1. ipaddress.ip_address(src_ip) parsea           -> DENY_MALFORMED_IP
      2. src_ip en NEVER_BAN_IPS (host + operador)     -> DENY_NEVER_BAN
      3. src_ip con sesion SSH establecida (ss vivo)   -> DENY_ACTIVE_SSH_SESSION
      4. is_private/loopback/link_local/multicast/reserved
         salvo TEST_ALLOWED_PRIVATE_IPS                -> DENY_PRIVATE_IP
  G5  idempotencia (fingerprint, startsAt) + cooldown 3 acciones / 900s

Notas de contrato (medidas):
  - El resolved libera la clave del fingerprint para que una futura caida
    con las MISMAS labels (mismo fingerprint) si se ejecute. G3 es comun
    a ambas ramas: se evalua ANTES del ruteo.
  - Se itera alerts[] por ITEM: un mismo envelope puede mezclar firing y
    resolved; el status de la raiz NO es el decisivo.
  - `docker start` es idempotente por diseno: si el contenedor ya corre,
    rc=0 sin efecto.
  - El resolved de la rama IP empareja el incidente SOLO por fingerprint
    (prefijo fp| de la clave en state.json): en Grafana 11.2.2 el
    resolved trae startsAt = inicio del estado Normal (mutado, medido
    2026-10-20T02:07Z), por lo que la igualdad de startsAt entre firing
    y resolved NO existe. El ban se localiza por el campo ban_ip del
    estado y se retira con -D en bucle (tope 3, idempotente). Desde 4C,
    antes de retirar la regla se aplica Ref-Counting por target: si otra
    alerta activa retiene esa src_ip (STATE_CLEARED_PARTIAL), no se
    desbanea aun.
  - Persistencia de bans: EFIMERA a proposito (sin iptables-persistent;
    una regla zombi eterna es peor que un ban perdido). La fuente de la
    verdad es state.json y reconcile_on_startup() la reconcilia al
    arrancar: bans < 10 min sin regla -> reinserta; > 10 min -> retira
    regla residual y purga entrada; reglas SOAR-BAN sin estado ->
    huerfanas, eliminadas. Las reglas fijas no llevan el comentario y
    jamas se tocan.

Proteccion del operador (Fase 4B, ajuste 3):
  - NEVER_BAN_IPS es la base ESTATICA (IP publica del host + ultima IP
    SSH conocida del operador).
  - get_active_ssh_ips() la complementa EN VIVO leyendo las sesiones TCP
    establecidas sobre el puerto 22 en el momento de evaluar el baneo:
    aunque la IP residencial del operador cambie por DHCP, cualquier IP
    con la que este sentado el operador queda rechazada (matematicamente
    imposible cortarse a si mismo la rama).

Uso:
  python3 soar_executor.py          # contenedores DRY_RUN, IP LIVE (dual)  
  python3 soar_executor.py --live   # contenedores LIVE + IP LIVE
"""
import hmac
import ipaddress
import json
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

DRY_RUN = True    # rama contenedores; --live lo pone a False en arranque
IP_DRY_RUN = False  # 4B.3/4B.4: rama IP LIVE (corte dual DOCKER-USER+INPUT)

SECRET_FILE = Path("/root/.gym-creds/soar-webhook-secret")
STATE_FILE = Path("/root/soar/state.json")
AUDIT_LOG = Path("/root/soar/soar-audit.log")
TEST_IPS_FILE = Path("/root/soar/test-allowed-ips.txt")
BIND_ADDR = "172.19.0.1"
BIND_PORT = 9099

# Fase 4D - NOTIFICACIONES FORENSES A TELEGRAM (canal directo del SOAR).
# Fuente DEDICADA de credenciales (separada de Grafana): el SOAR no depende
# del .env de Grafana ni del literal de contactpoints.yml. Permisos 600.
#   TELEGRAM_BOT_TOKEN=<token>
#   TELEGRAM_CHAT_ID=<chatid>
# El token/chatid JAMAS se pasan por argv ni se imprimen.
TELEGRAM_CREDS_FILE = Path("/root/.gym-creds/telegram")
TELEGRAM_TIMEOUT_S = 3       # <= Grafana tolera 10s -> sin interferencia
TELEGRAM_MAX_CHARS = 4000    # limite de la API es 4096; margen de seguridad
TELEGRAM_ENABLED = True      # se recalcula si faltan credenciales validas

EXPECTED_RECEIVER = "gym-alertas-webhook"
CONTAINER_RULE = "GYM - Contenedor caido"

# Fase 4C - PROMOCION DE CONTRATOS AL PLANO DE CORTE POR IP.
#
# El plano de corte (_ban_ip/_unban_ip/reconcile/G4-IP, corte dual
# DOCKER-USER+INPUT) ya estaba certificado en 4B.4 con UNA sola regla
# (Anomalia Protocolo). La 4C solo CONECTA dos contratos mas del Arnes
# P-6 al MISMO pipeline dimensional by (src_ip):
#
#   T-3-ENTROPIA-01 -> "GYM - SOAR Entropia URI"   (escaneo L7 por
#                      entropia de recursos: rutas distintas / peticiones)
#   T-3-WAF-01      -> "GYM - SOAR Suricata WAF"   (exploits de aplicacion
#                      por firmas del IDS Suricata)
#
# Las tres reglas comparten el MISMO contrato de ruteo: la etiqueta
# src_ip entra por G4-IP en orden estricto y sale por el corte dual. Lo
# unico que cambia entre ellas es QUE las dispara, no QUE hacen.
IP_RULE = "GYM - SOAR Anomalia Protocolo"
IP_RULE_ENTROPIA = "GYM - SOAR Entropia URI"
IP_RULE_WAF = "GYM - SOAR Suricata WAF"
IP_ALERT_RULES = {IP_RULE, IP_RULE_ENTROPIA, IP_RULE_WAF}
EXPECTED_ALERTNAMES = {CONTAINER_RULE} | IP_ALERT_RULES
SENTINEL_PREFIX = "0001-01-01"
NAME_RE = re.compile(r"^[a-z0-9_-]+$")

# Lista blanca 4A (piloto estricto): lab + web de la app.
# EXCLUIDOS a proposito: monitoreo/sensorial (grafana, loki, prometheus,
# node-exporter, cadvisor, suricata, promtail, docker-ro-proxy),
# perimeter/edge (nginx-proxy), laboratorio ofensivo (atacante,
# lab-server) y metrocoord-db (requiere decision del operador).
ALLOWED_CONTAINERS = {
    "dvwa", "kalilab", "msf3-lab",
    "metrocoord-backend", "metrocoord-frontend", "metrocoord-redis",
}

# G4-IP: base ESTATICA de proteccion. Cargar desde entorno o archivo externo.
# Ejemplo: GYM_NEVER_BAN_IPS="203.0.113.10,198.51.100.10" (RFC5737/TEST-NET)
# o bien desde /root/.gym-creds/neverban-ips (una IP por linea).
NEVER_BAN_IPS = set()
import os as _os
for _ip in _os.environ.get("GYM_NEVER_BAN_IPS", "").split(","):
    _ip = _ip.strip()
    if _ip:
        NEVER_BAN_IPS.add(_ip)
_nbfile = Path("/root/.gym-creds/neverban-ips")
try:
    if _nbfile.exists():
        for _l in _nbfile.read_text().splitlines():
            _l = _l.strip()
            if _l and not _l.startswith("#"):
                NEVER_BAN_IPS.add(_l)
except Exception:
    pass

# Fase 4B.3/4B.4 - CORTE DUAL SIMETRICO en la tabla filter. Ambas cadenas
# reciben la MISMA spec de regla (mismo target, mismo comentario) para que
# ban/unban/reconcile sean simetricos y la idempotencia (-C antes de -I)
# funcione igual en las dos.
#   DOCKER-USER: primer salto de FORWARD -> corta el trafico reenviado/
#                DNATado hacia contenedores (puerto 80 publicado).
#   INPUT:       trafico que TERMINA en el host -> sshd (:22) y el
#                docker-proxy userland de los puertos publicados.
CHAINS = ("DOCKER-USER", "INPUT")

# El comentario identifica las reglas DINAMICAS del SOAR en un
# `iptables -S <cadena>` (las fijas, como el aislamiento msf3
# 172.30.0.0/24 -> 172.30.0.1, no lo llevan).
# BAN_TTL_S: un ban mas antiguo que la ventana de la alerta ([5m] +
# margen) se considera residual y lo retira reconcile_on_startup().
BAN_COMMENT = "SOAR-BAN"
BAN_TTL_S = 600

# G4-IP: excepciones de test. Solo se usan para el disparo controlado con
# IPs privadas (bridge 172.18.0.1 / contenedor atacante). En produccion el
# conjunto esta VACIO; se rellena temporalmente (constante o fichero) y se
# vacia al cerrar la certificacion.
TEST_ALLOWED_PRIVATE_IPS: set = set()

COOLDOWN_MAX = 3
COOLDOWN_WINDOW_S = 900

state = {"executed": {}, "actions": {}}


def audit(event, **kw):
    linea = json.dumps(
        {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
         "event": event, **kw},
        ensure_ascii=False)
    with open(AUDIT_LOG, "a") as f:
        f.write(linea + "\n")
    print(linea, flush=True)


def _load_telegram_creds():
    """Carga token+chatid desde TELEGRAM_CREDS_FILE (permisos 600).

    Devuelve {"token": str, "chatid": str}. Si el fichero no existe, es
    ilegible o le falta alguna clave, devuelve cadenas vacias -> el
    notificador queda desactivado (no-op silencioso). NUNCA imprime el
    secreto.
    """
    vacio = {"token": "", "chatid": ""}
    try:
        if not TELEGRAM_CREDS_FILE.exists():
            return vacio
        token = chatid = ""
        for linea in TELEGRAM_CREDS_FILE.read_text().splitlines():
            linea = linea.strip()
            if not linea or linea.startswith("#") or "=" not in linea:
                continue
            k, v = linea.split("=", 1)
            k, v = k.strip(), v.strip().strip('"').strip("'")
            if k == "TELEGRAM_BOT_TOKEN":
                token = v
            elif k == "TELEGRAM_CHAT_ID":
                chatid = v
        # validacion de FORMA del token: <digits>:<secret> (sin revelar valor)
        if not re.match(r"^[0-9]{6,}:[A-Za-z0-9_-]{30,}$", token):
            return vacio
        if not re.match(r"^-?[0-9]{5,}$", chatid):
            return vacio
        return {"token": token, "chatid": chatid}
    except Exception:
        return vacio


# Cache de credenciales; None = recargar del fichero en el proximo uso. La
# suite de tests la fija a {"token": "", "chatid": ""} para forzar el no-op.
_TG_CREDS = None


def _telegram_send(text):
    """Envia `text` al chat configurado. FAIL-SAFE por diseno.

    Principio de NO-INTERFERENCIA (Fase 4D): esta funcion se invoca SIEMPRE
    DESPUES de aplicar la accion en kernel/Docker, con timeout corto, y
    captura cualquier excepcion. Un fallo de red/DNS/timeout JAMAS altera el
    rc de la accion ni la respuesta al webhook de Grafana: solo se audita
    TELEGRAM_NOTIFY_ERROR. Devuelve True si se entrego, False si no.

    Es el UNICO punto de salida del notificador -> inyectable en tests
    (monkeypatch) para verificar el texto sin llamadas de red.
    """
    global _TG_CREDS, TELEGRAM_ENABLED
    if _TG_CREDS is None:
        _TG_CREDS = _load_telegram_creds()
    creds = _TG_CREDS
    if not creds.get("token") or not creds.get("chatid"):
        TELEGRAM_ENABLED = False
        return False
    TELEGRAM_ENABLED = True
    texto = text[:TELEGRAM_MAX_CHARS]
    url = f"https://api.telegram.org/bot{creds['token']}/sendMessage"
    datos = urllib.parse.urlencode(
        {"chat_id": creds["chatid"], "text": texto,
         "disable_web_page_preview": "true"}).encode()
    try:
        return _telegram_post(url, datos)
    except Exception as e:
        # Fail-safe: la accion ya se aplico; esto es solo telemetria de canal.
        audit("TELEGRAM_NOTIFY_ERROR",
              error=f"{type(e).__name__}: {str(e)[:160]}", accion="sendMessage")
        return False


def _telegram_post(url, datos):
    """POST HTTPS al API de Telegram con timeout corto. Punto inyectable.

    Aislado de `_telegram_send` para que los tests puedan forzar un fallo
    de red SIN desactivar el try/except de fail-safe que audita
    TELEGRAM_NOTIFY_ERROR. Devuelve True si la entrega fue 200.
    """
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, data=datos, method="POST")
    with urllib.request.urlopen(req, timeout=TELEGRAM_TIMEOUT_S,
                                context=ctx) as resp:
        if resp.status != 200:
            audit("TELEGRAM_NOTIFY_ERROR",
                  error=f"HTTP {resp.status}", accion="sendMessage")
            return False
    return True


def _notify_banned(target, rule, fp, detalles):
    """Mensaje forense para BANNED_IP (corte dual). Fail-safe."""
    ms = max((d.get("duracion_ms", 0) for d in detalles
              if d.get("accion") == "insertada"), default=0)
    txt = (
        "🛡️ [SOAR-LIVE] IP Bloqueada en Kernel\n"
        f"• IP Atacante: {target}\n"
        f"• Contrato/Regla: {rule or 'N/D'}\n"
        f"• Corte Dual: DOCKER-USER + INPUT (en {ms} ms)\n"
        f"• Fingerprint: {fp}")
    return _telegram_send(txt)


def _notify_unbanned(target, rule, dropped):
    """Mensaje forense para UNBANNED_IP con dropped_pkts por cadena."""
    du = dropped.get("DOCKER-USER", "?")
    ip = dropped.get("INPUT", "?")
    txt = (
        "🟢 [SOAR-LIVE] Bloqueo Expirado / Liberado\n"
        f"• IP: {target} | Regla: {rule or 'N/D'}\n"
        f"• Paquetes bloqueados (Kernel): DOCKER-USER={du}, INPUT={ip}")
    return _telegram_send(txt)


def _notify_executed(name, exit_previo, duracion_ms, rc):
    """Mensaje forense para EXECUTED (contenedor auto-recuperado, 4A)."""
    txt = (
        "🔄 [SOAR-LIVE] Contenedor Auto-Recuperado\n"
        f"• Contenedor: {name} (ExitCode previo: {exit_previo})\n"
        f"• Resultado: docker start rc={rc} ({duracion_ms} ms)")
    return _telegram_send(txt)


def load_state():
    if STATE_FILE.exists():
        try:
            guardado = json.loads(STATE_FILE.read_text())
            state.update(guardado)
        except Exception:
            audit("STATE_RESETEADO", detalle="state.json ilegible")


def save_state():
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state))
    tmp.replace(STATE_FILE)


def get_active_ssh_ips():
    """IPs con sesion TCP ESTABLECIDA sobre el puerto 22 del host.

    Guarda dinamica G4-IP.3: se consulta en el momento exacto de evaluar
    un baneo (no hay cache: una sesion nueva entre dos evaluaciones tiene
    que verse). `ss -tn state established '( sport = :22 )'` cubre tanto
    sesiones entrantes (el operador conectado) como salientes.
    """
    try:
        r = subprocess.run(
            ["ss", "-tn", "state", "established", "( sport = :22 )"],
            capture_output=True, text=True, timeout=10)
    except Exception:
        return set()
    ips = set()
    for linea in (r.stdout or "").splitlines():
        campos = linea.split()
        if len(campos) < 4 or not campos[0].isdigit():
            continue  # cabecera o linea mal formada
        peer = campos[3]  # Peer Address:Port
        if peer.startswith("["):  # IPv6 '[addr]:port'
            ip = peer[1:].split("]")[0]
        else:
            ip = peer.rsplit(":", 1)[0] if ":" in peer else peer
        ips.add(ip)
    return ips


def test_allowed_private_ips():
    """Conjunto TEST_ALLOWED_PRIVATE_IPS en vigor.

    Union de la constante en codigo con /root/soar/test-allowed-ips.txt
    (un IP por linea, '#' comenta). El fichero se relee en CADA
    evaluacion: permite habilitar/deshabilitar la IP privada del test
    E2E sin reiniciar el servicio.
    """
    extra = set(TEST_ALLOWED_PRIVATE_IPS)
    try:
        crudo = TEST_IPS_FILE.read_text()
    except OSError:
        crudo = ""
    for linea in crudo.splitlines():
        ip = linea.split("#", 1)[0].strip()
        if ip:
            extra.add(ip)
    return extra


def _run(cmd, timeout=30):
    """subprocess.run con captura: punto unico de ejecucion de comandos
    (los tests unitarios sustituyen esta llamada por un firewall falso)."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _ban_cmd(op, ipt, target, cadena, posicion=False):
    """Spec canonica de la regla de baneo: IDENTICA para -C / -I / -D.

    La igualdad de specs es la idempotencia a nivel de kernel: -C decide
    si falta y -D borra exactamente esta regla (nunca una fija ajena).
    `cadena` es una de CHAINS (DOCKER-USER o INPUT).
    """
    cmd = [ipt, op, cadena]
    if posicion:
        cmd.append("1")
    cmd += ["-s", target, "-m", "comment", "--comment", BAN_COMMENT,
            "-j", "DROP"]
    return cmd


def _familia(target):
    """Binario iptables/ip6tables segun la familia de la IP.

    Pasar una IPv6 a iptables (v4) devuelve rc!=0 sin cortar nada; el
    LogQL y G4-IP.1 ya aceptan ambas familias, asi que el despacho es
    obligatorio.
    """
    return "ip6tables" if ipaddress.ip_address(target).version == 6 else "iptables"


def _contador_pkts(ipt, cadena, target):
    """Paquetes bloqueados por la regla SOAR-BAN del target en una cadena.

    Lee `iptables -L <cadena> -v -n -x` y localiza la linea cuya columna
    de origen coincide EXACTAMENTE con el target (comparando el campo
    limpio, no por substring, para no confundir 8.8.8.8 con 8.8.8.80).
    Devuelve None si no se puede leer (no interrumpe el unban por una
    metrica). Es solo informativo para soar-audit.log.
    """
    try:
        r = _run([ipt, "-L", cadena, "-v", "-n", "-x"], timeout=10)
    except Exception:
        return None
    if r.returncode != 0:
        return None
    for linea in (r.stdout or "").splitlines():
        campos = linea.split()
        # pkts bytes target prot opt in out source destination
        #   0     1      2     3    4   5   6     7         8
        if len(campos) < 8:
            continue
        if campos[7] != target:  # columna 'source' (con -x: sin sufijo /32)
            continue
        if BAN_COMMENT not in linea and campos[2].upper() != "DROP":
            continue
        try:
            return int(campos[0])
        except ValueError:
            return None
    return None


def _ban_ip(target, rule=None, fp=None):
    """Inserta la regla SOAR-BAN en TODAS las CHAINS si falta (-C antes -I).

    Corte dual simetrico: la misma spec se aplica a DOCKER-USER (trafico
    reenviado/DNATado a contenedores) y a INPUT (trafico local del host:
    sshd, docker-proxy userland). Devuelve el rc agregado (0 = todas las
    cadenas quedaron baneadas; 1 si alguna fallo).

    `rule` es el alertname que disparo el ban (Fase 4C): queda en la
    auditoria para saber QUE contrato corto la IP, no solo que se corto.
    `fp` (Fase 4D) se usa solo para el mensaje forense a Telegram.
    """
    ipt = _familia(target)
    rc_total = 0
    detalles = []
    for cadena in CHAINS:
        chk = _ban_cmd("-C", ipt, target, cadena)
        if _run(chk, timeout=10).returncode == 0:
            detalles.append({"cadena": cadena, "accion": "ya_existia",
                             "rc": 0})
            continue
        cmd = _ban_cmd("-I", ipt, target, cadena, posicion=True)
        t0 = time.time()
        r = _run(cmd)
        detalles.append({
            "cadena": cadena, "accion": "insertada", "rc": r.returncode,
            "duracion_ms": int((time.time() - t0) * 1000),
            "stderr": (r.stderr or "").strip()[:200]})
        if r.returncode != 0:
            rc_total = 1
    audit("BANNED_IP", target=target, rule=rule, rc=rc_total,
          cadenas=list(CHAINS), detalles=detalles)
    # Fase 4D: notificacion forense SOLO tras aplicar la accion (fail-safe).
    if rc_total == 0:
        _notify_banned(target, rule, fp, detalles)
    return rc_total


def _unban_ip(target, rule=None):
    """Retira TODAS las reglas SOAR-BAN del target en TODAS las CHAINS.

    Bucle -D con tope 3 por cadena (cubre reglas duplicadas por carrera);
    si la regla no existia, rc!=0 a la primera y no lanza. Antes de borrar
    captura el contador de paquetes bloqueados por cadena y lo registra en
    el evento UNBANNED_IP como metrica de EFECTIVIDAD (dropped_pkts).
    Verifica con -C que la regla desaparecio en ambas cadenas antes de dar
    el ban por retirado. Devuelve True si desaparecio de todas.

    `rule` (Fase 4C): alertname cuyo resolved libero el ULTIMO ban de la
    IP. Con Ref-Counting, un unban solo ocurre cuando ninguna regla
    activa retiene la src_ip, asi que `rule` identifica la que cerro.
    """
    ipt = _familia(target)
    dropped = {}
    borradas = {}
    for cadena in CHAINS:
        d = _contador_pkts(ipt, cadena, target)
        if d is not None:
            dropped[cadena] = d
        cmd = _ban_cmd("-D", ipt, target, cadena)
        n = 0
        while n < 3:
            if _run(cmd, timeout=10).returncode != 0:
                break
            n += 1
        borradas[cadena] = n
    sigue = False
    for cadena in CHAINS:
        if _run(_ban_cmd("-C", ipt, target, cadena),
                timeout=10).returncode == 0:
            sigue = True
    audit("UNBANNED_IP", target=target, rule=rule, rc=0 if not sigue else 1,
          cadenas=list(CHAINS), reglas_borradas=borradas,
          dropped_pkts=dropped, sigue_presente=sigue)
    # Fase 4D: mensaje forense SOLO si se retiro realmente alguna regla.
    if not sigue and sum(borradas.values()) > 0:
        _notify_unbanned(target, rule, dropped)
    return not sigue


def _accion_contenedor(name, clave, fp, now):
    """Rama 4A: whitelist estricta + idempotencia + docker start."""
    # G4 - lista blanca estricta
    if not name or not NAME_RE.match(name) or name not in ALLOWED_CONTAINERS:
        audit("DENY_NOT_WHITELISTED", target=name, fingerprint=fp)
        return "DENY_NOT_WHITELISTED", f"target={name!r}"

    # G5 - idempotencia (fingerprint, startsAt) + cooldown por target
    if clave in state["executed"]:
        return "SKIP_DUPLICATE", f"clave={clave}"
    recientes = [t for t in state["actions"].get(name, [])
                 if now - t < COOLDOWN_WINDOW_S]
    if len(recientes) >= COOLDOWN_MAX:
        audit("RATE_LIMITED", target=name, acciones_ventana=len(recientes))
        return "RATE_LIMITED", f"target={name} acciones_900s={len(recientes)}"

    # accion
    state["executed"][clave] = now
    state["actions"][name] = recientes + [now]
    save_state()
    if DRY_RUN:
        audit("WOULD_EXECUTE", target=name, cmd=["docker", "start", name])
        return "WOULD_EXECUTE", f"docker start {name}"
    try:
        # Fase 4D: capturar el ExitCode PREVIO antes de arrancar (fail-safe:
        # si la inspeccion falla, se usa '?' y la accion continua).
        exit_previo = "?"
        try:
            ri = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.ExitCode}}", name],
                capture_output=True, text=True, timeout=10)
            if ri.returncode == 0 and (ri.stdout or "").strip():
                exit_previo = (ri.stdout or "").strip()[:20]
        except Exception:
            pass
        t_exec = time.time()
        r = subprocess.run(["docker", "start", name], capture_output=True,
                           text=True, timeout=60)
        duracion_ms = int((time.time() - t_exec) * 1000)
        audit("EXECUTED", target=name, rc=r.returncode,
              duracion_ms=duracion_ms,
              stdout=(r.stdout or "").strip()[:120],
              stderr=(r.stderr or "").strip()[:200],
              exit_code_previo=exit_previo)
        if r.returncode == 0:
            # Fase 4D: notificacion forense tras el arranque efectivo.
            _notify_executed(name, exit_previo, duracion_ms, r.returncode)
            return "EXECUTED", f"docker start {name} rc=0"
        return "EXEC_FAIL", f"rc={r.returncode} {r.stderr[:200]}"
    except Exception as e:
        audit("EXEC_FAIL", target=name, error=str(e)[:200])
        return "EXEC_FAIL", str(e)[:200]


def _accion_ip(target, clave, fp, now, rule=None):
    """Rama 4B/4C: guardas G4-IP en orden estricto + baneo DUAL.

    Orden medido: parseo -> NEVER_BAN -> sesion SSH activa -> privada.
    Cada fallo es DENY con auditoria; ninguna denegacion toca estado
    (el resolved posterior libera el fingerprint igualmente, con
    claves_liberadas=0 porque nunca hubo regla que retirar).

    `rule` (Fase 4C): alertname que disparo la accion. Se propaga a la
    auditoria (BANNED_IP/WOULD_BAN_IP/SKIP_DUPLICATE) para trazar que
    contrato corto cada IP.
    """
    # G4-IP.1 - parseo estricto
    try:
        ip = ipaddress.ip_address(target)
    except (ValueError, TypeError):
        audit("DENY_MALFORMED_IP", target=str(target)[:80], fingerprint=fp,
              rule=rule)
        return "DENY_MALFORMED_IP", f"src_ip={target!r} no parsea como IP"

    # G4-IP.2 - proteccion estatica host + operador
    if target in NEVER_BAN_IPS:
        audit("DENY_NEVER_BAN", target=target, fingerprint=fp, rule=rule)
        return "DENY_NEVER_BAN", f"src_ip={target} en NEVER_BAN_IPS"

    # G4-IP.3 - proteccion dinamica: sesion SSH activa en este instante
    activas = get_active_ssh_ips()
    if target in activas:
        audit("DENY_ACTIVE_SSH_SESSION", target=target, fingerprint=fp,
              rule=rule)
        return "DENY_ACTIVE_SSH_SESSION", f"src_ip={target} con sesion SSH activa"

    # G4-IP.4 - nada de espacio privado/loopback salvo excepcion de test
    if (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved):
        if target not in test_allowed_private_ips():
            audit("DENY_PRIVATE_IP", target=target, fingerprint=fp, rule=rule)
            return "DENY_PRIVATE_IP", f"src_ip={target} en espacio privado"
        # habilitado explicitamente para el TP controlado -> sigue

    # G5 - idempotencia (fingerprint, startsAt) + cooldown por IP
    if clave in state["executed"]:
        audit("SKIP_DUPLICATE", target=target, fingerprint=fp, rule=rule)
        return "SKIP_DUPLICATE", f"clave={clave}"
    recientes = [t for t in state["actions"].get(target, [])
                 if now - t < COOLDOWN_WINDOW_S]
    if len(recientes) >= COOLDOWN_MAX:
        audit("RATE_LIMITED", target=target, acciones_ventana=len(recientes),
              rule=rule)
        return "RATE_LIMITED", f"target={target} acciones_900s={len(recientes)}"

    # Estado con la IP baneada: el resolved la localiza por fingerprint y
    # necesita el target (ban_ip) para ejecutar el -D sin depender del
    # startsAt (Grafana 11.2.2 lo muta en el resolved). `rule` queda en la
    # entrada para el Ref-Counting (STATE_CLEARED_PARTIAL) y la auditoria.
    state["executed"][clave] = {"ts": now, "ban_ip": target, "rule": rule}
    state["actions"][target] = recientes + [now]
    save_state()
    if IP_DRY_RUN:
        cmd = _ban_cmd("-I", _familia(target), target, CHAINS[0],
                       posicion=True)
        audit("WOULD_BAN_IP", target=target, rule=rule, cadenas=list(CHAINS),
              cmd=cmd)
        return "WOULD_BAN_IP", f"{'+'.join(CHAINS)} DROP {target} (DRY_RUN)"
    try:
        rc = _ban_ip(target, rule=rule, fp=fp)
        if rc == 0:
            return "BANNED_IP", f"{'+'.join(CHAINS)} DROP {target} rc=0"
        return "EXEC_FAIL", f"rc={rc} (ver BANNED_IP en auditoria)"
    except Exception as e:
        audit("EXEC_FAIL", target=target, error=str(e)[:200], rule=rule)
        return "EXEC_FAIL", str(e)[:200]


def reconcile_on_startup():
    """Reconciliacion de baneos IP tras (re)iniciar el servicio.

    Sin iptables-persistent a proposito: la persistencia de los bans es
    EFIMERA (una regla zombi eterna es peor que un ban perdido). state.json
    es la fuente de la verdad y esta rutina la aplica al kernel:

      - ban vigente (edad <= BAN_TTL_S): si la regla SOAR-BAN falta en
        ALGUNA de las CHAINS (un reinicio de dockerd/host la habria
        perdido), se re-inserta en las que falten. Gracias al corte dual
        simetrico, un estado consistente exige la regla en DOCKER-USER Y
        en INPUT.
      - ban expirado (edad > BAN_TTL_S): se retira la regla residual de
        ambas cadenas y se purga la entrada; nadie queda bloqueado para
        siempre.
      - barrida final: cualquier regla SOAR-BAN en CUALQUIERA de las
        CHAINS (DOCKER-USER o INPUT, v4/v6) sin entrada activa en
        state.json es huerfana -> se elimina de TODAS las cadenas. Las
        reglas fijas no llevan el comentario y no se tocan.
    """
    ahora = time.time()
    activas = set()
    for clave, entrada in list(state["executed"].items()):
        if not isinstance(entrada, dict) or not entrada.get("ban_ip"):
            continue  # ejecucion de la rama 4A (valor numerico): no tocar
        ip_ban = entrada["ban_ip"]
        try:
            ipt = _familia(ip_ban)
        except ValueError:
            continue  # estado corrupto: no arriesgar un iptables malformado
        ts = float(entrada.get("ts") or 0.0)
        edad = (ahora - ts) if ts else BAN_TTL_S + 1
        try:
            if edad <= BAN_TTL_S:
                for cadena in CHAINS:
                    if _run(_ban_cmd("-C", ipt, ip_ban, cadena),
                            timeout=10).returncode != 0:
                        rc = _run(_ban_cmd("-I", ipt, ip_ban, cadena,
                                           posicion=True),
                                  timeout=10).returncode
                        audit("RECONCILED_IP", target=ip_ban,
                              cadena=cadena, accion="reinsertada", rc=rc,
                              edad_s=int(edad))
                activas.add(ip_ban)
            else:
                _unban_ip(ip_ban)
                del state["executed"][clave]
                audit("RECONCILED_IP", target=ip_ban,
                      accion="expirada_retirada", edad_s=int(edad))
        except Exception as e:
            audit("RECONCILE_FAIL", target=ip_ban, error=str(e)[:200])
    # Barrida de huerfanas: reglas SOAR-BAN sin entrada activa, en ambas
    # cadenas y ambas familias.
    for ipt in ("iptables", "ip6tables"):
        for cadena in CHAINS:
            try:
                r = _run([ipt, "-S", cadena], timeout=10)
            except Exception:
                continue  # binario ausente (p.ej. ip6tables sin dockerd v6)
            for linea in (r.stdout or "").splitlines():
                if BAN_COMMENT not in linea:
                    continue
                m = re.search(r"-s (\S+)", linea)
                if not m:
                    continue
                huerfana = m.group(1).split("/")[0]
                if huerfana in activas:
                    continue
                try:
                    _unban_ip(huerfana)
                    audit("RECONCILED_IP", target=huerfana, cadena=cadena,
                          accion="huerfana_retirada")
                except Exception as e:
                    audit("RECONCILE_FAIL", target=huerfana,
                          error=str(e)[:200])
    save_state()


def evaluar_alerta(alert, now):
    """Veredicto para UN elemento de alerts[]. Devuelve (decision, detalle)."""
    labels = alert.get("labels") or {}
    name = labels.get("name", "")
    alertname = labels.get("alertname", "")
    fp = alert.get("fingerprint", "")
    starts = alert.get("startsAt", "")
    st = alert.get("status", "")
    ends = alert.get("endsAt", "")
    clave = f"{fp}|{starts}"

    # G2 por ITEM (el envelope puede mezclar reglas)
    if alertname not in EXPECTED_ALERTNAMES:
        return "SKIP_UNMATCHED_RULE", f"alertname={alertname!r}"

    # G3 - coherencia status / endsAt (COMUN a ambas ramas)
    if st == "resolved":
        if ends.startswith(SENTINEL_PREFIX):
            return "MALFORMED_STATE", f"resolved con endsAt sentinel fp={fp}"
        # Emparejamiento SOLO por fingerprint (prefijo de la clave): en
        # Grafana 11.2.2 el resolved trae startsAt = inicio del estado
        # Normal (mutado; medido 2026-10-20T02:07Z), por lo que la
        # igualdad de startsAt entre firing y resolved NO existe.
        liberadas = [k for k in list(state["executed"]) if k.startswith(fp + "|")]

        # Fase 4C - REF-COUNTING por target (anti-desbaneo prematuro).
        #
        # Con varias reglas IP activas, una MISMA src_ip puede tener 2
        # fingerprints distintos (p.ej. Protocolo fp1 + Entropia fp2). El
        # resolved de la primera NO puede ejecutar el -D: la IP sigue
        # siendo un atacante para la segunda regla, y retirar la regla
        # ahora abriria una ventana ciega. Primero se purgan las claves
        # del fingerprint resuelto; DESPUES se comprueba si queda alguna
        # OTRA entrada activa cuyo ban_ip == la misma IP.
        ip_resuelta = None
        for k in liberadas:
            entrada = state["executed"][k]
            if isinstance(entrada, dict) and entrada.get("ban_ip"):
                ip_resuelta = entrada["ban_ip"]
                break

        for k in liberadas:
            del state["executed"][k]
        save_state()

        if ip_resuelta is None:
            # Resolved de una clave que nunca llego a banear (DENY previo)
            # o de la rama 4A: nada que retirar en el kernel.
            audit("STATE_CLEARED", fingerprint=fp, startsAt=starts,
                  claves_liberadas=len(liberadas))
            return "STATE_CLEARED", f"fp={fp} liberadas={len(liberadas)}"

        # Ref-Counting: quedan otras alertas activas para la MISMA IP?
        retenedoras = [
            (k, e.get("rule"))
            for k, e in state["executed"].items()
            if isinstance(e, dict) and e.get("ban_ip") == ip_resuelta]
        if retenedoras:
            audit("STATE_CLEARED_PARTIAL", fingerprint=fp, target=ip_resuelta,
                  rule=labels.get("alertname"),
                  claves_liberadas=len(liberadas),
                  retenido_por=[{"clave": k, "rule": r}
                                for k, r in retenedoras])
            return ("STATE_CLEARED_PARTIAL",
                    f"fp={fp} target={ip_resuelta} retenido_por="
                    f"{[k for k, _ in retenedoras]}")

        # Ultima alerta activa para esa IP: retirar la regla SOAR-BAN del
        # kernel (si el -D falla, UNBAN_FAIL lo audita y la barrida
        # huerfana de reconcile_on_startup() lo recoge en el proximo
        # arranque).
        try:
            _unban_ip(ip_resuelta, rule=labels.get("alertname"))
        except Exception as e:
            audit("UNBAN_FAIL", target=ip_resuelta, error=str(e)[:200])
        audit("STATE_CLEARED", fingerprint=fp, startsAt=starts,
              target=ip_resuelta, rule=labels.get("alertname"),
              claves_liberadas=len(liberadas))
        return ("STATE_CLEARED",
                f"fp={fp} target={ip_resuelta} liberadas={len(liberadas)}")
    if st != "firing":
        return "SKIP_UNMATCHED_RULE", f"status={st!r}"
    if not ends.startswith(SENTINEL_PREFIX):
        return "MALFORMED_STATE", f"firing con endsAt={ends} fp={fp}"

    # ruteo por alertname (Fase 4C: las 3 reglas IP comparten el corte dual)
    if alertname in IP_ALERT_RULES:
        return _accion_ip(labels.get("src_ip"), clave, fp, now, rule=alertname)
    return _accion_contenedor(name, clave, fp, now)


class Handler(BaseHTTPRequestHandler):
    def _responder(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        ahora = time.time()
        # G1 - autenticacion
        auth = self.headers.get("Authorization", "")
        secreto = SECRET_FILE.read_text().strip() if SECRET_FILE.exists() else ""
        if not secreto or not hmac.compare_digest(auth, f"Bearer {secreto}"):
            audit("AUTH_FAIL", ip=self.client_address[0], path=self.path)
            self._responder(401, {"veredicto": "AUTH_FAIL"})
            return
        largo = int(self.headers.get("Content-Length", 0))
        crudo = self.rfile.read(largo).decode("utf-8", errors="replace")
        try:
            payload = json.loads(crudo)
        except Exception:
            audit("MALFORMED_JSON", ip=self.client_address[0])
            self._responder(400, {"veredicto": "MALFORMED_JSON"})
            return
        # G2 por ENVELOPE
        if payload.get("receiver") != EXPECTED_RECEIVER:
            audit("SKIP_UNMATCHED_RULE", razon="receiver",
                  receiver=payload.get("receiver"))
            self._responder(200, {"veredicto": "SKIP_UNMATCHED_RULE"})
            return
        decisiones = []
        for alert in payload.get("alerts", []):
            dec, det = evaluar_alerta(alert, ahora)
            decisiones.append({"fingerprint": alert.get("fingerprint"),
                               "status": alert.get("status"),
                               "veredicto": dec, "detalle": det})
        self._responder(200, {"decisiones": decisiones})

    def log_message(self, fmt, *args):
        pass  # la auditoria estructurada la hace audit()


if __name__ == "__main__":
    if "--live" in sys.argv:
        DRY_RUN = False
        print("MODO: contenedores LIVE (docker start real), "
              "IP_LIVE (corte dual DOCKER-USER+INPUT)", flush=True)
    else:
        print("MODO: contenedores DRY_RUN, IP_LIVE (corte dual "
              "DOCKER-USER+INPUT)", flush=True)
    load_state()
    reconcile_on_startup()
    # Fase 4D: cargar credenciales de Telegram una vez al arranque para que
    # el flag operativo sea exacto (sin exponer el secreto).
    _TG_CREDS = _load_telegram_creds()
    TELEGRAM_ENABLED = bool(_TG_CREDS.get("token") and _TG_CREDS.get("chatid"))
    audit("EXECUTOR_START",
          mode=("LIVE" if not DRY_RUN else "DRY_RUN"),
          dry_run=DRY_RUN,
          ip_dry_run=IP_DRY_RUN,
          ban_ttl_s=BAN_TTL_S,
          chains=list(CHAINS),
          bind=f"{BIND_ADDR}:{BIND_PORT}",
          allow=list(sorted(ALLOWED_CONTAINERS)),
          never_ban=sorted(NEVER_BAN_IPS),
          alertnames=sorted(EXPECTED_ALERTNAMES),
          ip_alert_rules=sorted(IP_ALERT_RULES),
          telegram_enabled=TELEGRAM_ENABLED,
          telegram_timeout_s=TELEGRAM_TIMEOUT_S)
    srv = ThreadingHTTPServer((BIND_ADDR, BIND_PORT), Handler)
    srv.serve_forever()
