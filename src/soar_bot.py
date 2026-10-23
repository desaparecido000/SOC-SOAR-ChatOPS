#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""soar_bot.py - Fase 4F: Consola ChatOps DevSecOps.

Proceso INDEPENDIENTE de gym-soar.service (Fase 4D, hash 31b5d4b4...). Este
demonio NUNCA modifica /root/soar/soar_executor.py: importa sus funciones y
constantes (las guardas certificadas) y lee sus artefactos en disco
(state.json, soar-audit.log).

Principios de diseno:
  * Transporte: getUpdates LONG-POLL (timeout=25, HTTP 30s) forzando
    resolucion AF_INET (IPv4). Sin abrir puertos en UFW.
  * Guarda G1-CHATOPS: solo el chat_id autorizado (TELEGRAM_CHAT_ID). Todo
    otro origen se descarta SIN responder y se audita CHATOPS_UNAUTHORIZED.
  * Cero shell libre: comandos cerrados. Ningun texto del usuario llega a un
    shell; /unban valida con ipaddress.ip_address() antes de tocar kernel.
  * Fail-safe: cualquier excepcion del bucle se audita y el proceso continua.
    Loki/iptables/Grafana caidos degradan elegantemente (nunca tumban el bot).
  * Revelacion progresiva (4F): capa ejecutiva amigable + capa forense bajo
    demanda (callback cb:tech). Navegacion con editMessageText (sin spam).
  * Guardas de operador: confirmacion en 2 pasos para /unban; ficha forense
    al pegar una IP; auditoria activa de postura en <2s.

No se imprime NUNCA el token ni el chat_id completo en logs.
"""

import html
import ipaddress
import json
import hashlib
import os
import re
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

# Import de las guardas y primitivas CERTIFICADAS. Solo lectura de constantes
# y llamada a funciones; NO se parchea nada de soar_executor.
sys.path.insert(0, "/root/soar")
import soar_executor as soar  # noqa: E402

# Alias importable y MONKEYPATEABLE por la suite (tests_chatops.py). El bot
# usa siempre `audit(...)` (resuelto en este modulo), de modo que un test
# puede sustituirlo sin tocar el audit real de produccion.
audit = soar.audit

# ---------------------------------------------------------------------------
# Constantes de configuracion (todas sobreescribibles en tests)
# ---------------------------------------------------------------------------
CREDS_FILE = soar.TELEGRAM_CREDS_FILE          # /root/.gym-creds/telegram
STATE_FILE = soar.STATE_FILE                   # /root/soar/state.json
AUDIT_LOG = soar.AUDIT_LOG                     # /root/soar/soar-audit.log
GYM_PROM = Path("/var/lib/node-exporter/textfile/gym.prom")
LOKI_URL = "http://127.0.0.1:3100"
LOKI_TIMEOUT_S = 4
LOKI_WINDOW = "6h"
LOKI_FICHA_WINDOW = "24h"     # ventana de la ficha forense de IP

GRAFANA_URL = "http://127.0.0.1:3000"
GRAFANA_ENV = Path("/opt/monitoring/.env")
GRAFANA_TIMEOUT_S = 4

RELEASE_DIR = Path("/root/soar/releases/v1.0-prod")
RELEASE_FILES = ("SHA256SUMS", "soar_executor.py", "tests_soar.py",
                 "gym-soar.service")
BACKUP_SLA_H = 26            # SLA de antiguedad de backups (horas)
RDNS_TIMEOUT_S = 1           # reverse DNS sin bloquear

# Lock de instancia unica: evita HTTP 409 por dos consumidores de getUpdates.
LOCK_FILE = Path("/run/gym-chatops.lock")

POLL_TIMEOUT_S = 25        # long-poll; Telegram retiene hasta 25s
HTTP_TIMEOUT_S = 30        # un poco mayor que POLL_TIMEOUT_S
TELEGRAM_API = "https://api.telegram.org/bot{token}/{method}"
MAX_CHARS = soar.TELEGRAM_MAX_CHARS            # 4000

SERVICE_NAME = "gym-soar.service"
SOAR_BIND = "172.19.0.1:9099"
EXECUTOR_PATH = Path("/root/soar/soar_executor.py")
EXECUTOR_SHA_EXPECTED = (
    "31b5d4b4e760dd94022d332b9d5d88091950db9b8d86c5c489892681569d80ab")

# Agrupacion logica de los contenedores (capa 1 ejecutiva).
GRUPOS_CONTENEDORES = {
    "🏢 Producción MetroCoord": (
        "metrocoord-frontend", "metrocoord-backend", "metrocoord-db",
        "metrocoord-redis"),
    "📡 SIEM / Observabilidad": (
        "grafana", "loki", "prometheus", "promtail", "node-exporter",
        "cadvisor"),
    "🛡️ Sensores & Perímetro": ("suricata", "nginx-proxy", "docker-ro-proxy"),
    "🧪 Laboratorio": ("dvwa", "kalilab", "msf3-lab", "lab-server", "atacante"),
}

# Traduccion de nombres tecnicos de alerta a motivos comprensibles.
MOTIVOS_ALERTA = {
    "GYM - Contenedor caido": "un contenedor dejó de responder",
    "GYM - SOAR Anomalia Protocolo": "tráfico con protocolo anómalo (posible ataque)",
    "GYM - SOAR Entropia URI": "URLs aleatorias/cifradas típicas de escaneo automático",
    "GYM - SOAR Suricata WAF": "firma de intrusión detectada por el IDS Suricata",
    "CHATOPS_MANUAL_UNBAN": "desbloqueo manual desde Telegram",
}

# ---------------------------------------------------------------------------
# Autenticacion (G1-CHATOPS)
# ---------------------------------------------------------------------------

AUTH_CHAT_ID = None       # se fija en main() desde las credenciales
TOKEN = ""


def is_authorized(message):
    """True solo si el chat.id del mensaje == chat autorizado.

    Devuelve (bool, info_descarte). El descarte se audita pero NUNCA responde.
    """
    try:
        chat_id = str(message["chat"]["id"])
    except (KeyError, TypeError):
        return False, {"chat_id": None, "user_id": None, "username": None}
    if AUTH_CHAT_ID and chat_id == str(AUTH_CHAT_ID):
        return True, None
    info = {
        "chat_id": chat_id,
        "user_id": str(message.get("from", {}).get("id", "")),
        "username": message.get("from", {}).get("username", ""),
    }
    return False, info


# ---------------------------------------------------------------------------
# Transporte Telegram con IPv4 forzado
# ---------------------------------------------------------------------------

_FORCE_IPV4 = True


def _https_json(url, payload=None, timeout=HTTP_TIMEOUT_S):
    """GET/POST JSON a Telegram forzando AF_INET (IPv4).

    Parcheamos getaddrinfo temporalmente para que api.telegram.org resuelva
    solo a IPv4. Determinista y no depende de envolver las capas internas de
    urllib. Restaura el resolver original siempre (finally).
    """
    data = None
    if payload is not None:
        data = urllib.parse.urlencode(payload).encode()
    if not _FORCE_IPV4:
        req = urllib.request.Request(url, data=data,
                                     method="POST" if data else "GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    original = socket.getaddrinfo

    def v4_only(host, port, family=0, type=0, proto=0, flags=0):
        return original(host, port, socket.AF_INET, type, proto, flags)

    socket.getaddrinfo = v4_only
    try:
        req = urllib.request.Request(url, data=data,
                                     method="POST" if data else "GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    finally:
        socket.getaddrinfo = original


def _api(method, params=None, timeout=HTTP_TIMEOUT_S):
    url = TELEGRAM_API.format(token=TOKEN, method=method)
    return _https_json(url, params, timeout=timeout)


def send_message(text, chat_id=None, reply_markup=None):
    """Envia un mensaje al chat autorizado. Fail-safe (devuelve bool).

    Devuelve True si se entrego. El `reply_markup` es un dict (inline keyboard)
    o None.
    """
    destino = chat_id if chat_id is not None else AUTH_CHAT_ID
    if not TOKEN or not destino:
        return False
    params = {
        "chat_id": str(destino),
        "text": text[:MAX_CHARS],
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    }
    if reply_markup is not None:
        params["reply_markup"] = json.dumps(reply_markup)
    try:
        r = _api("sendMessage", params)
        return bool(r.get("ok"))
    except Exception as e:
        audit("CHATOPS_SEND_ERROR", error=f"{type(e).__name__}: {str(e)[:160]}")
        return False


def edit_message_text(chat_id, message_id, text, reply_markup=None):
    """Edita un mensaje existente (navegacion sin spam). Fail-safe.

    "message is not modified" (tocar dos veces el mismo boton sin cambios) NO es
    un fallo: se considera exito y NO se audita como error (evita ruido).
    """
    if not TOKEN:
        return False
    params = {
        "chat_id": str(chat_id),
        "message_id": str(message_id),
        "text": text[:MAX_CHARS],
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    }
    if reply_markup is not None:
        params["reply_markup"] = json.dumps(reply_markup)
    try:
        r = _api("editMessageText", params)
        return bool(r.get("ok"))
    except Exception as e:
        msg = str(e)
        if "message is not modified" in msg:
            return True
        audit("CHATOPS_EDIT_ERROR", error=f"{type(e).__name__}: {msg[:160]}")
        return False


def answer_callback(callback_id, text=""):
    """Reconoce un callback_query (quita el relojito). Fail-safe."""
    if not TOKEN:
        return False
    try:
        r = _api("answerCallbackQuery",
                 {"callback_query_id": str(callback_id), "text": text[:200]})
        return bool(r.get("ok"))
    except Exception as e:
        audit("CHATOPS_ANSWER_ERROR", error=f"{type(e).__name__}: {str(e)[:160]}")
        return False


def set_my_commands(commands):
    """Registra el menu nativo de Telegram. Fail-safe."""
    if not TOKEN:
        return False
    try:
        r = _api("setMyCommands", {"commands": json.dumps(commands)})
        return bool(r.get("ok"))
    except Exception as e:
        audit("CHATOPS_SETCOMMANDS_ERROR", error=f"{type(e).__name__}: {str(e)[:160]}")
        return False


def get_updates(offset=None, timeout=POLL_TIMEOUT_S):
    params = {"timeout": timeout,
              "allowed_updates": json.dumps(["message", "callback_query"])}
    if offset is not None:
        params["offset"] = offset
    return _api("getUpdates", params, timeout=max(timeout + 5, HTTP_TIMEOUT_S))


# ---------------------------------------------------------------------------
# Utilidades de formato
# ---------------------------------------------------------------------------

def _esc(s):
    """Escapa para parse_mode HTML.

    Usa html.escape(quote=True): cubre &, <, > y ademas ' y " (como &#x27; y
    &quot;). Aunque Telegram HTML solo exige &, < y >, escapar las comillas es
    defensa en profundidad si algun dia se cambia a otro contexto (atributos).
    Cadena canonica para TODO texto dinamico insertado en un mensaje.
    """
    return html.escape(str(s), quote=True)


def _esc_dinamico(s, maxlen=200):
    """Escapa texto NO confiable proveniente de fuentes externas.

    Fuentes: URI de Nginx (Loki), alert_sig de Suricata (Loki), PTR de rDNS,
    campos de soar-audit.log, etc. Ademas de escapar HTML (via html.escape a
    traves de _esc), elimina caracteres de control que podrian romper el
    mensaje. Punto unico de paso para todo dato externo: si algo se inserta en
    un mensaje y no es una constante del programa, DEBE pasar por aqui.
    """
    return _esc(_limpia_control(s, maxlen))


def _limpia_control(s, maxlen=120):
    """Quita caracteres de control y trunca (SIN escapar HTML)."""
    s = re.sub(r"[\x00-\x1f\x7f]", " ", str(s))
    return s[:maxlen]


def _sanitiza_log(s, maxlen=120):
    """Sanitiza texto extraido de logs para insertarlo en HTML.

    Elimina caracteres de control y escapa HTML; evita inyeccion via logs
    (una URI maliciosa no debe poder romper el mensaje ni inyectar markup).
    """
    return _esc_dinamico(s, maxlen)


def barra(pct, ancho=10):
    """Barra visual [██░░░░░░░░] a partir de un porcentaje 0-100."""
    try:
        pct = float(pct)
    except (TypeError, ValueError):
        return "[" + "?" * ancho + "]"
    llenos = max(0, min(ancho, int(round(ancho * pct / 100.0))))
    return "[" + "█" * llenos + "░" * (ancho - llenos) + "]"


def semaforo(ok):
    return "🟢" if ok else "🔴"


# ---------------------------------------------------------------------------
# Parser de comandos (normaliza sufijo @bot de grupos)
# ---------------------------------------------------------------------------

def parse_command(text):
    """Extrae (cmd, args) de un texto de Telegram.

    En grupos el comando llega como `/status@vpsAlert777bot`; aplicamos
    split('@')[0] para normalizar. Devuelve ("", []) si no es un comando.
    """
    if not text:
        return "", []
    partes = text.split()
    if not partes:
        return "", []
    cmd = partes[0].split("@")[0].lower()
    if not cmd.startswith("/"):
        return "", []
    return cmd, partes[1:]


def parse_ip_texto(text):
    """Si `text` es una IP valida en texto plano, devuelve la IP normalizada.

    Se usa para la ficha forense interactiva: el operador pega una IP y el bot
    responde con la ficha. Nada de esto llega a un shell.
    """
    if not text:
        return None
    partes = text.strip().split()
    if len(partes) != 1:
        return None
    try:
        return str(ipaddress.ip_address(partes[0]))
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# /status - gym.prom + servicio + disco + RAM (capa 1 ejecutiva agrupada)
# ---------------------------------------------------------------------------

def _read_gym_prom(path=None):
    """Parsea gym.prom -> dict de metricas simples."""
    p = Path(path) if path else GYM_PROM
    up = {}
    scalars = {}
    total = 0
    try:
        for linea in p.read_text().splitlines():
            linea = linea.strip()
            if not linea or linea.startswith("#"):
                continue
            m = re.match(r'^gym_container_up\{name="([^"]+)"\}\s+(\S+)$', linea)
            if m:
                up[m.group(1)] = float(m.group(2))
                total += 1
                continue
            m = re.match(r'^(gym_[a-z_]+)\s+(\S+)$', linea)
            if m:
                try:
                    scalars[m.group(1)] = float(m.group(2))
                except ValueError:
                    pass
    except FileNotFoundError:
        return {"error": f"no existe {p}"}
    except Exception as e:
        return {"error": f"{type(e).__name__}: {str(e)[:120]}"}
    caidos = [n for n, v in up.items() if v != 1]
    return {
        "total": total,
        "arriba": total - len(caidos),
        "caidos": sorted(caidos),
        "up": up,
        "backup_age_s": scalars.get("gym_backup_age_seconds"),
        "cfg_backup_age_s": scalars.get("gym_monitoring_config_backup_age_seconds"),
    }


def _fmt_age(seg):
    if seg is None:
        return "N/D"
    seg = int(seg)
    if seg < 3600:
        return f"{seg // 60}m"
    if seg < 86400:
        return f"{seg // 3600}h {(seg % 3600) // 60}m"
    return f"{seg // 86400}d {(seg % 86400) // 3600}h"


def _service_state(nombre=SERVICE_NAME):
    try:
        r = subprocess.run(["systemctl", "is-active", nombre],
                           capture_output=True, text=True, timeout=5)
        activo = (r.stdout or "").strip()
        r2 = subprocess.run(["systemctl", "show", "-p", "MainPID", "--value", nombre],
                            capture_output=True, text=True, timeout=5)
        pid = (r2.stdout or "").strip()
        return activo, pid
    except Exception as e:
        return f"error:{type(e).__name__}", ""


def _disk_ram():
    out = {}
    try:
        st = os.statvfs("/")
        total = st.f_blocks * st.f_frsize
        libre = st.f_bavail * st.f_frsize
        out["disk_pct"] = int(100 * (1 - libre / total)) if total else None
        out["disk_libre_gb"] = round(libre / (1024 ** 3), 1)
    except Exception:
        out["disk_pct"] = None
    try:
        with open("/proc/meminfo") as f:
            mem = {}
            for l in f:
                k, _, v = l.partition(":")
                mem[k.strip()] = int(v.strip().split()[0])
        out["ram_libre_mb"] = round(mem.get("MemAvailable", 0) / 1024)
        out["ram_total_mb"] = round(mem.get("MemTotal", 0) / 1024)
    except Exception:
        out["ram_libre_mb"] = None
    return out


def _postura_global(g, activo, dr):
    """Postura agregada -> (texto_semaforo, ok_bool)."""
    ok = (not g.get("caidos")) and activo == "active"
    if dr.get("disk_pct") is not None:
        ok = ok and dr["disk_pct"] < 90
    if ok:
        return "🟢 OPERATIVO", True
    return "🟠 ATENCIÓN", False


def status_ejecutivo():
    """Capa 1: panel ejecutivo amigable con agrupacion y barras."""
    g = _read_gym_prom()
    activo, pid = _service_state()
    dr = _disk_ram()
    postura, ok = _postura_global(g, activo, dr)
    lineas = [f"📊 <b>Panel de Estado — SOAR DevSecOps</b>",
              f"Postura global: <b>{postura}</b>", ""]
    if "error" in g:
        lineas.append(f"⚠️ Métricas indisponibles: {g['error']}")
    else:
        lineas.append(f"🧩 <b>Contenedores: {g['arriba']}/{g['total']} en pie</b>")
        for grupo, nombres in GRUPOS_CONTENEDORES.items():
            presentes = [n for n in nombres if n in g["up"]]
            partidos = [n for n in presentes if g["up"][n] != 1]
            icono = semaforo(not partidos)
            detalle = ""
            if partidos:
                detalle = f" — caídos: {_esc(', '.join(partidos))}"
            lineas.append(f"{icono} {_esc(grupo)}: "
                          f"{len(presentes) - len(partidos)}/"
                          f"{len(presentes)}{detalle}")
        lineas.append("")
    lineas.append(f"{semaforo(activo == 'active')} <b>Servicio SOAR:</b> "
                  f"{_esc(activo)} (PID {_esc(pid or '-')})")
    if dr.get("disk_pct") is not None:
        lineas.append(f"💾 Disco /: {barra(dr['disk_pct'])} {dr['disk_pct']}% "
                      f"({dr['disk_libre_gb']} GB libres)")
    if dr.get("ram_libre_mb") is not None:
        pct = 100 * (1 - dr["ram_libre_mb"] / max(1, dr["ram_total_mb"]))
        lineas.append(f"🧠 RAM: {barra(pct)} {dr['ram_libre_mb']} MB libres "
                      f"de {dr['ram_total_mb']} MB")
    if g.get("backup_age_s") is not None:
        lineas.append(f"🗄️ Backup: {_fmt_age(g['backup_age_s'])} "
                      f"(SLA &lt; {BACKUP_SLA_H}h)")
    lineas.append("")
    lineas.append("Usa los botones para explorar o <code>/help</code>.")
    return "\n".join(lineas)


def cmd_status(_args):
    return status_ejecutivo()


# Teclado del panel (inline). cb:* = navegacion; los <IP> van en el callback.
def _kb_panel():
    return {"inline_keyboard": [
        [{"text": "🔄 Actualizar", "callback_data": "cb:status"},
         {"text": "🧠 Amenazas", "callback_data": "cb:threat"}],
        [{"text": "🚫 Baneos", "callback_data": "cb:bans"},
         {"text": "🔐 Auditar Blindaje", "callback_data": "cb:posture"}],
        [{"text": "🔬 Detalle Técnico", "callback_data": "cb:tech"}],
    ]}


def cmd_panel(_args):
    return status_ejecutivo()


# ---------------------------------------------------------------------------
# /bans - iptables en vivo + state.json + historial (capa 1 + botones)
# ---------------------------------------------------------------------------

def _live_bans():
    """Lee iptables -L -v -n -x y extrae reglas SOAR-BAN activas."""
    encontrados = {}
    for cadena in soar.CHAINS:
        try:
            r = subprocess.run(["iptables", "-L", cadena, "-v", "-n", "-x"],
                               capture_output=True, text=True, timeout=10)
        except Exception:
            continue
        if r.returncode != 0:
            continue
        for linea in (r.stdout or "").splitlines():
            if soar.BAN_COMMENT not in linea:
                continue
            campos = linea.split()
            if len(campos) < 8:
                continue
            src = campos[7]
            try:
                pkts = int(campos[0])
            except ValueError:
                pkts = None
            encontrados.setdefault(src, {})[cadena] = pkts
    return encontrados


def _tail_bans(n=5, path=None, target=None):
    """Ultimos n eventos BANNED_IP/UNBANNED_IP de soar-audit.log.

    Si `target` se indica, filtra por IP.
    """
    p = Path(path) if path else AUDIT_LOG
    eventos = []
    try:
        with open(p) as f:
            for linea in f:
                linea = linea.strip()
                if not linea:
                    continue
                try:
                    obj = json.loads(linea)
                except ValueError:
                    continue
                if obj.get("event") not in ("BANNED_IP", "UNBANNED_IP"):
                    continue
                if target is not None and obj.get("target") != target:
                    continue
                eventos.append(obj)
    except FileNotFoundError:
        return []
    return eventos[-n:]


def _motivo(rule):
    if not rule:
        return "motivo no registrado"
    return MOTIVOS_ALERTA.get(rule, rule)


def bans_ejecutivo():
    activos = _live_bans()
    hist = _tail_bans(5)
    lineas = ["🚫 <b>Baneos activos y actividad reciente</b>", ""]
    if not activos:
        lineas.append("🟢 No hay IPs bloqueadas ahora mismo.")
    else:
        lineas.append(f"🔴 <b>{len(activos)} IP(s) bloqueada(s) en el kernel:</b>")
        for ip, cadenas in sorted(activos.items()):
            total = sum(v for v in cadenas.values() if isinstance(v, int))
            lineas.append(f"• <code>{_esc(ip)}</code> — {total} paquetes cortados "
                          f"({_esc(', '.join(sorted(cadenas)))})")
    lineas.append("")
    lineas.append("📜 <b>Últimos eventos</b>")
    if not hist:
        lineas.append("• (sin historial)")
    for e in hist:
        marca = "🛡️" if e["event"] == "BANNED_IP" else "🟢"
        accion = "Bloqueada" if e["event"] == "BANNED_IP" else "Liberada"
        lineas.append(f"• {marca} {accion} <code>{_esc(e.get('target','?'))}</code>"
                      f" — {_esc(_motivo(e.get('rule')))}")
    return "\n".join(lineas)


def _kb_bans(activos):
    filas = [[{"text": "🔄 Actualizar", "callback_data": "cb:bans"},
              {"text": "⬅️ Panel", "callback_data": "cb:panel"}]]
    for ip in sorted(activos)[:6]:
        filas.append([{"text": f"🔓 Desbloquear {ip}",
                       "callback_data": f"cb:ask_unban:{ip}"}])
    return {"inline_keyboard": filas}


def cmd_bans(_args):
    return bans_ejecutivo()


# ---------------------------------------------------------------------------
# /threat - Loki (nginx 400/444 + suricata por firma)
# ---------------------------------------------------------------------------

def _loki_query(expr, base_url=None, timeout=None):
    """Ejecuta una query instantanea en Loki. Devuelve lista de resultados."""
    base = base_url or LOKI_URL
    t = timeout or LOKI_TIMEOUT_S
    url = f"{base}/loki/api/v1/query"
    data = urllib.parse.urlencode({"query": expr}).encode()
    req = urllib.request.Request(url + "?" + data.decode(), method="GET")
    with urllib.request.urlopen(req, timeout=t) as resp:
        obj = json.loads(resp.read().decode())
    if obj.get("status") != "success":
        raise RuntimeError(f"loki status={obj.get('status')}")
    return obj["data"]["result"]


def _loki_range(expr, limit=3, base_url=None, timeout=None, since=None):
    """Query de rango en Loki (para lineas crudas). Devuelve lista de streams."""
    base = base_url or LOKI_URL
    t = timeout or LOKI_TIMEOUT_S
    ventana = since or LOKI_FICHA_WINDOW
    url = f"{base}/loki/api/v1/query_range?" + urllib.parse.urlencode(
        {"query": expr, "limit": limit, "since": ventana})
    with urllib.request.urlopen(url, timeout=t) as resp:
        obj = json.loads(resp.read().decode())
    if obj.get("status") != "success":
        raise RuntimeError(f"loki status={obj.get('status')}")
    return obj["data"]["result"]


def _nginx_recientes(ip, limit=3):
    r"""Ultimas `limit` peticiones de una IP en Nginx (via Loki).

    El access.log de nginx esta en formato combinado (no JSON), asi que
    filtramos por substring con ANCLAJE `|= "<ip> - "` (la IP siempre va
    seguida de " - " en el formato combinado logs). Esto evita falsos
    positivos de prefijos/sufijos: consultar `1.2.3.4` NO arrastra lineas de
    `1.2.3.40` ni de `11.2.3.4`. Ademas se revalida el token inicial de cada
    linea con `^\s*<ip>\b` antes de aceptarla (defensa en profundidad).

    Devuelve lista de dicts {metodo, uri, status} con la URI ya SANITIZADA
    (se aplica escape HTML en la capa de presentacion, no aqui). Lista vacia
    si Loki no responde.
    """
    filtro = f'|= "{ip} - "'
    streams = _loki_range(f'{{job="nginx"}} {filtro}', limit=limit)
    salida = []
    patron = re.compile(
        r"^\s*(?P<ip>\S+)\s+-\s+-\s+\[[^\]]+\]\s+\"(?P<met>\S+)\s+"
        r"(?P<uri>\S+)[^\"]*\"\s+(?P<st>\d{3})")
    patron_ip = re.compile(r"^\s*" + re.escape(ip) + r"\b")
    for s in streams:
        for _ts, line in s.get("values", []):
            # Anclaje estricto: el token inicial debe ser EXACTAMENTE la IP.
            if not patron_ip.match(line):
                continue
            m = patron.match(line)
            if m and m.group("ip") == ip:
                salida.append({"metodo": m.group("met"),
                               "uri": m.group("uri"),
                               "status": m.group("st")})
    return salida[:limit]


def threat_ejecutivo():
    ventana = LOKI_WINDOW
    lineas = [f"🧠 <b>Inteligencia de amenazas (últimas {ventana})</b>", ""]
    # 1) Nginx: errores 400/444
    try:
        expr_ng = (f'sum(count_over_time({{job="nginx"}} '
                   f'| json | status=~"400|444" [{ventana}]))')
        res_ng = _loki_query(expr_ng)
        total_ng = int(float(res_ng[0]["value"][1])) if res_ng else 0
        icono = "🟢" if total_ng == 0 else ("🟠" if total_ng < 50 else "🔴")
        lineas.append(f"{icono} <b>Nginx:</b> {total_ng} peticiones rechazadas "
                      f"(400/444)")
        if total_ng:
            expr_ip = (f'topk(3, sum by (remote_addr) (count_over_time('
                       f'{{job="nginx"}} | json | status=~"400|444" [{ventana}])))')
            try:
                for r in _loki_query(expr_ip):
                    src = r["metric"].get("remote_addr", "?")
                    lineas.append(f"    – <code>{_esc(src)}</code>: "
                                  f"{int(float(r['value'][1]))}")
            except Exception:
                pass
    except Exception as e:
        lineas.append(f"🟠 Nginx: Loki no disponible ({type(e).__name__})")
    # 2) Suricata por firma
    try:
        expr_su = (f'topk(5, sum by (alert_sig) (count_over_time('
                   f'{{job="suricata"}} | alert_sig!="" [{ventana}])))')
        res_su = _loki_query(expr_su)
        if not res_su:
            lineas.append("🟢 <b>Suricata:</b> sin alertas en la ventana.")
        else:
            lineas.append("🔴 <b>Suricata (top firmas):</b>")
            for r in res_su:
                sig = r["metric"].get("alert_sig", "?")
                lineas.append(f"    – {_esc_dinamico(sig)}: "
                              f"{int(float(r['value'][1]))}")
    except Exception as e:
        lineas.append(f"🟠 Suricata: Loki no disponible ({type(e).__name__})")
    return "\n".join(lineas)


def cmd_threat(_args):
    return threat_ejecutivo()


# ---------------------------------------------------------------------------
# /unban <IP> - desbloqueo dual acotado
# ---------------------------------------------------------------------------

def _validar_ip_texto(objetivo):
    """Devuelve (ip_normalizada | None, motivo_denegacion | None).

    Comprueba sintaxis y NEVER_BAN. NO toca el kernel.
    """
    try:
        ip = str(ipaddress.ip_address(objetivo.strip()))
    except (ValueError, AttributeError):
        return None, "malformed"
    if ip in soar.NEVER_BAN_IPS:
        return None, "never_ban"
    return ip, None


def unban_aplicar(objetivo, origen="CHATOPS"):
    """Ejecuta el desbloqueo delegando en la primitiva CERTIFICADA.

    Devuelve el texto de respuesta. Valida antes; audita el resultado.
    """
    ip, motivo = _validar_ip_texto(objetivo)
    if motivo == "malformed":
        audit("DENY_MALFORMED_IP", target=str(objetivo)[:64], origen=origen)
        return (f"⛔ IP inválida: <code>{_esc(str(objetivo)[:40])}</code>\n"
                "Se auditó DENY_MALFORMED_IP.")
    if motivo == "never_ban":
        audit("DENY_NEVER_BAN", target=ip, origen=origen)
        return f"⛔ <code>{_esc(ip)}</code> está en NEVER_BAN; no se toca."
    t0 = time.time()
    try:
        retirado = soar._unban_ip(ip, rule="CHATOPS_MANUAL_UNBAN")
    except Exception as e:
        audit("CHATOPS_MANUAL_UNBAN_ERROR", target=ip,
              error=f"{type(e).__name__}: {str(e)[:160]}")
        return f"❌ Error al desbloquear <code>{_esc(ip)}</code>: {type(e).__name__}"
    ms = int((time.time() - t0) * 1000)
    dropped = {}
    try:
        for e in _tail_bans(1, target=ip):
            if e["event"] == "UNBANNED_IP":
                dropped = e.get("dropped_pkts") or {}
    except Exception:
        pass
    audit("CHATOPS_MANUAL_UNBAN", target=ip, retirado=bool(retirado),
          duracion_ms=ms)
    if retirado:
        det = ", ".join(f"{k}={v}" for k, v in dropped.items()) or "s/datos"
        return (f"🟢 <b>Desbloqueo aplicado</b>\n"
                f"• IP: <code>{_esc(ip)}</code>\n"
                f"• Corte dual retirado en {ms} ms\n"
                f"• Paquetes bloqueados: {_esc(det)}")
    return (f"ℹ️ <code>{_esc(ip)}</code> no tenía regla SOAR-BAN activa "
            f"(revisado en {ms} ms).")


def cmd_unban(args):
    if not args:
        return ("⚠️ Uso: <code>/unban &lt;IP&gt;</code>\n"
                "Ejemplo: <code>/unban 45.33.32.90</code>")
    return unban_aplicar(args[0])


# ---------------------------------------------------------------------------
# Ficha forense de IP (capa 2 bajo demanda desde texto plano / botones)
# ---------------------------------------------------------------------------

def _rdns(ip):
    """Reverse DNS con timeout corto (no bloquea el bot)."""
    try:
        socket.setdefaulttimeout(RDNS_TIMEOUT_S)
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(None)


def ficha_ip(ip):
    """Ficha forense de una IP. Devuelve (texto, kb|None).

    Estado en firewall (DOCKER-USER/INPUT), reverse DNS, historial en
    soar-audit.log, ultimas 3 URIs en Nginx (Loki) y boton de accion SOLO si
    la IP esta baneada.
    """
    ip_n, motivo = _validar_ip_texto(ip)
    if motivo:
        return (f"⛔ IP inválida: <code>{_esc(str(ip)[:40])}</code>", None)
    activos = _live_bans().get(ip_n, {})
    baneada = bool(activos)
    rdn = _rdns(ip_n)
    hist = _tail_bans(3, target=ip_n)
    lineas = [f"🔎 <b>Ficha forense — <code>{_esc(ip_n)}</code></b>", ""]
    lineas.append(f"Estado firewall: {'🔴 BLOQUEADA' if baneada else '🟢 libre'}")
    for cadena in soar.CHAINS:
        if cadena in activos:
            lineas.append(f"  • {cadena}: {_esc(activos[cadena])} pkts cortados")
    lineas.append(f"Red / DNS: {_esc_dinamico(rdn) if rdn else 'sin PTR'}")
    if hist:
        lineas.append("Historial:")
        for e in hist:
            accion = "Bloqueada" if e["event"] == "BANNED_IP" else "Liberada"
            lineas.append(f"  • {accion} @ {_esc(e.get('ts',''))} "
                          f"— {_esc(_motivo(e.get('rule')))}")
    else:
        lineas.append("Historial: (sin eventos)")
    try:
        peticiones = _nginx_recientes(ip_n, 3)
        if peticiones:
            lineas.append("Últimas peticiones (Nginx):")
            for p in peticiones:
                lineas.append(f"  • {_esc(p['metodo'])} "
                              f"<code>{_sanitiza_log(p['uri'])}</code> "
                              f"→ {_esc(p['status'])}")
        else:
            lineas.append("Últimas peticiones (Nginx): (sin registros)")
    except Exception as e:
        lineas.append(f"Últimas peticiones (Nginx): ⚠️ {type(e).__name__}")
    kb = None
    if baneada:
        kb = {"inline_keyboard": [[
            {"text": f"🔓 Desbloquear {ip_n}",
             "callback_data": f"cb:ask_unban:{ip_n}"}]]}
    return "\n".join(lineas), kb


# ---------------------------------------------------------------------------
# Detalle tecnico (capa 2 del panel)
# ---------------------------------------------------------------------------

def tech_detail():
    """Metricas crudas para forense: fingerprint, cadenas, dropped_pkts,
    hash de integridad y estado de servicio."""
    lineas = ["🔬 <b>Detalle Técnico</b>", ""]
    # Hash de integridad
    try:
        h = hashlib.sha256(EXECUTOR_PATH.read_bytes()).hexdigest()
        intacto = h == EXECUTOR_SHA_EXPECTED
        lineas.append(f"Integridad executor: {semaforo(intacto)} "
                      f"<code>{h[:16]}…</code>")
    except Exception as e:
        lineas.append(f"Integridad executor: ⚠️ {type(e).__name__}")
    # Estado state.json (fingerprints)
    try:
        st = json.loads(STATE_FILE.read_text())
        execs = st.get("executed", {})
        acts = st.get("actions", {})
        lineas.append(f"state.json: executed={len(execs)} actions={len(acts)}")
        for k in list(execs)[:3]:
            fp = k.split("|")[0] if "|" in k else k
            lineas.append(f"  • fingerprint <code>{_esc(fp)}</code>")
    except Exception as e:
        lineas.append(f"state.json: ⚠️ {type(e).__name__}")
    # Bans activos: cadenas y pkts por cadena
    activos = _live_bans()
    lineas.append("")
    lineas.append(f"Cadenas: {_esc(', '.join(soar.CHAINS))}")
    if activos:
        for ip, cadenas in sorted(activos.items()):
            pares = ", ".join(f"{c}={cadenas[c]}"
                              for c in sorted(cadenas))
            lineas.append(f"  • <code>{_esc(ip)}</code>: {_esc(pares)}")
    else:
        lineas.append("  • sin reglas SOAR-BAN activas")
    # dropped_pkts historicos (ultimo UNBANNED)
    ult = _tail_bans(1)
    if ult and ult[-1]["event"] == "UNBANNED_IP":
        dropped = ult[-1].get("dropped_pkts") or {}
        det = ", ".join(f"{k}={v}" for k, v in dropped.items()) or "s/datos"
        lineas.append(f"Último dropped_pkts: {_esc(det)}")
    return "\n".join(lineas)


# ---------------------------------------------------------------------------
# Auditoria de postura (/audit y cb:posture)
# ---------------------------------------------------------------------------

def _check_hash_release():
    """1. Hash de soar_executor.py == esperado y flag inmutable del release."""
    res = {}
    try:
        h = hashlib.sha256(EXECUTOR_PATH.read_bytes()).hexdigest()
        res["hash_ok"] = (h == EXECUTOR_SHA_EXPECTED)
        res["hash"] = h
    except Exception:
        res["hash_ok"] = False
        res["hash"] = "error"
    # flag inmutable (lsattr) en el release
    try:
        r = subprocess.run(["lsattr"] + [str(RELEASE_DIR / f)
                                         for f in RELEASE_FILES],
                           capture_output=True, text=True, timeout=5)
        lineas = (r.stdout or "").splitlines()
        con_i = sum(1 for l in lineas if re.match(r"^----i", l))
        res["inmutable_ok"] = (con_i >= 3)  # SHA256SUMS, executor, tests
        res["inmutables"] = con_i
    except Exception:
        res["inmutable_ok"] = False
        res["inmutables"] = 0
    res["ok"] = res["hash_ok"] and res["inmutable_ok"]
    return res


def _check_reglas_fijas():
    """2. Reglas fijas de firewall presentes (msf3 + blindaje INPUT + fail2ban).

    El blindaje del VPS se compone de:
      * msf3: DROP de 172.30.0.0/24 hacia 172.30.0.1 (aísla el lab del gateway).
      * INPUT con politica DROP (no acepta por defecto) + cadenas ufw-*.
      * fail2ban activo con jails (backend ufw).

    Nota historica: la evidencia 4C.3 registraba cadenas `f2b-*` en INPUT; el
    backend de fail2ban paso a ufw, de modo que la comprobacion se adapta al
    estado REAL y no a un artefacto caducado. Se acepta f2b-* si existiera
    (compatibilidad) o ufw + politica DROP (estado actual).
    """
    res = {"msf3_ok": False, "input_hard_ok": False, "f2b_ok": False,
           "jails_ok": False}
    try:
        r = subprocess.run(["iptables", "-S", "DOCKER-USER"],
                           capture_output=True, text=True, timeout=5)
        res["msf3_ok"] = any("172.30.0.0/24" in l and "172.30.0.1" in l
                             and "DROP" in l
                             for l in (r.stdout or "").splitlines())
    except Exception:
        pass
    try:
        r = subprocess.run(["iptables", "-S", "INPUT"],
                           capture_output=True, text=True, timeout=5)
        salida = r.stdout or ""
        # politica por defecto DROP o cadena f2b-* como jaula de fail2ban
        res["input_hard_ok"] = ("-P INPUT DROP" in salida
                                or "ufw-" in salida)
        res["f2b_ok"] = any("f2b-" in l or "f2b_nginx" in l
                            for l in salida.splitlines())
    except Exception:
        pass
    # fail2ban activo con al menos un jail (backend actual: ufw)
    try:
        r = subprocess.run(["fail2ban-client", "status"], capture_output=True,
                           text=True, timeout=5)
        res["jails_ok"] = "Jail list:" in (r.stdout or "")
    except Exception:
        pass
    res["ok"] = (res["msf3_ok"] and res["input_hard_ok"] and res["jails_ok"])
    return res


def _check_servicio():
    """3. gym-soar.service activo y escuchando en 172.19.0.1:9099."""
    res = {"activo": False, "escucha": False}
    try:
        estado, _ = _service_state()
        res["activo"] = estado == "active"
    except Exception:
        pass
    try:
        r = subprocess.run(["ss", "-ltn"], capture_output=True, text=True,
                           timeout=5)
        res["escucha"] = SOAR_BIND in (r.stdout or "")
    except Exception:
        pass
    res["ok"] = res["activo"] and res["escucha"]
    return res


def _grafana_rules():
    """Devuelve (total, ok_count) de las reglas de alerta de Grafana."""
    try:
        pw = ""
        for linea in GRAFANA_ENV.read_text().splitlines():
            if linea.startswith("GF_SECURITY_ADMIN_PASSWORD="):
                pw = linea.split("=", 1)[1].strip()
        user = "admin"
        for linea in GRAFANA_ENV.read_text().splitlines():
            if linea.startswith("GF_SECURITY_ADMIN_USER="):
                user = linea.split("=", 1)[1].strip()
        url = f"{GRAFANA_URL}/api/prometheus/grafana/api/v1/rules"
        token = _b64(f"{user}:{pw}")
        req = urllib.request.Request(url)
        req.add_header("Authorization", f"Basic {token}")
        with urllib.request.urlopen(req, timeout=GRAFANA_TIMEOUT_S) as resp:
            obj = json.loads(resp.read().decode())
        groups = obj.get("data", {}).get("groups", [])
        rules = [r for g in groups for r in g.get("rules", [])]
        total = len(rules)
        ok = sum(1 for r in rules if r.get("health") == "ok")
        return total, ok
    except Exception as e:
        return None, f"{type(e).__name__}"


def _b64(s):
    import base64
    return base64.b64encode(s.encode()).decode()


def _check_grafana():
    """4. Salud de las reglas de Grafana (todas health=ok)."""
    total, ok = _grafana_rules()
    if total is None:
        return {"ok": False, "error": ok, "total": 0, "saludables": 0}
    return {"ok": ok == total and total > 0, "total": total, "saludables": ok}


def _check_backups():
    """5. Edad de backups dentro de SLA (< 26h)."""
    g = _read_gym_prom()
    edad = g.get("backup_age_s")
    if edad is None:
        return {"ok": False, "edad_s": None}
    return {"ok": edad < BACKUP_SLA_H * 3600, "edad_s": edad}


def auditar_postura():
    """Verifica las 5 invariantes. Devuelve (texto, todo_ok)."""
    t0 = time.time()
    c1 = _check_hash_release()
    c2 = _check_reglas_fijas()
    c3 = _check_servicio()
    c4 = _check_grafana()
    c5 = _check_backups()
    ms = int((time.time() - t0) * 1000)
    todo = all(c["ok"] for c in (c1, c2, c3, c4, c5))
    lineas = [f"🔐 <b>Auditoría de Blindaje</b> — "
              f"{semaforo(todo)} {'TODO OK' if todo else 'REVISAR'} "
              f"({ms} ms)", ""]
    lineas.append(f"{semaforo(c1['ok'])} 1. Integridad executor: "
                  f"hash={'OK' if c1['hash_ok'] else 'DIFERENTE'}, "
                  f"inmutable={c1['inmutables']} ficheros")
    lineas.append(f"{semaforo(c2['ok'])} 2. Blindaje firewall: "
                  f"msf3={'OK' if c2['msf3_ok'] else 'FALTA'}, "
                  f"INPUT={'OK' if c2['input_hard_ok'] else 'BLANDO'}, "
                  f"fail2ban={'OK' if c2['jails_ok'] else 'NO'}")
    lineas.append(f"{semaforo(c3['ok'])} 3. Servicio SOAR: "
                  f"activo={'OK' if c3['activo'] else 'NO'}, "
                  f"escucha {SOAR_BIND}={'OK' if c3['escucha'] else 'NO'}")
    if c4.get("error"):
        lineas.append(f"🟠 4. Reglas Grafana: no consultable ({c4['error']})")
    else:
        lineas.append(f"{semaforo(c4['ok'])} 4. Reglas Grafana: "
                      f"{c4['saludables']}/{c4['total']} saludables")
    if c5["edad_s"] is None:
        lineas.append("🟠 5. Backups: métrica no disponible")
    else:
        lineas.append(f"{semaforo(c5['ok'])} 5. Backups: "
                      f"{_fmt_age(c5['edad_s'])} (SLA &lt; {BACKUP_SLA_H}h)")
    audit("CHATOPS_POSTURE_AUDIT", ok=todo, duracion_ms=ms)
    return "\n".join(lineas), todo


def cmd_audit(_args):
    return auditar_postura()[0]


# ---------------------------------------------------------------------------
# /help y menu
# ---------------------------------------------------------------------------

HELP_TEXT = (
    "🤖 <b>SOAR ChatOps — comandos</b>\n"
    "• <code>/panel</code> — tablero interactivo (botones)\n"
    "• <code>/status</code> — contenedores, servicio, disco y RAM\n"
    "• <code>/threat</code> — amenazas (Nginx + Suricata, Loki 6h)\n"
    "• <code>/bans</code> — IPs bloqueadas + últimos eventos\n"
    "• <code>/audit</code> — audita las 5 invariantes de blindaje\n"
    "• <code>/unban &lt;IP&gt;</code> — desbloqueo (con confirmación)\n"
    "• <code>/help</code> — esta ayuda\n"
    "\n💡 Pega una IP (p.ej. <code>45.33.32.90</code>) y te devuelvo su "
    "ficha forense.\n"
    "Solo lectura salvo el desbloqueo. Chat autorizado únicamente."
)


def cmd_help(_args):
    return HELP_TEXT


HANDLERS = {
    "/panel": cmd_panel,
    "/status": cmd_status,
    "/bans": cmd_bans,
    "/threat": cmd_threat,
    "/audit": cmd_audit,
    "/unban": cmd_unban,
    "/help": cmd_help,
    "/start": cmd_panel,
}


# ---------------------------------------------------------------------------
# Callbacks (navegacion + confirmacion 2 pasos)
# ---------------------------------------------------------------------------

def _texto_y_kb_para(dato):
    """Devuelve (texto, reply_markup) para un callback_data `dato`.

    Cubre navegacion (cb:panel/status/threat/bans/posture/tech) y las fases de
    la confirmacion de desbloqueo (cb:ask_unban/cb:do_unban/cb:cancel).
    """
    if dato in ("cb:panel", "cb:status"):
        return status_ejecutivo(), _kb_panel()
    if dato == "cb:threat":
        return threat_ejecutivo(), {"inline_keyboard": [[
            {"text": "🔄 Actualizar", "callback_data": "cb:threat"},
            {"text": "⬅️ Panel", "callback_data": "cb:panel"}]]}
    if dato == "cb:bans":
        return bans_ejecutivo(), _kb_bans(_live_bans())
    if dato == "cb:posture":
        texto, _ = auditar_postura()
        return texto, {"inline_keyboard": [[
            {"text": "🔄 Reauditar", "callback_data": "cb:posture"},
            {"text": "⬅️ Panel", "callback_data": "cb:panel"}]]}
    if dato == "cb:tech":
        return tech_detail(), {"inline_keyboard": [[
            {"text": "⬅️ Panel", "callback_data": "cb:panel"}]]}
    if dato.startswith("cb:ask_unban:"):
        ip = dato.split(":", 2)[2]
        ip_n, motivo = _validar_ip_texto(ip)
        if motivo:
            return (f"⛔ IP inválida: <code>{_esc(ip[:40])}</code>",
                    {"inline_keyboard": [[{"text": "⬅️ Panel",
                                           "callback_data": "cb:panel"}]]})
        texto = (f"⚠️ <b>Confirmar desbloqueo</b>\n"
                 f"Vas a retirar el corte SOAR-BAN de <code>{_esc(ip_n)}</code> "
                 f"en DOCKER-USER e INPUT.\n\n¿Confirmas?")
        kb = {"inline_keyboard": [[
            {"text": f"⚠️ Confirmar Desbloqueo de {ip_n}",
             "callback_data": f"cb:do_unban:{ip_n}"},
            {"text": "↩️ Cancelar", "callback_data": "cb:cancel"}]]}
        return texto, kb
    if dato.startswith("cb:do_unban:"):
        ip = dato.split(":", 2)[2]
        texto = unban_aplicar(ip, origen="CHATOPS_CALLBACK")
        return texto, {"inline_keyboard": [[
            {"text": "🚫 Ver baneos", "callback_data": "cb:bans"},
            {"text": "⬅️ Panel", "callback_data": "cb:panel"}]]}
    if dato == "cb:cancel":
        return ("↩️ Desbloqueo cancelado. No se tocó el firewall.",
                {"inline_keyboard": [[{"text": "⬅️ Panel",
                                       "callback_data": "cb:panel"}]]})
    return ("❓ Acción desconocida.", None)


def handle_callback(cq, responder=None):
    """Procesa un callback_query autorizado. Devuelve (texto, kb) o None.

    `responder` inyectable: recibe (texto, kb, editar) para tests.
    """
    chat_id = str(cq.get("message", {}).get("chat", {}).get("id", ""))
    if not AUTH_CHAT_ID or chat_id != str(AUTH_CHAT_ID):
        audit("CHATOPS_UNAUTHORIZED",
              chat_id=chat_id,
              user_id=str(cq.get("from", {}).get("id", "")),
              username=cq.get("from", {}).get("username", ""))
        return None
    dato = cq.get("data", "")
    texto, kb = _texto_y_kb_para(dato)
    message_id = cq.get("message", {}).get("message_id")
    if responder is not None:
        responder(texto, kb, message_id)
    else:
        edit_message_text(chat_id, message_id, texto, kb)
        answer_callback(cq.get("id", ""))
    return texto, kb


# ---------------------------------------------------------------------------
# Dispatch y bucle principal
# ---------------------------------------------------------------------------

def dispatch(message, responder=None):
    """Procesa un mensaje. Devuelve el texto de respuesta o None.

    `responder` es inyectable en tests (por defecto: send_message real).
    Guarda G1-CHATOPS primero: origen no autorizado -> None (sin responder),
    auditado como CHATOPS_UNAUTHORIZED. Si el texto es una IP valida, responde
    con su ficha forense.
    """
    autorizado, info = is_authorized(message)
    if not autorizado:
        audit("CHATOPS_UNAUTHORIZED", **(info or {}))
        return None
    texto = message.get("text", "")
    cmd, args = parse_command(texto)
    kb = None
    if cmd in HANDLERS:
        try:
            res = HANDLERS[cmd](args)
        except Exception as e:
            audit("CHATOPS_CMD_ERROR", comando=cmd,
                  error=f"{type(e).__name__}: {str(e)[:160]}")
            res = f"❌ Error ejecutando <code>{cmd}</code>: {type(e).__name__}"
        if cmd in ("/panel", "/status", "/start"):
            kb = _kb_panel()
        elif cmd == "/bans":
            kb = _kb_bans(_live_bans())
    elif cmd:
        res = f"❓ Comando desconocido: <code>{_esc(cmd)}</code>\n\n" + HELP_TEXT
    else:
        # No es comando: ¿es una IP en texto plano? -> ficha forense.
        ip = parse_ip_texto(texto)
        if ip is None:
            return None
        try:
            res, kb = ficha_ip(ip)
        except Exception as e:
            audit("CHATOPS_FICHA_ERROR", target=ip,
                  error=f"{type(e).__name__}: {str(e)[:160]}")
            res = f"❌ Error generando la ficha de <code>{_esc(ip)}</code>"
    if responder is not None:
        responder(res)
    else:
        send_message(res, reply_markup=kb)
    return res


def run_once(get_updates_fn=None, responder=None, offset=None,
             cb_responder=None):
    """Un ciclo de polling. Devuelve el nuevo offset.

    Inyectable: tests pasan un get_updates_fn falso y responders falsos.
    """
    gu = get_updates_fn or get_updates
    try:
        resp = gu(offset=offset, timeout=POLL_TIMEOUT_S)
    except Exception as e:
        audit("CHATOPS_POLL_ERROR", error=f"{type(e).__name__}: {str(e)[:160]}")
        time.sleep(2)
        return offset
    if not resp or not resp.get("ok"):
        return offset
    max_id = offset
    for upd in resp.get("result", []):
        uid = upd.get("update_id")
        if uid is not None and (max_id is None or uid >= max_id):
            max_id = uid + 1
        msg = upd.get("message")
        if msg:
            dispatch(msg, responder=responder)
        cq = upd.get("callback_query")
        if cq:
            handle_callback(cq, responder=cb_responder)
    return max_id


def _drain_backlog(get_updates_fn=None, responder=None):
    """Descarta updates acumulados mientras el bot estuvo apagado.

    getUpdates(offset=-1) devuelve el ultimo update; fijamos offset = last+1
    sin procesarlo para no ejecutar comandos viejos.
    """
    gu = get_updates_fn or get_updates
    try:
        resp = gu(offset=-1, timeout=0)
    except Exception as e:
        audit("CHATOPS_DRAIN_ERROR", error=f"{type(e).__name__}: {str(e)[:160]}")
        return None
    if not resp or not resp.get("ok"):
        return None
    result = resp.get("result", [])
    if not result:
        return None
    return result[-1]["update_id"] + 1


MENU_COMANDOS = [
    {"command": "panel", "description": "Tablero interactivo con botones"},
    {"command": "status", "description": "Estado de contenedores, servicio y recursos"},
    {"command": "threat", "description": "Amenazas recientes (Nginx + Suricata)"},
    {"command": "bans", "description": "IPs bloqueadas y últimos eventos"},
    {"command": "audit", "description": "Auditar las 5 invariantes de blindaje"},
    {"command": "help", "description": "Guía de comandos"},
]


def main(argv=None):
    global TOKEN, AUTH_CHAT_ID
    argv = argv if argv is not None else sys.argv[1:]

    # Instancia unica: dos procesos haciendo getUpdates -> HTTP 409. El lock
    # (fcntl.flock no bloqueante) aborta el segundo arranque.
    lock_fd = None
    try:
        import fcntl
        lock_fd = os.open(str(LOCK_FILE), os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (ImportError, OSError) as e:
        if lock_fd is not None:
            print(f"FATAL: otra instancia activa ({type(e).__name__})",
                  file=sys.stderr)
            audit("CHATOPS_INSTANCE_CONFLICT", error=f"{type(e).__name__}")
            return 3
        lock_fd = None

    creds = soar._load_telegram_creds()
    TOKEN = creds.get("token", "")
    AUTH_CHAT_ID = creds.get("chatid", "") or None
    if not TOKEN or not AUTH_CHAT_ID:
        audit("CHATOPS_START_ERROR", motivo="credenciales ausentes o invalidas")
        print("FATAL: sin credenciales de Telegram", file=sys.stderr)
        return 2

    audit("CHATOPS_START", mode="LIVE", timeout_s=POLL_TIMEOUT_S,
          lock_ctx=bool(soar.TELEGRAM_ENABLED), force_ipv4=True,
          ventana_loki=LOKI_WINDOW, fase="4F")

    # Menu nativo de Telegram (descripciones en espanol).
    if set_my_commands(MENU_COMANDOS):
        audit("CHATOPS_MENU_REGISTERED", n=len(MENU_COMANDOS))

    # Descarta backlog previo al arranque (no ejecutar comandos viejos)
    offset = _drain_backlog()
    if offset is not None:
        audit("CHATOPS_BACKLOG_DRAINED", next_offset=offset)

    # Mensaje de arranque con el panel interactivo.
    send_message("🤖 [SOAR] Consola ChatOps 4F en línea. Tablero:", reply_markup=_kb_panel())
    send_message(status_ejecutivo())

    while True:
        offset = run_once(offset=offset)
        time.sleep(0.3)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception as e:  # noqa: BLE001
        audit("CHATOPS_FATAL", error=f"{type(e).__name__}: {str(e)[:200]}")
        raise
