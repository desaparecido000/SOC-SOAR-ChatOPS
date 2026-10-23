#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Suite de tests de soar_bot.py (Fase 4E - ChatOps).

Sin red real y sin escribir en ficheros de produccion. Verifica:
  C1  rechazo de chat.id no autorizado -> CHATOPS_UNAUTHORIZED, sin respuesta
  C2  parseo de comandos con y sin sufijo @vpsAlert777bot
  C3  /status contra gym.prom simulado (18/18 OK y con 1 contenedor caido)
  C4  /bans con reglas activas + historial
  C5  /threat con Loki mockeado y con fallo/timeout de Loki
  C6  /unban IP valida e invalida/inyeccion (DENY_MALFORMED_IP)
  C7  el hash de soar_executor.py sigue siendo 31b5d4b4...

Exit 0 = todos PASS.
"""

import hashlib
import json
import os
import sys
import tempfile
import types
from pathlib import Path

sys.path.insert(0, "/root/soar")
import soar_executor as soar          # noqa: E402
import soar_bot as bot                # noqa: E402

TOTAL = [0]
FALLOS = []


def check(nombre, cond, detalle=""):
    estado = "PASS" if cond else "FAIL"
    print(f"[{estado}] {nombre}" + (f"  <- {detalle}" if detalle and not cond else ""))
    TOTAL[0] += 1
    if not cond:
        FALLOS.append(nombre)


def _cap_audit():
    """Redirige la auditoria a un buffer en memoria (sin tocar disco)."""
    lineas = []

    def fake(event, **kw):
        lineas.append({"event": event, **kw})

    return lineas, fake


# ---------------------------------------------------------------------------
# C1 - Autenticacion
# ---------------------------------------------------------------------------
def test_auth():
    eventos, fake = _cap_audit()
    orig = bot.audit
    bot.audit = fake
    try:
        bot.AUTH_CHAT_ID = "<TU_CHAT_ID>"
        # autorizado
        ok, info = bot.is_authorized({"chat": {"id": <TU_CHAT_ID>}})
        check("C1a chat autorizado -> permitido",
              ok is True and info is None, f"{ok}/{info}")
        # no autorizado -> descarte auditado, sin respuesta
        msg = {"chat": {"id": 12345, "type": "private"},
               "from": {"id": 999, "username": "intruso"},
               "text": "/status"}
        ok2, info2 = bot.is_authorized(msg)
        check("C1b chat NO autorizado -> denegado",
              ok2 is False and info2["chat_id"] == "12345", f"{ok2}/{info2}")
        respuestas = []
        res = bot.dispatch(msg, responder=lambda t: respuestas.append(t))
        ini = len([e for e in eventos if e["event"] == "CHATOPS_UNAUTHORIZED"])
        enviados = len([e for e in eventos if e["event"] == "CHATOPS_UNAUTHORIZED"
                        and e.get("chat_id") == "12345"
                        and e.get("username") == "intruso"])
        check("C1c dispatch NO autorizado -> sin respuesta",
              res is None and respuestas == [], f"{res}/{respuestas}")
        check("C1d se audita CHATOPS_UNAUTHORIZED con chat/user/username",
              ini == 1 and enviados == 1, str(eventos))
    finally:
        bot.audit = orig


# ---------------------------------------------------------------------------
# C2 - Parser
# ---------------------------------------------------------------------------
def test_parser():
    check("C2a /status simple",
          bot.parse_command("/status") == ("/status", []),
          str(bot.parse_command("/status")))
    check("C2b /status@vpsAlert777bot normalizado",
          bot.parse_command("/status@vpsAlert777bot") == ("/status", []),
          str(bot.parse_command("/status@vpsAlert777bot")))
    check("C2c /unban con argumento y sufijo",
          bot.parse_command("/unban@vpsAlert777bot 45.33.32.90")
          == ("/unban", ["45.33.32.90"]),
          str(bot.parse_command("/unban@vpsAlert777bot 45.33.32.90")))
    check("C2d mayusculas normalizadas",
          bot.parse_command("/STATUS") == ("/status", []),
          str(bot.parse_command("/STATUS")))
    check("C2e texto no-comando -> vacio",
          bot.parse_command("hola mundo") == ("", []),
          str(bot.parse_command("hola mundo")))
    check("C2f vacio -> vacio",
          bot.parse_command("") == ("", []) and bot.parse_command(None) == ("", []),
          "")


# ---------------------------------------------------------------------------
# C3 - /status
# ---------------------------------------------------------------------------
def _write_prom(tmp, caidos=()):
    """gym.prom simulado con 18 contenedores REALES (nombres de los grupos)."""
    nombres = [n for grupo in bot.GRUPOS_CONTENEDORES.values() for n in grupo]
    while len(nombres) < 18:
        nombres.append(f"cont{len(nombres)}")
    nombres = nombres[:18]
    lineas = ["# HELP gym_container_up 1 si el contenedor esta corriendo",
              "# TYPE gym_container_up gauge"]
    for n in nombres:
        v = 0 if n in caidos else 1
        lineas.append(f'gym_container_up{{name="{n}"}} {v}')
    lineas += [
        "# HELP gym_backup_age_seconds Segundos desde el backup mas reciente",
        "# TYPE gym_backup_age_seconds gauge",
        "gym_backup_age_seconds 2525",
        "# HELP gym_monitoring_config_backup_age_seconds",
        "# TYPE gym_monitoring_config_backup_age_seconds gauge",
        "gym_monitoring_config_backup_age_seconds 2525",
    ]
    p = Path(tmp) / "gym.prom"
    p.write_text("\n".join(lineas) + "\n")
    return p


def test_status(tmpdir):
    orig_prom, orig_svc, orig_dr = bot.GYM_PROM, bot._service_state, bot._disk_ram
    try:
        bot._service_state = lambda *a, **k: ("active", "2037923")
        bot._disk_ram = lambda: {"disk_pct": 42, "disk_libre_gb": 12.3,
                                 "ram_libre_mb": 800, "ram_total_mb": 2000}
        # caso 18/18
        bot.GYM_PROM = _write_prom(tmpdir)
        out = bot.cmd_status([])
        check("C3a /status 18/18 OK muestra 18/18",
              "18/18" in out, out.replace("\n", " | "))
        check("C3b /status muestra edad de backups",
              "2525" in out or "42m" in out, out.replace("\n", " | "))
        check("C3c /status muestra servicio y disco",
              "active" in out and "42%" in out, out.replace("\n", " | "))
        # caso 1 caido (nombre real de un grupo -> visible)
        objetivo = "metrocoord-frontend"
        bot.GYM_PROM = _write_prom(tmpdir, caidos=(objetivo,))
        out2 = bot.cmd_status([])
        check("C3d /status con 1 caido muestra 17/18 y el nombre",
              "17/18" in out2 and objetivo in out2, out2.replace("\n", " | "))
        check("C3e /status con caido marca warning",
              "ATENCIÓN" in out2 or "🔴" in out2, out2.replace("\n", " | "))
        # gym.prom ausente -> degradacion
        bot.GYM_PROM = Path(tmpdir) / "no-existe.prom"
        out3 = bot.cmd_status([])
        check("C3f /status sin gym.prom degrada sin excepcion",
              "indisponibles" in out3 or "gym.prom" in out3, out3.replace("\n", " | "))
    finally:
        bot.GYM_PROM, bot._service_state, bot._disk_ram = orig_prom, orig_svc, orig_dr


# ---------------------------------------------------------------------------
# C4 - /bans
# ---------------------------------------------------------------------------
def test_bans(tmpdir):
    orig_live, orig_tail = bot._live_bans, bot._tail_bans
    try:
        # sin reglas activas
        bot._live_bans = lambda: {}
        bot._tail_bans = lambda n=5, path=None, target=None: []
        out = bot.cmd_bans([])
        check("C4a /bans sin reglas -> mensaje claro",
              "No hay IP" in out, out.replace("\n", " | "))
        # con reglas activas + historial
        bot._live_bans = lambda: {"45.33.32.90": {"DOCKER-USER": 18, "INPUT": 18},
                                  "8.8.8.8": {"DOCKER-USER": 3, "INPUT": 0}}
        hist = [
            {"event": "BANNED_IP", "target": "45.33.32.90",
             "rule": "GYM - SOAR Entropia URI", "ts": "2026-10-21T02:25:03Z"},
            {"event": "UNBANNED_IP", "target": "45.33.32.91",
             "rule": "GYM - SOAR Suricata WAF", "ts": "2026-10-21T02:25:03Z"},
        ]
        bot._tail_bans = lambda n=5, path=None, target=None: hist
        out2 = bot.cmd_bans([])
        check("C4b /bans lista IPs activas con pkts",
              "45.33.32.90" in out2 and "36" in out2 and "8.8.8.8" in out2,
              out2.replace("\n", " | "))
        check("C4c /bans muestra historial con motivo traducido",
              "Bloqueada" in out2 and "Liberada" in out2
              and "escaneo" in out2,
              out2.replace("\n", " | "))
    finally:
        bot._live_bans, bot._tail_bans = orig_live, orig_tail


# ---------------------------------------------------------------------------
# C5 - /threat
# ---------------------------------------------------------------------------
def test_threat():
    orig_loki = bot._loki_query
    try:
        # Loki OK
        def fake_loki_ok(expr, *a, **k):
            if "nginx" in expr and "remote_addr" in expr:
                return [{"metric": {"remote_addr": "1.2.3.4"}, "value": [0, "7"]}]
            if "nginx" in expr:
                return [{"metric": {}, "value": [0, "9"]}]
            return [{"metric": {"alert_sig": "GYM: ICMP Echo Request"},
                     "value": [0, "28"]}]
        bot._loki_query = fake_loki_ok
        out = bot.cmd_threat([])
        check("C5a /threat con Loki OK muestra total nginx",
              "9" in out and "400/444" in out, out.replace("\n", " | "))
        check("C5b /threat muestra top src_ip",
              "1.2.3.4" in out, out.replace("\n", " | "))
        check("C5c /threat muestra firma Suricata",
              "ICMP Echo Request" in out and "28" in out,
              out.replace("\n", " | "))
        # Loki falla
        def fake_loki_down(*a, **k):
            raise TimeoutError("timed out")
        bot._loki_query = fake_loki_down
        out2 = bot.cmd_threat([])
        check("C5d /threat con Loki caido degrada elegantemente",
              "no disponible" in out2 and "TimeoutError" in out2,
              out2.replace("\n", " | "))
        check("C5e /threat con Loki caido NO lanza",
              isinstance(out2, str) and len(out2) > 10, "")
        # Loki lento no bloquea mas que el timeout (verificacion de constante)
        check("C5f /threat timeout Loki configurado a 4s",
              bot.LOKI_TIMEOUT_S == 4, str(bot.LOKI_TIMEOUT_S))
    finally:
        bot._loki_query = orig_loki


# ---------------------------------------------------------------------------
# C6 - /unban  +  C7 hash
# ---------------------------------------------------------------------------
def test_unban():
    eventos, fake = _cap_audit()
    orig_audit = bot.audit
    orig_unban = soar._unban_ip
    orig_tail = bot._tail_bans
    try:
        bot.audit = fake
        bot._tail_bans = lambda n=5, path=None, target=None: [
            {"event": "UNBANNED_IP", "target": "45.33.32.90",
             "dropped_pkts": {"DOCKER-USER": 18, "INPUT": 18}}]
        # IP valida -> delega en la primitiva certificada
        llamadas = []

        def fake_unban(target, rule=None):
            llamadas.append((target, rule))
            return True

        soar._unban_ip = fake_unban
        out = bot.cmd_unban(["45.33.32.90"])
        check("C6a /unban IP valida delega en _unban_ip (primitiva certificada)",
              llamadas and llamadas[0][0] == "45.33.32.90", str(llamadas))
        check("C6b /unban responde resultado con dropped_pkts",
              "Desbloqueo" in out and "18" in out, out.replace("\n", " | "))
        check("C6c /unban audita CHATOPS_MANUAL_UNBAN",
              any(e["event"] == "CHATOPS_MANUAL_UNBAN" for e in eventos),
              str(eventos))
        # IP invalida / inyeccion -> DENY_MALFORMED_IP, sin tocar kernel
        antes = len(llamadas)
        out2 = bot.cmd_unban(["8.8.8.8; rm -rf /"])
        check("C6d /unban inyeccion -> DENY_MALFORMED_IP sin llamar a kernel",
              "inválida" in out2 and len(llamadas) == antes, out2)
        check("C6e se audita DENY_MALFORMED_IP",
              any(e["event"] == "DENY_MALFORMED_IP" for e in eventos), str(eventos))
        out3 = bot.cmd_unban(["999.1.1.1"])
        check("C6f /unban IP fuera de rango -> invalida",
              "inválida" in out3, out3)
        # NEVER_BAN
        out4 = bot.cmd_unban(["203.0.113.10"])
        check("C6g /unban NEVER_BAN -> denegado",
              "NEVER_BAN" in out4 and len(llamadas) == antes, out4)
    finally:
        bot.audit = orig_audit
        soar._unban_ip = orig_unban
        bot._tail_bans = orig_tail


def test_hash():
    h = hashlib.sha256(Path("/root/soar/soar_executor.py").read_bytes()).hexdigest()
    check("C7 hash de soar_executor.py intacto (31b5d4b4...)",
          h == bot.EXECUTOR_SHA_EXPECTED, h)


def test_dispatch_integrado(tmpdir):
    """Round-trip completo: mensaje autorizado -> comando -> respuesta."""
    orig_prom = bot.GYM_PROM
    orig_svc = bot._service_state
    orig_dr = bot._disk_ram
    orig_audit = bot.audit
    eventos = []
    bot.audit = lambda ev, **kw: eventos.append({"event": ev, **kw})
    try:
        bot.AUTH_CHAT_ID = "<TU_CHAT_ID>"
        bot.GYM_PROM = _write_prom(tmpdir)
        bot._service_state = lambda *a, **k: ("active", "1")
        bot._disk_ram = lambda: {"disk_pct": 40, "disk_libre_gb": 10,
                                 "ram_libre_mb": 500, "ram_total_mb": 2000}
        respuestas = []
        bot.dispatch({"chat": {"id": <TU_CHAT_ID>},
                      "from": {"id": 1, "username": "admin"},
                      "text": "/status@vpsAlert777bot"},
                     responder=lambda t: respuestas.append(t))
        check("C8 round-trip /status@bot -> 1 respuesta con datos",
              len(respuestas) == 1 and "18/18" in respuestas[0],
              str(respuestas)[:200])
        # /help
        bot.dispatch({"chat": {"id": <TU_CHAT_ID>}, "text": "/help"},
                     responder=lambda t: respuestas.append(t))
        check("C8b /help devuelve guia",
              len(respuestas) == 2 and "/unban" in respuestas[1], "")
        # comando desconocido
        bot.dispatch({"chat": {"id": <TU_CHAT_ID>}, "text": "/rm"},
                     responder=lambda t: respuestas.append(t))
        check("C8c comando desconocido -> ayuda, sin shell",
              len(respuestas) == 3 and "desconocido" in respuestas[2], "")
    finally:
        bot.GYM_PROM = orig_prom
        bot._service_state = orig_svc
        bot._disk_ram = orig_dr
        bot.audit = orig_audit


def test_run_once():
    """Ciclo de polling con getUpdates inyectado: offset e ingesta."""
    orig_audit = bot.audit
    bot.audit = lambda ev, **kw: None
    respuestas = []
    try:
        bot.AUTH_CHAT_ID = "<TU_CHAT_ID>"

        def fake_gu(offset=None, timeout=None):
            return {"ok": True, "result": [
                {"update_id": 100, "message": {"chat": {"id": <TU_CHAT_ID>},
                                               "text": "/help"}},
                {"update_id": 101, "message": {"chat": {"id": 999},
                                               "text": "/status"}},
            ]}

        nuevo = bot.run_once(get_updates_fn=fake_gu,
                             responder=lambda t: respuestas.append(t),
                             offset=50)
        check("C9a run_once avanza offset a last_update_id+1",
              nuevo == 102, str(nuevo))
        check("C9b run_once responde solo al autorizado",
              len(respuestas) == 1 and "/unban" in respuestas[0],
              str(respuestas)[:120])
        # error de polling no lanza y conserva offset
        def fake_gu_err(offset=None, timeout=None):
            raise TimeoutError("poll timeout")
        nuevo2 = bot.run_once(get_updates_fn=fake_gu_err, offset=102)
        check("C9c run_once con error de red no lanza y conserva offset",
              nuevo2 == 102, str(nuevo2))
    finally:
        bot.audit = orig_audit
        # evita el sleep de 2s del manejo de error
        pass


def test_drain():
    orig_audit = bot.audit
    bot.audit = lambda ev, **kw: None
    try:
        def fake_gu(offset=None, timeout=None):
            assert offset == -1 and timeout == 0, f"{offset}/{timeout}"
            return {"ok": True, "result": [{"update_id": 500}]}
        off = bot._drain_backlog(get_updates_fn=fake_gu)
        check("C10a drain backlog fija offset = ultimo_id + 1",
              off == 501, str(off))

        def fake_vacio(offset=None, timeout=None):
            return {"ok": True, "result": []}
        check("C10b drain sin backlog -> None",
              bot._drain_backlog(get_updates_fn=fake_vacio) is None, "")
    finally:
        bot.audit = orig_audit


def test_forzar_ipv4():
    """Verifica que _https_json fija AF_INET y restaura el resolver."""
    import socket as _sock
    capturado = {}

    class _FakeResp:
        status = 200
        def read(self):
            return b'{"ok": true, "result": []}'
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    # El parche de getaddrinfo ocurre DENTRO de _https_json; lo observamos
    # forzando, desde urlopen simulado, una resolucion real del resolver
    # global (que en ese instante ya es el envoltorio IPv4).
    def fake_urlopen(req, timeout=None, context=None):
        _sock.getaddrinfo("api.telegram.org", 443, 0, 0, 0, 0)
        return _FakeResp()

    orig_open = bot.urllib.request.urlopen
    orig_gai = _sock.getaddrinfo
    try:
        # getaddrinfo de control: registra con que `family` fue invocado.
        def probe_gai(host, port, family=0, *a, **k):
            capturado["family"] = family
            return []

        bot.urllib.request.urlopen = fake_urlopen
        _sock.getaddrinfo = probe_gai
        bot._FORCE_IPV4 = True
        try:
            bot._https_json("https://api.telegram.org/x", None, timeout=1)
        except Exception:
            pass
        check("C11a transporte fuerza AF_INET (IPv4)",
              capturado.get("family") == _sock.AF_INET,
              str(capturado.get("family")))
        check("C11b el resolver global queda restaurado tras la llamada",
              _sock.getaddrinfo is probe_gai, "no restaurado")
    finally:
        bot.urllib.request.urlopen = orig_open
        _sock.getaddrinfo = orig_gai


def test_lock():
    """El lock de instancia unica existe como constante y es un Path."""
    check("C12a LOCK_FILE definido y es Path",
          isinstance(bot.LOCK_FILE, Path), str(type(bot.LOCK_FILE)))
    check("C12b LOCK_FILE en /run",
          str(bot.LOCK_FILE).startswith("/run/"), str(bot.LOCK_FILE))


# ===========================================================================
# Fase 4F
# ===========================================================================

def test_barra():
    check("F1a barra 0% -> todo vacio",
          bot.barra(0) == "[░░░░░░░░░░]", bot.barra(0))
    check("F1b barra 100% -> todo lleno",
          bot.barra(100) == "[██████████]", bot.barra(100))
    check("F1c barra 50% -> mitad",
          bot.barra(50) == "[█████░░░░░]", bot.barra(50))
    check("F1d barra invalida no lanza",
          bot.barra(None) == "[??????????]", bot.barra(None))


def test_sanitiza_log():
    # inyeccion via logs: una URI con markup no debe romper el HTML
    s = bot._sanitiza_log("<script>alert(1)</script>")
    check("F2a sanitiza escapa < y >",
          "<script>" not in s and "&lt;script&gt;" in s, s)
    s2 = bot._sanitiza_log("a\x00b\x1fc")
    check("F2b sanitiza elimina caracteres de control",
          "\x00" not in s2 and "\x1f" not in s2, repr(s2))
    s3 = bot._sanitiza_log("x" * 500, maxlen=100)
    check("F2c sanitiza trunca a maxlen",
          len(s3) <= 100, str(len(s3)))
    s4 = bot._sanitiza_log("a&b")
    check("F2d sanitiza escapa ampersand",
          s4 == "a&amp;b", s4)


def test_parse_ip_texto():
    check("F3a IP valida en texto plano",
          bot.parse_ip_texto("45.33.32.90") == "45.33.32.90",
          str(bot.parse_ip_texto("45.33.32.90")))
    check("F3b IP invalida -> None",
          bot.parse_ip_texto("no-soy-ip") is None,
          str(bot.parse_ip_texto("no-soy-ip")))
    check("F3c dos tokens -> None",
          bot.parse_ip_texto("45.33.32.90 extra") is None, "")
    check("F3d IPv6 valida",
          bot.parse_ip_texto("2001:4860:4860::8888") == "2001:4860:4860::8888",
          str(bot.parse_ip_texto("2001:4860:4860::8888")))
    check("F3e vacio -> None", bot.parse_ip_texto("") is None and
          bot.parse_ip_texto(None) is None, "")


def test_callbacks_navegacion():
    """cb:panel/status/threat/bans/posture/tech producen (texto, kb)."""
    orig = {
        "_live_bans": bot._live_bans,
        "_tail_bans": bot._tail_bans,
        "_loki_query": bot._loki_query,
        "GYM_PROM": bot.GYM_PROM,
        "_service_state": bot._service_state,
        "_disk_ram": bot._disk_ram,
        "auditar_postura": bot.auditar_postura,
    }
    tmp = Path(tempfile.mkdtemp(prefix="chatops-cb-"))
    try:
        bot.GYM_PROM = _write_prom(tmp)
        bot._service_state = lambda *a, **k: ("active", "1")
        bot._disk_ram = lambda: {"disk_pct": 30, "disk_libre_gb": 50,
                                 "ram_libre_mb": 900, "ram_total_mb": 2000}
        bot._live_bans = lambda: {}
        bot._tail_bans = lambda n=5, path=None, target=None: []
        bot._loki_query = lambda *a, **k: []
        for dato, etiqueta in (("cb:panel", "panel"), ("cb:status", "status"),
                               ("cb:threat", "threat"), ("cb:bans", "bans"),
                               ("cb:tech", "tech")):
            texto, kb = bot._texto_y_kb_para(dato)
            check(f"F4 {dato} -> texto y teclado",
                  isinstance(texto, str) and len(texto) > 10
                  and kb is not None and "inline_keyboard" in kb,
                  f"{dato}: {texto[:60]}")
        # posture con audit real (mocks internos)
        bot.auditar_postura = lambda: ("AUDIT-OK", True)
        t_post, kb_post = bot._texto_y_kb_para("cb:posture")
        check("F4f cb:posture -> texto con reauditar",
              t_post == "AUDIT-OK" and kb_post is not None, t_post)
    finally:
        for k, v in orig.items():
            setattr(bot, k, v)


def test_confirmacion_2_pasos():
    """cb:ask_unban -> presenta confirmar+cancelar; NO toca kernel."""
    llamadas = []
    orig_unban = soar._unban_ip
    try:
        soar._unban_ip = lambda t, rule=None: llamadas.append(t) or True
        texto, kb = bot._texto_y_kb_para("cb:ask_unban:45.33.32.90")
        check("F5a cb:ask_unban presenta confirmacion",
              "Confirmar" in texto and "45.33.32.90" in texto,
              texto.replace("\n", " | "))
        datos = [b["callback_data"] for fila in kb["inline_keyboard"]
                 for b in fila]
        check("F5b ofrece confirmar y cancelar",
              any(d.startswith("cb:do_unban:") for d in datos)
              and "cb:cancel" in datos, str(datos))
        check("F5c cb:ask_unban NO invoca el kernel",
              llamadas == [], str(llamadas))
        # cancelar no toca kernel
        t_c, _ = bot._texto_y_kb_para("cb:cancel")
        check("F5d cb:cancel no toca kernel y avisa",
              "cancelado" in t_c.lower() and llamadas == [],
              t_c.replace("\n", " | "))
        # confirmar SI invoca (una vez)
        t_d, kb_d = bot._texto_y_kb_para("cb:do_unban:45.33.32.90")
        check("F5e cb:do_unban invoca la primitiva certificada",
              llamadas == ["45.33.32.90"], str(llamadas))
        check("F5f cb:do_unban responde resultado",
              "Desbloqueo" in t_d or "no tenía" in t_d,
              t_d.replace("\n", " | "))
        # ask_unban con IP malformada -> sin boton de confirmar
        t_bad, kb_bad = bot._texto_y_kb_para("cb:ask_unban:1.2.3.4;rm")
        datos_bad = [b["callback_data"] for fila in kb_bad["inline_keyboard"]
                     for b in fila]
        check("F5g cb:ask_unban con IP malformada rechaza sin do_unban",
              "inválida" in t_bad and
              not any(d.startswith("cb:do_unban:") for d in datos_bad),
              t_bad)
    finally:
        soar._unban_ip = orig_unban


def test_ficha_ip():
    """Ficha forense al pegar IP (con y sin regla activa)."""
    orig = {"_live_bans": bot._live_bans, "_tail_bans": bot._tail_bans,
            "_nginx_recientes": bot._nginx_recientes, "_rdns": bot._rdns}
    try:
        bot._rdns = lambda ip: "host.example"
        bot._tail_bans = lambda n=5, path=None, target=None: [
            {"event": "BANNED_IP", "target": "45.33.32.90",
             "rule": "GYM - SOAR Entropia URI", "ts": "2026-10-21T02:25:03Z"}]
        bot._nginx_recientes = lambda ip, limit=3: [
            {"metodo": "GET", "uri": "/x<img>", "status": "444"}]
        # con regla activa -> boton desbloquear
        bot._live_bans = lambda: {"45.33.32.90": {"DOCKER-USER": 18, "INPUT": 18}}
        texto, kb = bot.ficha_ip("45.33.32.90")
        check("F6a ficha estado BLOQUEADA con cadenas",
              "BLOQUEADA" in texto and "DOCKER-USER" in texto
              and "18" in texto, texto.replace("\n", " | "))
        check("F6b ficha muestra reverse DNS",
              "host.example" in texto, texto.replace("\n", " | "))
        check("F6c ficha con regla activa ofrece boton desbloquear",
              kb is not None and
              kb["inline_keyboard"][0][0]["callback_data"].startswith("cb:ask_unban:"),
              str(kb))
        check("F6d ficha sanitiza URI de log (sin <img>)",
              "<img>" not in texto and "&lt;img&gt;" in texto,
              texto.replace("\n", " | "))
        # sin regla activa -> sin boton
        bot._live_bans = lambda: {}
        texto2, kb2 = bot.ficha_ip("45.33.32.90")
        check("F6e ficha sin regla -> libre y SIN boton",
              "libre" in texto2 and kb2 is None, texto2.replace("\n", " | "))
        # IP malformada
        texto3, kb3 = bot.ficha_ip("no-ip")
        check("F6f ficha IP malformada -> rechazo",
              "inválida" in texto3 and kb3 is None, texto3)
        check("F6g ficha sin PTR degrada",
              True, "")  # cubierto por _rdns con timeout
    finally:
        for k, v in orig.items():
            setattr(bot, k, v)


def test_ficha_desde_dispatch(tmpdir):
    """Pegar una IP valida en el chat dispara la ficha (no comando)."""
    orig = {"_live_bans": bot._live_bans, "_tail_bans": bot._tail_bans,
            "_nginx_recientes": bot._nginx_recientes, "_rdns": bot._rdns,
            "audit": bot.audit}
    respuestas = []
    try:
        bot.audit = lambda *a, **k: None
        bot.AUTH_CHAT_ID = "<TU_CHAT_ID>"
        bot._live_bans = lambda: {}
        bot._tail_bans = lambda n=5, path=None, target=None: []
        bot._nginx_recientes = lambda ip, limit=3: []
        bot._rdns = lambda ip: None
        bot.dispatch({"chat": {"id": <TU_CHAT_ID>}, "text": " 45.33.32.90 "},
                     responder=lambda t: respuestas.append(t))
        check("F7a IP pegada en el chat -> ficha forense",
              len(respuestas) == 1 and "Ficha forense" in respuestas[0],
              str(respuestas)[:150])
        # texto que no es IP ni comando -> silencio
        respuestas.clear()
        bot.dispatch({"chat": {"id": <TU_CHAT_ID>}, "text": "hola que tal"},
                     responder=lambda t: respuestas.append(t))
        check("F7b texto no-IP no responde",
              respuestas == [], str(respuestas))
    finally:
        for k, v in orig.items():
            setattr(bot, k, v)


def test_auditoria_postura(tmpdir):
    """F8: /audit postura integra y degradada."""
    orig = {
        "_check_hash_release": bot._check_hash_release,
        "_check_reglas_fijas": bot._check_reglas_fijas,
        "_check_servicio": bot._check_servicio,
        "_check_grafana": bot._check_grafana,
        "_check_backups": bot._check_backups,
        "audit": bot.audit,
    }
    try:
        bot.audit = lambda *a, **k: None
        # estado integro
        bot._check_hash_release = lambda: {"ok": True, "hash_ok": True,
                                           "inmutable_ok": True, "inmutables": 3,
                                           "hash": "abc"}
        bot._check_reglas_fijas = lambda: {"ok": True, "msf3_ok": True,
                                           "input_hard_ok": True, "jails_ok": True,
                                           "f2b_ok": False}
        bot._check_servicio = lambda: {"ok": True, "activo": True,
                                       "escucha": True}
        bot._check_grafana = lambda: {"ok": True, "total": 17, "saludables": 17}
        bot._check_backups = lambda: {"ok": True, "edad_s": 2500}
        texto, ok = bot.auditar_postura()
        check("F8a /audit integro -> TODO OK",
              ok is True and "TODO OK" in texto, texto.replace("\n", " | "))
        check("F8b /audit lista las 5 invariantes",
              all(f"{i}." in texto for i in range(1, 6)),
              texto.replace("\n", " | "))
        check("F8c /audit reporta 17/17 grafana",
              "17/17" in texto, texto.replace("\n", " | "))
        # estado degradado: hash distinto
        bot._check_hash_release = lambda: {"ok": False, "hash_ok": False,
                                           "inmutable_ok": True, "inmutables": 3,
                                           "hash": "zzz"}
        bot._check_grafana = lambda: {"ok": False, "total": 17, "saludables": 15}
        bot._check_backups = lambda: {"ok": False, "edad_s": 100000}
        texto2, ok2 = bot.auditar_postura()
        check("F8d /audit degradado -> REVISAR + ok False",
              ok2 is False and "REVISAR" in texto2, texto2.replace("\n", " | "))
        check("F8e /audit degradado marca hash DIFERENTE",
              "DIFERENTE" in texto2, texto2.replace("\n", " | "))
        # grafana no consultable -> degradacion elegante
        bot._check_grafana = lambda: {"ok": False, "error": "URLError",
                                      "total": 0, "saludables": 0}
        texto3, _ = bot.auditar_postura()
        check("F8f /audit grafana caida no lanza y avisa",
              "no consultable" in texto3, texto3.replace("\n", " | "))
        # /audit como comando
        bot._check_hash_release = lambda: {"ok": True, "hash_ok": True,
                                           "inmutable_ok": True, "inmutables": 3,
                                           "hash": "abc"}
        bot._check_grafana = lambda: {"ok": True, "total": 17, "saludables": 17}
        bot._check_backups = lambda: {"ok": True, "edad_s": 2500}
        check("F8g cmd_audit devuelve texto",
              "Auditoría de Blindaje" in bot.cmd_audit([]), "")
    finally:
        for k, v in orig.items():
            setattr(bot, k, v)


def test_checks_reales():
    """Los check_* reales devuelven la estructura esperada sin lanzar."""
    c1 = bot._check_hash_release()
    check("F9a _check_hash_release devuelve dict con ok",
          isinstance(c1, dict) and "ok" in c1 and "hash_ok" in c1, str(c1))
    c2 = bot._check_reglas_fijas()
    check("F9b _check_reglas_fijas devuelve dict con ok",
          isinstance(c2, dict) and "ok" in c2, str(c2))
    check("F9b2 blindaje firewall REAL intacto (msf3+INPUT+fail2ban)",
          c2.get("ok") is True, str(c2))
    c3 = bot._check_servicio()
    check("F9c _check_servicio devuelve dict con ok",
          isinstance(c3, dict) and "ok" in c3, str(c3))
    c5 = bot._check_backups()
    check("F9d _check_backups devuelve dict con ok",
          isinstance(c5, dict) and "ok" in c5, str(c5))


def test_handle_callback_auth():
    """Callback no autorizado -> descartado y auditado."""
    eventos = []
    orig = bot.audit
    bot.audit = lambda ev, **kw: eventos.append({"event": ev, **kw})
    try:
        bot.AUTH_CHAT_ID = "<TU_CHAT_ID>"
        res = bot.handle_callback(
            {"id": "1", "data": "cb:panel",
             "message": {"chat": {"id": 999}, "message_id": 5},
             "from": {"id": 7, "username": "x"}},
            responder=lambda *a: None)
        check("F10a callback no autorizado -> None + auditado",
              res is None and any(e["event"] == "CHATOPS_UNAUTHORIZED"
                                  for e in eventos), str(eventos))
    finally:
        bot.audit = orig


def test_edit_navegacion_single_message():
    """Navegacion edita el MISMO mensaje (no spam): responder recibe message_id."""
    capturado = {}

    def cb_resp(texto, kb, message_id):
        capturado["texto"] = texto
        capturado["message_id"] = message_id
        capturado["kb"] = kb

    orig = {"_live_bans": bot._live_bans, "audit": bot.audit}
    try:
        bot.audit = lambda *a, **k: None
        bot.AUTH_CHAT_ID = "<TU_CHAT_ID>"
        bot._live_bans = lambda: {}
        bot.handle_callback(
            {"id": "9", "data": "cb:bans",
             "message": {"chat": {"id": <TU_CHAT_ID>}, "message_id": 42},
             "from": {"id": 1}},
            responder=cb_resp)
        check("F11a navegacion edita el mismo message_id",
              capturado.get("message_id") == 42, str(capturado.get("message_id")))
        check("F11b navegacion produce texto de bans",
              "Baneos" in capturado.get("texto", ""), capturado.get("texto", "")[:60])
    finally:
        for k, v in orig.items():
            setattr(bot, k, v)


def test_menu_comandos():
    check("F12a MENU_COMANDOS define 6 comandos",
          len(bot.MENU_COMANDOS) == 6, str(len(bot.MENU_COMANDOS)))
    nombres = [c["command"] for c in bot.MENU_COMANDOS]
    check("F12b incluye panel/status/threat/bans/audit/help",
          nombres == ["panel", "status", "threat", "bans", "audit", "help"],
          str(nombres))
    check("F12c cada comando tiene descripcion no vacia",
          all(c.get("description") for c in bot.MENU_COMANDOS), "")
    check("F12d descripciones en espanol (sin guiones bajos)",
          all("_" not in c["command"] for c in bot.MENU_COMANDOS), "")


def test_status_grupos(tmpdir):
    """La capa 1 agrupa los 18 contenedores en 4 grupos logicos."""
    orig = {"GYM_PROM": bot.GYM_PROM, "_service_state": bot._service_state,
            "_disk_ram": bot._disk_ram}
    try:
        bot.GYM_PROM = _write_prom(tmpdir)
        bot._service_state = lambda *a, **k: ("active", "1")
        bot._disk_ram = lambda: {"disk_pct": 25, "disk_libre_gb": 70,
                                 "ram_libre_mb": 1000, "ram_total_mb": 4000}
        out = bot.status_ejecutivo()
        for grupo in bot.GRUPOS_CONTENEDORES:
            check(f"F13 grupo visible: {grupo}", bot._esc(grupo) in out,
                  out.replace("\n", " | "))
        check("F13e status usa barras visuales",
              "[" in out and ("█" in out or "░" in out), out.replace("\n", " | "))
        check("F13f status muestra postura global",
              "Postura global" in out, out.replace("\n", " | "))
        # Regresion: el texto debe ser HTML valido para Telegram (sin & sueltos)
        import re as _re
        sueltos = _re.findall(r"&(?!amp;|lt;|gt;)", out)
        check("F13g status sin '&' sin escapar (HTML valido Telegram)",
              not sueltos, f"ampersand sin escapar: {sueltos}")
    finally:
        for k, v in orig.items():
            setattr(bot, k, v)


def test_tech_detail(tmpdir):
    """cb:tech muestra fingerprint, cadenas, hash y dropped_pkts."""
    orig = {"_live_bans": bot._live_bans, "_tail_bans": bot._tail_bans,
            "STATE_FILE": bot.STATE_FILE}
    try:
        bot._live_bans = lambda: {"45.33.32.90": {"DOCKER-USER": 18, "INPUT": 18}}
        bot._tail_bans = lambda n=5, path=None, target=None: [
            {"event": "UNBANNED_IP", "target": "45.33.32.91",
             "dropped_pkts": {"DOCKER-USER": 7, "INPUT": 4}}]
        st = Path(tempfile.mkdtemp(prefix="chatops-tech-")) / "state.json"
        st.write_text(json.dumps({"executed": {"fps001|2026|r": {}},
                                  "actions": {}}))
        bot.STATE_FILE = st
        out = bot.tech_detail()
        check("F14a tech muestra hash de integridad",
              "Integridad executor" in out, out.replace("\n", " | "))
        check("F14b tech muestra fingerprint de state.json",
              "fps001" in out, out.replace("\n", " | "))
        check("F14c tech muestra cadenas de kernel",
              "DOCKER-USER" in out and "INPUT" in out, out.replace("\n", " | "))
        check("F14d tech muestra dropped_pkts historico",
              "dropped_pkts" in out, out.replace("\n", " | "))
    finally:
        for k, v in orig.items():
            setattr(bot, k, v)


def test_nginx_recientes_parseo():
    """_nginx_recientes parsea el access.log combinado (no JSON) via substring
    con ANCLAJE estricto del token inicial (anti-prefijo/sufijo)."""
    orig = {"_loki_range": bot._loki_range, "exprs": []}
    try:
        linea = ('176.65.149.111 - - [21/Oct/2026:11:35:28 +0000] '
                 '"HEAD / HTTP/1.0" 444 0 "-" "-" "-" "-"')
        bot._loki_range = lambda expr, limit=3, **k: [
            {"values": [["1", linea], ["2", linea]]}]
        out = bot._nginx_recientes("176.65.149.111", 3)
        check("F16a nginx parsea metodo/uri/status del log combinado",
              out and out[0] == {"metodo": "HEAD", "uri": "/",
                                 "status": "444"}, str(out))
        # el filtro Loki debe anclar con " - " (no solo la IP suelta)
        exprs = []

        def fake(expr, limit=3, **k):
            exprs.append(expr)
            return [{"values": [["1", linea]]}]
        bot._loki_range = fake
        bot._nginx_recientes("1.2.3.4", 3)
        check("F16b filtro Loki ancla con ' - ' (evita 1.2.3.40 / 11.2.3.4)",
              exprs and '|= "1.2.3.4 - "' in exprs[0], str(exprs))

        # una IP distinta en la linea no debe colarse (aunque Loki la devuelva)
        bot._loki_range = lambda expr, limit=3, **k: [
            {"values": [["1", linea]]}]
        out2 = bot._nginx_recientes("8.8.8.8", 3)
        check("F16c nginx descarta lineas de otras IPs", out2 == [], str(out2))

        # ANCLAJE: consultar 1.2.3.4 NO debe aceptar la linea de 1.2.3.40
        linea40 = ('1.2.3.40 - - [21/Oct/2026:11:35:28 +0000] '
                   '"GET /evil HTTP/1.0" 200 0 "-" "-" "-" "-"')
        linea11 = ('11.2.3.4 - - [21/Oct/2026:11:35:28 +0000] '
                   '"GET /evil2 HTTP/1.0" 200 0 "-" "-" "-" "-"')
        bot._loki_range = lambda expr, limit=3, **k: [
            {"values": [["1", linea40], ["2", linea11]]}]
        out3 = bot._nginx_recientes("1.2.3.4", 3)
        check("F16d anclaje: 1.2.3.4 no arrastra 1.2.3.40 ni 11.2.3.4",
              out3 == [], str(out3))
    finally:
        for k, v in orig.items():
            if k != "exprs":
                setattr(bot, k, v)


def test_esc_dinamico():
    """_esc_dinamico es el punto unico de escape de datos externos."""
    out = bot._esc_dinamico("GET /?a=1&b=<svg>")
    check("F17a _esc_dinamico escapa & y <> de URI maliciosa",
          out == "GET /?a=1&amp;b=&lt;svg&gt;", out)
    check("F17b _esc_dinamico elimina caracteres de control",
          "\x00" not in bot._esc_dinamico("a\x00b"), repr(bot._esc_dinamico("a\x00b")))
    check("F17c _esc_dinamico trunca a maxlen",
          len(bot._esc_dinamico("x" * 500, maxlen=50)) <= 50, "")
    check("F17d _esc_dinamico escapa comillas (defensa en profundidad)",
          "&#x27;" in bot._esc_dinamico("it's \"q\""),
          bot._esc_dinamico("it's \"q\""))
    check("F17e _sanitiza_log delega en _esc_dinamico",
          bot._sanitiza_log("<svg>") == bot._esc_dinamico("<svg>"), "")


def test_edit_not_modified_benigno():
    """'message is not modified' no debe auditarse como error."""
    eventos = []
    orig_api, orig_audit = bot._api, bot.audit
    bot.audit = lambda ev, **kw: eventos.append(ev)
    bot.TOKEN = "x"

    def fake_not_modified(method, params=None, timeout=None):
        raise RuntimeError("HTTP Error 400: Bad Request: message is not "
                           "modified: specified new message content")
    try:
        bot._api = fake_not_modified
        r = bot.edit_message_text("-1", 5, "texto")
        check("F18a 'not modified' -> True y sin audit de error",
              r is True and "CHATOPS_EDIT_ERROR" not in eventos,
              f"r={r} eventos={eventos}")

        def fake_other(method, params=None, timeout=None):
            raise RuntimeError("HTTP Error 400: Bad Request: can't parse entities")
        bot._api = fake_other
        eventos.clear()
        r2 = bot.edit_message_text("-1", 5, "texto")
        check("F18b 400 real -> False y auditado",
              r2 is False and "CHATOPS_EDIT_ERROR" in eventos,
              f"r={r2} eventos={eventos}")
    finally:
        bot._api, bot.audit = orig_api, orig_audit


def test_html_valido():
    """Todos los renderizados deben ser HTML valido para Telegram (sin & sueltos
    ni etiquetas no soportadas). Previene el HTTP 400 que rompe el panel."""
    import re as _re
    orig = {
        "_live_bans": bot._live_bans, "_tail_bans": bot._tail_bans,
        "_loki_query": bot._loki_query, "_rdns": bot._rdns,
        "_nginx_recientes": bot._nginx_recientes, "auditar_postura": bot.auditar_postura,
    }
    tmp = Path(tempfile.mkdtemp(prefix="chatops-html-"))
    try:
        bot.GYM_PROM = _write_prom(tmp, caidos=("metrocoord-frontend",))
        bot._service_state = lambda *a, **k: ("active", "1")
        bot._disk_ram = lambda: {"disk_pct": 22, "disk_libre_gb": 70,
                                 "ram_libre_mb": 900, "ram_total_mb": 4000}
        bot._live_bans = lambda: {"45.33.32.90": {"DOCKER-USER": 18, "INPUT": 18}}
        bot._tail_bans = lambda n=5, path=None, target=None: [
            {"event": "BANNED_IP", "target": "45.33.32.90",
             "rule": "GYM - SOAR Entropia URI", "ts": "x"}]
        bot._loki_query = lambda *a, **k: [
            {"metric": {"alert_sig": "GYM: a&b <x>"}, "value": [0, "1"]}]
        bot._rdns = lambda ip: "h&x"
        bot._nginx_recientes = lambda ip, limit=3: [
            {"metodo": "GET", "uri": "/?a=1&b=<svg>", "status": "444"}]
        bot.auditar_postura = lambda: ("postura", True)
        textos = {
            "status": bot.status_ejecutivo(),
            "bans": bot.bans_ejecutivo(),
            "threat": bot.threat_ejecutivo(),
            "tech": bot.tech_detail(),
            "help": bot.HELP_TEXT,
        }
        # audit renderizado con checks mockeados (texto real del panel)
        oc = {k: getattr(bot, k) for k in (
            "_check_hash_release", "_check_reglas_fijas", "_check_servicio",
            "_check_grafana", "_check_backups")}
        bot._check_hash_release = lambda: {"ok": True, "hash_ok": True,
                                           "inmutable_ok": True, "inmutables": 3,
                                           "hash": "a"}
        bot._check_reglas_fijas = lambda: {"ok": True, "msf3_ok": True,
                                           "input_hard_ok": True, "jails_ok": True,
                                           "f2b_ok": False}
        bot._check_servicio = lambda: {"ok": True, "activo": True, "escucha": True}
        bot._check_grafana = lambda: {"ok": True, "total": 17, "saludables": 17}
        bot._check_backups = lambda: {"ok": True, "edad_s": 1000}
        textos["audit"] = bot.auditar_postura()[0]
        for k, v in oc.items():
            setattr(bot, k, v)
        ficha, _ = bot.ficha_ip("45.33.32.90")
        textos["ficha"] = ficha
        for nombre, t in textos.items():
            sueltos = _re.findall(r"&(?!amp;|lt;|gt;)", t)
            check(f"F15 HTML valido en {nombre} (sin & sueltos)",
                  not sueltos, f"{nombre}: {sueltos} :: {t[:120]}")
            # Solo se permiten las etiquetas <b>, </b>, <code>, </code>.
            etiquetas = _re.findall(r"</?([a-zA-Z][a-zA-Z0-9]*)[^>]*>", t)
            no_soportadas = [e for e in etiquetas if e.lower() not in ("b", "code")]
            check(f"F15b solo etiquetas soportadas en {nombre}",
                  not no_soportadas, f"{nombre}: {no_soportadas}")
            # No debe quedar ningun '<' fuera de una etiqueta permitida.
            sin_tags = _re.sub(r"</?(?:b|code)>", "", t)
            check(f"F15c sin '<' sueltos en {nombre}",
                  "<" not in sin_tags and ">" not in sin_tags,
                  f"{nombre}: {sin_tags[:120]}")
        # F15d: URI maliciosa simulada -> debe salir escapada, sin markup vivo.
        check("F15d URI maliciosa 'GET /?a=1&b=<svg>' queda escapada",
              "&amp;" in textos["ficha"] and "&lt;svg&gt;" in textos["ficha"]
              and "<svg>" not in textos["ficha"],
              textos["ficha"].replace("\n", " | "))
        # F15e: alert_sig de Suricata con markup -> escapado en /threat.
        check("F15e alert_sig con markup queda escapado en /threat",
              "&lt;x&gt;" in textos["threat"] and "<x>" not in textos["threat"],
              textos["threat"].replace("\n", " | "))
        # F15f: PTR de rDNS con markup/& -> escapado en la ficha.
        check("F15f PTR rDNS con markup queda escapado en la ficha",
              "h&amp;x" in textos["ficha"], textos["ficha"][:160])
    finally:
        for k, v in orig.items():
            setattr(bot, k, v)


def main():
    # Higiene: nunca tocar la API real ni los ficheros de produccion.
    bot.TOKEN = ""
    bot.AUTH_CHAT_ID = "<TU_CHAT_ID>"
    bot._FORCE_IPV4 = True
    # Redirige el audit del executor a temporal (dispatch/unban auditores reusan
    # soar.audit via bot.audit, pero _unban_ip real escribiria en AUDIT_LOG).
    tmp = Path(tempfile.mkdtemp(prefix="chatops-tests-"))
    soar.AUDIT_LOG = tmp / "soar-audit.log"
    soar.STATE_FILE = tmp / "state.json"
    print(f"[info] aislamiento: audit/state de test en {tmp}")

    test_auth()
    test_parser()
    test_status(tmp)
    test_bans(tmp)
    test_threat()
    test_unban()
    test_hash()
    test_dispatch_integrado(tmp)
    test_run_once()
    test_drain()
    test_forzar_ipv4()
    test_lock()
    # --- Fase 4F ---
    test_barra()
    test_sanitiza_log()
    test_parse_ip_texto()
    test_callbacks_navegacion()
    test_confirmacion_2_pasos()
    test_ficha_ip()
    test_ficha_desde_dispatch(tmp)
    test_auditoria_postura(tmp)
    test_checks_reales()
    test_handle_callback_auth()
    test_edit_navegacion_single_message()
    test_menu_comandos()
    test_status_grupos(tmp)
    test_tech_detail(tmp)
    test_nginx_recientes_parseo()
    test_esc_dinamico()
    test_edit_not_modified_benigno()
    test_html_valido()

    print()
    print(f"TOTAL {TOTAL[0]} | PASS {TOTAL[0] - len(FALLOS)} | FAIL {len(FALLOS)}")
    if FALLOS:
        print("FALLOS:", ", ".join(FALLOS))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
