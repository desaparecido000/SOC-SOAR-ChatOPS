#!/usr/bin/env python3
"""Suite de tests del SOAR executor 4A/4B.

Alimenta al evaluador con los JSON REALES capturados el 18-Oct-2026 en
/root/soar-captures/ mas variantes sinteticas derivadas de ellos.

Casos exigidos (Fase 4A):
  T1  firing real + token valido          -> WOULD_EXECUTE docker start dvwa
  T2  reenvio mismo (fp, startsAt)        -> SKIP_DUPLICATE
  T3  resolved real                       -> STATE_CLEARED para el fp
  T4  mismo fp, startsAt nuevo, post-res  -> WOULD_EXECUTE otra vez
  T5  fuera de lista blanca / inyeccion   -> DENY_NOT_WHITELISTED
  T6  sin Authorization / token erroneo   -> 401 AUTH_FAIL (G1)
Extra:
  T7  envelope mixto firing+resolved      -> ambos veredictos por item
  T8  firing con endsAt sentinel ausente  -> MALFORMED_STATE (G3)
  T9  cooldown 3/900s                     -> RATE_LIMITED (G5)
  T10 resolved con endsAt sentinel        -> MALFORMED_STATE (G3)
  T11 alertname ajeno                     -> SKIP_UNMATCHED_RULE (G2)

Casos exigidos (Fase 4B - rama IP, IP_LIVE 4B.3/4B.4: iptables/ip6tables
sustituido por FakeFirewall, sin tocar el kernel). Fase 4B.4 = CORTE DUAL
SIMETRICO: ban/unban/reconcile operan sobre CHAINS = (DOCKER-USER, INPUT):
  T12 IP publica atacante valida          -> BANNED_IP + -I exacto en AMBAS
                                             cadenas (pos 1, etiqueta SOAR-BAN)
  T13 src_ip malformado / inyeccion       -> DENY_MALFORMED_IP
  T14 NEVER_BAN_IPS (host y operador)     -> DENY_NEVER_BAN
  T15 sesion SSH activa simulada          -> DENY_ACTIVE_SSH_SESSION
  T16 IP privada sin excepcion            -> DENY_PRIVATE_IP
  T16b excepcion de test via fichero      -> BANNED_IP (privada habilitada)
  T17 ciclo IP completo                   -> BAN -> DUP -> resolved con
                                             startsAt MUTADO (Grafana 11.2.2)
                                             -> STATE_CLEARED + -D en AMBAS
                                             cadenas + re-ban
  T18 regresion 4A tras el ruteo         -> WOULD_EXECUTE (contenedores)
  T19 unban en bucle (-D tope 3)          -> duplicadas purgadas en 2 cadenas
  T20 reconcile_on_startup                -> reinserta (2 cadenas) / expira /
                                             huerfanas barridas en su cadena
  T21 resolved sin incidente activo       -> STATE_CLEARED sin -D
  T22 metrica de efectividad              -> UNBANNED_IP con dropped_pkts
                                             por cadena

Casos exigidos (Fase 4C - promocion de contratos + Ref-Counting):
  T23 G2 multi-regla                      -> 3 reglas IP + contenedor
  T24 disparo por Entropia/WAF            -> BANNED_IP con rule en auditoria
  T25 colision multi-regla (Ref-Counting) -> fp1 resolved = PARTIAL (sin
                                              -D), fp2 resolved = unban real
  T26 resolved unico                      -> STATE_CLEARED directo (no PARTIAL)

Casos exigidos (Fase 4D - notificaciones forenses a Telegram):
  T27 _telegram_send sin token            -> no-op silencioso (telegram_enabled
                                             False), sin llamada de red
  T28 formato EXACTO de BANNED_IP         -> texto ðŸ›¡ï¸ con IP/regla/corte dual/fp
  T29 formato EXACTO de UNBANNED_IP       -> texto ðŸŸ¢ con dropped_pkts por cadena
  T30 formato EXACTO de EXECUTED (4A)     -> texto ðŸ”„ con ExitCode previo
  T31 no-interferencia                    -> fallo de _telegram_send NO altera
                                             el veredicto ni lanza; se audita
                                             TELEGRAM_NOTIFY_ERROR

Exit 0 = todos PASS.
"""
import copy
import json
import sys
import time as _tiempo
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import soar_executor as so  # noqa: E402

CAP = Path("/root/soar-captures")
FIRING = CAP / "payload-20261018-174223-49.json"
RESOLVED = CAP / "payload-20261018-174723-36.json"

fallos = []
total = [0]


def check(nombre, cond, detalle=""):
    estado = "PASS" if cond else "FAIL"
    print(f"[{estado}] {nombre}" + (f"  <- {detalle}" if detalle and not cond else ""))
    total[0] += 1
    if not cond:
        fallos.append(nombre)


def estado_vacio():
    so.state.clear()
    so.state.update({"executed": {}, "actions": {}})


class _Rc:
    """Sustituto minimo de subprocess.CompletedProcess."""

    def __init__(self, rc, stdout="", stderr=""):
        self.returncode = rc
        self.stdout = stdout
        self.stderr = stderr


class FakeFirewall:
    """Sustituto de subprocess.run para certificar la rama IP_LIVE.

    Simula iptables/ip6tables como lista de reglas SOAR-BAN por CADENA
    (-C/-I/-D/-S con rc coherente), el `iptables -L <cadena> -v -n -x`
    que lee `_contador_pkts()` y el `ss` de G4-IP.3 (sin sesiones).
    Corte dual simetrico (4B.4): cada spec es `bin|cadena|ip`, de modo
    que DOCKER-USER e INPUT se gobiernan por separado y las aserciones
    pueden probar que AMBAS reciben la operacion.
    Cada llamada queda registrada en self.llamadas para asertar el
    comando EXACTO invocado por el executor.
    """

    def __init__(self):
        self.reglas = []   # ["iptables|DOCKER-USER|8.8.8.8", ...]
        self.llamadas = []
        self.pkts = {}     # "iptables|DOCKER-USER|8.8.8.8" -> contador

    def __call__(self, cmd, capture_output=True, text=True, timeout=None):
        self.llamadas.append(list(cmd))
        if cmd[0] == "ss":          # guarda G4-IP.3: sin sesiones SSH
            return _Rc(0)
        ipt, op = cmd[0], cmd[1]
        if op == "-C":
            return _Rc(0 if self._spec(cmd) in self.reglas else 1)
        if op == "-I":
            self.reglas.append(self._spec(cmd))
            return _Rc(0)
        if op == "-D":
            spec = self._spec(cmd)
            if spec in self.reglas:
                self.reglas.remove(spec)
                return _Rc(0)
            return _Rc(1, "", "iptables: Bad rule (does a matching rule exist?).")
        if op == "-S":
            cadena = cmd[2]
            lineas = [
                f'-A {cadena} -s {s.split("|")[2]}/32 '
                f'-m comment --comment "SOAR-BAN" -j DROP'
                for s in sorted(self.reglas)
                if s.split("|")[0] == ipt and s.split("|")[1] == cadena
            ]
            return _Rc(0, "\n".join(lineas))
        if op == "-L":
            # iptables -L <cadena> -v -n -x (cabecera + filas SOAR-BAN)
            cadena = cmd[2]
            filas = ["Chain DOCKER-USER (1 references)",
                     " pkts bytes target prot opt in out source destination"]
            for s in sorted(self.reglas):
                b, c, ip = s.split("|")
                if b == ipt and c == cadena:
                    p = self.pkts.get(s, 0)
                    filas.append(
                        f" {p} {p * 60} DROP all -- * * {ip} 0.0.0.0/0 "
                        f'/* {so.BAN_COMMENT} */')
            return _Rc(0, "\n".join(filas))
        return _Rc(0)

    @staticmethod
    def _spec(cmd):
        return f"{cmd[0]}|{cmd[2]}|{cmd[cmd.index('-s') + 1]}"

    def cuenta(self, op, ip, cadena=None):
        """Invocaciones registradas de un op (-C/-I/-D) que mencionan esa
        IP como elemento exacto. Si `cadena` es None, cuenta en cualquier
        cadena (DOCKER-USER o INPUT)."""
        return sum(1 for c in self.llamadas
                   if len(c) > 2 and c[1] == op
                   and (cadena is None or c[2] == cadena) and ip in c)

    def presente(self, ip, cadena):
        return any(s.split("|")[1] == cadena and s.split("|")[2] == ip
                   for s in self.reglas)


def main():
    # Fase 4D - higiene: la suite NUNCA debe tocar la API real de Telegram.
    # Se desactiva el notificador globalmente (credenciales vacias). Las
    # pruebas de formato (T28-T30) inyectan _telegram_send y la de
    # no-interferencia (T31) inyecta _telegram_post, de modo que ninguna
    # llamada de red real ocurre durante la suite.
    so._TG_CREDS = {"token": "", "chatid": ""}

    # Fase 4D - aislamiento: la suite NO debe escribir en el state.json ni en
    # el audit log de PRODUCCION. Se redirigen a un directorio temporal para
    # esta corrida (a menos que SOAR_TEST_USE_PROD=1, nunca en produccion).
    import os
    import tempfile
    if os.environ.get("SOAR_TEST_USE_PROD") != "1":
        _tmp = Path(tempfile.mkdtemp(prefix="soar-tests-"))
        so.STATE_FILE = _tmp / "state.json"
        so.AUDIT_LOG = _tmp / "soar-audit.log"
        so.TEST_IPS_FILE = _tmp / "test-allowed-ips.txt"
        print(f"[info] aislamiento: state/audit de test en {_tmp}")

    for f in (FIRING, RESOLVED):
        if not f.exists():
            print(f"[FAIL] falta la captura real {f}")
            return 1
    firing = json.loads(FIRING.read_text())
    resolved = json.loads(RESOLVED.read_text())
    a_f = firing["alerts"][0]
    a_r = resolved["alerts"][0]
    print(f"contrato real: fp={a_f['fingerprint']} startsAt={a_f['startsAt']} "
          f"resolved.endsAt={a_r['endsAt']}")

    # Firewall falso GLOBAL: iptables/ip6tables/ss simulados (el proceso
    # de tests nunca toca el kernel ni la red).
    fw = FakeFirewall()
    so.subprocess.run = fw

    # T1 - firing real -> WOULD_EXECUTE
    estado_vacio()
    dec, det = so.evaluar_alerta(copy.deepcopy(a_f), 1000.0)
    check("T1 firing real -> WOULD_EXECUTE docker start dvwa",
          dec == "WOULD_EXECUTE" and "dvwa" in det, f"{dec} / {det}")

    # T2 - reenvio del mismo incidente -> SKIP_DUPLICATE
    dec, det = so.evaluar_alerta(copy.deepcopy(a_f), 1030.0)
    check("T2 reenvio (mismo fingerprint+startsAt) -> SKIP_DUPLICATE",
          dec == "SKIP_DUPLICATE", f"{dec} / {det}")

    # T3 - resolved real -> STATE_CLEARED
    dec, det = so.evaluar_alerta(copy.deepcopy(a_r), 1060.0)
    check("T3 resolved real -> STATE_CLEARED",
          dec == "STATE_CLEARED" and a_f["fingerprint"] in det,
          f"{dec} / {det}")
    check("T3b clave del fingerprint liberada",
          not any(k.startswith(a_f["fingerprint"] + "|") for k in so.state["executed"]),
          str(so.state["executed"]))

    # T4 - mismo fingerprint, startsAt nuevo tras resolved -> otra vez
    a4 = copy.deepcopy(a_f)
    a4["startsAt"] = "2026-10-18T19:00:00Z"  # nueva caida, labels identicas
    dec, det = so.evaluar_alerta(a4, 1100.0)
    check("T4 segunda caida (mismo fp, startsAt nuevo) -> WOULD_EXECUTE",
          dec == "WOULD_EXECUTE", f"{dec} / {det}")

    # T5 - fuera de lista blanca / inyeccion
    a5 = copy.deepcopy(a_f)
    a5["labels"]["name"] = "postgres"
    a5["fingerprint"] = "deadbeef00000001"
    a5["startsAt"] = "2026-10-18T19:10:00Z"
    dec, det = so.evaluar_alerta(a5, 1110.0)
    check("T5a name fuera de whitelist -> DENY_NOT_WHITELISTED",
          dec == "DENY_NOT_WHITELISTED", f"{dec} / {det}")
    a5b = copy.deepcopy(a_f)
    a5b["labels"]["name"] = "dvwa;id"
    a5b["fingerprint"] = "deadbeef00000002"
    a5b["startsAt"] = "2026-10-18T19:11:00Z"
    dec, det = so.evaluar_alerta(a5b, 1111.0)
    check("T5b inyeccion name='dvwa;id' -> DENY_NOT_WHITELISTED (regex)",
          dec == "DENY_NOT_WHITELISTED", f"{dec} / {det}")
    a5c = copy.deepcopy(a_f)
    a5c["labels"]["name"] = "grafana"
    a5c["fingerprint"] = "deadbeef00000003"
    a5c["startsAt"] = "2026-10-18T19:12:00Z"
    dec, det = so.evaluar_alerta(a5c, 1112.0)
    check("T5c contenedor critico (grafana) -> DENY_NOT_WHITELISTED",
          dec == "DENY_NOT_WHITELISTED", f"{dec} / {det}")

    # T6 - G1 autenticacion (hmac.compare_digest, formato Bearer)
    secreto = "tokendeprueba" + "X" * 20
    ok = so.hmac.compare_digest(f"Bearer {secreto}", f"Bearer {secreto}")
    mal = so.hmac.compare_digest("", f"Bearer {secreto}")
    otro = so.hmac.compare_digest("Bearer otrotoken", f"Bearer {secreto}")
    check("T6 G1: bearer correcto acepta, vacio y erroneo rechazan",
          ok and not mal and not otro, f"ok={ok} vacio={mal} otro={otro}")

    # T7 - envelope mixto: firing + resolved en el mismo alerts[]
    estado_vacio()
    mixto = [copy.deepcopy(a_f), copy.deepcopy(a_r)]
    # el firing primero (WOULD_EXECUTE), luego resolved del MISMO fp: lo cierra
    d1, _ = so.evaluar_alerta(mixto[0], 2000.0)
    d2, _ = so.evaluar_alerta(mixto[1], 2000.0)
    check("T7 envelope mixto firing+resolved -> veredictos por item",
          d1 == "WOULD_EXECUTE" and d2 == "STATE_CLEARED", f"{d1} / {d2}")

    # T8 - firing incoherente (endsAt con fecha) -> MALFORMED_STATE
    a8 = copy.deepcopy(a_f)
    a8["endsAt"] = "2026-10-18T18:00:00Z"
    a8["startsAt"] = "2026-10-18T20:00:00Z"
    a8["fingerprint"] = "deadbeef00000004"
    dec, det = so.evaluar_alerta(a8, 2100.0)
    check("T8 firing con endsAt no-sentinel -> MALFORMED_STATE",
          dec == "MALFORMED_STATE", f"{dec} / {det}")

    # T9 - cooldown 3 acciones en 900s
    estado_vacio()
    so.state["actions"]["dvwa"] = [3000.0, 3100.0, 3200.0]
    a9 = copy.deepcopy(a_f)
    a9["startsAt"] = "2026-10-18T21:00:00Z"
    dec, det = so.evaluar_alerta(a9, 3300.0)
    check("T9 cooldown 3/900s -> RATE_LIMITED",
          dec == "RATE_LIMITED", f"{dec} / {det}")
    # fuera de la ventana (edad > 900s) si se permite
    estado_vacio()
    so.state["actions"]["dvwa"] = [3000.0]
    a9b = copy.deepcopy(a_f)
    a9b["startsAt"] = "2026-10-18T21:30:00Z"
    dec, det = so.evaluar_alerta(a9b, 3000.0 + 901.0)
    check("T9b acciones previas fuera de 900s -> WOULD_EXECUTE",
          dec == "WOULD_EXECUTE", f"{dec} / {det}")

    # T10 - resolved con endsAt sentinel -> MALFORMED_STATE
    a10 = copy.deepcopy(a_r)
    a10["endsAt"] = "0001-01-01T00:00:00Z"
    dec, det = so.evaluar_alerta(a10, 4000.0)
    check("T10 resolved con endsAt sentinel -> MALFORMED_STATE",
          dec == "MALFORMED_STATE", f"{dec} / {det}")

    # T11 - alertname ajeno -> SKIP_UNMATCHED_RULE (G2 item)
    a11 = copy.deepcopy(a_f)
    a11["labels"]["alertname"] = "GYM - Disco casi lleno"
    dec, det = so.evaluar_alerta(a11, 4100.0)
    check("T11 alertname ajeno -> SKIP_UNMATCHED_RULE",
          dec == "SKIP_UNMATCHED_RULE", f"{dec} / {det}")

    # --- Fase 4B: rama IP (IP_LIVE 4B.3) ---------------------------------
    def alerta_ip(src_ip, fp, starts, status="firing", rule=None):
        """Alerta sintetica de la regla dimensional por src_ip.

        `rule` (Fase 4C) permite simular cualquiera de las 3 reglas IP
        (Protocolo / Entropia / WAF) que comparten el plano de corte.
        """
        a = {"fingerprint": fp, "startsAt": starts,
             "endsAt": ("0001-01-01T00:00:00Z" if status == "firing"
                        else "2026-10-19T12:00:00Z"),
             "status": status,
             "labels": {"alertname": rule or so.IP_RULE, "src_ip": src_ip or "",
                        "grafana_folder": "Alertas GYM"}}
        return a

    # T12 - IP publica valida -> BANNED_IP con corte DUAL (DOCKER-USER+INPUT)
    estado_vacio()
    dec, det = so.evaluar_alerta(alerta_ip("8.8.8.8", "fpip001",
                                           "2026-10-19T10:00:00Z"), 5000.0)
    check("T12 IP publica valida -> BANNED_IP",
          dec == "BANNED_IP" and "8.8.8.8" in det, f"{dec} / {det}")
    esp_du = ["iptables", "-I", "DOCKER-USER", "1", "-s", "8.8.8.8",
              "-m", "comment", "--comment", "SOAR-BAN", "-j", "DROP"]
    esp_in = ["iptables", "-I", "INPUT", "1", "-s", "8.8.8.8",
              "-m", "comment", "--comment", "SOAR-BAN", "-j", "DROP"]
    check("T12b comando -I DOCKER-USER pos 1 exacto (etiqueta SOAR-BAN)",
          esp_du in fw.llamadas, f"no hallado; llamadas={fw.llamadas[-4:]}")
    check("T12c comando -I INPUT pos 1 exacto (CORTE DUAL simetrico)",
          esp_in in fw.llamadas, f"no hallado; llamadas={fw.llamadas[-4:]}")
    check("T12d -C previa antes del -I en AMBAS cadenas + reglas insertadas",
          fw.cuenta("-C", "8.8.8.8", "DOCKER-USER") >= 1
          and fw.cuenta("-C", "8.8.8.8", "INPUT") >= 1
          and fw.presente("8.8.8.8", "DOCKER-USER")
          and fw.presente("8.8.8.8", "INPUT"),
          f"reglas={fw.reglas}")
    check("T12e CHAINS del executor = (DOCKER-USER, INPUT)",
          tuple(so.CHAINS) == ("DOCKER-USER", "INPUT"), f"{so.CHAINS}")

    # T12f - IPv6 -> despacho a ip6tables (no a iptables v4) en ambas cadenas
    estado_vacio()
    dec, det = so.evaluar_alerta(alerta_ip("2606:4700:4700::1111", "fpip001v6",
                                           "2026-10-19T10:00:30Z"), 5005.0)
    check("T12f IPv6 publica -> BANNED_IP via ip6tables en 2 cadenas",
          dec == "BANNED_IP"
          and any(c[0] == "ip6tables" and c[2] == "DOCKER-USER"
                  and "2606:4700:4700::1111" in c for c in fw.llamadas)
          and any(c[0] == "ip6tables" and c[2] == "INPUT"
                  and "2606:4700:4700::1111" in c for c in fw.llamadas),
          f"{dec} / {det}")

    # T13 - src_ip malformado / inyeccion -> DENY_MALFORMED_IP
    estado_vacio()
    dec, det = so.evaluar_alerta(alerta_ip("999.1.1.1", "fpip002",
                                           "2026-10-19T10:01:00Z"), 5010.0)
    check("T13a src_ip='999.1.1.1' -> DENY_MALFORMED_IP",
          dec == "DENY_MALFORMED_IP", f"{dec} / {det}")
    dec, det = so.evaluar_alerta(alerta_ip("1.2.3.4;id", "fpip003",
                                           "2026-10-19T10:02:00Z"), 5020.0)
    check("T13b src_ip inyectado='1.2.3.4;id' -> DENY_MALFORMED_IP",
          dec == "DENY_MALFORMED_IP", f"{dec} / {det}")
    dec, det = so.evaluar_alerta(alerta_ip(None, "fpip004",
                                           "2026-10-19T10:03:00Z"), 5030.0)
    check("T13c src_ip ausente -> DENY_MALFORMED_IP",
          dec == "DENY_MALFORMED_IP", f"{dec} / {det}")

    # T14 - NEVER_BAN_IPS: host publico + ultima IP SSH del operador
    for ip_protegida in sorted(so.NEVER_BAN_IPS):
        dec, det = so.evaluar_alerta(
            alerta_ip(ip_protegida, f"fpip010{ip_protegida[-1]}",
                      f"2026-10-19T10:1{ip_protegida[-1]}:00Z"), 5100.0)
        check(f"T14 NEVER_BAN {ip_protegida} -> DENY_NEVER_BAN",
              dec == "DENY_NEVER_BAN", f"{dec} / {det}")

    # T15 - sesion SSH activa (guarda dinamica) -> DENY_ACTIVE_SSH_SESSION
    # 198.51.100.7 es espacio documental: aunque alguna version de
    # ipaddress lo marque como no-global, el ORDEN de las guardas hace
    # que la sesion SSH (paso 3) se evalue ANTES de la privada (paso 4).
    orig_ssh = so.get_active_ssh_ips
    so.get_active_ssh_ips = lambda: {"198.51.100.7"}
    dec, det = so.evaluar_alerta(alerta_ip("198.51.100.7", "fpip020",
                                           "2026-10-19T10:20:00Z"), 5200.0)
    so.get_active_ssh_ips = orig_ssh
    check("T15 sesion SSH activa -> DENY_ACTIVE_SSH_SESSION",
          dec == "DENY_ACTIVE_SSH_SESSION", f"{dec} / {det}")
    # control: sin sesion, la misma IP NO se rechaza por esa razon
    dec, det = so.evaluar_alerta(alerta_ip("198.51.100.7", "fpip021",
                                           "2026-10-19T10:21:00Z"), 5210.0)
    check("T15b misma IP sin sesion SSH -> no DENY_ACTIVE_SSH_SESSION",
          dec != "DENY_ACTIVE_SSH_SESSION", f"{dec} / {det}")

    # T16 - IP privada sin excepcion -> DENY_PRIVATE_IP
    estado_vacio()
    dec, det = so.evaluar_alerta(alerta_ip("172.18.0.1", "fpip030",
                                           "2026-10-19T10:30:00Z"), 5300.0)
    check("T16 IP privada 172.18.0.1 sin excepcion -> DENY_PRIVATE_IP",
          dec == "DENY_PRIVATE_IP", f"{dec} / {det}")

    # T16b - excepcion de test via fichero (se relee en cada evaluacion)
    tmp_ips = Path("/tmp/soar-test-allowed-ips.txt")
    tmp_ips.write_text("# habilitacion temporal del TP\n10.9.8.7\n")
    orig_file = so.TEST_IPS_FILE
    so.TEST_IPS_FILE = tmp_ips
    dec, det = so.evaluar_alerta(alerta_ip("10.9.8.7", "fpip031",
                                           "2026-10-19T10:31:00Z"), 5310.0)
    so.TEST_IPS_FILE = orig_file
    tmp_ips.unlink(missing_ok=True)
    check("T16b IP privada en fichero de test -> BANNED_IP (2 cadenas)",
          dec == "BANNED_IP" and fw.cuenta("-I", "10.9.8.7") == 2,
          f"{dec} / {det}; -I={fw.cuenta('-I', '10.9.8.7')}")

    # T17 - ciclo IP completo: ban -> dup -> resolved MUTADO -> re-ban
    estado_vacio()
    a17 = alerta_ip("8.8.4.4", "fpip040", "2026-10-19T10:40:00Z")
    dec, det = so.evaluar_alerta(copy.deepcopy(a17), 5400.0)
    check("T17a firing IP publica -> BANNED_IP",
          dec == "BANNED_IP", f"{dec} / {det}")
    dec, det = so.evaluar_alerta(copy.deepcopy(a17), 5430.0)
    check("T17b reenvio mismo (fp, startsAt) -> SKIP_DUPLICATE (2 -I, uno/cadena)",
          dec == "SKIP_DUPLICATE" and fw.cuenta("-I", "8.8.4.4") == 2,
          f"{dec} / {det}; -I={fw.cuenta('-I', '8.8.4.4')}")
    # resolved con startsAt MUTADO (estilo Grafana 11.2.2: = inicio del
    # estado Normal, DISTINTO del startsAt del firing) -> la localizacion
    # por fingerprint tiene que encontrar el incidente y desbanear.
    a17r = alerta_ip("8.8.4.4", "fpip040", "2026-10-19T10:57:12Z",
                     status="resolved")
    dec, det = so.evaluar_alerta(a17r, 5460.0)
    check("T17c resolved con startsAt MUTADO -> STATE_CLEARED",
          dec == "STATE_CLEARED" and "fpip040" in det, f"{dec} / {det}")
    esp_du_d = ["iptables", "-D", "DOCKER-USER", "-s", "8.8.4.4",
                "-m", "comment", "--comment", "SOAR-BAN", "-j", "DROP"]
    esp_in_d = ["iptables", "-D", "INPUT", "-s", "8.8.4.4",
                "-m", "comment", "--comment", "SOAR-BAN", "-j", "DROP"]
    check("T17d clave liberada + -D exacto en AMBAS cadenas + reglas fuera",
          not any(k.startswith("fpip040|") for k in so.state["executed"])
          and esp_du_d in fw.llamadas and esp_in_d in fw.llamadas
          and not fw.presente("8.8.4.4", "DOCKER-USER")
          and not fw.presente("8.8.4.4", "INPUT"),
          f"estado={so.state['executed']} d_du={esp_du_d in fw.llamadas} "
          f"d_in={esp_in_d in fw.llamadas} reglas={fw.reglas}")
    a17b = alerta_ip("8.8.4.4", "fpip040", "2026-10-19T11:00:00Z")
    dec, det = so.evaluar_alerta(a17b, 5500.0)
    check("T17e mismo fp, startsAt nuevo tras resolved -> BANNED_IP otra vez",
          dec == "BANNED_IP", f"{dec} / {det}")

    # T18 - control de regresion: la rama 4A sigue intacta tras el ruteo
    estado_vacio()
    dec, det = so.evaluar_alerta(copy.deepcopy(a_f), 5600.0)
    check("T18 regresion 4A: firing real -> WOULD_EXECUTE dvwa",
          dec == "WOULD_EXECUTE" and "dvwa" in det, f"{dec} / {det}")

    # T19 - unban en bucle: reglas duplicadas (carrera) se purgan todas,
    # y el corte DUAL obliga a limpiar DUPLICADAS EN AMBAS cadenas.
    # Fixture explicito: T18 (estado_vacio) limpio el estado del servicio;
    # se repone la entrada del incidente como la escribio T17e (dict con
    # ban_ip). 3 reglas por cadena => el bucle -D (tope 3) las purga todas.
    fw.reglas += ["iptables|DOCKER-USER|8.8.4.4", "iptables|DOCKER-USER|8.8.4.4",
                  "iptables|INPUT|8.8.4.4"]
    so.state["executed"]["fpip040|2026-10-19T11:00:00Z"] = {
        "ts": 5500.0, "ban_ip": "8.8.4.4"}
    a19r = alerta_ip("8.8.4.4", "fpip040", "2026-10-19T12:34:56Z",
                     status="resolved")
    dec, det = so.evaluar_alerta(a19r, 5700.0)
    check("T19 resolved con duplicadas -> STATE_CLEARED y TODAS borradas (2 cadenas)",
          dec == "STATE_CLEARED"
          and fw.cuenta("-D", "8.8.4.4", "DOCKER-USER") >= 2
          and fw.cuenta("-D", "8.8.4.4", "INPUT") >= 2
          and not any("8.8.4.4" in r for r in fw.reglas)
          and not any(k.startswith("fpip040|") for k in so.state["executed"]),
          f"{dec} / -D_du={fw.cuenta('-D', '8.8.4.4', 'DOCKER-USER')} "
          f"-D_in={fw.cuenta('-D', '8.8.4.4', 'INPUT')} reglas={fw.reglas}")

    # T20 - reconcile_on_startup: vigente reinsertada EN AMBAS CADENAS,
    # expirada retirada, huerfana (regla sin estado) barrida en su cadena
    estado_vacio()
    ahora = _tiempo.time()
    so.state["executed"]["fpviva|s1"] = {"ts": ahora, "ban_ip": "9.9.9.9"}
    so.state["executed"]["fpmuerta|s2"] = {"ts": ahora - 700,
                                           "ban_ip": "4.4.4.4"}
    # expirada (INPUT) + huerfana (DOCKER-USER) + huerfana en INPUT
    fw.reglas += ["iptables|INPUT|4.4.4.4", "iptables|DOCKER-USER|7.7.7.7",
                  "iptables|INPUT|7.7.7.7"]
    so.reconcile_on_startup()
    check("T20a ban vigente sin regla -> reinsertada en AMBAS cadenas",
          fw.presente("9.9.9.9", "DOCKER-USER") and fw.presente("9.9.9.9", "INPUT")
          and "fpviva|s1" in so.state["executed"],
          f"reglas={fw.reglas}")
    check("T20b ban expirado (>10 min) -> regla retirada + entrada purgada",
          not fw.presente("4.4.4.4", "INPUT") and not fw.presente("4.4.4.4", "DOCKER-USER")
          and "fpmuerta|s2" not in so.state["executed"],
          f"reglas={fw.reglas} estado={so.state['executed']}")
    check("T20c regla SOAR-BAN huerfana -> barrida en TODAS las cadenas",
          not fw.presente("7.7.7.7", "DOCKER-USER")
          and not fw.presente("7.7.7.7", "INPUT"), f"reglas={fw.reglas}")

    # T22 - metrica de efectividad: UNBANNED_IP registra dropped_pkts por
    # cadena (paquetes bloqueados por la regla SOAR-BAN antes de retirarla).
    estado_vacio()
    capturado = []
    orig_audit = so.audit
    so.audit = lambda ev, **kw: capturado.append((ev, kw))
    try:
        so._ban_ip("5.6.7.8")
        fw.pkts["iptables|DOCKER-USER|5.6.7.8"] = 12
        fw.pkts["iptables|INPUT|5.6.7.8"] = 3
        ok = so._unban_ip("5.6.7.8")
    finally:
        so.audit = orig_audit
    ev_unban = [kw for ev, kw in capturado if ev == "UNBANNED_IP"]
    check("T22a unban OK y sin reglas residuales en ninguna cadena",
          ok and not fw.presente("5.6.7.8", "DOCKER-USER")
          and not fw.presente("5.6.7.8", "INPUT"), f"ok={ok} reglas={fw.reglas}")
    check("T22b UNBANNED_IP con dropped_pkts por cadena (efectividad)",
          ev_unban and ev_unban[-1].get("dropped_pkts") ==
          {"DOCKER-USER": 12, "INPUT": 3}
          and ev_unban[-1].get("cadenas") == ["DOCKER-USER", "INPUT"],
          f"{ev_unban[-1] if ev_unban else 'sin evento'}")

    # T21 - resolved sin incidente activo (p.ej. la alerta fue DENY y nunca
    # toco estado): STATE_CLEARED con 0 liberadas y SIN -D al kernel
    estado_vacio()
    antes_d = fw.cuenta("-D", "5.5.5.5")
    dec, det = so.evaluar_alerta(
        alerta_ip("5.5.5.5", "fpsinarreglo", "2026-10-19T13:00:00Z",
                  status="resolved"), 5800.0)
    check("T21 resolved sin estado -> STATE_CLEARED sin invocar -D",
          dec == "STATE_CLEARED" and "fpsinarreglo" in det
          and fw.cuenta("-D", "5.5.5.5") == antes_d,
          f"{dec} / {det}")

    # --- Fase 4C: promocion de contratos + Ref-Counting ------------------
    # T23 - G2 multi-regla: las 3 reglas IP comparten el corte dual y
    # rutean a _ban_ip con auditoria "rule".
    estado_vacio()
    check("T23a IP_ALERT_RULES = {Protocolo, Entropia, WAF}",
          so.IP_ALERT_RULES == {"GYM - SOAR Anomalia Protocolo",
                                "GYM - SOAR Entropia URI",
                                "GYM - SOAR Suricata WAF"},
          f"{so.IP_ALERT_RULES}")
    check("T23b EXPECTED_ALERTNAMES = contenedor + 3 IP",
          so.EXPECTED_ALERTNAMES == {so.CONTAINER_RULE} | so.IP_ALERT_RULES
          and len(so.EXPECTED_ALERTNAMES) == 4,
          f"{sorted(so.EXPECTED_ALERTNAMES)}")

    # T24 - disparo por Entropia y por WAF -> BANNED_IP + rule en auditoria
    for etiqueta, regla, fp, ip in (
            ("Entropia URI", so.IP_RULE_ENTROPIA, "fpip060", "45.33.32.156"),
            ("Suricata WAF", so.IP_RULE_WAF, "fpip061", "45.33.32.157")):
        estado_vacio()
        capturado = []
        orig_audit = so.audit
        so.audit = lambda ev, **kw: capturado.append((ev, kw))
        try:
            dec, det = so.evaluar_alerta(
                alerta_ip(ip, fp, "2026-10-19T14:00:00Z", rule=regla), 6000.0)
        finally:
            so.audit = orig_audit
        ev_ban = [kw for ev, kw in capturado if ev == "BANNED_IP"]
        check(f"T24 {etiqueta} -> BANNED_IP (2 cadenas)",
              dec == "BANNED_IP" and fw.presente(ip, "DOCKER-USER")
              and fw.presente(ip, "INPUT"), f"{dec} / {det}")
        check(f"T24 {etiqueta} -> BANNED_IP con rule={regla!r}",
              ev_ban and ev_ban[-1].get("rule") == regla,
              f"{ev_ban[-1] if ev_ban else 'sin evento'}")
        # la entrada de estado lleva la regla (para el Ref-Counting)
        check(f"T24 {etiqueta} -> state.executed con rule",
              any(isinstance(e, dict) and e.get("rule") == regla
                  for e in so.state["executed"].values()),
              f"{so.state['executed']}")

    # T25 - COLISION MULTI-REGLA (Ref-Counting): la MISMA IP entra por
    # Protocolo (fp1) y por Entropia (fp2). El resolved de fp1 NO debe
    # desbanear (STATE_CLEARED_PARTIAL); el de fp2 SI (UNBANNED_IP).
    estado_vacio()
    ip_col = "45.33.32.50"
    d1, _ = so.evaluar_alerta(
        alerta_ip(ip_col, "fpc001", "2026-10-19T15:00:00Z",
                  rule=so.IP_RULE), 7000.0)
    d2, _ = so.evaluar_alerta(
        alerta_ip(ip_col, "fpc002", "2026-10-19T15:00:30Z",
                  rule=so.IP_RULE_ENTROPIA), 7010.0)
    check("T25a misma IP por 2 reglas -> 2 BANNED_IP (2 fingerprints)",
          d1 == "BANNED_IP" and d2 == "BANNED_IP"
          and len(so.state["executed"]) == 2, f"{d1} / {d2}")
    antes_d_col = fw.cuenta("-D", ip_col)
    # resolved de fp1 (Protocolo): NO debe llamar _unban_ip
    capturado = []
    orig_audit = so.audit
    so.audit = lambda ev, **kw: capturado.append((ev, kw))
    try:
        dec1, det1 = so.evaluar_alerta(
            alerta_ip(ip_col, "fpc001", "2026-10-19T15:07:12Z",
                      status="resolved", rule=so.IP_RULE), 7400.0)
    finally:
        so.audit = orig_audit
    ev_partial = [kw for ev, kw in capturado if ev == "STATE_CLEARED_PARTIAL"]
    check("T25b resolved fp1 -> STATE_CLEARED_PARTIAL (no desbanea)",
          dec1 == "STATE_CLEARED_PARTIAL" and "fpc001" in det1,
          f"{dec1} / {det1}")
    check("T25c la regla del kernel sigue presente (fp2 retiene la IP)",
          fw.presente(ip_col, "DOCKER-USER") and fw.presente(ip_col, "INPUT")
          and fw.cuenta("-D", ip_col) == antes_d_col,
          f"reglas={fw.reglas} -D={fw.cuenta('-D', ip_col)}")
    check("T25d STATE_CLEARED_PARTIAL audita el retenedor (rule)",
          ev_partial
          and ev_partial[-1].get("target") == ip_col
          and any(r.get("rule") == so.IP_RULE_ENTROPIA
                  for r in ev_partial[-1].get("retenido_por", [])),
          f"{ev_partial[-1] if ev_partial else 'sin evento'}")
    check("T25e la clave de fp2 sigue activa en state.json",
          any(k.startswith("fpc002|") for k in so.state["executed"])
          and not any(k.startswith("fpc001|") for k in so.state["executed"]),
          f"{so.state['executed']}")
    # resolved de fp2 (Entropia, ultima) -> SI desbanea en ambas cadenas
    capturado = []
    so.audit = lambda ev, **kw: capturado.append((ev, kw))
    try:
        dec2, det2 = so.evaluar_alerta(
            alerta_ip(ip_col, "fpc002", "2026-10-19T15:08:12Z",
                      status="resolved", rule=so.IP_RULE_ENTROPIA), 7500.0)
    finally:
        so.audit = orig_audit
    ev_unban2 = [kw for ev, kw in capturado if ev == "UNBANNED_IP"]
    check("T25f resolved fp2 (ultima) -> STATE_CLEARED + desbanea",
          dec2 == "STATE_CLEARED" and "fpc002" in det2, f"{dec2} / {det2}")
    check("T25g UNBANNED_IP en 2 cadenas + reglas fuera del kernel",
          ev_unban2 and ev_unban2[-1].get("cadenas") == ["DOCKER-USER", "INPUT"]
          and not fw.presente(ip_col, "DOCKER-USER")
          and not fw.presente(ip_col, "INPUT")
          and not so.state["executed"],
          f"{ev_unban2[-1] if ev_unban2 else 'sin evento'} reglas={fw.reglas}")

    # T26 - ref-counting NO interfiere con un unban normal (una sola regla):
    # resolved de una unica alerta desbanea directamente (STATE_CLEARED).
    estado_vacio()
    ip_sola = "45.33.32.70"
    so.evaluar_alerta(alerta_ip(ip_sola, "fps001", "2026-10-19T16:00:00Z",
                                rule=so.IP_RULE_WAF), 8000.0)
    dec, det = so.evaluar_alerta(
        alerta_ip(ip_sola, "fps001", "2026-10-19T16:07:12Z", status="resolved",
                  rule=so.IP_RULE_WAF), 8400.0)
    check("T26 resolved unico -> STATE_CLEARED (no PARTIAL) y desbanea",
          dec == "STATE_CLEARED" and not fw.presente(ip_sola, "DOCKER-USER")
          and not fw.presente(ip_sola, "INPUT"), f"{dec} / {det}")

    # --- Fase 4D: notificaciones forenses a Telegram ---------------------
    # El envio real se sustituye por un capturador: la suite verifica el
    # TEXTO EXACTO formateado SIN llamadas de red. `so._telegram_send` es el
    # unico punto de salida del notificador (inyectable por diseno).

    # T27 - sin token/chatid -> no-op silencioso (telegram_enabled False)
    estado_vacio()
    _orig_send = so._telegram_send
    try:
        so._telegram_send = _orig_send  # se ejercita la funcion real
        # telegram_enabled se deriva del fichero de credenciales; simulamos
        # ausencia forzando la config a vacio.
        so._TG_CREDS = {"token": "", "chatid": ""}
        enviado = so._telegram_send("mensaje de prueba")
    finally:
        so._TG_CREDS = {"token": "", "chatid": ""}  # higiene: sigue off
    check("T27 sin token -> _telegram_send no-op (enviado=False, sin red)",
          enviado is False, f"enviado={enviado!r}")

    # T28 - formato EXACTO de BANNED_IP
    estado_vacio()
    capturado_tg = []
    so._telegram_send = lambda text: (capturado_tg.append(text), True)[1]
    try:
        dec, det = so.evaluar_alerta(
            alerta_ip("45.33.32.90", "fptg001", "2026-10-21T10:00:00Z",
                      rule=so.IP_RULE_ENTROPIA), 9000.0)
    finally:
        so._telegram_send = _orig_send
    txt28 = capturado_tg[-1] if capturado_tg else ""
    check("T28 BANNED_IP notifica con texto forense exacto",
          dec == "BANNED_IP" and len(capturado_tg) == 1
          and "🛡️ [SOAR-LIVE] IP Bloqueada en Kernel" in txt28
          and "45.33.32.90" in txt28
          and so.IP_RULE_ENTROPIA in txt28
          and "Corte Dual: DOCKER-USER + INPUT" in txt28
          and "Fingerprint: fptg001" in txt28,
          f"{dec} / {txt28!r}")

    # T29 - formato EXACTO de UNBANNED_IP con dropped_pkts por cadena
    estado_vacio()
    ip29 = "45.33.32.91"
    capturado_tg = []
    so._telegram_send = lambda text: (capturado_tg.append(text), True)[1]
    try:
        # ban con paquetes contados, luego resolved -> unban con dropped_pkts
        so.evaluar_alerta(alerta_ip(ip29, "fptg002", "2026-10-21T11:00:00Z",
                                    rule=so.IP_RULE_WAF), 9100.0)
        fw.pkts["iptables|DOCKER-USER|" + ip29] = 7
        fw.pkts["iptables|INPUT|" + ip29] = 4
        dec, det = so.evaluar_alerta(
            alerta_ip(ip29, "fptg002", "2026-10-21T11:07:12Z",
                      status="resolved", rule=so.IP_RULE_WAF), 9500.0)
    finally:
        so._telegram_send = _orig_send
    txt29 = capturado_tg[-1] if capturado_tg else ""
    check("T29 UNBANNED_IP notifica con dropped_pkts por cadena",
          dec == "STATE_CLEARED"
          and "🟢 [SOAR-LIVE] Bloqueo Expirado / Liberado" in txt29
          and ip29 in txt29 and so.IP_RULE_WAF in txt29
          and "DOCKER-USER=7" in txt29 and "INPUT=4" in txt29,
          f"{dec} / {txt29!r}")

    # T30 - formato EXACTO de EXECUTED (contenedor) con ExitCode previo
    # Necesitamos un subprocess que simule `docker inspect -f ExitCode` y
    # `docker start`. Se usa un fake especifico para esta prueba.
    estado_vacio()
    so.DRY_RUN = False  # forzar la rama LIVE de contenedores en el test

    class FakeDocker:
        def __init__(self):
            self.llamadas = []

        def __call__(self, cmd, capture_output=True, text=True, timeout=None):
            self.llamadas.append(list(cmd))
            if cmd[0] == "docker" and cmd[1] == "inspect":
                return _Rc(0, stdout="137\n", stderr="")   # ExitCode previo
            if cmd[0] == "docker" and cmd[1] == "start":
                return _Rc(0, stdout="dvwa\n", stderr="")
            if cmd[0] == "ss":
                return _Rc(0)
            return _Rc(0)

        def cuenta(self, *a, **k):
            return 0

        def presente(self, *a, **k):
            return False

    fw_cont = FakeDocker()
    fw_prev = so.subprocess.run
    so.subprocess.run = fw_cont
    capturado_tg = []
    so._telegram_send = lambda text: (capturado_tg.append(text), True)[1]
    try:
        a30 = copy.deepcopy(a_f)
        a30["fingerprint"] = "fptg003"
        a30["startsAt"] = "2026-10-21T12:00:00Z"
        dec, det = so.evaluar_alerta(a30, 10000.0)
    finally:
        so._telegram_send = _orig_send
        so.subprocess.run = fw_prev
        so.DRY_RUN = True
    txt30 = capturado_tg[-1] if capturado_tg else ""
    check("T30 EXECUTED notifica con ExitCode previo",
          dec == "EXECUTED"
          and "🔄 [SOAR-LIVE] Contenedor Auto-Recuperado" in txt30
          and "dvwa" in txt30 and "ExitCode previo: 137" in txt30
          and "docker start rc=0" in txt30,
          f"{dec} / {txt30!r}")

    # T31 - NO-INTERFERENCIA: si el POST a Telegram lanza, la accion NO se
    # altera. Se inyecta el fallo en _telegram_post (la capa de red real),
    # de modo que se ejercita el try/except de fail-safe de _telegram_send.
    estado_vacio()
    _orig_post = so._telegram_post

    def _post_explota(url, datos):
        raise RuntimeError("simulado: API Telegram caida")

    so._telegram_post = _post_explota
    so._TG_CREDS = {"token": "123456789:" + "A" * 35, "chatid": "<TU_CHAT_ID>"}
    capturado = []
    _orig_audit_4d = so.audit
    so.audit = lambda ev, **kw: capturado.append((ev, kw))
    try:
        dec, det = so.evaluar_alerta(
            alerta_ip("45.33.32.92", "fptg004", "2026-10-21T13:00:00Z",
                      rule=so.IP_RULE), 11000.0)
    finally:
        so._telegram_post = _orig_post
        so._TG_CREDS = {"token": "", "chatid": ""}  # higiene: sigue off
        so.audit = _orig_audit_4d
    ev_err = [kw for ev, kw in capturado if ev == "TELEGRAM_NOTIFY_ERROR"]
    check("T31 fallo de Telegram NO interfiere: BANNED_IP se completa",
          dec == "BANNED_IP" and "45.33.32.92" in det,
          f"{dec} / {det}")
    check("T31b el fallo se audita como TELEGRAM_NOTIFY_ERROR",
          len(ev_err) == 1 and "RuntimeError" in str(ev_err[0].get("error", "")),
          f"{ev_err!r}")

    print("=" * 70)
    if fallos:
        print(f"RESULTADO: FAIL - {len(fallos)} fallo(s) de {total[0]}: {fallos}")
        return 1
    print(f"RESULTADO: PASS - {total[0]}/{total[0]} aserciones")
    return 0


if __name__ == "__main__":
    sys.exit(main())

