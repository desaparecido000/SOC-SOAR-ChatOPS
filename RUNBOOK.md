# RUNBOOK — srv1823413 (SIEM + SOAR + ChatOps)

> **Documento maestro de Operaciones de Día 2.**
> Manual de supervivencia y mantenimiento del nodo `srv1823413` (`203.0.113.10`).
> Todo lo aquí escrito está **verificado contra el estado real del VPS** (recon 2026-10-21/22,
> Session 48). Los comandos asumen acceso `root` por SSH.
>
> **Regla de oro:** ante duda, no improvisar. Este nodo tiene 3 planos certificados con
> snapshots inmutables y rollback en 1 comando. Primero se lee, después se actúa.

---

## 0. Ficha rápida del nodo

| Campo | Valor |
|---|---|
| Host | `srv1823413` — `203.0.113.10` |
| Rol | Nodo de producción: app MetroCoord + plataforma SIEM/SOAR + laboratorio |
| SSH | `ssh -i ~/.ssh/id_ed25519 root@203.0.113.10` |
| Contenedores | **18** (todos `up`; 1 firma Suricata activa) |
| Reglas de alerta Grafana | **17** (`health=ok`) |
| Snapshots inmutables | `v1.0-prod` (SOAR), `v1.1-chatops` (ChatOps) |
| Servicios clave | `gym-soar.service`, `gym-chatops.service` |
| Documentación viva | `D:\00_HUB\opencode\CHANGELOG.md` (sesiones 38–47) |

---

## 1. Topología de alto nivel (los 3 bloques)

```
                         ┌─────────────────────────────────────────────┐
                         │            srv1823413 (203.0.113.10)          │
                         └─────────────────────────────────────────────┘

  BLOQUE A — SENSORES / INFRA            BLOQUE B — SOAR DE KERNEL
  (observabilidad + app en producción)   (decisión automática sobre kernel)
  ┌────────────────────────────────┐     ┌──────────────────────────────┐
  │ 18 contenedores Docker:        │     │ gym-soar.service (PID dín.)  │
  │  🏢 Producción MetroCoord      │     │  python3 soar_executor.py    │
  │     frontend, backend, db,     │     │           --live             │
  │     redis                      │     │  Listener: 172.19.0.1:9099   │
  │  📡 SIEM/Observabilidad        │     │  Recibe webhooks de Grafana  │
  │     grafana, loki, prometheus, │     │                              │
  │     promtail, node-exporter,   │     │  Primitivas CERTIFICADAS:    │
  │     cadvisor                   │     │   · _ban_ip / _unban_ip      │
  │  🛡️ Sensores & Perímetro       │     │   · CHAINS=DOCKER-USER,INPUT │
  │     suricata, nginx-proxy,     │     │   · BAN_COMMENT="SOAR-BAN"   │
  │     docker-ro-proxy            │     │   · NEVER_BAN_IPS (proteg.)  │
  │  🧪 Laboratorio                │     │   · Ref-Counting + reconcile │
  │     dvwa, kalilab, msf3-lab,   │     │  Estado:  /root/soar/state.json
  │     lab-server, atacante       │     │  Auditoría: soar-audit.log   │
  └────────────────────────────────┘     └──────────────────────────────┘
             │                                          ▲
             │ métricas (gym.prom)                      │ webhook alerta
             │ logs (promtail → loki)                   │
             ▼                                          │
  ┌────────────────────────────────┐                   │
  │ node-exporter textfile         │                   │
  │ /var/lib/node-exporter/        │                   │
  │   textfile/gym.prom            │                   │
  │ gym-metrics.timer (60s) ───────┼───────────────────┘
  │ gym-autoheal.timer (60s)       │  (auto-heal de contenedores colgados)
  └────────────────────────────────┘

  BLOQUE C — INTERFAZ CHATOPS (humano en el bucle)
  ┌──────────────────────────────────────────────────────────────────────┐
  │ gym-chatops.service  →  python3 /root/soar/soar_bot.py                │
  │ Telegram @vpsAlert777bot (bot id 8268635195) · long-poll getUpdates   │
  │ Chat autorizado ÚNICO: <TU_CHAT_ID>   (guarda G1-CHATOPS)             │
  │ Solo lectura + /unban. Delega el desbloqueo en la primitiva SOAR.     │
  │ NO toca soar_executor.py (proceso independiente).                     │
  └──────────────────────────────────────────────────────────────────────┘
```

**Flujo de una alerta (camino completo):**

1. **Sensor** (suricata/nginx) emite log → promtail → **Loki**.
2. **Grafana** evalúa las 17 reglas → si dispara, envía webhook al listener SOAR.
3. **SOAR** aplica la guarda (allowlist, NEVER_BAN, dedup por fingerprint) y decide:
   - Contenedor caído → `docker start` (auto-healing).
   - IP maliciosa → corte **dual** en `DOCKER-USER` + `INPUT` (`BAN_COMMENT=SOAR-BAN`).
4. Toda decisión se **audita** en `/root/soar/soar-audit.log` (evento + timestamp).
5. **ChatOps** lee esos mismos artefactos (no los escribe) y los presenta al operador.

**Puertos internos (todos en `127.0.0.1`, solo UFW desde fuera):**

| Puerto | Servicio | Escucha |
|---|---|---|
| `3000` | Grafana | `127.0.0.1` |
| `3100` | Loki | `127.0.0.1` |
| `9090` | Prometheus | `127.0.0.1` |
| `9099` | Listener SOAR (webhook) | `172.19.0.1` (red Docker) |

---

## 2. Procedimientos de recuperación (Disaster Recovery)

> **Filosofía:** cada bloque tiene un snapshot **inmutable** (`chattr +i`) con verificación
> SHA-256 y su propio `rollback.sh`. Restaurar = 1 comando + verificación automática.

### 2.1. Rollback del SOAR (`v1.0-prod`)

Restaura `soar_executor.py` + `tests_soar.py` + la unit `gym-soar.service`.

```bash
ssh -i ~/.ssh/id_ed25519 root@203.0.113.10

# 1) Ver qué contiene y que los hashes siguen íntegros
cd /root/soar/releases/v1.0-prod
sha256sum -c SHA256SUMS          # Debe imprimir "OK" 3 veces

# 2) Ejecutar el rollback (verifica, respalda .bak, restaura, rearranca)
./rollback.sh
# Salida esperada al final:
#   active
#   executor sha256: 31b5d4b4e760dd94022d332b9d5d88091950db9b8d86c5c489892681569d80ab
```

**Qué hace `rollback.sh` exactamente** (704 permisos, **sin** `+i`, a propósito para
poder ejecutarse): verifica `SHA256SUMS` → para `gym-soar.service` → copia el executor
y los tests actuales a `.pre-rollback-<timestamp>.bak` → restaura desde el snapshot →
`daemon-reload` → arranca → espera 2s → imprime el hash.

> **Si el hash impreso NO es `31b5d4b4…`**, algo tocó el snapshot o el deploy:
> deténgase y revise con `lsattr /root/soar/releases/v1.0-prod/*` (debe mostrar `i`).

### 2.2. Rollback del ChatOps (`v1.1-chatops`)

Restaura `soar_bot.py` + `tests_chatops.py` + la unit `gym-chatops.service`.
**No toca el SOAR** (son bloques independientes).

```bash
cd /root/soar/releases/v1.1-chatops
sha256sum -c SHA256SUMS          # "OK" 3 veces
./rollback.sh
# Salida esperada:
#   active
#   soar_bot sha256: c0590654fabebb1b1bec41e71c13b09f6a2b7406555469cfb726c089eb6c87a4
```

**Diferencia clave con el SOAR:** el rollback del ChatOps además `rm -f /run/gym-chatops.lock`
antes de rearrancar, para limpiar el lock de instancia única.

### 2.3. Verificación post-rollback (siempre, en ambos casos)

```bash
systemctl is-active gym-soar.service gym-chatops.service
cd /root/soar && python3 tests_soar.py   2>&1 | tail -1   # RESULTADO: PASS - 65/65
cd /root/soar && python3 tests_chatops.py 2>&1 | grep TOTAL   # TOTAL 145 | PASS 145 | FAIL 0
sha256sum /root/soar/soar_executor.py     # 31b5d4b4… (SOAR intacto)
```

### 2.4. Restaurar la base de datos de MetroCoord (PostgreSQL)

Los backups son **automáticos**, diarios a las **03:17** (cron), en formato
`pg_dump -Fc` (custom, comprimido). Retención **7 días**. Verificación estructural
en el momento del dump (`pg_restore -l`).

| Ruta | Contenido |
|---|---|
| `/var/backups/postgres/metrocoord-<TS>.dump` | Dump completo (pg_restore) |
| `/var/backups/postgres/metrocoord-globals-<TS>.sql` | Roles y tablespaces |
| `/var/lib/metrocoord-backup/estado.json` | Estado del último backup (`ok`, tablas, filas) |
| `/usr/local/bin/metrocoord-backup.sh` | Script generador (sin contraseñas) |
| `/usr/local/bin/metrocoord-restore-test.sh` | Prueba de restauración semanal (dom 04:23) |

**Prueba de restauración (recomendado: primero esto, no toca la base viva):**

```bash
/usr/local/bin/metrocoord-restore-test.sh
# Crea una base de trabajo, restaura el último dump, compara fila por fila
# contra la base viva y borra la base de trabajo. Veredicto:
#   "COINCIDENCIA EXACTA"  → el backup es válido y restaurable
#   "DIVERGENCIA"          → el dump NO sirve; investigar antes de nada
```

**Restauración real sobre la base viva (destructivo, requiere confirmación):**

```bash
# 0) PARAR la app para evitar escrituras durante el restore
docker stop metrocoord-backend metrocoord-frontend

# 1) Identificar el dump más reciente
DUMP=$(ls -1t /var/backups/postgres/metrocoord-2*.dump | head -1)
echo "$DUMP"

# 2) Restaurar (por stdin, con -i: sin -i pg_restore lee 0 bytes)
docker exec -i -u postgres metrocoord-db \
    pg_restore -U postgres -d metrocoord --no-owner --clean \
    < "$DUMP"

# 3) Reaplicar los globales (roles) — fichero metrocoord-globals-<TS>.sql
TS="${DUMP##*metrocoord-}"; TS="${TS%.dump}"
GLOBALS="/var/backups/postgres/metrocoord-globals-${TS}.sql"
docker exec -u postgres metrocoord-db \
    psql -U postgres -d postgres < "$GLOBALS"

# 4) Rearrancar la app y verificar
docker start metrocoord-backend metrocoord-frontend
```

> ⚠️ **El restore real es la única operación destructiva de este RUNBOOK.**
> Antes de ejecutarlo: lanzar `metrocoord-restore-test.sh` (valida el dump), avisar
> al responsable de MetroCoord, y comprobar espacio libre en `/var/backups/postgres`.
> Existe `metrocoord-restore-test.sh` precisamente para no tener que improvisar aquí.

### 2.5. Restaurar la configuración de monitoreo

Backups automáticos diarios a las **02:00** (timer `gym-backup.timer`), en
`/root/monitoring-backups/`:

| Ruta | Contenido |
|---|---|
| `files/monitoring-config-<TS>.tar.gz` | Config del stack (compose, .env, provisionings) |
| `dashboards/gym-sec-<TS>.json` | Dashboards Grafana exportados |
| `/root/vps-gym-backup.sh` | Script generador (verifica tamaño mínimo + manifiesto) |

**Restauración:**

```bash
# 1) Ver los backups disponibles (más reciente primero)
ls -1t /root/monitoring-backups/files/monitoring-config-*.tar.gz | head -3

# 2) Inspeccionar el contenido ANTES de extraer
TAR=$(ls -1t /root/monitoring-backups/files/monitoring-config-*.tar.gz | head -1)
tar -tzf "$TAR" | head -30

# 3) Extraer a un directorio de staging (NO encima de /opt/monitoring)
mkdir -p /root/restore-staging && tar -xzf "$TAR" -C /root/restore-staging

# 4) Comparar y aplicar de forma selectiva
diff -u /opt/monitoring/docker-compose.yml /root/restore-staging/<ruta>/docker-compose.yml
```

> 🔁 **Tras restaurar configuración de monitoreo**, recrear el stack:
> `cd /opt/monitoring && docker compose up -d`. Verificar con `/audit` en el bot.

### 2.6. Verificación del mecanismo de backup (frescura)

La métrica `gym_backup_age_seconds` (en `gym.prom`) refleja la antigüedad del backup
más reciente **de cualquiera de los dos sistemas**. SLA: **< 26h**.

```bash
grep -E 'gym_backup_age_seconds|gym_backup_ok|gym_backup_count' \
    /var/lib/node-exporter/textfile/gym.prom
# gym_backup_ok 1            → último backup con éxito
# gym_backup_age_seconds N   → si N > 93600 (26h) → investigar ya
```

---

## 3. Gestión diaria (ChatOps)

Todos los comandos se ejecutan escribiendo al bot desde el **chat autorizado**
(`<TU_CHAT_ID>`). Cualquier otro origen se **descarta sin respuesta** y se audita como
`CHATOPS_UNAUTHORIZED`.

### 3.1. Los 6 comandos

| Comando | Para qué | Qué muestra |
|---|---|---|
| `/panel` | Tablero interactivo principal | Postura global + botones de navegación |
| `/status` | Estado ejecutivo en texto | Contenedores por grupo, servicio, disco, RAM, backup |
| `/threat` | Inteligencia de amenazas (Loki 6h) | Rechazos Nginx (400/444) + firmas Suricata |
| `/bans` | Estado de bloqueos | IPs con regla `SOAR-BAN` activa + últimos eventos |
| `/audit` | Auditoría de postura | Las 5 invariantes de blindaje (ver 3.3) |
| `/help` | Guía | Referencia de comandos + sugerencia de ficha de IP |

**Extras interactivos:**

- **Ficha forense de IP:** pega una IP en el chat (p. ej. `176.65.149.111`) y el bot
  responde con su estado en firewall, rDNS, historial y sus últimas peticiones Nginx.
  Si la IP está baneada, ofrece un botón **🔓 Desbloquear**.
- **Botones de navegación:** el panel usa `editMessageText` (un solo mensaje, sin spam).
- **🔬 Detalle Técnico:** capa forense (hash de integridad, fingerprints, cadenas y `dropped_pkts`).

### 3.2. Cómo interpretar el panel (`/panel`)

```
📊 Panel de Estado — SOAR DevSecOps
Postura global: 🟢 OPERATIVO | 🟠 ATENCIÓN       ← semáforo agregado
🧩 Contenedores: 18/18 en pie
🟢 🏢 Producción MetroCoord: 4/4                 ← agrupado por bloque lógico
🟢 📡 SIEM / Observabilidad: 6/6
🟢 🛡️ Sensores & Perímetro: 3/3
🟢 🧪 Laboratorio: 5/5
🟢 Servicio SOAR: active (PID …)
💾 Disco /: [██░░░░░░░░] 22% (73.9 GB libres)     ← barra = umbral visual
🧠 RAM: [██░░░░░░░░] 6330 MB libres de 7941 MB
🗄️ Backup: 11h 9m (SLA < 26h)
```

- **🟢 OPERATIVO:** todo arriba, servicio activo, disco < 90%.
- **🟠 ATENCIÓN:** algún contenedor caído o disco ≥ 90% → seguir el grupo marcado.
- Una barra `[██████████]` ≥ 90% en disco es motivo de intervención inmediata.

### 3.3. Cómo interpretar `/audit` (auditoría de postura)

Verifica **5 invariantes** en < 200 ms:

```
🔐 Auditoría de Blindaje — 🟢 TODO OK (140 ms)

🟢 1. Integridad executor: hash=OK, inmutable=4 ficheros
🟢 2. Blindaje firewall: msf3=OK, INPUT=OK, fail2ban=OK
🟢 3. Servicio SOAR: activo=OK, escucha 172.19.0.1:9099=OK
🟢 4. Reglas Grafana: 17/17 saludables
🟢 5. Backups: 11h 9m (SLA < 26h)
```

| # | Invariante | Cómo se verifica | Si sale 🔴 |
|---|---|---|---|
| 1 | **Integridad del executor** | SHA-256 de `soar_executor.py` == `31b5d4b4…` **y** flag inmutable (`lsattr`) en el release | ¡Alerta! No tocar; comparar con snapshot. Ver §2.1 |
| 2 | **Blindaje firewall** | `msf3` DROP en `DOCKER-USER` + `INPUT`=DROP/ufw + fail2ban con jails | Reglas de firewall degradadas → revisar `iptables -S` |
| 3 | **Servicio SOAR** | `gym-soar.service active` **y** listener en `172.19.0.1:9099` | SOAR caído → ver §4.1 |
| 4 | **Reglas Grafana** | 17 reglas con `health=ok` | Regla con `health != ok` → revisar Grafana |
| 5 | **Backups** | `gym_backup_age_seconds < 26h` | Backup vencido → ver §2.6 |

> **Nota de alcance (fail2ban/ufw):** fail2ban NO usa cadenas `f2b-*` independientes;
> opera sobre el backend **ufw** (`ufw-user-input`), con 3 jails activos
> (`nginx-http-auth`, `sshd`, `ufw-bot-scan`). Es el estado real desde antes de la
> Fase 4F y así está codificado en la invariante 2.

---

## 4. Mantenimiento del SOAR

> **El SOAR NO tiene hoy un "Modo Mantenimiento" (botón o endpoint de pausa).**
> Pausarlo se hace con las herramientas estándar del sistema (systemd / iptables),
> que es exactamente lo que documenta esta sección. *Ver §5 — Backlog Day 2.*

### 4.1. Pausar temporalmente el SOAR (auto-healing + bloqueo perimetral)

El SOAR es **un solo proceso** que hace ambas cosas (auto-healing de contenedores
**y** bloqueo de IPs). Pararlo pausa todo:

```bash
# PAUSAR (intervención manual en el servidor)
systemctl stop gym-soar.service
systemctl is-active gym-soar.service        # → inactive

# …trabajo manual…

# REANUDAR
systemctl start gym-soar.service
systemctl is-active gym-soar.service        # → active
```

**Qué deja de ocurrir al parar el SOAR:**
- ❌ No se reinician contenedores que queden "colgados" (unhealthy sostenido).
- ❌ No se aplican nuevas reglas `SOAR-BAN`.
- ✅ Los bloqueos **ya existentes** siguen activos en el kernel (una vez puestas,
  las reglas iptables no dependen del proceso).
- ✅ El ChatOps (`gym-chatops`) sigue funcionando (es un proceso independiente que
  solo lee artefactos).

> **Alternativa no intrusiva:** el auto-healing del SOAR puede convivir con el
> auto-heal independiente del sistema (`gym-autoheal.timer`, cada 60s). Para evitar
> que AMBOS toquen un contenedor durante una intervención manual, excluir el
> contenedor del autoheal de sistema:

```bash
echo metrocoord-db >> /etc/gym-autoheal.exclude    # excluir de gym-autoheal.sh
systemctl stop gym-soar.service                     # pausar el SOAR
# …trabajo manual…
systemctl start gym-soar.service
sed -i '/^metrocoord-db$/d' /etc/gym-autoheal.exclude   # revertir la exclusión
```

### 4.2. Modo DRY-RUN del SOAR (auditar sin ejecutar)

El executor tiene dos flags internos en `soar_executor.py`:

| Flag | Valor por defecto | Efecto |
|---|---|---|
| `DRY_RUN` | `True` | Rama de contenedores: registra `WOULD_START_*` sin reiniciar |
| `IP_DRY_RUN` | `False` | `True` = registra `WOULD_BAN_IP` sin tocar iptables |

En producción `gym-soar.service` arranca con `--live`, que pone `DRY_RUN=False`
(contenedores) manteniendo `IP_DRY_RUN=False` (IPs live). **No se recomienda editar
estos flags directamente** — para eso está el rollback y el stop del servicio.

### 4.3. Levantar/parar el ChatOps sin afectar al SOAR

```bash
systemctl stop gym-chatops.service      # el SOAR sigue operando
systemctl start gym-chatops.service
# Si hubiera quedado un lock de instancia huérfano:
rm -f /run/gym-chatops.lock && systemctl restart gym-chatops.service
```

### 4.4. Intervención manual en una IP baneada

```bash
# Ver reglas SOAR-BAN activas (por cadena)
iptables -S DOCKER-USER | grep SOAR-BAN
iptables -S INPUT       | grep SOAR-BAN

# Preferido: desbloquear desde el bot (con confirmación en 2 pasos) o
# delegando en la primitiva certificada (NO a mano con iptables -D):
cd /root/soar && python3 -c \
  "import soar_executor as s; print(s._unban_ip('45.33.32.90', rule='MANUAL'))"
```

> El desbloqueo a mano con `iptables -D` **desincroniza** `state.json` (Ref-Counting)
> y el reconcile posterior. Usar siempre la primitiva `_unban_ip`.

---

## 5. Backlog Day 2 (mejoras conocidas, NO implementadas)

Documentadas para transparencia; **no forman parte del estado actual**:

1. **Modo Mantenimiento nativo en el bot.** Un botón `🛠️ Modo Mantenimiento` que
   haga `systemctl stop/start gym-soar.service` con confirmación en 2 pasos (reusa el
   patrón ya certificado de `cb:ask_unban` → `cb:do_unban`). ✅ Compatible con el
   diseño actual (no tocaría el executor).
2. **`gym-bot.service` en estado `failed`** — unidad obsoleta de un bot anterior,
   sustituida por `gym-chatops.service`. Comandos de limpieza (no ejecutados):
   ```bash
   systemctl disable --now gym-bot.service
   rm -f /etc/systemd/system/gym-bot.service /etc/systemd/system/gym-bot.service.d/limits.conf
   rmdir /etc/systemd/system/gym-bot.service.d 2>/dev/null
   systemctl daemon-reload && systemctl reset-failed gym-bot.service
   ```
3. **Actualizar la evidencia `4C.3`** con la nota post-4F de fail2ban/ufw
   (ya redactada en `soar-4c3-entropia-e2e-2026-10-21.md`).

---

## 6. Anexo — referencia rápida

### 6.1. Rutas críticas

| Ruta | Qué es |
|---|---|
| `/root/soar/soar_executor.py` | SOAR (v1.0-prod, hash `31b5d4b4…`) |
| `/root/soar/soar_bot.py` | ChatOps (v1.1-chatops, hash `c0590654…`) |
| `/root/soar/state.json` | Estado SOAR (executed/actions) |
| `/root/soar/soar-audit.log` | Auditoría SOAR (una línea JSON por evento) |
| `/root/soar/executor.log`, `chatops.log` | Logs de servicio |
| `/root/soar/releases/v1.0-prod/` | Snapshot inmutable SOAR (+ `rollback.sh`) |
| `/root/soar/releases/v1.1-chatops/` | Snapshot inmutable ChatOps (+ `rollback.sh`) |
| `/root/.gym-creds/` | Credenciales (600): `telegram`, `soar-webhook-secret`, `grafana.db` |
| `/opt/monitoring/` | Stack SIEM (compose, `.env`, provisionings) |
| `/var/backups/postgres/` | Dumps PostgreSQL de MetroCoord |
| `/root/monitoring-backups/` | Backups de config de monitoreo |
| `/var/lib/node-exporter/textfile/gym.prom` | Métricas propias (fuente de `/status`) |

### 6.2. Comandos de diagnóstico (read-only, seguros)

```bash
# Salud general
systemctl is-active gym-soar.service gym-chatops.service gym-backup.timer gym-autoheal.timer
docker ps --format '{{.Names}}\t{{.Status}}' | sort

# SOAR
ss -ltnp | grep 9099                       # listener activo
tail -20 /root/soar/soar-audit.log         # últimos eventos

# Firewall
iptables -S DOCKER-USER | grep SOAR-BAN
iptables -S INPUT       | grep -E 'SOAR-BAN|DROP'
fail2ban-client status                     # jails activos

# Backups
cat /var/lib/metrocoord-backup/estado.json
ls -1t /var/backups/postgres/metrocoord-*.dump | head -3
ls -1t /root/monitoring-backups/files/*.tar.gz | head -3

# Snapshots inmutables
sha256sum -c /root/soar/releases/v1.0-prod/SHA256SUMS
sha256sum -c /root/soar/releases/v1.1-chatops/SHA256SUMS
```

### 6.3. Escalado / criterios de parada

| Síntoma | Acción inmediata |
|---|---|
| `/audit` invariante 1 🔴 (hash executor) | **No tocar nada.** Comparar con snapshot; §2.1 |
| `/audit` invariante 5 🔴 (backup vencido) | Revisar §2.6 y el log `/var/log/gym-backup.log` |
| Contenedor de producción caído y no vuelve | §4.1 (pausar SOAR) + `docker logs <cont>` |
| ChatOps sin responder | `systemctl status gym-chatops` + `tail /root/soar/chatops.log` |
| Se necesita restaurar MetroCoord | **Confirmar con el responsable** → §2.4 |

---

*Última actualización: 2026-10-21/22 — Session 48 (Operaciones de Día 2).*
*Fuente de verdad de cambios: `D:\00_HUB\opencode\CHANGELOG.md`.*
