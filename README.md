# gym-soar-ecosystem

[![Tests: SOAR 65/65 | ChatOps 145/145](https://img.shields.io/badge/Tests-SOAR%2065%2F65%20%7C%20ChatOps%20145%2F145-success)]()
[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-blue)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Sistema inmunológico para VPS**: Detección L7, bloqueo en kernel en < 5ms, auto-healing de contenedores y panel interactivo ChatOps vía Telegram.

## ¿Por qué?

Los VPS de producción necesitan reaccionar ante ataques sin esperar intervención humana. Este ecosistema combina **observabilidad (SIEM)**, **orquestación reactiva (SOAR)** y **operación humana asistida (ChatOps)** para:

- **Detectar**: Reglas Grafana Alerting + Suricata (L7) alimentadas desde Loki/Prometheus.
- **Decidir**: Motor SOAR con corte dual simétrico (`DOCKER-USER` + `INPUT`), ref-counting anti-desbaneo prematuro y allowlists.
- **Actuar**: Bloqueo iptables en kernel (< 5ms), auto-healing de contenedores (`docker start`) y auditoría inmutable.
- **Operar**: Consola ChatOps interactiva (panel, `/audit`, ficha forense de IP, desbloqueo con confirmación 2 pasos).

## Arquitectura

```text
┌─────────────┐   ┌─────────────┐   ┌─────────────┐   ┌─────────────┐
│   Sensores   │ → │     Loki     │ → │   Grafana    │ → │  SOAR Exec.  │
│ Suricata/Nginx│   │   Promtail   │   │   Alerting   │   │  (webhook)   │
└─────────────┘   └─────────────┘   └─────────────┘   └─────────────┘
                                                              │
                                        ┌─────────────────────┼─────────────────────┐
                                        ▼                     ▼                     ▼
                                    iptables            docker start        Telegram Notify
                                   (DOCKER-USER)        (whitelist)          (forense)
                                        │                                           │
                                        └─────────────┬─────────────────────────────┘
                                                      ▼
                                                   ChatOps Bot
                                                  (panel /audit)
```

### Componentes principales

| Componente | Ruta | Descripción |
|---|---|---|
| **SOAR Executor** | `src/soar_executor.py` | Motor principal. Recibe webhooks Grafana, enruta por `alertname` (`GYM - Contenedor caido`, `GYM - SOAR Anomalia Protocolo`, `GYM - SOAR Entropia URI`, `GYM - SOAR Suricata WAF`). Corte dual simétrico, ref-counting, `NEVER_BAN`, auditoría JSON. |
| **ChatOps Console** | `src/soar_bot.py` | Bot interactivo Telegram (long-polling). Solo lectura + `/unban` delegado a primitivas certificadas. Panel con navegación, revelación progresiva, ficha forense de IP, `/audit` con 5 invariantes. |
| **Tests SOAR** | `tests/tests_soar.py` | 65 aserciones (contratos L7, corte dual, ref-counting, idempotencia). |
| **Tests ChatOps** | `tests/tests_chatops.py` | 145 aserciones (autorización, callbacks, navegación, ficha IP, escape HTML, invariantes). |
| **Grafana Provisioning** | `config/grafana/` | Reglas y contact points (rutas SOAR webhook con `continue: true`, agrupación por `src_ip`). |
| **Suricata Rules** | `config/suricata/gym.rules` | Firmas propias para el pipeline SOAR. |
| **Systemd Units** | `config/systemd/` | `gym-soar.service`, `gym-chatops.service`. |
| **Rollback/DR** | `scripts/rollback.sh` | Sistema de inmutabilidad con verificación SHA256 y restauración. |
| **Runbook** | `RUNBOOK.md` | Manual de operaciones Día 2 (topología, DR, gestión diaria, mantenimiento). |
| **Changelog** | `CHANGELOG.md` | Historial detallado por sesión. |

## Inicio rápido

### Requisitos
- Python 3.11+
- Linux con `iptables` (filtrado en kernel)
- Docker (para auto-healing)
- Telegram Bot Token + Chat ID
- Grafana/Loki/Prometheus (para el pipeline completo)

### Configuración (sanitizada)

Las credenciales **nunca** van hardcodeadas. Se cargan desde:
- `/root/.gym-creds/telegram` (formato `TELEGRAM_BOT_TOKEN=...` / `TELELEGRAM_CHAT_ID=...` o claves separadas, permisos 600)
- `/root/.gym-creds/soar-webhook-secret` (secreto Bearer para el webhook Grafana)
- Variables de entorno: `GYM_NEVER_BAN_IPS` (lista separada por comas), `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `SOAR_WEBHOOK_SECRET`

Para Grafana provisioning, usa variables de entorno (`${TELEGRAM_BOT_TOKEN}`, `${TELEGRAM_CHAT_ID}`, `${SOAR_WEBHOOK_SECRET}`).

### Instalación (ejemplo)

```bash
# Copiar código
cp src/soar_executor.py /root/soar/
cp src/soar_bot.py /root/soar/

# Configurar unidades
cp config/systemd/gym-soar.service /etc/systemd/system/
cp config/systemd/gym-chatops.service /etc/systemd/system/
systemctl daemon-reload

# Arrancar
systemctl enable --now gym-soar.service gym-chatops.service
```

### Ejecutar tests

```bash
cd /root/soar
python3 tests/tests_soar.py
python3 tests/tests_chatops.py
```

## Características destacadas

- **Corte dual simétrico**: Ban/Unban/Reconcile idénticos en `DOCKER-USER` + `INPUT`. Ref-counting evita desbanear prematuramente cuando múltiples reglas comparten IP.
- **Auto-healing**: Reinicio automático de contenedores de la lista blanca con `docker start` (modo LIVE tras certificación).
- **ChatOps seguro**: Único chat autorizado, comandos cerrados, escape HTML de datos dinámicos, lock de instancia única, IPv4 forzado.
- **Auditoría completa**: Cada acción genera evento JSON en `soar-audit.log` (`BANNED_IP`, `UNBANNED_IP`, `EXECUTED`, `RECONCILED_IP`, `TELEGRAM_NOTIFY_ERROR`, etc.).
- **Inmutabilidad**: Snapshots SHA256 + `chattr +i` + `rollback.sh` para recuperación en 1 comando.
- **Auditoría de postura**: `/audit` verifica 5 invariantes (< 200ms) — integridad del executor, blindaje firewall, servicio SOAR, reglas Grafana, backups (SLA < 26h).

## Seguridad (sanitización para repositorio público)

Este repositorio ha sido **sanitizado**:
- ❌ Sin tokens, secretos o credenciales
- ❌ Sin `state.json`, logs o archivos `.lock`
- ❌ IPs propias y `TELEGRAM_CHAT_ID` reemplazados por placeholders/env vars
- ❌ `NEVER_BAN_IPS` cargable desde entorno/archivo externo
- ❌ Contact points Grafana usan variables de entorno

Ver `.gitignore` para detalles.

## Documentación

- [RUNBOOK.md](RUNBOOK.md) — Operaciones de Día 2 (topología, Disaster Recovery, gestión diaria, mantenimiento)
- [CHANGELOG.md](CHANGELOG.md) — Historial completo de 48 sesiones

## Licencia

MIT License - Ver [LICENSE](LICENSE) para detalles.
