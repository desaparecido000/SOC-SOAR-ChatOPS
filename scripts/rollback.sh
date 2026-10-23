#!/usr/bin/env bash
# Rollback instantaneo a la consola ChatOps v1.1-chatops certificada
# (Fase 4F, Session 46). NO toca soar_executor.py (v1.0-prod es de otro bloque).
set -euo pipefail
REL="/root/soar/releases/v1.1-chatops"
STAMP="$(date +%Y%m%d-%H%M%S)"
cd "$REL"
sha256sum -c SHA256SUMS
systemctl stop gym-chatops.service || true
cp -p /root/soar/soar_bot.py      "/root/soar/soar_bot.py.pre-rollback-${STAMP}.bak" 2>/dev/null || true
cp -p /root/soar/tests_chatops.py "/root/soar/tests_chatops.py.pre-rollback-${STAMP}.bak" 2>/dev/null || true
cp -p "$REL/soar_bot.py"        /root/soar/soar_bot.py
cp -p "$REL/tests_chatops.py"   /root/soar/tests_chatops.py
cp -p "$REL/gym-chatops.service" /etc/systemd/system/gym-chatops.service
rm -f /run/gym-chatops.lock || true
systemctl daemon-reload
systemctl start gym-chatops.service
sleep 3
systemctl is-active gym-chatops.service
python3 -c "import hashlib; print('soar_bot sha256:', hashlib.sha256(open('/root/soar/soar_bot.py','rb').read()).hexdigest())"
