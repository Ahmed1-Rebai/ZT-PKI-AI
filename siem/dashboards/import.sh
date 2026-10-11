#!/usr/bin/env bash
# Import the ZT saved searches + dashboard into the Wazuh dashboard.
# Run ON siem as root. The admin password is read from the installer's
# archive on the VM; it is never printed, logged or stored in the repo.
set -euo pipefail
ND="${1:-/tmp/zt-dashboards.ndjson}"
PW=$(tar -O -xf /root/wazuh-install-files.tar wazuh-install-files/wazuh-passwords.txt \
     | awk "/indexer_username: 'admin'/{getline; print}" | sed -E "s/.*indexer_password: '([^']+)'.*/\1/")
[ -n "$PW" ] || { echo "admin password not found" >&2; exit 1; }
curl -sk -u "admin:$PW" -H 'osd-xsrf: true' \
     -X POST 'https://localhost/api/saved_objects/_import?overwrite=true' \
     --form file=@"$ND" | python3 -c 'import sys,json;r=json.load(sys.stdin);print("success:",r.get("success"),"count:",r.get("successCount"),"errors:",[e.get("id") for e in r.get("errors",[])])'
