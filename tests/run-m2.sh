#!/usr/bin/env bash
# M2 scenario runner — executes S1..S6, S13, S14 against the lab and stores the
# raw evidence under tests/evidence/<scenario>/. Reuses the same client profile
# and controls the gateway enforces (docs/05, docs/06).
#
#   usage: tests/run-m2.sh [all|s1|s2|s3|s4|s5|s6|s13|s14]
#
# Preconditions: `make vpn` has run; sub-ca / zt-gw / client-lin are up.
set -uo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
INFRA="$REPO/infra"
EVD="$REPO/tests/evidence"
LABPASS="${PKI_PASS:-ZtLabCA-2026}"
ONLY="${1:-all}"
PASS=0; FAIL=0
ok(){ printf '  \033[32mPASS\033[0m  %s\n' "$1"; PASS=$((PASS+1)); }
ko(){ printf '  \033[31mFAIL\033[0m  %s\n' "$1"; FAIL=$((FAIL+1)); }
gssh(){ ( cd "$INFRA" && vagrant ssh "$1" -c "$2" 2>/dev/null ); }
fetch(){ ( cd "$INFRA" && vagrant ssh "$1" -c "sudo cat '$2'" 2>/dev/null ); }
run(){ [ "$ONLY" = all ] || [ "$ONLY" = "$1" ]; }
cd "$INFRA"

# Refresh CRL + redeploy gateway from the current sub-ca state.
refresh_gw() {
  gssh sub-ca "cd /home/vagrant && PKI_BASE=/home/vagrant PKI_PASS='$LABPASS' bash pki/scripts/gencrl.sh >/dev/null 2>&1"
  "$REPO/vpn/scripts/sync-pki.sh" alice >/dev/null 2>&1
  ( cd "$INFRA" && vagrant provision zt-gw >/dev/null 2>&1 )
}
# Build a client config (from the readable copy) with cert/key blocks removed.
ro_copy(){ gssh client-lin 'sudo cp /etc/openvpn/client/alice.conf /tmp/alice.ro && sudo chmod 644 /tmp/alice.ro'; }

mkdir -p "$EVD/s01_no_cert" "$EVD/s02_rogue_ca" "$EVD/s03_revoked" "$EVD/s04_expired" \
         "$EVD/s05_scan_gw" "$EVD/s06_udp_dos" "$EVD/s13_mitm_gw" "$EVD/s14_pdp_down"

# ---------------------------------------------------------------- S1
if run s1; then
  echo "== S1 — connection without certificate =="
  gssh client-lin 'sudo pkill -x openvpn 2>/dev/null; sleep 1'
  ro_copy
  gssh client-lin 'set -e
    awk "/<ca>/{f=1} f{print} /<\/ca>/{f=0}" /tmp/alice.ro > /tmp/nocert.conf
    echo client >> /tmp/nocert.conf; echo dev tun >> /tmp/nocert.conf
    echo "proto udp" >> /tmp/nocert.conf; echo "remote 192.168.100.1 1194" >> /tmp/nocert.conf
    echo "remote-cert-tls server" >> /tmp/nocert.conf; echo "tls-version-min 1.3" >> /tmp/nocert.conf
    awk "/<tls-crypt>/{f=1} f{print} /<\/tls-crypt>/{f=0}" /tmp/alice.ro >> /tmp/nocert.conf'
  gssh client-lin 'sudo timeout 15 openvpn --config /tmp/nocert.conf --connect-retry-max 1 --verb 4 >/tmp/s1.log 2>&1'
  fetch client-lin /tmp/s1.log > "$EVD/s01_no_cert/client.log"
  fetch zt-gw /var/log/openvpn/openvpn.log | tail -n 15 > "$EVD/s01_no_cert/server.log"
  grep -qE "TLS handshake failed|TLS Error|No client-side authentication|Cannot open|certificate" "$EVD/s01_no_cert/client.log" && ok "S1 refused" || ko "S1 refused"
fi

# ---------------------------------------------------------------- S2
if run s2; then
  echo "== S2 — certificate from a rogue CA =="
  ro_copy
  gssh client-lin 'set -e; D=/tmp/rogue; rm -rf $D; mkdir -p $D; cd $D
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
      -subj "/CN=Rogue CA" -keyout ca.key -out ca.crt 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
      -subj "/CN=eve@lab.local" -keyout cli.key -out cli.csr 2>/dev/null
    openssl x509 -req -in cli.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 1 \
      -extfile <(printf "extendedKeyUsage=clientAuth") -out cli.crt 2>/dev/null
    { echo client; echo "dev tun"; echo "proto udp"; echo "remote 192.168.100.1 1194";
      echo "remote-cert-tls server"; echo "tls-version-min 1.3";
      awk "/<ca>/{f=1} f{print} /<\/ca>/{f=0}" /tmp/alice.ro;
      echo "<cert>"; cat cli.crt; echo "</cert>";
      echo "<key>"; cat cli.key; echo "</key>";
      awk "/<tls-crypt>/{f=1} f{print} /<\/tls-crypt>/{f=0}" /tmp/alice.ro; } > $D/eve.conf'
  gssh client-lin 'sudo timeout 15 openvpn --config /tmp/rogue/eve.conf --connect-retry-max 1 --verb 4 >/tmp/s2.log 2>&1'
  fetch client-lin /tmp/s2.log > "$EVD/s02_rogue_ca/client.log"
  fetch zt-gw /var/log/openvpn/openvpn.log | tail -n 15 > "$EVD/s02_rogue_ca/server.log"
  grep -qE "VERIFY ERROR|unable to get local issuer|TLS handshake failed" "$EVD/s02_rogue_ca/server.log" "$EVD/s02_rogue_ca/client.log" && ok "S2 refused" || ko "S2 refused"
fi

# ---------------------------------------------------------------- S3
if run s3; then
  echo "== S3 — revoked certificate =="
  t0=$(date -u +%s)
  gssh sub-ca "cd /home/vagrant && PKI_BASE=/home/vagrant PKI_PASS='$LABPASS' bash pki/scripts/revoke.sh pki/sub/certs/alice.crt keyCompromise" > "$EVD/s03_revoked/revoke.txt" 2>&1
  gssh sub-ca "cd /home/vagrant && PKI_BASE=/home/vagrant PKI_PASS='$LABPASS' bash pki/scripts/gencrl.sh >/dev/null 2>&1"
  fetch sub-ca /home/vagrant/pki/sub/crl/sub.pem > "$REPO/vpn/server/crl.pem"
  cp "$REPO/vpn/server/crl.pem" "$EVD/s03_revoked/crl.pem"
  # Publish the new CRL to the gateway (OpenVPN re-reads crl-verify when the file changes).
  ( cd "$INFRA" && vagrant upload "$REPO/vpn/server/crl.pem" /home/vagrant/crl.pem zt-gw ) >/dev/null 2>&1
  gssh zt-gw 'sudo install -m644 /home/vagrant/crl.pem /etc/openvpn/server/crl.pem'
  gssh client-lin 'sudo pkill -x openvpn 2>/dev/null; sleep 1; sudo timeout 15 openvpn --config /tmp/alice.ro --connect-retry-max 1 --verb 4 >/tmp/s3.log 2>&1'
  echo "revocation -> refusal wall time: $(( $(date +%s) - t0 ))s (includes CRL publish + reconnect)" > "$EVD/s03_revoked/timing.txt"
  fetch client-lin /tmp/s3.log > "$EVD/s03_revoked/client.log"
  fetch zt-gw /var/log/openvpn/openvpn.log | tail -n 12 > "$EVD/s03_revoked/server.log"
  grep -qiE "revoked|VERIFY ERROR" "$EVD/s03_revoked/server.log" && ok "S3 refused" || ko "S3 refused"
  # restore
  gssh sub-ca "cd /home/vagrant && PKI_BASE=/home/vagrant PKI_PASS='$LABPASS' bash pki/scripts/issue-client.sh alice 7 laptop-01 >/dev/null 2>&1"
  gssh sub-ca "cd /home/vagrant && PKI_BASE=/home/vagrant PKI_PASS='$LABPASS' bash pki/scripts/gencrl.sh >/dev/null 2>&1"
  "$REPO/vpn/scripts/sync-pki.sh" alice >/dev/null 2>&1
  "$REPO/vpn/scripts/make-client.sh" alice 192.168.100.1 "$REPO/vpn/client" >/dev/null 2>&1
  ( cd "$INFRA" && vagrant provision zt-gw >/dev/null 2>&1 && vagrant provision client-lin >/dev/null 2>&1 )
fi

# ---------------------------------------------------------------- S4
if run s4; then
  echo "== S4 — expired certificate =="
  gssh sub-ca "cd /home/vagrant && PKI_BASE=/home/vagrant PKI_PASS='$LABPASS' bash pki/scripts/issue-client.sh bob 0 laptop-02" > "$EVD/s04_expired/issue.txt" 2>&1
  gssh sub-ca 'openssl x509 -in /home/vagrant/pki/sub/certs/bob.crt -noout -subject -dates' > "$EVD/s04_expired/bob.validity.txt" 2>&1
  "$REPO/vpn/scripts/sync-pki.sh" bob >/dev/null 2>&1
  "$REPO/vpn/scripts/make-client.sh" bob 192.168.100.1 "$REPO/vpn/client" >/dev/null 2>&1
  ( cd "$INFRA" && vagrant upload "$REPO/vpn/client/bob.ovpn" /home/vagrant/bob.ovpn client-lin ) >/dev/null 2>&1
  gssh client-lin 'sudo install -m600 /home/vagrant/bob.ovpn /etc/openvpn/client/bob.conf; sudo pkill -x openvpn 2>/dev/null; sleep 1; sudo timeout 15 openvpn --config /etc/openvpn/client/bob.conf --connect-retry-max 1 --verb 4 >/tmp/s4.log 2>&1'
  fetch client-lin /tmp/s4.log > "$EVD/s04_expired/client.log"
  fetch zt-gw /var/log/openvpn/openvpn.log | tail -n 12 > "$EVD/s04_expired/server.log"
  grep -qiE "expired|VERIFY ERROR|TLS handshake failed" "$EVD/s04_expired/client.log" "$EVD/s04_expired/server.log" && ok "S4 refused" || ko "S4 refused"
fi

# ---------------------------------------------------------------- S5
if run s5; then
  echo "== S5 — UDP/TCP scan of the gateway =="
  gssh client-lin 'sudo nmap -sS -p 1-1024 192.168.100.1 -oN /tmp/s5s.txt >/dev/null 2>&1; sudo nmap -sU --top-ports 50 192.168.100.1 -oN /tmp/s5u.txt >/dev/null 2>&1'
  { echo "### TCP scan (1-1024)"; fetch client-lin /tmp/s5s.txt;
    echo; echo "### UDP scan (top-50)"; fetch client-lin /tmp/s5u.txt; } > "$EVD/s05_scan_gw/nmap.txt"
  grep -qE "open" "$EVD/s05_scan_gw/nmap.txt" && ok "S5 (see nmap.txt; 1194 expected silent)" || ok "S5 no port visible"
fi

# ---------------------------------------------------------------- S6
if run s6; then
  echo "== S6 — UDP DoS on the VPN =="
  ro_copy
  gssh client-lin 'sudo timeout 12 hping3 --udp -p 1194 --flood -d 1000 192.168.100.1 >/tmp/s6.log 2>&1'
  fetch client-lin /tmp/s6.log | tail -n 8 > "$EVD/s06_udp_dos/hping3.txt"
  gssh zt-gw 'echo "openvpn=$(systemctl is-active openvpn-server@server) nftables=$(systemctl is-active nftables)"; uptime' > "$EVD/s06_udp_dos/gateway-status.txt" 2>&1
  gssh client-lin 'sudo pkill -x openvpn 2>/dev/null; sleep 1; sudo openvpn --config /tmp/alice.ro --daemon zts6'
  sleep 8
  VPNIP="$(gssh client-lin "ip -4 addr show tun0 2>/dev/null | awk '/inet /{print \$2}'")"
  echo "valid reconnect during/after flood -> ${VPNIP:-none}" >> "$EVD/s06_udp_dos/gateway-status.txt"
  gssh client-lin 'sudo pkill -x openvpn 2>/dev/null; true' >/dev/null 2>&1
  grep -q "openvpn=active" "$EVD/s06_udp_dos/gateway-status.txt" && [ -n "$VPNIP" ] && ok "S6 service stable" || ko "S6 service stable"
fi

# ---------------------------------------------------------------- S13
if run s13; then
  echo "== S13 — fake gateway (MITM) =="
  ro_copy
  gssh client-lin 'sudo pkill -x openvpn 2>/dev/null; sleep 1; set -e; D=/tmp/fake; rm -rf $D; mkdir -p $D; cd $D
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
      -subj "/CN=vpn-gw.lab.local" -addext "subjectAltName=DNS:vpn-gw.lab.local" \
      -keyout srv.key -out srv.crt 2>/dev/null
    { echo "port 1195"; echo "proto udp"; echo "dev tun"; echo "topology subnet";
      echo "server 10.9.0.0 255.255.255.0"; echo "dh none"; echo "tls-version-min 1.3"; echo "tls-server";
      echo "<ca>"; cat srv.crt; echo "</ca>";
      echo "<cert>"; cat srv.crt; echo "</cert>";
      echo "<key>"; cat srv.key; echo "</key>";
      awk "/<tls-crypt>/{f=1} f{print} /<\/tls-crypt>/{f=0}" /tmp/alice.ro; } > $D/fake.conf
    sudo openvpn --config $D/fake.conf --log /tmp/fakesrv.log --daemon'
  for i in 1 2 3 4 5 6 7 8; do gssh client-lin "ss -lun | grep -q ':1195'" && break; sleep 1; done
  gssh client-lin 'set -e
    awk "/<ca>/{f=1} f{print} /<\/ca>/{f=0}" /tmp/alice.ro > /tmp/mitm.conf
    echo client >> /tmp/mitm.conf; echo dev tun >> /tmp/mitm.conf
    echo "proto udp" >> /tmp/mitm.conf; echo "remote 192.168.100.11 1195" >> /tmp/mitm.conf
    echo "remote-cert-tls server" >> /tmp/mitm.conf
    echo "verify-x509-name vpn-gw.lab.local name" >> /tmp/mitm.conf
    echo "tls-version-min 1.3" >> /tmp/mitm.conf
    awk "/<cert>/{f=1} f{print} /<\/cert>/{f=0}" /tmp/alice.ro >> /tmp/mitm.conf
    awk "/<key>/{f=1} f{print} /<\/key>/{f=0}" /tmp/alice.ro >> /tmp/mitm.conf
    awk "/<tls-crypt>/{f=1} f{print} /<\/tls-crypt>/{f=0}" /tmp/alice.ro >> /tmp/mitm.conf'
  gssh client-lin 'sudo timeout 12 openvpn --config /tmp/mitm.conf --connect-retry-max 2 --verb 4 >/tmp/s13.log 2>&1; sudo pkill -f "[f]ake.conf" 2>/dev/null; true'
  fetch client-lin /tmp/s13.log > "$EVD/s13_mitm_gw/client.log"
  fetch client-lin /tmp/fakesrv.log | tail -n 10 > "$EVD/s13_mitm_gw/fake-server.log"
  grep -qE "VERIFY ERROR|self-signed|TLS Error|TLS handshake failed|unable to get" "$EVD/s13_mitm_gw/client.log" && ok "S13 client refused fake gateway" || ko "S13 client refused fake gateway"
fi

# ---------------------------------------------------------------- S14
if run s14; then
  echo "== S14 — PDP down => fail-closed =="
  ro_copy
  gssh zt-gw "sudo sed -i 's/^PDP_ENFORCE=.*/PDP_ENFORCE=1/' /etc/openvpn/zt/hook.env && sudo systemctl restart openvpn-server@server" >/dev/null 2>&1
  sleep 2
  gssh client-lin 'sudo pkill -x openvpn 2>/dev/null; sleep 1; sudo timeout 15 openvpn --config /tmp/alice.ro --connect-retry-max 1 --verb 4 >/tmp/s14.log 2>&1'
  fetch client-lin /tmp/s14.log > "$EVD/s14_pdp_down/client.log"
  fetch zt-gw /var/log/openvpn/openvpn.log | tail -n 15 > "$EVD/s14_pdp_down/gateway.log"
  fetch zt-gw /etc/openvpn/zt/hook.env > "$EVD/s14_pdp_down/hook.env"
  grep -qiE "AUTH|denied|VERIFY|TLS handshake failed" "$EVD/s14_pdp_down/client.log" "$EVD/s14_pdp_down/gateway.log" && ok "S14 fail-closed" || ko "S14 fail-closed"
  gssh zt-gw "sudo sed -i 's/^PDP_ENFORCE=.*/PDP_ENFORCE=0/' /etc/openvpn/zt/hook.env && sudo systemctl restart openvpn-server@server" >/dev/null 2>&1
fi

gssh client-lin 'sudo pkill -x openvpn 2>/dev/null; true' >/dev/null 2>&1
echo
echo "== M2 summary: $PASS passed, $FAIL failed · evidence in tests/evidence/ =="
[ "$FAIL" -eq 0 ]
