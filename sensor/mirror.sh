#!/usr/bin/env bash
# Traffic mirror for the sensor. VirtualBox has no switch port-mirroring, so we
# use tc `mirred` on the GATEWAY to copy packets from each zone interface to a
# dedicated mirror interface that the sensor listens on (promiscuous).
#
# Run ON zt-gw. Requires a mirror NIC on both gw and zt-sensor on a shared
# internal network "zt-mirror" (add at M4). SRC_IFACES = the zone NICs to tap.
#
#   usage: sudo SRC_IFACES="enp0s9 enp0s10 enp0s16 enp0s17" MIRROR_IF=enp0s18 ./mirror.sh
set -euo pipefail
SRC_IFACES="${SRC_IFACES:?set SRC_IFACES to the gateway zone interfaces}"
MIRROR_IF="${MIRROR_IF:?set MIRROR_IF to the interface facing the sensor}"

for IF in $SRC_IFACES; do
  echo "[*] mirroring $IF -> $MIRROR_IF"
  tc qdisc replace dev "$IF" ingress
  tc filter replace dev "$IF" parent ffff: protocol all u32 match u8 0 0 \
     action mirred egress mirror dev "$MIRROR_IF"
  # also mirror egress of the zone iface
  tc qdisc replace dev "$IF" handle 1: root prio
  tc filter replace dev "$IF" parent 1: protocol all u32 match u8 0 0 \
     action mirred egress mirror dev "$MIRROR_IF"
done
echo "[+] Mirror active. On zt-sensor, run Suricata/NFStream on $MIRROR_IF (promisc)."
