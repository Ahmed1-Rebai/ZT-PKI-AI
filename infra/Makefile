# ZT-PKI-AI — convenience targets. Run from infra/.
.PHONY: help tools core detection workloads client up provision ai mgmt-host isolate reconnect status halt destroy lint vpn vpn-check redteam abcd

help:
	@echo "tools       - install Vagrant + Ansible (Debian/Ubuntu host, needs sudo)"
	@echo "core        - bring up sub-ca, zt-gw, zt-pdp (M2/M3)"
	@echo "detection   - bring up zt-sensor, siem (M4/M6)   [AI runs on the host, not a VM]"
	@echo "workloads   - bring up web-proxy, web-app, db (M6)"
	@echo "client      - bring up client-lin"
	@echo "up          - bring up ALL VMs (~18 GB RAM; AI is on the host)"
	@echo "provision   - re-run Ansible on all running VMs"
	@echo "vpn         - M2: sync PKI, provision zt-gw, build alice.ovpn, provision client-lin"
	@echo "vpn-check   - M2: run the VPN/gateway verification checks"
	@echo "redteam     - M5/M7: run Red Team scenarios (S7-S12, S15-S17) from client-lin"
	@echo "abcd        - M7: run full A/B/C/D surface + attack benchmark from client-lin"
	@echo "ai          - configure the AI engine on THIS host (GPU), via Ansible --limit ai"
	@echo "mgmt-host   - set this host's mgmt IP to 10.10.99.2 on the host-only adapter"
	@echo "isolate     - detach NAT (eth0) from lab VMs for attack tests"
	@echo "reconnect   - re-attach NAT (eth0) to install packages"
	@echo "status / halt / destroy / lint"

tools:
	sudo apt-get update
	sudo apt-get install -y vagrant ansible
	vagrant plugin install vagrant-vbguest || true

core:        ; vagrant up sub-ca zt-gw zt-pdp
detection:   ; vagrant up zt-sensor siem
workloads:   ; vagrant up web-proxy web-app db
client:      ; vagrant up client-lin
up:          ; vagrant up
provision:   ; vagrant provision
ai:          ; cd ansible && ansible-playbook -i inventory.ini site.yml --limit ai -K

# M2 — VPN + gateway (docs/05). Builds the OpenVPN gateway + client profile.
vpn:         ; bash ../vpn/scripts/deploy.sh
vpn-check:   ; bash ../vpn/scripts/verify.sh
redteam:     ; bash ../tests/run-redteam.sh
abcd:        ; bash ../tests/abcd/run-all.sh && bash ../tests/abcd/attack-abcd.sh

# Give THIS host an address on the mgmt host-only network (AI node = 10.10.99.2).
# Finds the vboxnet backing 10.10.99.0/24 and assigns the host side .2.
mgmt-host:
	@net=$$(VBoxManage list hostonlyifs | awk '/^Name:/{n=$$2} /IPAddress:.*10\.10\.99/{print n}'); \
	if [ -z "$$net" ]; then echo "Bring up a mgmt VM first (make core), then re-run"; exit 1; fi; \
	echo "setting $$net host IP to 10.10.99.2"; \
	VBoxManage hostonlyif ipconfig $$net --ip 10.10.99.2 --netmask 255.255.255.0
status:      ; vagrant status
halt:        ; vagrant halt
destroy:     ; vagrant destroy -f

# Toggle Vagrant's NAT adapter (nic1) so lab VMs have no Internet during tests.
LABVMS = sub-ca zt-gw zt-pdp zt-sensor siem web-proxy web-app db client-lin
isolate:
	@for vm in $(LABVMS); do VBoxManage modifyvm $$vm --nic1 null 2>/dev/null && echo "isolated $$vm"; done
reconnect:
	@for vm in $(LABVMS); do VBoxManage modifyvm $$vm --nic1 nat 2>/dev/null && echo "reconnected $$vm"; done

lint:
	cd ansible && ansible-playbook --syntax-check site.yml
