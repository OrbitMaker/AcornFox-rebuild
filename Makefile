SHELL := /usr/bin/env bash
export KUBECONFIG ?= $(CURDIR)/artifacts/kubeconfig

.PHONY: help preflight provision kubernetes storage openkruise higress demo postgres monitoring drills install verify

help:
	@printf '%s\n' \
	  'make preflight   - verify hosts, capacity and local configuration' \
	  'make provision   - create/start the four isolated libvirt VMs' \
	  'make kubernetes  - install and verify the four-node k3s cluster' \
	  'make storage     - install and verify Open-Local' \
	  'make openkruise  - install and verify OpenKruise' \
	  'make higress     - install and verify Higress' \
	  'make demo        - install and verify the three-replica demo' \
	  'make postgres    - install and verify CloudNativePG' \
	  'make monitoring  - install and verify Prometheus/Grafana' \
	  'make drills      - run the bounded failure drills' \
	  'make install     - run the complete ordered PoC install'

preflight:
	./scripts/00-preflight.sh

provision: preflight
	./scripts/01-provision-vms.sh

kubernetes: provision
	./scripts/02-install-k3s.sh
	./scripts/verify-k8s.sh

storage:
	./scripts/03-install-storage.sh
	./scripts/verify-storage.sh

openkruise:
	./scripts/04-install-openkruise.sh
	./scripts/verify-openkruise.sh

higress:
	./scripts/05-install-higress.sh
	./scripts/verify-higress.sh

demo:
	./scripts/06-install-demo.sh
	./scripts/verify-demo.sh

postgres:
	./scripts/07-install-postgres.sh
	./scripts/verify-postgres.sh

monitoring:
	./scripts/08-install-monitoring.sh
	./scripts/verify-monitoring.sh

drills:
	./scripts/drill-demo-pod.sh
	./scripts/drill-postgres-primary.sh

install: kubernetes storage openkruise higress demo postgres monitoring drills

verify:
	./scripts/verify-k8s.sh
	./scripts/verify-storage.sh
	./scripts/verify-openkruise.sh
	./scripts/verify-higress.sh
	./scripts/verify-demo.sh
	./scripts/verify-postgres.sh
	./scripts/verify-monitoring.sh
