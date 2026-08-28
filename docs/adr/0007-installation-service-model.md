# ADR-0007: Ubuntu 24.04 amd64 systemd installation target

- Status: Accepted; clean Ubuntu 24.04 amd64 Spike passed
- Gate: G7 / S5

The first supported installation target is Ubuntu 24.04 amd64. Package the
server, Agent, Caddy and BuildKit as separate systemd units; treat Docker Engine
as an external preflight dependency and embed the built web assets in the
server. Linux arm64 binaries are built but do not become an installation target
until a clean-host test passes.

The release manifest, checksum verification, directory contract, systemd units,
offline install, atomic N-1 upgrade, failed-health rollback, preserve-by-default
uninstall and checksum-verified backup/restore fixture are implemented. The
task-scoped user-space lifecycle passed on the physical development host without
activating systemd or changing host state.

An authorized task-owned clean VM completed offline installation, four-unit
activation, service restart, guest reboot/autostart, three N-1/N upgrade rounds,
injected migration failure rollback, PostgreSQL dump/restore and
preserve-by-default uninstall. The VM and every task libvirt/bundle resource
were then deleted. This closes the G7/S5 Spike for Ubuntu 24.04 amd64; it does
not by itself complete the M7 release-candidate matrix.
