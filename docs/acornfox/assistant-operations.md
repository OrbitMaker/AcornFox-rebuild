# AcornFox assistant operations

The Pi assistant is optional. A fresh host installs its account, files, and
systemd unit, but leaves `acornfox-pi-worker.service` disabled and inactive
until a root operator configures a DeepSeek key.

Configure it with a root-owned, single-link key file whose mode is `0400` or
`0600`:

```text
/opt/acornfox/upgrade-tools/acornfox-upgrade configure-assistant --deepseek-key-file /root/deepseek-key
```

The command copies the key into the protected AcornFox configuration, starts
and verifies the worker, then restarts `acornfox-server.service` so the console
composes the assistant and its protected tool socket. This restarts the
control-plane console service only; it does not restart application containers.

Disable it with:

```text
/opt/acornfox/upgrade-tools/acornfox-upgrade disable-assistant
```

Disable stops and disables the worker, keeps the protected model
configuration, and restarts `acornfox-server.service` so the console reports
the assistant as unavailable. Re-running `configure-assistant` enables it
again.
