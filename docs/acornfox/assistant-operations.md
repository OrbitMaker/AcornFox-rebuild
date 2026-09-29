# AcornFox assistant operations (Retired)

The built-in Pi assistant runtime has been retired in favor of external AI clients interacting with AcornFox CLI / API.

## Built-in Assistant Retirement Policy
- Fresh installations do not include the `acornfox-pi-worker` binary, systemd unit, or Pi runtime packages.
- On upgrades from previous versions (schema 1), existing active workers are stopped and disabled during the upgrade transaction, and their live systemd unit files are transactionally removed while leaving historical credentials and session data intact.
- Attempting to configure or enable the assistant via `acornfox-upgrade configure-assistant` returns `assistant_retired`.
- `disable-assistant` remains available as a safe cleanup operation to disable any lingering assistant state and restart server without activating models.

