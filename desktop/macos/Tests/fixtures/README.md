`debian16-recover-finalize.json` is the exact successful JSON returned by the installed Debian beta.16 helper for `recover-finalize --pending` (exit 0). The main task captured it in `debian16-recover-finalize-observed.json`. It contains public release/evidence digests only.

This fixture proves the observed return shape, not a macOS installation. Its Debian binding is intentionally separate from the ARM candidate binding. Tests derive a matching surrounding contract from the fixture and do not pretend this is the Mac guest's receipt.

For the new `verify-prepared` consumer, tests reuse only this observed **receipt payload** under the independently tested new CLI envelope. The original fixture stays unchanged. This is not a claim that `verify-prepared` was run on that Debian guest. Native CLI parsing and the real Go dispatcher tests establish the new zero-argument, no-recovery entry contract.
