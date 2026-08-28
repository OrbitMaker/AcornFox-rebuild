// open-card-dns-dry-run is an operator-side, offline planner. It reads JSON
// fixtures and emits a dry-run; it contains no provider transport or write API.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/open-card/open-card/internal/dnschange"
)

func main() {
	desiredPath := flag.String("desired", "", "desired-record JSON file")
	observedPath := flag.String("observed", "", "observed-record JSON file")
	ownedPath := flag.String("owned", "", "owned-record JSON file")
	key := flag.String("idempotency-key", "", "dry-run idempotency key")
	flag.Parse()
	if *desiredPath == "" || *observedPath == "" || *ownedPath == "" || *key == "" {
		fmt.Fprintln(os.Stderr, "--desired, --observed, --owned, and --idempotency-key are required")
		os.Exit(2)
	}
	var desired []dnschange.DesiredRecord
	var observed []dnschange.Record
	var owned []dnschange.OwnedRecord
	if err := readJSON(*desiredPath, &desired); err != nil {
		fail(err)
	}
	if err := readJSON(*observedPath, &observed); err != nil {
		fail(err)
	}
	if err := readJSON(*ownedPath, &owned); err != nil {
		fail(err)
	}
	plan, err := dnschange.BuildDryRun(*key, desired, observed, owned, time.Now().UTC())
	if err != nil {
		fail(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(plan); err != nil {
		fail(err)
	}
}
func readJSON(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}
func fail(err error) { fmt.Fprintln(os.Stderr, "dry-run:", err); os.Exit(1) }
