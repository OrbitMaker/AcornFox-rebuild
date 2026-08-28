package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/open-card/open-card/internal/providers/imagegc"
)

type snapshot struct {
	Releases []imagegc.ReleaseRecord `json:"releases"`
	Builds   []imagegc.BuildRecord   `json:"builds"`
}

func (s snapshot) ListGCReleases(context.Context) ([]imagegc.ReleaseRecord, error) {
	return append([]imagegc.ReleaseRecord(nil), s.Releases...), nil
}
func (s snapshot) ListGCBuilds(context.Context) ([]imagegc.BuildRecord, error) {
	return append([]imagegc.BuildRecord(nil), s.Builds...), nil
}

type output struct {
	Before []imagegc.Resource     `json:"before"`
	Plan   imagegc.Plan           `json:"plan"`
	Result *imagegc.CollectResult `json:"result,omitempty"`
	After  []imagegc.Resource     `json:"after"`
}

func main() {
	var taskPrefix, diskPath, snapshotPath, confirmation string
	var execute bool
	flag.StringVar(&taskPrefix, "task-prefix", "", "exact Open Card task resource prefix")
	flag.StringVar(&diskPath, "disk-path", "/var/lib/docker", "filesystem used for capacity watermarks")
	flag.StringVar(&snapshotPath, "snapshot", "", "read-only Release/Build protection snapshot JSON")
	flag.BoolVar(&execute, "execute", false, "delete eligible image digests")
	flag.StringVar(&confirmation, "confirmation", "", "exact execution confirmation phrase")
	flag.Parse()
	if flag.NArg() != 0 || snapshotPath == "" || (execute && confirmation != "collect-task-images:"+taskPrefix) {
		fatal(errors.New("exact task prefix, snapshot and execution confirmation are required"))
	}
	data, err := os.ReadFile(snapshotPath)
	if err != nil {
		fatal(errors.New("image GC snapshot is unavailable"))
	}
	var state snapshot
	decoderErr := json.Unmarshal(data, &state)
	for index := range data {
		data[index] = 0
	}
	if decoderErr != nil {
		fatal(errors.New("image GC snapshot is invalid"))
	}
	inventory, err := imagegc.NewDockerInventory(imagegc.DockerConfig{TaskPrefix: taskPrefix, DiskPath: diskPath, Snapshot: state, Timeout: 2 * time.Minute})
	if err != nil {
		fatal(err)
	}
	provider, err := imagegc.New(imagegc.DefaultConfig(), inventory, inventory)
	if err != nil {
		fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	before, err := inventory.ListResources(ctx)
	if err != nil {
		fatal(err)
	}
	plan, err := provider.Plan(ctx)
	if err != nil {
		fatal(err)
	}
	value := output{Before: before, Plan: plan}
	if execute {
		result, collectErr := provider.Collect(ctx)
		value.Result = &result
		if collectErr != nil {
			fatalJSON(value, collectErr)
		}
	}
	value.After, err = inventory.ListResources(ctx)
	if err != nil {
		fatalJSON(value, err)
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fatal(err)
	}
	fmt.Println(string(encoded))
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func fatalJSON(value output, err error) {
	encoded, _ := json.Marshal(value)
	fmt.Println(string(encoded))
	fatal(err)
}
