package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/open-card/open-card/internal/contracts"
	"github.com/open-card/open-card/internal/domain"
	secretprovider "github.com/open-card/open-card/internal/providers/secret"
)

func main() {
	root := flag.String("root", "", "encrypted secret root")
	material := flag.String("material-root", "", "temporary material root")
	key := flag.String("master-key", "", "master key file")
	id := flag.String("id", "", "secret reference id")
	name := flag.String("name", "", "BuildKit secret id")
	version := flag.String("version", "v1", "secret version")
	flag.Parse()
	if flag.NArg() != 0 || *root == "" || *material == "" || *key == "" || *id == "" || *name == "" {
		fatal("required bounded secret arguments are missing")
	}
	value, err := io.ReadAll(io.LimitReader(os.Stdin, (1<<20)+1))
	if err != nil || len(value) == 0 || len(value) > 1<<20 {
		fatal("secret stdin is empty or exceeds limit")
	}
	defer func() {
		for index := range value {
			value[index] = 0
		}
	}()
	if len(value) > 0 && value[len(value)-1] == '\n' {
		value = value[:len(value)-1]
	}
	provider, err := secretprovider.New(secretprovider.Config{Root: *root, MaterialRoot: *material, MasterKeyPath: *key, MaterialTTL: 2 * time.Minute})
	if err != nil {
		fatal("secret provider initialization failed")
	}
	reference := domain.SecretReference{ID: domain.ID(*id), Name: *name, Provider: "filesystem-secret", Version: *version}
	digest := sha256.Sum256(append([]byte(reference.ID.String()+"\x00"+reference.Name+"\x00"+reference.Version+"\x00"), value...))
	stored, err := provider.Store(context.Background(), contracts.SecretRequest{Reference: reference, Value: value, Operation: contracts.OperationContext{IdempotencyKey: "secretctl:" + hex.EncodeToString(digest[:])}})
	if err != nil {
		fatal("secret store failed")
	}
	if err := json.NewEncoder(os.Stdout).Encode(stored); err != nil {
		fatal("secret reference output failed")
	}
}

func fatal(message string) { _, _ = fmt.Fprintln(os.Stderr, message); os.Exit(1) }
