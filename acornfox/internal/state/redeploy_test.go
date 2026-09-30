package state

import (
	"context"
	"testing"
)

func TestRedeployBypassesDigestButKeepsRequestIdempotency(t *testing.T) {
	ctx := context.Background()
	s := openAddonStore(t)
	if _, _, err := s.EnsureApp(ctx, "shop"); err != nil {
		t.Fatal(err)
	}
	in := NewDeployment{App: "shop", SourceKind: SourceImage, SourceRef: "test:image", SourceDigest: "same-image"}
	first, created, err := s.CreateDeployment(ctx, in)
	if err != nil || !created {
		t.Fatalf("first deployment: created=%v err=%v", created, err)
	}
	duplicate, created, err := s.CreateDeployment(ctx, in)
	if err != nil || created || duplicate.ID != first.ID {
		t.Fatalf("normal digest dedup: created=%v err=%v", created, err)
	}
	in.BypassDedup = true
	in.RequestKey = "redeploy-first"
	redeploy, created, err := s.CreateDeployment(ctx, in)
	if err != nil || !created || redeploy.ID == first.ID {
		t.Fatalf("explicit redeploy: created=%v err=%v", created, err)
	}
	duplicate, created, err = s.CreateDeployment(ctx, in)
	if err != nil || created || duplicate.ID != redeploy.ID {
		t.Fatalf("redeploy request retry: created=%v err=%v", created, err)
	}
	in.RequestKey = "redeploy-next"
	next, created, err := s.CreateDeployment(ctx, in)
	if err != nil || !created || next.ID == redeploy.ID {
		t.Fatalf("second explicit redeploy: created=%v err=%v", created, err)
	}
	list, err := s.ListDeployments(ctx, "shop", 10)
	if err != nil || len(list) != 3 {
		t.Fatalf("redeploy count=%d err=%v", len(list), err)
	}
}
