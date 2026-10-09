package state

import (
	"context"
	"testing"
)

func TestCreateDeploymentRecordsOrigin(t *testing.T) {
	ctx := context.Background()
	s := openAddonStore(t)
	if _, _, err := s.EnsureApp(ctx, "shop"); err != nil {
		t.Fatal(err)
	}
	fresh, _, err := s.CreateDeployment(ctx, NewDeployment{App: "shop", SourceKind: SourceUpload, SourceRef: "/u/1", SourceDigest: "aaa"})
	if err != nil {
		t.Fatal(err)
	}
	if fresh.BasedOnSeq != 0 || fresh.OriginKind != "" || fresh.Reason != "" {
		t.Fatalf("fresh deployment carries origin fields: %+v", fresh)
	}
	re, _, err := s.CreateDeployment(ctx, NewDeployment{
		App: "shop", SourceKind: SourceImage, SourceRef: "sha256:x", SourceDigest: "sha256:x", BypassDedup: true,
		BasedOnSeq: fresh.Seq, OriginKind: SourceUpload, Reason: ReasonAddonAdd + ":postgres",
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetDeployment(ctx, re.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.BasedOnSeq != fresh.Seq || got.OriginKind != SourceUpload || got.Reason != "addon_add:postgres" {
		t.Fatalf("stored origin = %d %q %q", got.BasedOnSeq, got.OriginKind, got.Reason)
	}
	// The column constraint rejects unknown origin kinds.
	if _, _, err := s.CreateDeployment(ctx, NewDeployment{
		App: "shop", SourceKind: SourceImage, SourceRef: "sha256:y", SourceDigest: "sha256:y", BypassDedup: true, OriginKind: "ftp",
	}); err == nil {
		t.Fatal("unknown origin kind was accepted")
	}
}

func TestBackfillDeploymentOrigin(t *testing.T) {
	ctx := context.Background()
	s := openAddonStore(t)
	for _, app := range []string{"shop", "nginx"} {
		if _, _, err := s.EnsureApp(ctx, app); err != nil {
			t.Fatal(err)
		}
	}
	mk := func(in NewDeployment, image string) Deployment {
		d, _, err := s.CreateDeployment(ctx, in)
		if err != nil {
			t.Fatal(err)
		}
		if image != "" {
			if _, err := s.UpdateDeployment(ctx, d.ID, func(x *Deployment) error { x.ImageID = image; return nil }); err != nil {
				t.Fatal(err)
			}
		}
		return d
	}
	// shop: built from an upload, then redeployed before origin was recorded,
	// then redeployed again inheriting the wrong "image" origin.
	mk(NewDeployment{App: "shop", SourceKind: SourceUpload, SourceRef: "/u", SourceDigest: "aaa"}, "sha256:built")
	old := mk(NewDeployment{App: "shop", SourceKind: SourceImage, SourceRef: "sha256:built", SourceDigest: "sha256:built", BypassDedup: true}, "sha256:built")
	inherited := mk(NewDeployment{App: "shop", SourceKind: SourceImage, SourceRef: "sha256:built", SourceDigest: "sha256:built", BypassDedup: true,
		OriginKind: SourceImage, BasedOnSeq: old.Seq, Reason: ReasonRedeploy}, "sha256:built")
	// nginx: deployed straight from an image; must stay "image".
	direct := mk(NewDeployment{App: "nginx", SourceKind: SourceImage, SourceRef: "nginx:1.27", SourceDigest: "nginx:1.27"}, "sha256:nginx")

	if _, err := s.db.ExecContext(ctx, migration0007); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		id, want string
	}{{old.ID, SourceUpload}, {inherited.ID, SourceUpload}, {direct.ID, ""}} {
		got, err := s.GetDeployment(ctx, c.id)
		if err != nil {
			t.Fatal(err)
		}
		if got.OriginKind != c.want {
			t.Fatalf("deployment %s origin = %q, want %q", c.id, got.OriginKind, c.want)
		}
	}
}

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
