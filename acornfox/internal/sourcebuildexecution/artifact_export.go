package sourcebuildexecution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strconv"
	"time"

	appcontracts "github.com/acornfox/acornfox/internal/application/contracts"
	"github.com/acornfox/acornfox/internal/contracts"
	"github.com/acornfox/acornfox/internal/packprotocol"
	imageprovider "github.com/acornfox/acornfox/internal/providers/image"
)

var ErrBuiltOCI = errors.New("source-built OCI handoff was not verified")

func validBuiltFact(f appcontracts.SourceBuiltArtifactFact) bool {
	return !f.AdminID.Empty() && !f.ApplicationID.Empty() && !f.EnvironmentID.Empty() && !f.BuildIntentID.Empty() && !f.BuildID.Empty() && !f.SourceRevisionID.Empty() && !f.BuildPlanID.Empty() && !f.ArtifactID.Empty() && f.Image.Validate() == nil && f.StorageRef != "" && contracts.IsSHA256Digest(f.ArchiveSHA256) && f.SizeBytes > 0
}

type contextArchiveReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextArchiveReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// Source role exposes only the original Core-owned image identity, never a
// source-selected file path. NewExecutionServer already verifies exact Core peer.
func serveBuiltOCI(w http.ResponseWriter, r *http.Request, store contracts.ImageStore) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	rc := http.NewResponseController(w)
	if err := rc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, packprotocol.MaxProtocolMessageBytes+1))
	if clearErr := rc.SetReadDeadline(time.Time{}); clearErr != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	var fact appcontracts.SourceBuiltArtifactFact
	if err != nil || strictMessage(body, &fact) != nil || !validBuiltFact(fact) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	op := contracts.OperationContext{IdempotencyKey: "source-export:" + fact.ArtifactID.String(), Actor: "core-source-built-handoff"}
	reader, result, err := store.OpenOCI(r.Context(), fact.Image, op)
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if result.Image.Repository != fact.Image.Repository || result.Image.Digest != fact.Image.Digest || result.StorageRef != fact.StorageRef || result.SizeBytes != fact.SizeBytes || result.Evidence.Digest != fact.ArchiveSHA256 {
		reader.Close()
		w.WriteHeader(http.StatusConflict)
		return
	}
	seeker, ok := reader.(io.ReadSeeker)
	if !ok {
		reader.Close()
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	identity, err := imageprovider.InspectOCI(r.Context(), seeker, fact.Image.Digest, fact.SizeBytes)
	if err != nil || identity.ArchiveSize != result.SizeBytes {
		reader.Close()
		w.WriteHeader(http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/vnd.oci.image.layout.v1.tar")
	w.Header().Set("X-AcornFox-Archive-SHA256", result.Evidence.Digest)
	w.Header().Set("X-AcornFox-Archive-Size", strconv.FormatInt(result.SizeBytes, 10))
	w.Header().Set("X-AcornFox-Manifest-Digest", identity.ManifestDigest)
	w.Header().Set("X-AcornFox-Config-Digest", identity.ConfigDigest)
	w.Header().Set("X-AcornFox-OCI-OS", identity.OS)
	w.Header().Set("X-AcornFox-OCI-Architecture", identity.Architecture)
	w.Header().Set("X-AcornFox-Storage-Ref", result.StorageRef)
	w.Header().Set("Trailer", "X-AcornFox-Archive-Complete")
	w.WriteHeader(http.StatusOK)
	written, copyErr := io.CopyN(w, contextArchiveReader{ctx: r.Context(), reader: reader}, result.SizeBytes)
	closeErr := reader.Close()
	if copyErr == nil && closeErr == nil && r.Context().Err() == nil && written == result.SizeBytes {
		w.Header().Set("X-AcornFox-Archive-Complete", "true")
	}
}

type BuiltOCIReader struct {
	response  *http.Response
	remaining int64
	hasher    hash.Hash
	expected  string
	verified  bool
	identity  imageprovider.OCIIdentity
}

func (r *BuiltOCIReader) Read(p []byte) (int, error) {
	if r == nil || r.response == nil {
		return 0, ErrBuiltOCI
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.remaining > 0 {
		if int64(len(p)) > r.remaining {
			p = p[:r.remaining]
		}
		n, err := r.response.Body.Read(p)
		if n > 0 {
			r.hasher.Write(p[:n])
			r.remaining -= int64(n)
		}
		if err == io.EOF {
			if r.remaining > 0 {
				return n, io.ErrUnexpectedEOF
			}
			if "sha256:"+hex.EncodeToString(r.hasher.Sum(nil)) != r.expected || r.response.Trailer.Get("X-AcornFox-Archive-Complete") != "true" {
				return n, ErrBuiltOCI
			}
			r.verified = true
		}
		return n, err
	}
	var probe [1]byte
	n, err := r.response.Body.Read(probe[:])
	if n > 0 || err != io.EOF {
		return 0, ErrBuiltOCI
	}
	actual := "sha256:" + hex.EncodeToString(r.hasher.Sum(nil))
	if actual != r.expected || r.response.Trailer.Get("X-AcornFox-Archive-Complete") != "true" {
		return 0, ErrBuiltOCI
	}
	r.verified = true
	return 0, io.EOF
}
func (r *BuiltOCIReader) Close() error {
	if r == nil || r.response == nil {
		return ErrBuiltOCI
	}
	err := r.response.Body.Close()
	if err != nil {
		return err
	}
	if !r.verified {
		return ErrBuiltOCI
	}
	return nil
}
func (c *Client) OpenBuiltOCI(ctx context.Context, fact appcontracts.SourceBuiltArtifactFact) (*BuiltOCIReader, error) {
	if c == nil || !validBuiltFact(fact) {
		return nil, ErrBuiltOCI
	}
	payload, err := json.Marshal(fact)
	if err != nil || len(payload) > packprotocol.MaxProtocolMessageBytes {
		return nil, ErrBuiltOCI
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://unix/v1/source-build/open-oci", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := c.http.DoStream(req, fact.SizeBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: source role stream unavailable: %v", ErrBuiltOCI, err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("X-AcornFox-Archive-SHA256") != fact.ArchiveSHA256 || response.Header.Get("X-AcornFox-Archive-Size") != strconv.FormatInt(fact.SizeBytes, 10) || response.Header.Get("X-AcornFox-Manifest-Digest") != fact.Image.Digest || response.Header.Get("X-AcornFox-Storage-Ref") != fact.StorageRef || !contracts.IsSHA256Digest(response.Header.Get("X-AcornFox-Config-Digest")) || response.Header.Get("X-AcornFox-OCI-OS") != "linux" || response.Header.Get("X-AcornFox-OCI-Architecture") != "amd64" {
		response.Body.Close()
		return nil, ErrBuiltOCI
	}
	identity := imageprovider.OCIIdentity{ArchiveSize: fact.SizeBytes, ManifestDigest: fact.Image.Digest, ConfigDigest: response.Header.Get("X-AcornFox-Config-Digest"), OS: "linux", Architecture: "amd64"}
	return &BuiltOCIReader{response: response, remaining: fact.SizeBytes, expected: fact.ArchiveSHA256, hasher: sha256.New(), identity: identity}, nil
}

func (r *BuiltOCIReader) Identity() imageprovider.OCIIdentity {
	if r == nil {
		return imageprovider.OCIIdentity{}
	}
	return r.identity
}
