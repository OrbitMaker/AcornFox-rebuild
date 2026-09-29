package contracts

import "testing"

func TestPublicDNSStatusVocabularyIsStable(t *testing.T) {
	values := []PublicDNSStatus{PublicDNSVerified, PublicDNSPending, PublicDNSNotFound, PublicDNSMismatch, PublicDNSTimeout, PublicDNSResolverError, PublicDNSConflict, PublicDNSUnknown}
	seen := map[PublicDNSStatus]struct{}{}
	for _, value := range values {
		if value == "" {
			t.Fatal("empty public DNS status")
		}
		if _, exists := seen[value]; exists {
			t.Fatalf("duplicate public DNS status %q", value)
		}
		seen[value] = struct{}{}
	}
}
