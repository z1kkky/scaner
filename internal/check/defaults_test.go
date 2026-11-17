package check

import "testing"

func TestNewDefaultChecksUsesSameCategoriesForBothPolicies(t *testing.T) {
	normal := NewDefaultChecks(DefaultChecksOptions{})
	guarded := NewDefaultChecks(DefaultChecksOptions{PublicTargetsOnly: true})
	want := []string{"headers", "email"}
	for _, checks := range [][]Check{normal, guarded} {
		if len(checks) != len(want) {
			t.Fatalf("got %d default checks, want %d", len(checks), len(want))
		}
		for i, c := range checks {
			if got := c.Name(); got != want[i] {
				t.Errorf("check[%d] = %q, want %q", i, got, want[i])
			}
		}
	}
	if got := normal[0].(*HeadersCheck).Client; got != nil {
		t.Fatal("normal configuration unexpectedly replaced the CLI HTTP client")
	}
	if got := guarded[0].(*HeadersCheck).Client; got == nil || got.Transport == nil {
		t.Fatal("public-target policy did not configure guarded HTTP transport")
	}
	if normal[0] == guarded[0] || normal[1] == guarded[1] {
		t.Fatal("default checks must be fresh instances")
	}
}
