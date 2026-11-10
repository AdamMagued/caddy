package httpcaddyfile

import (
	"slices"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

func TestAutomationPolicyIsSubset(t *testing.T) {
	for i, test := range []struct {
		a, b   []string
		expect bool
	}{
		{
			a:      []string{"example.com"},
			b:      []string{},
			expect: true,
		},
		{
			a:      []string{},
			b:      []string{"example.com"},
			expect: false,
		},
		{
			a:      []string{"foo.example.com"},
			b:      []string{"*.example.com"},
			expect: true,
		},
		{
			a:      []string{"foo.example.com"},
			b:      []string{"foo.example.com"},
			expect: true,
		},
		{
			a:      []string{"foo.example.com"},
			b:      []string{"example.com"},
			expect: false,
		},
		{
			a:      []string{"example.com", "foo.example.com"},
			b:      []string{"*.com", "*.*.com"},
			expect: true,
		},
		{
			a:      []string{"example.com", "foo.example.com"},
			b:      []string{"*.com"},
			expect: false,
		},
	} {
		apA := &caddytls.AutomationPolicy{SubjectsRaw: test.a}
		apB := &caddytls.AutomationPolicy{SubjectsRaw: test.b}
		if actual := automationPolicyIsSubset(apA, apB); actual != test.expect {
			t.Errorf("Test %d: Expected %t but got %t (A: %v  B: %v)", i, test.expect, actual, test.a, test.b)
		}
	}
}

func TestAutomationPoliciesAllowSameHostOnDifferentPorts(t *testing.T) {
	input := `https://example.com:5000 localhost:5000 {
	respond "one"
}

https://example.net localhost:8080 {
	respond "two"
}
`

	adapter := caddyfile.Adapter{ServerType: ServerType{}}
	_, _, err := adapter.Adapt([]byte(input), nil)
	if err != nil {
		t.Fatalf("adapting Caddyfile: %v", err)
	}
}

func TestConsolidateAutomationPoliciesSpecificity(t *testing.T) {
	t.Run("wildcard before specific sorted by specificity", func(t *testing.T) {
		pWildcard := &caddytls.AutomationPolicy{
			SubjectsRaw: []string{"*.example.com", "other.com", "third.com"},
			KeyType:     "rsa2048",
		}
		pSpecific := &caddytls.AutomationPolicy{
			SubjectsRaw: []string{"foo.example.com", "e.com"},
			KeyType:     "ed25519",
		}

		res, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{pWildcard, pSpecific})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res) != 2 {
			t.Fatalf("expected 2 policies, got %d", len(res))
		}
		if res[0] != pSpecific {
			t.Errorf("expected specific policy at index 0, got %v", res[0].SubjectsRaw)
		}
		if res[1] != pWildcard {
			t.Errorf("expected wildcard policy at index 1, got %v", res[1].SubjectsRaw)
		}
	})

	t.Run("merge-equivalent crossed policies consolidate without error", func(t *testing.T) {
		t.Run("empty policies", func(t *testing.T) {
			p1 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"foo.example.com", "*.other.com"}}
			p2 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"*.example.com", "bar.other.com"}}

			res, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{p1, p2})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// Empty policies are cleaned up by auto-HTTPS
			if res != nil {
				t.Fatalf("expected nil for all-empty policies, got %v", res)
			}
		})

		t.Run("configured policies", func(t *testing.T) {
			p1 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"foo.example.com", "*.other.com"}, KeyType: "rsa2048"}
			p2 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"*.example.com", "bar.other.com"}, KeyType: "rsa2048"}

			res, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{p1, p2})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(res) != 1 {
				t.Fatalf("expected 1 consolidated policy, got %d", len(res))
			}
			if res[0].KeyType != "rsa2048" {
				t.Errorf("expected KeyType rsa2048, got %s", res[0].KeyType)
			}
			expectedSubjs := []string{"foo.example.com", "*.other.com", "*.example.com", "bar.other.com"}
			for _, exp := range expectedSubjs {
				if !slices.Contains(res[0].SubjectsRaw, exp) {
					t.Errorf("expected subject %s in consolidated policy, got %v", exp, res[0].SubjectsRaw)
				}
			}
		})
	})

	t.Run("bidirectional conflict with different configurations returns error", func(t *testing.T) {
		p1 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"foo.example.com", "*.other.com"}, KeyType: "rsa2048"}
		p2 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"*.example.com", "bar.other.com"}, KeyType: "ed25519"}

		_, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{p1, p2})
		if err == nil {
			t.Fatalf("expected error for conflicting policies with different configurations, got nil")
		}
	})

	t.Run("merge-equivalent crossed policies that shadow intermediate policy returns error", func(t *testing.T) {
		p1 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"foo.example.com", "*.other.com"}, KeyType: "rsa2048"}
		p2 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"baz.example.com"}, KeyType: "ed25519"}
		p3 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"*.example.com", "bar.other.com"}, KeyType: "rsa2048"}

		_, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{p1, p2, p3})
		if err == nil {
			t.Fatalf("expected error when merge would shadow intermediate policy, got nil")
		}
	})

	t.Run("disjoint policies maintain declaration order", func(t *testing.T) {
		p1 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"alpha.example.com"}, KeyType: "ed25519"}
		p2 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"beta.example.org"}, KeyType: "rsa2048"}
		p3 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"gamma.example.net"}, KeyType: "rsa4096"}

		res, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{p1, p2, p3})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res) != 3 || res[0] != p1 || res[1] != p2 || res[2] != p3 {
			t.Fatalf("expected order [p1, p2, p3], got %v", res)
		}

		resRev, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{p3, p2, p1})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resRev) != 3 || resRev[0] != p3 || resRev[1] != p2 || resRev[2] != p1 {
			t.Fatalf("expected order [p3, p2, p1], got %v", resRev)
		}
	})

	t.Run("disjoint interleaved with specific and wildcard", func(t *testing.T) {
		pWildcard := &caddytls.AutomationPolicy{SubjectsRaw: []string{"*.example.com"}, KeyType: "rsa2048"}
		pDisjoint1 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"unrelated.org"}, KeyType: "ed25519"}
		pSpecific := &caddytls.AutomationPolicy{SubjectsRaw: []string{"foo.example.com"}, KeyType: "rsa4096"}
		pDisjoint2 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"another.net"}, KeyType: "p256"}

		res, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{pWildcard, pDisjoint1, pSpecific, pDisjoint2})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res) != 4 {
			t.Fatalf("expected 4 policies, got %d", len(res))
		}
		if res[0] != pDisjoint1 || res[1] != pSpecific || res[2] != pWildcard || res[3] != pDisjoint2 {
			t.Fatalf("expected [pDisjoint1, pSpecific, pWildcard, pDisjoint2], got %v", res)
		}
	})

	t.Run("exact wildcard catchall specificity hierarchy", func(t *testing.T) {
		pCatchAll := &caddytls.AutomationPolicy{SubjectsRaw: nil, KeyType: "p256"}
		pWildcard := &caddytls.AutomationPolicy{SubjectsRaw: []string{"*.example.com"}, KeyType: "rsa2048"}
		pExact := &caddytls.AutomationPolicy{SubjectsRaw: []string{"foo.example.com"}, KeyType: "ed25519"}

		res, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{pCatchAll, pWildcard, pExact})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res) != 3 {
			t.Fatalf("expected 3 policies, got %d", len(res))
		}
		if res[0] != pExact || res[1] != pWildcard || res[2] != pCatchAll {
			t.Fatalf("expected [pExact, pWildcard, pCatchAll], got %v", res)
		}
	})

	t.Run("partial overlaps with disjoint elements", func(t *testing.T) {
		pWildcard := &caddytls.AutomationPolicy{SubjectsRaw: []string{"*.a.com", "shared-disjoint.org"}, KeyType: "rsa2048"}
		pExact := &caddytls.AutomationPolicy{SubjectsRaw: []string{"sub.a.com", "other-disjoint.org"}, KeyType: "ed25519"}
		pUnrelated := &caddytls.AutomationPolicy{SubjectsRaw: []string{"completely-unrelated.com"}, KeyType: "p384"}

		res, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{pWildcard, pExact, pUnrelated})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res) != 3 {
			t.Fatalf("expected 3 policies, got %d", len(res))
		}
		if res[0] != pExact || res[1] != pWildcard || res[2] != pUnrelated {
			t.Fatalf("expected [pExact, pWildcard, pUnrelated], got %v", res)
		}
	})

	t.Run("cyclic dependency among three merge-equivalent policies consolidates without error", func(t *testing.T) {
		pA := &caddytls.AutomationPolicy{SubjectsRaw: []string{"sub.a.com", "*.c.com"}, KeyType: "rsa2048"}
		pB := &caddytls.AutomationPolicy{SubjectsRaw: []string{"sub.b.com", "*.a.com"}, KeyType: "rsa2048"}
		pC := &caddytls.AutomationPolicy{SubjectsRaw: []string{"sub.c.com", "*.b.com"}, KeyType: "rsa2048"}

		res, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{pA, pB, pC})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res) != 1 {
			t.Fatalf("expected 1 consolidated policy, got %d", len(res))
		}
		if res[0].KeyType != "rsa2048" {
			t.Errorf("expected KeyType rsa2048, got %s", res[0].KeyType)
		}
		expectedSubjs := []string{"sub.a.com", "*.c.com", "sub.b.com", "*.a.com", "sub.c.com", "*.b.com"}
		for _, exp := range expectedSubjs {
			if !slices.Contains(res[0].SubjectsRaw, exp) {
				t.Errorf("expected subject %s in consolidated policy, got %v", exp, res[0].SubjectsRaw)
			}
		}
	})

	t.Run("cyclic dependency among three policies with different configurations returns error", func(t *testing.T) {
		pA := &caddytls.AutomationPolicy{SubjectsRaw: []string{"sub.a.com", "*.c.com"}, KeyType: "rsa2048"}
		pB := &caddytls.AutomationPolicy{SubjectsRaw: []string{"sub.b.com", "*.a.com"}, KeyType: "ed25519"}
		pC := &caddytls.AutomationPolicy{SubjectsRaw: []string{"sub.c.com", "*.b.com"}, KeyType: "p256"}

		_, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{pA, pB, pC})
		if err == nil {
			t.Fatalf("expected error for cyclic specificity dependency, got nil")
		}
	})

	t.Run("deterministic ordering across repeated runs", func(t *testing.T) {
		for i := 0; i < 50; i++ {
			p1 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"*.example.com"}, KeyType: "rsa2048"}
			p2 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"unrelated.org"}, KeyType: "ed25519"}
			p3 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"foo.example.com"}, KeyType: "rsa4096"}
			p4 := &caddytls.AutomationPolicy{SubjectsRaw: []string{"another.net"}, KeyType: "p256"}

			res, err := consolidateAutomationPolicies([]*caddytls.AutomationPolicy{p1, p2, p3, p4})
			if err != nil {
				t.Fatalf("run %d: unexpected error: %v", i, err)
			}
			if len(res) != 4 || res[0] != p2 || res[1] != p3 || res[2] != p1 || res[3] != p4 {
				t.Fatalf("run %d: nondeterministic result: %v", i, res)
			}
		}
	})
}

func TestConsolidateAutomationPoliciesCaddyfileAdapt(t *testing.T) {
	t.Run("merge-equivalent crossed site blocks adapt cleanly", func(t *testing.T) {
		input := `foo.example.com, *.other.com {
	tls {
		key_type rsa2048
	}
}

*.example.com, bar.other.com {
	tls {
		key_type rsa2048
	}
}
`
		adapter := caddyfile.Adapter{ServerType: ServerType{}}
		_, _, err := adapter.Adapt([]byte(input), nil)
		if err != nil {
			t.Fatalf("unexpected error adapting merge-equivalent crossed site blocks: %v", err)
		}
	})

	t.Run("conflicting crossed site blocks fail adapt", func(t *testing.T) {
		input := `foo.example.com, *.other.com {
	tls {
		key_type rsa2048
	}
}

*.example.com, bar.other.com {
	tls {
		key_type ed25519
	}
}
`
		adapter := caddyfile.Adapter{ServerType: ServerType{}}
		_, _, err := adapter.Adapt([]byte(input), nil)
		if err == nil {
			t.Fatalf("expected error adapting conflicting crossed site blocks, got nil")
		}
	})
}

