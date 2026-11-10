package caddytls

import (
	"testing"

	"github.com/caddyserver/certmagic"
	"go.uber.org/zap"

	"github.com/caddyserver/caddy/v2"
)

func TestAutomationPolicyMakeCertMagicConfigImplicitTailscaleManagersOnly(t *testing.T) {
	ap := AutomationPolicy{
		Managers: []certmagic.Manager{Tailscale{}},
		subjects: []string{"test-node.example.ts.net"},
	}

	cfg, err := ap.makeCertMagicConfig(&TLS{
		logger: zap.NewNop(),
	}, nil, &certmagic.FileStorage{Path: t.TempDir()})
	if err != nil {
		t.Fatalf("making certmagic config: %v", err)
	}
	if cfg.OnDemand == nil {
		t.Fatal("expected on-demand config to be set")
	}
	if len(cfg.Issuers) != 0 {
		t.Fatalf("expected no issuers for tailscale-managed ts.net policy, got %d", len(cfg.Issuers))
	}
}

func TestAutomationPolicyImplicitTailscaleManagersOnlyCatchAll(t *testing.T) {
	ap := AutomationPolicy{
		Managers: []certmagic.Manager{Tailscale{}},
	}
	if ap.implicitTailscaleManagersOnly() {
		t.Fatal("expected catch-all manager policy to remain outside tailscale-only special case")
	}
}

func newTestTLSApp(t *testing.T) *TLS {
	t.Helper()
	certCacheMu.Lock()
	prevCache := certCache
	certCache = certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return nil, nil },
	})
	certCacheMu.Unlock()
	t.Cleanup(func() {
		certCacheMu.Lock()
		if certCache != nil {
			certCache.Stop()
		}
		certCache = prevCache
		certCacheMu.Unlock()
	})

	caddyCtx, cancel := caddy.NewContext(caddy.Context{Context: t.Context()})
	t.Cleanup(cancel)
	return &TLS{
		ctx:    caddyCtx,
		logger: zap.NewNop(),
	}
}

func TestCompareAutomationPolicies(t *testing.T) {
	tests := []struct {
		name        string
		a           []string
		b           []string
		expectedCmp int
		expectErr   bool
	}{
		{
			name:        "exact matches wildcard",
			a:           []string{"foo.example.com"},
			b:           []string{"*.example.com"},
			expectedCmp: -1,
		},
		{
			name:        "wildcard matches exact",
			a:           []string{"*.example.com"},
			b:           []string{"foo.example.com"},
			expectedCmp: 1,
		},
		{
			name:        "identical exact subjects",
			a:           []string{"foo.example.com"},
			b:           []string{"foo.example.com"},
			expectedCmp: 0,
		},
		{
			name:        "identical wildcards",
			a:           []string{"*.example.com"},
			b:           []string{"*.example.com"},
			expectedCmp: 0,
		},
		{
			name:        "disjoint unequal-size sets",
			a:           []string{"a.com", "b.com", "c.com"},
			b:           []string{"x.com"},
			expectedCmp: 0,
		},
		{
			name:        "specific vs catch-all",
			a:           []string{"foo.com"},
			b:           nil,
			expectedCmp: -1,
		},
		{
			name:        "catch-all vs specific",
			a:           nil,
			b:           []string{"foo.com"},
			expectedCmp: 1,
		},
		{
			name:        "both catch-all",
			a:           nil,
			b:           nil,
			expectedCmp: 0,
		},
		{
			name:        "multiple overlaps in same direction",
			a:           []string{"foo.example.com", "bar.example.com"},
			b:           []string{"*.example.com"},
			expectedCmp: -1,
		},
		{
			name:        "bidirectional conflict",
			a:           []string{"foo.example.com", "*.other.com"},
			b:           []string{"*.example.com", "bar.other.com"},
			expectedCmp: 0,
			expectErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			apA := &AutomationPolicy{SubjectsRaw: tc.a}
			apB := &AutomationPolicy{SubjectsRaw: tc.b}
			cmp, err := CompareAutomationPolicies(apA, apB)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cmp != tc.expectedCmp {
				t.Fatalf("expected cmp %d, got %d", tc.expectedCmp, cmp)
			}
		})
	}
}

func newTestPolicy(t *testing.T, subjects []string) *AutomationPolicy {
	t.Helper()
	return &AutomationPolicy{
		SubjectsRaw: subjects,
		storage:     &certmagic.FileStorage{Path: t.TempDir()},
	}
}

func TestAddAutomationPolicy_SpecificityOrder_ReportedExample(t *testing.T) {
	wildcardSubjects := []string{"*.example.com", "other.com", "third.com"}
	specificSubjects := []string{"foo.example.com", "e.com"}

	t.Run("wildcard first then specific", func(t *testing.T) {
		tlsApp := newTestTLSApp(t)
		pWildcard := newTestPolicy(t, wildcardSubjects)
		pSpecific := newTestPolicy(t, specificSubjects)

		if err := tlsApp.AddAutomationPolicy(pWildcard); err != nil {
			t.Fatalf("adding wildcard policy: %v", err)
		}
		if err := tlsApp.AddAutomationPolicy(pSpecific); err != nil {
			t.Fatalf("adding specific policy: %v", err)
		}

		if len(tlsApp.Automation.Policies) != 2 {
			t.Fatalf("expected 2 policies, got %d", len(tlsApp.Automation.Policies))
		}
		if tlsApp.Automation.Policies[0] != pSpecific {
			t.Errorf("expected specific policy at index 0, got %v", tlsApp.Automation.Policies[0].SubjectsRaw)
		}
		if tlsApp.Automation.Policies[1] != pWildcard {
			t.Errorf("expected wildcard policy at index 1, got %v", tlsApp.Automation.Policies[1].SubjectsRaw)
		}

		if matched := tlsApp.getAutomationPolicyForName("foo.example.com"); matched != pSpecific {
			t.Errorf("expected specific policy for foo.example.com, got %v", matched)
		}
		if matched := tlsApp.getAutomationPolicyForName("bar.example.com"); matched != pWildcard {
			t.Errorf("expected wildcard policy for bar.example.com, got %v", matched)
		}
	})

	t.Run("specific first then wildcard", func(t *testing.T) {
		tlsApp := newTestTLSApp(t)
		pWildcard := newTestPolicy(t, wildcardSubjects)
		pSpecific := newTestPolicy(t, specificSubjects)

		if err := tlsApp.AddAutomationPolicy(pSpecific); err != nil {
			t.Fatalf("adding specific policy: %v", err)
		}
		if err := tlsApp.AddAutomationPolicy(pWildcard); err != nil {
			t.Fatalf("adding wildcard policy: %v", err)
		}

		if len(tlsApp.Automation.Policies) != 2 {
			t.Fatalf("expected 2 policies, got %d", len(tlsApp.Automation.Policies))
		}
		if tlsApp.Automation.Policies[0] != pSpecific {
			t.Errorf("expected specific policy at index 0, got %v", tlsApp.Automation.Policies[0].SubjectsRaw)
		}
		if tlsApp.Automation.Policies[1] != pWildcard {
			t.Errorf("expected wildcard policy at index 1, got %v", tlsApp.Automation.Policies[1].SubjectsRaw)
		}

		if matched := tlsApp.getAutomationPolicyForName("foo.example.com"); matched != pSpecific {
			t.Errorf("expected specific policy for foo.example.com, got %v", matched)
		}
		if matched := tlsApp.getAutomationPolicyForName("bar.example.com"); matched != pWildcard {
			t.Errorf("expected wildcard policy for bar.example.com, got %v", matched)
		}
	})
}

func TestAddAutomationPolicy_DisjointUnequalSizeSets(t *testing.T) {
	largeSubjects := []string{"a.com", "b.com", "c.com", "d.com", "e.com"}
	smallSubjects := []string{"x.com"}

	t.Run("large first then small", func(t *testing.T) {
		tlsApp := newTestTLSApp(t)
		pLarge := newTestPolicy(t, largeSubjects)
		pSmall := newTestPolicy(t, smallSubjects)

		if err := tlsApp.AddAutomationPolicy(pLarge); err != nil {
			t.Fatalf("adding large policy: %v", err)
		}
		if err := tlsApp.AddAutomationPolicy(pSmall); err != nil {
			t.Fatalf("adding small policy: %v", err)
		}

		if len(tlsApp.Automation.Policies) != 2 {
			t.Fatalf("expected 2 policies, got %d", len(tlsApp.Automation.Policies))
		}
		if tlsApp.Automation.Policies[0] != pLarge {
			t.Errorf("expected large policy at index 0 to preserve insertion order")
		}
		if tlsApp.Automation.Policies[1] != pSmall {
			t.Errorf("expected small policy at index 1 to preserve insertion order")
		}
	})

	t.Run("small first then large", func(t *testing.T) {
		tlsApp := newTestTLSApp(t)
		pLarge := newTestPolicy(t, largeSubjects)
		pSmall := newTestPolicy(t, smallSubjects)

		if err := tlsApp.AddAutomationPolicy(pSmall); err != nil {
			t.Fatalf("adding small policy: %v", err)
		}
		if err := tlsApp.AddAutomationPolicy(pLarge); err != nil {
			t.Fatalf("adding large policy: %v", err)
		}

		if len(tlsApp.Automation.Policies) != 2 {
			t.Fatalf("expected 2 policies, got %d", len(tlsApp.Automation.Policies))
		}
		if tlsApp.Automation.Policies[0] != pSmall {
			t.Errorf("expected small policy at index 0 to preserve insertion order")
		}
		if tlsApp.Automation.Policies[1] != pLarge {
			t.Errorf("expected large policy at index 1 to preserve insertion order")
		}
	})
}

func TestAddAutomationPolicy_CatchAll(t *testing.T) {
	specificSubjects := []string{"foo.com"}

	t.Run("catch-all first then specific", func(t *testing.T) {
		tlsApp := newTestTLSApp(t)
		pCatchAll := newTestPolicy(t, nil)
		pSpecific := newTestPolicy(t, specificSubjects)

		if err := tlsApp.AddAutomationPolicy(pCatchAll); err != nil {
			t.Fatalf("adding catch-all policy: %v", err)
		}
		if err := tlsApp.AddAutomationPolicy(pSpecific); err != nil {
			t.Fatalf("adding specific policy: %v", err)
		}

		if len(tlsApp.Automation.Policies) != 2 {
			t.Fatalf("expected 2 policies, got %d", len(tlsApp.Automation.Policies))
		}
		if tlsApp.Automation.Policies[0] != pSpecific {
			t.Errorf("expected specific policy before catch-all policy")
		}
		if tlsApp.Automation.Policies[1] != pCatchAll {
			t.Errorf("expected catch-all policy after specific policy")
		}

		if matched := tlsApp.getAutomationPolicyForName("foo.com"); matched != pSpecific {
			t.Errorf("expected specific policy for foo.com, got %v", matched)
		}
		if matched := tlsApp.getAutomationPolicyForName("other.com"); matched != pCatchAll {
			t.Errorf("expected catch-all policy for other.com, got %v", matched)
		}
	})

	t.Run("specific first then catch-all", func(t *testing.T) {
		tlsApp := newTestTLSApp(t)
		pCatchAll := newTestPolicy(t, nil)
		pSpecific := newTestPolicy(t, specificSubjects)

		if err := tlsApp.AddAutomationPolicy(pSpecific); err != nil {
			t.Fatalf("adding specific policy: %v", err)
		}
		if err := tlsApp.AddAutomationPolicy(pCatchAll); err != nil {
			t.Fatalf("adding catch-all policy: %v", err)
		}

		if len(tlsApp.Automation.Policies) != 2 {
			t.Fatalf("expected 2 policies, got %d", len(tlsApp.Automation.Policies))
		}
		if tlsApp.Automation.Policies[0] != pSpecific {
			t.Errorf("expected specific policy before catch-all policy")
		}
		if tlsApp.Automation.Policies[1] != pCatchAll {
			t.Errorf("expected catch-all policy after specific policy")
		}

		if matched := tlsApp.getAutomationPolicyForName("foo.com"); matched != pSpecific {
			t.Errorf("expected specific policy for foo.com, got %v", matched)
		}
		if matched := tlsApp.getAutomationPolicyForName("other.com"); matched != pCatchAll {
			t.Errorf("expected catch-all policy for other.com, got %v", matched)
		}
	})
}

func TestAddAutomationPolicy_BidirectionalConflict(t *testing.T) {
	p1Subjects := []string{"foo.example.com", "*.other.com"}
	p2Subjects := []string{"*.example.com", "bar.other.com"}

	t.Run("policy 1 first then policy 2", func(t *testing.T) {
		tlsApp := newTestTLSApp(t)
		p1 := newTestPolicy(t, p1Subjects)
		p2 := newTestPolicy(t, p2Subjects)

		if err := tlsApp.AddAutomationPolicy(p1); err != nil {
			t.Fatalf("adding policy 1: %v", err)
		}
		if err := tlsApp.AddAutomationPolicy(p2); err == nil {
			t.Fatalf("expected error when adding policy with bidirectional conflict, got nil")
		}
	})

	t.Run("policy 2 first then policy 1", func(t *testing.T) {
		tlsApp := newTestTLSApp(t)
		p1 := newTestPolicy(t, p1Subjects)
		p2 := newTestPolicy(t, p2Subjects)

		if err := tlsApp.AddAutomationPolicy(p2); err != nil {
			t.Fatalf("adding policy 2: %v", err)
		}
		if err := tlsApp.AddAutomationPolicy(p1); err == nil {
			t.Fatalf("expected error when adding policy with bidirectional conflict, got nil")
		}
	})
}

func TestAddAutomationPolicy_SpecificityChain(t *testing.T) {
	pExact := newTestPolicy(t, []string{"foo.example.com"})
	pWildcard := newTestPolicy(t, []string{"*.example.com"})
	pCatchAll := newTestPolicy(t, nil)

	tlsApp := newTestTLSApp(t)
	// Add in reverse specificity order: catch-all, wildcard, exact
	for _, p := range []*AutomationPolicy{pCatchAll, pWildcard, pExact} {
		if err := tlsApp.AddAutomationPolicy(p); err != nil {
			t.Fatalf("adding policy: %v", err)
		}
	}

	if len(tlsApp.Automation.Policies) != 3 {
		t.Fatalf("expected 3 policies, got %d", len(tlsApp.Automation.Policies))
	}
	expected := []*AutomationPolicy{pExact, pWildcard, pCatchAll}
	for i, exp := range expected {
		if tlsApp.Automation.Policies[i] != exp {
			t.Errorf("at index %d: expected %v, got %v", i, exp.SubjectsRaw, tlsApp.Automation.Policies[i].SubjectsRaw)
		}
	}
}

func TestSortAutomationPoliciesBySpecificity(t *testing.T) {
	t.Run("nil and single policy", func(t *testing.T) {
		res, err := SortAutomationPoliciesBySpecificity(nil)
		if err != nil {
			t.Fatalf("unexpected error on nil slice: %v", err)
		}
		if res != nil {
			t.Fatalf("expected nil slice, got %v", res)
		}

		single := []*AutomationPolicy{{SubjectsRaw: []string{"example.com"}}}
		res, err = SortAutomationPoliciesBySpecificity(single)
		if err != nil {
			t.Fatalf("unexpected error on single slice: %v", err)
		}
		if len(res) != 1 || res[0] != single[0] {
			t.Fatalf("expected single policy returned as-is")
		}
	})

	t.Run("orders from most specific to least specific", func(t *testing.T) {
		pExact := &AutomationPolicy{SubjectsRaw: []string{"foo.example.com"}}
		pWildcard := &AutomationPolicy{SubjectsRaw: []string{"*.example.com"}}
		pCatchAll := &AutomationPolicy{}

		input := []*AutomationPolicy{pCatchAll, pWildcard, pExact}
		sorted, err := SortAutomationPoliciesBySpecificity(input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(sorted) != 3 {
			t.Fatalf("expected 3 policies, got %d", len(sorted))
		}
		if sorted[0] != pExact || sorted[1] != pWildcard || sorted[2] != pCatchAll {
			t.Errorf("unexpected ordering: got %v", sorted)
		}
	})

	t.Run("preserves declaration order for disjoint policies", func(t *testing.T) {
		p1 := &AutomationPolicy{SubjectsRaw: []string{"a.com"}}
		p2 := &AutomationPolicy{SubjectsRaw: []string{"b.com"}}
		p3 := &AutomationPolicy{SubjectsRaw: []string{"c.com"}}

		sorted, err := SortAutomationPoliciesBySpecificity([]*AutomationPolicy{p1, p2, p3})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if sorted[0] != p1 || sorted[1] != p2 || sorted[2] != p3 {
			t.Errorf("expected preserved order [p1, p2, p3], got %v", sorted)
		}
	})

	t.Run("returns error on conflicting cycle", func(t *testing.T) {
		p1 := &AutomationPolicy{SubjectsRaw: []string{"foo.example.com", "*.other.com"}}
		p2 := &AutomationPolicy{SubjectsRaw: []string{"*.example.com", "bar.other.com"}}

		_, err := SortAutomationPoliciesBySpecificity([]*AutomationPolicy{p1, p2})
		if err == nil {
			t.Fatal("expected error on cycle, got nil")
		}
	})
}
