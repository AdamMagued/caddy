// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddytls

import (
	"strings"
	"testing"
)

func TestAddAutomationPolicy_AcyclicTopologicalOrdering(t *testing.T) {
	// A is general on example.com
	// B is specific on other.com
	// C is specific on example.com, general on other.com
	// The unique valid topological order is B, C, A.
	policyA := []string{"*.example.com"}
	policyB := []string{"foo.other.com"}
	policyC := []string{"foo.example.com", "*.other.com"}

	t.Run("insert A then B then C", func(t *testing.T) {
		tlsApp := newTestTLSApp(t)
		pA := newTestPolicy(t, policyA)
		pB := newTestPolicy(t, policyB)
		pC := newTestPolicy(t, policyC)

		if err := tlsApp.AddAutomationPolicy(pA); err != nil {
			t.Fatalf("adding policy A: %v", err)
		}
		if err := tlsApp.AddAutomationPolicy(pB); err != nil {
			t.Fatalf("adding policy B: %v", err)
		}
		if err := tlsApp.AddAutomationPolicy(pC); err != nil {
			t.Fatalf("adding policy C: %v", err)
		}

		if len(tlsApp.Automation.Policies) != 3 {
			t.Fatalf("expected 3 policies, got %d", len(tlsApp.Automation.Policies))
		}
		if tlsApp.Automation.Policies[0] != pB {
			t.Errorf("expected policy B at index 0, got %v", tlsApp.Automation.Policies[0].SubjectsRaw)
		}
		if tlsApp.Automation.Policies[1] != pC {
			t.Errorf("expected policy C at index 1, got %v", tlsApp.Automation.Policies[1].SubjectsRaw)
		}
		if tlsApp.Automation.Policies[2] != pA {
			t.Errorf("expected policy A at index 2, got %v", tlsApp.Automation.Policies[2].SubjectsRaw)
		}

		// Verify subject dispatch
		if got := tlsApp.getAutomationPolicyForName("foo.other.com"); got != pB {
			t.Errorf("expected foo.other.com to match policy B, got %v", got)
		}
		if got := tlsApp.getAutomationPolicyForName("bar.other.com"); got != pC {
			t.Errorf("expected bar.other.com to match policy C, got %v", got)
		}
		if got := tlsApp.getAutomationPolicyForName("foo.example.com"); got != pC {
			t.Errorf("expected foo.example.com to match policy C, got %v", got)
		}
		if got := tlsApp.getAutomationPolicyForName("bar.example.com"); got != pA {
			t.Errorf("expected bar.example.com to match policy A, got %v", got)
		}
	})

	t.Run("all insertion permutations resolve to B C A", func(t *testing.T) {
		permutations := [][]string{
			{"A", "B", "C"},
			{"A", "C", "B"},
			{"B", "A", "C"},
			{"B", "C", "A"},
			{"C", "A", "B"},
			{"C", "B", "A"},
		}

		for _, perm := range permutations {
			t.Run(strings.Join(perm, "-"), func(t *testing.T) {
				tlsApp := newTestTLSApp(t)
				policies := map[string]*AutomationPolicy{
					"A": newTestPolicy(t, policyA),
					"B": newTestPolicy(t, policyB),
					"C": newTestPolicy(t, policyC),
				}

				for _, name := range perm {
					if err := tlsApp.AddAutomationPolicy(policies[name]); err != nil {
						t.Fatalf("adding policy %s: %v", name, err)
					}
				}

				if len(tlsApp.Automation.Policies) != 3 {
					t.Fatalf("expected 3 policies, got %d", len(tlsApp.Automation.Policies))
				}
				expectedOrder := []*AutomationPolicy{policies["B"], policies["C"], policies["A"]}
				for i, exp := range expectedOrder {
					if tlsApp.Automation.Policies[i] != exp {
						t.Errorf("at index %d: expected %v, got %v", i, exp.SubjectsRaw, tlsApp.Automation.Policies[i].SubjectsRaw)
					}
				}
			})
		}
	})
}

func TestAddAutomationPolicy_CyclicDependencies(t *testing.T) {
	t.Run("direct two-policy cycle", func(t *testing.T) {
		tlsApp := newTestTLSApp(t)
		p1 := newTestPolicy(t, []string{"foo.example.com", "*.other.com"})
		p2 := newTestPolicy(t, []string{"*.example.com", "bar.other.com"})

		if err := tlsApp.AddAutomationPolicy(p1); err != nil {
			t.Fatalf("adding policy 1: %v", err)
		}
		if err := tlsApp.AddAutomationPolicy(p2); err == nil {
			t.Fatalf("expected error for direct cycle, got nil")
		}
		// Verify policy 1 was not corrupted
		if len(tlsApp.Automation.Policies) != 1 || tlsApp.Automation.Policies[0] != p1 {
			t.Fatalf("expected tlsApp to still have only policy 1, got %v", tlsApp.Automation.Policies)
		}
	})

	t.Run("indirect three-policy cycle", func(t *testing.T) {
		// P1 is more specific than P3 on a.com
		// P2 is more specific than P1 on b.com
		// P3 is more specific than P2 on c.com
		// Cycle: P1 -> P3 -> P2 -> P1
		tlsApp := newTestTLSApp(t)
		p1 := newTestPolicy(t, []string{"foo.a.com", "*.b.com"})
		p2 := newTestPolicy(t, []string{"foo.b.com", "*.c.com"})
		p3 := newTestPolicy(t, []string{"foo.c.com", "*.a.com"})

		if err := tlsApp.AddAutomationPolicy(p1); err != nil {
			t.Fatalf("adding policy 1: %v", err)
		}
		if err := tlsApp.AddAutomationPolicy(p2); err != nil {
			t.Fatalf("adding policy 2: %v", err)
		}
		if err := tlsApp.AddAutomationPolicy(p3); err == nil {
			t.Fatalf("expected error for indirect three-policy cycle, got nil")
		}
		// Verify only p1 and p2 remain
		if len(tlsApp.Automation.Policies) != 2 {
			t.Fatalf("expected 2 policies retained after cycle rejection, got %d", len(tlsApp.Automation.Policies))
		}
	})
}
