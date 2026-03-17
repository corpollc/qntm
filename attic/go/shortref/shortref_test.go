package shortref

import (
	"testing"
)

func TestTrieBasic(t *testing.T) {
	tr := New()
	tr.Insert("1fab342100000000000000000000abcd")
	tr.Insert("2abc000000000000000000000000dead")

	// With only two IDs differing at first char, prefixes should be minimum (3)
	ref1 := tr.ShortRef("1fab342100000000000000000000abcd")
	if ref1 != "1fa" {
		t.Errorf("expected '1fa', got %q", ref1)
	}

	ref2 := tr.ShortRef("2abc000000000000000000000000dead")
	if ref2 != "2ab" {
		t.Errorf("expected '2ab', got %q", ref2)
	}
}

func TestTrieMinPrefix(t *testing.T) {
	tr := New()
	tr.Insert("aaa0000000000000")
	tr.Insert("bbb0000000000000")

	// Even though unique at char 1, minimum is 3
	ref := tr.ShortRef("aaa0000000000000")
	if len(ref) < MinPrefixLen {
		t.Errorf("ref shorter than minimum: %q", ref)
	}
}

func TestTrieAmbiguity(t *testing.T) {
	tr := New()
	tr.Insert("1fab3421aabbccdd")
	tr.Insert("1fab3421eeff0011")

	// These share prefix "1fab3421", so short ref must be longer
	ref1 := tr.ShortRef("1fab3421aabbccdd")
	ref2 := tr.ShortRef("1fab3421eeff0011")
	if ref1 == ref2 {
		t.Errorf("refs should differ: %q vs %q", ref1, ref2)
	}
	if len(ref1) <= 8 {
		t.Errorf("expected ref longer than shared prefix, got %q", ref1)
	}
}

func TestResolveExact(t *testing.T) {
	tr := New()
	tr.Insert("1fab3421aabbccdd")
	tr.Insert("2abc000011223344")

	id, err := tr.ResolveExact("1fab")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != "1fab3421aabbccdd" {
		t.Errorf("got %q", id)
	}

	_, err = tr.ResolveExact("zzzz")
	if err == nil {
		t.Error("expected error for no match")
	}
}

func TestResolveAmbiguous(t *testing.T) {
	tr := New()
	tr.Insert("1fab3421aabbccdd")
	tr.Insert("1fab3421eeff0011")

	_, err := tr.ResolveExact("1fab")
	if err == nil {
		t.Error("expected ambiguous error")
	}
}

func TestRemove(t *testing.T) {
	tr := New()
	tr.Insert("aabb000000000000")
	tr.Insert("aacc000000000000")

	tr.Remove("aacc000000000000")

	matches := tr.Resolve("aa")
	if len(matches) != 1 {
		t.Errorf("expected 1 match after remove, got %d", len(matches))
	}
}

func TestCaseInsensitive(t *testing.T) {
	tr := New()
	tr.Insert("AABB000000000000")

	ref := tr.ShortRef("aabb000000000000")
	if ref != "aab" {
		t.Errorf("expected 'aab', got %q", ref)
	}
}
