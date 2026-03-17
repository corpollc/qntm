package naming

import (
	"os"
	"testing"
)

func TestSetAndGet(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.SetIdentityName("aabb000000000000", "Alice"); err != nil {
		t.Fatal(err)
	}
	if got := s.GetIdentityName("aabb000000000000"); got != "Alice" {
		t.Errorf("got %q, want Alice", got)
	}

	// Persist and reload
	s2, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.GetIdentityName("aabb000000000000"); got != "Alice" {
		t.Errorf("after reload: got %q, want Alice", got)
	}
}

func TestNameCollision(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir)
	s.SetIdentityName("aaa", "Alice")
	err := s.SetIdentityName("bbb", "Alice")
	if err == nil {
		t.Error("expected collision error")
	}
}

func TestRemove(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir)
	s.SetIdentityName("aaa", "Alice")
	if err := s.RemoveIdentityName("Alice"); err != nil {
		t.Fatal(err)
	}
	if got := s.GetIdentityName("aaa"); got != "" {
		t.Errorf("expected empty after remove, got %q", got)
	}
}

func TestRemoveNotFound(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir)
	if err := s.RemoveIdentityName("Nobody"); err == nil {
		t.Error("expected error for missing name")
	}
}

func TestConversationNames(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir)
	s.SetConversationName("conv1234", "Work Chat")
	if got := s.GetConversationName("conv1234"); got != "Work Chat" {
		t.Errorf("got %q", got)
	}
}

func TestListIdentities(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir)
	s.SetIdentityName("aaa", "Alice")
	s.SetIdentityName("bbb", "Bob")

	list := s.ListIdentities()
	if len(list) != 2 {
		t.Errorf("expected 2, got %d", len(list))
	}
}

func TestResolveByName(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir)
	s.SetIdentityName("aaa", "Alice")

	kid, ok := s.ResolveIdentityByName("Alice")
	if !ok || kid != "aaa" {
		t.Errorf("got %q, %v", kid, ok)
	}

	_, ok = s.ResolveIdentityByName("Nobody")
	if ok {
		t.Error("expected not found")
	}
}

func TestNewStoreCreatesDir(t *testing.T) {
	dir := t.TempDir()
	subdir := dir + "/sub/deep"
	// Remove it so NewStore has to create on save
	os.RemoveAll(subdir)
	s, err := NewStore(subdir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetIdentityName("aaa", "Test"); err != nil {
		t.Fatal(err)
	}
}
