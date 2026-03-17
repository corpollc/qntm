package group

import (
	"bytes"
	"crypto/ed25519"
	"testing"

	"github.com/corpo/qntm/crypto"
	"github.com/corpo/qntm/dropbox"
	"github.com/corpo/qntm/identity"
	"github.com/corpo/qntm/message"
	"github.com/corpo/qntm/pkg/cbor"
	"github.com/corpo/qntm/pkg/types"
)

func TestRekey_FullFlow(t *testing.T) {
	idMgr := identity.NewManager()
	suite := crypto.NewQSP1Suite()
	msgMgr := message.NewManager()

	alice, _ := idMgr.GenerateIdentity()
	bob, _ := idMgr.GenerateIdentity()
	charlie, _ := idMgr.GenerateIdentity()

	storage := dropbox.NewMemoryStorageProvider()
	groupMgr := NewManager()

	// Create group with alice, bob, charlie
	conv, groupState, err := groupMgr.CreateGroup(
		alice, "rekey-test", "",
		[]ed25519.PublicKey{bob.PublicKey, charlie.PublicKey},
		storage,
	)
	if err != nil {
		t.Fatal(err)
	}

	if conv.CurrentEpoch != 0 {
		t.Errorf("initial epoch should be 0, got %d", conv.CurrentEpoch)
	}

	// Send a message at epoch 0
	env, err := msgMgr.CreateMessage(alice, conv, "text", []byte("hello at epoch 0"), nil, 3600)
	if err != nil {
		t.Fatal(err)
	}
	if env.ConvEpoch != 0 {
		t.Errorf("message should be at epoch 0, got %d", env.ConvEpoch)
	}

	// Now remove charlie with rekey
	members := []RekeyMemberInfo{
		{KeyID: alice.KeyID, PublicKey: alice.PublicKey},
		{KeyID: bob.KeyID, PublicKey: bob.PublicKey},
		// charlie excluded
	}

	rekeyEnv, newGroupKey, err := groupMgr.CreateRekey(alice, conv, groupState, members, storage)
	if err != nil {
		t.Fatal(err)
	}

	if rekeyEnv.ConvEpoch != 0 {
		t.Error("rekey message should be encrypted under old epoch 0")
	}

	// Decrypt the rekey message as bob (should work)
	bobConv := &types.Conversation{
		ID:           conv.ID,
		Type:         types.ConversationTypeGroup,
		Keys:         conv.Keys,
		CurrentEpoch: 0,
	}
	rekeyMsg, err := msgMgr.DecryptMessage(rekeyEnv, bobConv)
	if err != nil {
		t.Fatalf("bob failed to decrypt rekey message: %v", err)
	}

	// Process the rekey
	unwrappedKey, newEpoch, err := groupMgr.ProcessRekeyMessage(rekeyMsg, bobConv, bob)
	if err != nil {
		t.Fatal(err)
	}
	if newEpoch != 1 {
		t.Errorf("expected epoch 1, got %d", newEpoch)
	}
	if !bytes.Equal(unwrappedKey, newGroupKey) {
		t.Error("bob's unwrapped key doesn't match")
	}

	// Try to process as charlie (excluded)
	charlieConv := &types.Conversation{
		ID:           conv.ID,
		Type:         types.ConversationTypeGroup,
		Keys:         conv.Keys,
		CurrentEpoch: 0,
	}
	charlieMsg, err := msgMgr.DecryptMessage(rekeyEnv, charlieConv)
	if err != nil {
		t.Fatalf("charlie should be able to decrypt the rekey message (old epoch): %v", err)
	}
	_, _, err = groupMgr.ProcessRekeyMessage(charlieMsg, charlieConv, charlie)
	if err == nil {
		t.Error("charlie should be excluded from rekey")
	}

	// Apply rekey for alice
	err = groupMgr.ApplyRekey(conv, newGroupKey, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Send message at epoch 1
	env2, err := msgMgr.CreateMessage(alice, conv, "text", []byte("hello at epoch 1"), nil, 3600)
	if err != nil {
		t.Fatal(err)
	}
	if env2.ConvEpoch != 1 {
		t.Errorf("message should be at epoch 1, got %d", env2.ConvEpoch)
	}

	// Bob applies rekey and can decrypt
	err = groupMgr.ApplyRekey(bobConv, unwrappedKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	msg2, err := msgMgr.DecryptMessage(env2, bobConv)
	if err != nil {
		t.Fatalf("bob should decrypt epoch 1 message: %v", err)
	}
	if string(msg2.Inner.Body) != "hello at epoch 1" {
		t.Error("bob got wrong message body")
	}

	// Charlie cannot decrypt epoch 1 messages (doesn't have new key)
	_, err = msgMgr.DecryptMessage(env2, charlieConv)
	if err == nil {
		t.Error("charlie should NOT be able to decrypt epoch 1 messages")
	}

	_ = suite
}

func TestRekey_ConflictResolution(t *testing.T) {
	env1 := &types.OuterEnvelope{MsgID: types.MessageID{0x00, 0x01}}
	env2 := &types.OuterEnvelope{MsgID: types.MessageID{0x00, 0x02}}
	env3 := &types.OuterEnvelope{MsgID: types.MessageID{0x00, 0x00}}

	winner := ResolveRekeyConflict([]*types.OuterEnvelope{env1, env2, env3})
	if winner.MsgID != env3.MsgID {
		t.Errorf("expected lowest msg_id to win, got %x", winner.MsgID)
	}
}

func TestApplyRekey_GracePeriod(t *testing.T) {
	suite := crypto.NewQSP1Suite()
	groupMgr := NewManager()

	convID := types.ConversationID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	rootKey := make([]byte, 32)
	for i := range rootKey {
		rootKey[i] = byte(i)
	}
	aeadKey, nonceKey, _ := suite.DeriveEpochKeys(rootKey, convID[:], 0)

	conv := &types.Conversation{
		ID:           convID,
		Type:         types.ConversationTypeGroup,
		CurrentEpoch: 0,
		Keys: types.ConversationKeys{
			Root:     rootKey,
			AEADKey:  aeadKey,
			NonceKey: nonceKey,
		},
	}

	newGroupKey, _ := suite.GenerateGroupKey()
	err := groupMgr.ApplyRekey(conv, newGroupKey, 1)
	if err != nil {
		t.Fatal(err)
	}

	// Old epoch keys should be retained
	if len(conv.EpochKeys) != 1 {
		t.Fatalf("expected 1 old epoch key, got %d", len(conv.EpochKeys))
	}
	if conv.EpochKeys[0].Epoch != 0 {
		t.Error("old epoch key should be epoch 0")
	}
	if conv.EpochKeys[0].ExpiresAt == 0 {
		t.Error("old epoch key should have expiry set")
	}

	// Do another rekey
	newGroupKey2, _ := suite.GenerateGroupKey()
	err = groupMgr.ApplyRekey(conv, newGroupKey2, 2)
	if err != nil {
		t.Fatal(err)
	}

	if conv.CurrentEpoch != 2 {
		t.Errorf("expected epoch 2, got %d", conv.CurrentEpoch)
	}
	if len(conv.EpochKeys) != 2 {
		t.Errorf("expected 2 old epoch keys, got %d", len(conv.EpochKeys))
	}
}

func TestRekey_RekeyBodySerialization(t *testing.T) {
	body := GroupRekeyBody{
		NewConvEpoch: 1,
		WrappedKeys: map[string][]byte{
			"test-kid": []byte("wrapped-data"),
		},
	}

	data, err := cbor.MarshalCanonical(body)
	if err != nil {
		t.Fatal(err)
	}

	var decoded GroupRekeyBody
	err = cbor.UnmarshalCanonical(data, &decoded)
	if err != nil {
		t.Fatal(err)
	}

	if decoded.NewConvEpoch != 1 {
		t.Error("epoch mismatch")
	}
	if !bytes.Equal(decoded.WrappedKeys["test-kid"], []byte("wrapped-data")) {
		t.Error("wrapped keys mismatch")
	}
}
