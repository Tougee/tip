package tip

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSign(t *testing.T) {
	f, err := os.ReadFile("../../tip.json")
	if err != nil {
		return
	}
	conf, err := LoadConfigurationJSON(string(f))
	if err != nil {
		return
	}
	client, _, err := NewClient(conf)
	if err != nil {
		return
	}
	grace := int64(time.Hour * 24 * 128)

	kb := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, kb)
	if err != nil {
		panic(err)
	}

	eb := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, eb)
	if err != nil {
		panic(err)
	}

	key := hex.EncodeToString(kb)
	ephemeral := hex.EncodeToString(eb)
	t.Logf("key %s", key)
	t.Logf("epehemral %s", ephemeral)

	ab := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, ab)
	if err != nil {
		panic(err)
	}

	nonce := int64(1024)

	sig, _, err := client.Sign(key, ephemeral, nonce, grace, "", "")
	t.Logf("sig %s", hex.EncodeToString(sig))
	assert.Nil(t, err)

	assignee := hex.EncodeToString(ab)
	t.Logf("assignee %s", assignee)

	nonce = int64(1025)

	sig, _, err = client.Sign(key, ephemeral, nonce, grace, "", assignee)
	t.Logf("sig %s", hex.EncodeToString(sig))
	assert.Nil(t, err)

	// update user
	key = assignee

	ab = make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, ab)
	if err != nil {
		panic(err)
	}
	assignee = hex.EncodeToString(ab)
	t.Logf("assignee %s", assignee)

	nonce = int64(1026)

	sig, _, err = client.Sign(key, ephemeral, nonce, grace, "", assignee)
	t.Logf("sig %s", hex.EncodeToString(sig))
	assert.Nil(t, err)

	// update user
	key = assignee

	nonce = int64(1027)

	sig, _, err = client.Sign(key, ephemeral, nonce, grace, "", "")
	t.Logf("sig %s", hex.EncodeToString(sig))
	assert.Nil(t, err)
}
