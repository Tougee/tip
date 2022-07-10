package keeper

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/MixinNetwork/tip/crypto"
	"github.com/MixinNetwork/tip/store"
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing/bn256"
	"github.com/stretchr/testify/assert"
)

func TestGuard1(t *testing.T) {
	assert := assert.New(t)

	dir, _ := os.MkdirTemp("/tmp", "tip-keeper-test")
	conf := &store.BadgerConfiguration{Dir: dir}
	bs, _ := store.OpenBadger(context.Background(), conf)
	defer bs.Close()

	suite := bn256.NewSuiteBn256()
	s, _ := hex.DecodeString("0da58ccc3b323d92af281367333f4c120418ed2700de803046947f59707b3479")
	signer := suite.Scalar().SetBytes(s)
	node := crypto.PublicKey(signer)

	uSk, _ := hex.DecodeString("b71501aa0da98385eb7345413bb38930fd214c92e6da4995d2156fc2f914bdc7")
	user := suite.Scalar().SetBytes(uSk)
	identity := crypto.PublicKeyString(crypto.PublicKey(user))
	fmt.Printf("1 u pk %s\n", hex.EncodeToString(crypto.PublicKeyBytes(crypto.PublicKey(user))))

	e, _ := hex.DecodeString("bb265d9cd6c823015eeff7a71f92f174825711c9157bb575bebe96ca8e6a234d")
	ephmr := crypto.PrivateKeyBytes(suite.Scalar().SetBytes(e))
	grace := uint64(time.Hour * 24 * 128)

	signature, data := makeTestRequest(t, user, node, ephmr, nil, 1024, grace, "")
	res, err := Guard(bs, signer, identity, signature, data)
	assert.Nil(err)
	fmt.Printf("res assignor %s\n\n", hex.EncodeToString(res.Assignor))

	// ab := make([]byte, 32)
	// _, err = io.ReadFull(rand.Reader, ab)
	// if err != nil {
	// 	panic(err)
	// }
	// assignee := hex.EncodeToString(ab)
	assignee := "cbf9b2651c568330984835d23b034c3baf136523651a340c9430551b4f7c8773"
	fmt.Printf("assignee %s\n", assignee)
	ab, _ := hex.DecodeString(assignee)

	signature, data = makeTestRequest(t, user, node, ephmr, nil, 1025, grace, assignee)
	res, err = Guard(bs, signer, identity, signature, data)
	assert.Nil(err)
	fmt.Printf("res assignor %s\n\n", hex.EncodeToString(res.Assignor))

	// update user use last assginee
	user = suite.Scalar().SetBytes(ab[:])
	identity = crypto.PublicKeyString(crypto.PublicKey(user))
	fmt.Printf("3 u pk %s\n", hex.EncodeToString(crypto.PublicKeyBytes(crypto.PublicKey(user))))

	// ab = make([]byte, 32)
	// _, err = io.ReadFull(rand.Reader, ab)
	// if err != nil {
	// 	panic(err)
	// }
	// assignee = hex.EncodeToString(ab)
	assignee = "b71501aa0da98385eb7345413bb38930fd214c92e6da4995d2156fc2f914bdc7"
	fmt.Printf("assignee %s\n", assignee)

	signature, data = makeTestRequest(t, user, node, ephmr, nil, 1026, grace, assignee)
	res, err = Guard(bs, signer, identity, signature, data)
	assert.Nil(err)
	fmt.Printf("res assignor %s\n", hex.EncodeToString(res.Assignor))
}

func makeTestRequest(t *testing.T, user kyber.Scalar, signer kyber.Point, ephmr, rtt []byte, nonce, grace uint64, assignee string) (string, string) {
	return makeTestRequestWithAssigneeAndRotation(t, user, signer, ephmr, rtt, nonce, grace, assignee, "")
}

func makeTestRequestWithAssigneeAndRotation(t *testing.T, user kyber.Scalar, signer kyber.Point, ephmr, rtt []byte, nonce, grace uint64, assignee string, rotation string) (string, string) {
	pkey := crypto.PublicKey(user)
	msg := crypto.PublicKeyBytes(pkey)
	msg = append(msg, ephmr...)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, nonce)
	msg = append(msg, buf...)
	binary.BigEndian.PutUint64(buf, grace)
	msg = append(msg, buf...)

	data := map[string]interface{}{
		"identity":  crypto.PublicKeyString(pkey),
		"ephemeral": hex.EncodeToString(ephmr),
		"nonce":     nonce,
		"grace":     grace,
	}

	if len(assignee) > 0 {
		as, _ := crypto.PrivateKeyFromHex(assignee)
		ap := crypto.PublicKey(as)
		ab := crypto.PublicKeyBytes(ap)
		sig, _ := crypto.Sign(as, ab)
		ab = append(ab, sig...)
		msg = append(msg, ab...)
		data["assignee"] = hex.EncodeToString(ab)
	}

	if rtt != nil {
		msg = append(msg, rtt[:]...)
		data["rotate"] = hex.EncodeToString(rtt)
	}

	b, _ := json.Marshal(data)
	cipher := crypto.Encrypt(signer, user, b)
	sig, _ := crypto.Sign(user, msg)
	return hex.EncodeToString(sig), base64.RawURLEncoding.EncodeToString(cipher[:])
}
