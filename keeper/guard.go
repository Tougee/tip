package keeper

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/MixinNetwork/tip/crypto"
	"github.com/MixinNetwork/tip/store"
	"github.com/drand/kyber"
)

const (
	EphemeralGracePeriod = time.Hour * 24 * 128
	EphemeralLimitWindow = time.Hour * 24
	EphemeralLimitQuota  = 42
	SecretLimitWindow    = time.Hour * 24 * 7
	SecretLimitQuota     = 7
)

func Guard(store store.Storage, priv kyber.Scalar, identity, signature, data string) (int, error) {
	b, err := base64.RawURLEncoding.DecodeString(data)
	if err != nil || len(b) < aes.BlockSize*2 {
		return 0, fmt.Errorf("invalid data %s", data)
	}
	pub, err := crypto.PubKeyFromBase58(identity)
	if err != nil {
		return 0, fmt.Errorf("invalid idenity %s", identity)
	}
	b = crypto.Decrypt(pub, priv, b)

	var body body
	err = json.Unmarshal(b, &body)
	if err != nil {
		return 0, fmt.Errorf("invalid data %s", string(b))
	}
	if body.Identity != identity {
		return 0, fmt.Errorf("invalid idenity %s", identity)
	}
	eb, valid := new(big.Int).SetString(body.Ephemeral, 16)
	if !valid {
		return 0, fmt.Errorf("invalid ephemeral %s", body.Ephemeral)
	}
	rb, _ := new(big.Int).SetString(body.Rotate, 16)
	sig, err := hex.DecodeString(signature)
	if err != nil {
		return 0, fmt.Errorf("invalid signature %s", signature)
	}
	key := crypto.PublicKeyBytes(pub)

	lkey := append(key, "EPHEMERAL"...)
	available, err := store.CheckLimit(lkey, EphemeralLimitWindow, EphemeralLimitQuota, false)
	if err != nil || available < 1 {
		return 0, err
	}
	nonce, grace := uint64(body.Nonce), time.Duration(body.Grace)
	if grace < EphemeralGracePeriod {
		grace = EphemeralGracePeriod
	}
	valid, err = store.CheckEphemeralNonce(key, eb.Bytes(), nonce, grace)
	if err != nil {
		return 0, err
	}
	if !valid {
		_, err = store.CheckLimit(lkey, EphemeralLimitWindow, EphemeralLimitQuota, true)
		return 0, err
	}
	if rb != nil && rb.Int64() > 0 {
		err = store.RotateEphemeralNonce(key, rb.Bytes(), nonce)
		if err != nil {
			return 0, err
		}
	}

	lkey = append(key, "SECRET"...)
	available, err = store.CheckLimit(lkey, SecretLimitWindow, SecretLimitQuota, false)
	if err != nil || available < 1 {
		return 0, err
	}
	err = checkSignature(pub, sig, eb, rb, nonce, uint64(grace))
	if err == nil {
		return available, nil
	}
	_, err = store.CheckLimit(lkey, SecretLimitWindow, SecretLimitQuota, true)
	return 0, err
}

func checkSignature(pub kyber.Point, sig []byte, eb, rb *big.Int, nonce, grace uint64) error {
	msg := crypto.PublicKeyBytes(pub)
	msg = append(msg, eb.Bytes()...)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, nonce)
	msg = append(msg, buf...)
	binary.BigEndian.PutUint64(buf, grace)
	msg = append(msg, buf...)
	if rb != nil && rb.Int64() > 0 {
		msg = append(msg, rb.Bytes()...)
	}
	return crypto.Verify(pub, msg, sig)
}

type body struct {
	Identity  string `json:"identity"`
	Ephemeral string `json:"ephemeral"`
	Grace     int64  `json:"grace"`
	Nonce     int64  `json:"nonce"`
	Rotate    string `json:"rotate"`
}
