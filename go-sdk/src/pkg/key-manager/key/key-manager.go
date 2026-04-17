package key

import (
	"github.com/hyperledger-labs/zeto/go-sdk/internal/key-manager/key"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/key-manager/core"
)

func NewKeyEntryFromPrivateKeyBytes(keyBytes [32]byte) *core.KeyEntry {
	return key.NewKeyEntryFromPrivateKeyBytes(keyBytes)
}
