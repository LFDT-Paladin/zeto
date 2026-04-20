package key

import (
	"github.com/LFDT-Paladin/zeto/go-sdk/internal/key-manager/key"
	"github.com/LFDT-Paladin/zeto/go-sdk/pkg/key-manager/core"
)

func NewKeyEntryFromPrivateKeyBytes(keyBytes [32]byte) *core.KeyEntry {
	return key.NewKeyEntryFromPrivateKeyBytes(keyBytes)
}
