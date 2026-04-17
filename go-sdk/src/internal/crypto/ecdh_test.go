// Copyright © 2024 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
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

package crypto

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/hyperledger-labs/zeto/go-sdk/internal/key-manager/key"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/stretchr/testify/assert"
)

func TestGenerateECDHSharedSecret(t *testing.T) {
	privKeyBytes, _ := hex.DecodeString("071ee2e78079dc65acedf508c6b7925fc9da9256b1fa587904f023dbd90f14f6")
	keyEntry := key.NewKeyEntryFromPrivateKeyBytes([32]byte(privKeyBytes))
	assert.Equal(t, "4532338485190197018098951877626853959968121575106182738140659704351327237813", babyjub.SkToBigInt(keyEntry.PrivateKey).Text(10))

	pubKeyBytes := []byte("3f7d4633f5e4ae60d005480ca8f8cfb3fd2fcd27c33e5354743831eb2454de82")
	var otherPartyPublicKey babyjub.PublicKey
	err := otherPartyPublicKey.UnmarshalText(pubKeyBytes)
	assert.NoError(t, err)

	sharedSecret := GenerateECDHSharedSecret(keyEntry.PrivateKey, &otherPartyPublicKey)
	x, _ := new(big.Int).SetString("541910283019899847970697361288826370780990225479189552333070747388630510763", 10)
	y, _ := new(big.Int).SetString("137416317897045242441765515781734290757020753544555776335583609907821726489", 10)
	expected := &babyjub.Point{
		X: x,
		Y: y,
	}
	assert.Equal(t, expected, sharedSecret)
}
