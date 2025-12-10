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

package node

import (
	"math/big"
	"testing"

	"github.com/hyperledger-labs/zeto/go-sdk/internal/crypto/hash"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/stretchr/testify/assert"
)

func TestNonFungibleUTXOs(t *testing.T) {
	x, _ := new(big.Int).SetString("14071052441699386420964762094868612757480677741190253249248703784837194954083", 10)
	y, _ := new(big.Int).SetString("10144222387217718469257170015212761087909907436961262709512987264580109747792", 10)
	alice := &babyjub.PublicKey{
		X: x,
		Y: y,
	}
	salt, _ := new(big.Int).SetString("14366367216420666010683918465570547601749064763665615379119566396413295472937", 10)
	uri := "http://ipfs.io/file-hash-1"
	utxo1 := NewNonFungible(big.NewInt(1001), uri, alice, salt, &hash.PoseidonHasher{})

	idx1, err := utxo1.CalculateIndex()
	assert.NoError(t, err)
	assert.Equal(t, "14387265223978393188138799516680159264477343701050531343910120918831961837958", idx1.BigInt().String())
}

func TestNonFungibleUTXOsWithNullifiers(t *testing.T) {
	privateKey, _ := new(big.Int).SetString("df7ff8191db562f4ed9404e91f184502fe67f880cd1fe67c0f84d224a53ee55", 16)
	salt, _ := new(big.Int).SetString("14366367216420666010683918465570547601749064763665615379119566396413295472937", 10)
	uri := "http://ipfs.io/file-hash-1"
	utxo1 := NewNonFungibleNullifier(big.NewInt(1001), uri, privateKey, salt, &hash.PoseidonHasher{})

	idx1, err := utxo1.CalculateIndex()
	assert.NoError(t, err)
	assert.Equal(t, "187a5bbc943a0fab725eaacf81872c4e023bb0deec1858ab2a43867f6646c0d8", idx1.BigInt().Text(16))
}

func TestNonFungibleUTXOsFail(t *testing.T) {
	x, _ := new(big.Int).SetString("14071052441699386420964762094868612757480677741190253249248703784837194954083", 10)
	y, _ := new(big.Int).SetString("10144222387217718469257170015212761087909907436961262709512987264580109747792", 10)
	alice := &babyjub.PublicKey{
		X: x,
		Y: y,
	}
	salt, _ := new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	uri := "http://ipfs.io/file-hash-1"
	utxo1 := NewNonFungible(big.NewInt(1001), uri, alice, salt, &hash.PoseidonHasher{})
	_, err := utxo1.CalculateIndex()
	assert.EqualError(t, err, "inputs values not inside Finite Field")
}

func TestNonFungibleUTXOsWithNullifiersFail(t *testing.T) {
	privateKey, _ := new(big.Int).SetString("df7ff8191db562f4ed9404e91f184502fe67f880cd1fe67c0f84d224a53ee55", 16)
	salt, _ := new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	uri := "http://ipfs.io/file-hash-1"
	utxo1 := NewNonFungibleNullifier(big.NewInt(1001), uri, privateKey, salt, &hash.PoseidonHasher{})
	_, err := utxo1.CalculateIndex()
	assert.EqualError(t, err, "inputs values not inside Finite Field")
}
