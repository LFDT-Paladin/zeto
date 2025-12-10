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

func TestFungibleUTXOs(t *testing.T) {
	x, _ := new(big.Int).SetString("825008057393653951717923193550498143270634388542414913039278922773034837543", 10)
	y, _ := new(big.Int).SetString("12283738323983038985315025769936102865095332379710901215078187917699827946177", 10)
	alice := &babyjub.PublicKey{
		X: x,
		Y: y,
	}
	salt, _ := new(big.Int).SetString("13de02d64a5736a56b2d35d2a83dd60397ba70aae6f8347629f0960d4fee5d58", 16)
	utxo1 := NewFungible(big.NewInt(10), alice, salt, &hash.PoseidonHasher{})

	idx1, err := utxo1.CalculateIndex()
	assert.NoError(t, err)
	assert.Equal(t, "26e3879b46b15a4ddbaca5d96af1bd2743f67f13f0bb85c40782950a2a700138", idx1.BigInt().Text(16))
}

func TestFungibleUTXOsWithNullifiers(t *testing.T) {
	privateKey, _ := new(big.Int).SetString("df7ff8191db562f4ed9404e91f184502fe67f880cd1fe67c0f84d224a53ee55", 16)
	salt, _ := new(big.Int).SetString("13de02d64a5736a56b2d35d2a83dd60397ba70aae6f8347629f0960d4fee5d58", 16)
	utxo1 := NewFungibleNullifier(big.NewInt(10), privateKey, salt, &hash.PoseidonHasher{})

	idx1, err := utxo1.CalculateIndex()
	assert.NoError(t, err)
	assert.Equal(t, "2e9d5efff5d38753195e9a0097a475c90e6bce0fe40b0408470fd81e53d145e6", idx1.BigInt().Text(16))
}

func TestFungibleUTXOsFail(t *testing.T) {
	x, _ := new(big.Int).SetString("825008057393653951717923193550498143270634388542414913039278922773034837543", 10)
	y, _ := new(big.Int).SetString("12283738323983038985315025769936102865095332379710901215078187917699827946177", 10)
	alice := &babyjub.PublicKey{
		X: x,
		Y: y,
	}
	salt, _ := new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	utxo1 := NewFungible(big.NewInt(10), alice, salt, &hash.PoseidonHasher{})

	_, err := utxo1.CalculateIndex()
	assert.EqualError(t, err, "inputs values not inside Finite Field")
}

func TestFungibleUTXOsWithNullifiersFail(t *testing.T) {
	privateKey, _ := new(big.Int).SetString("df7ff8191db562f4ed9404e91f184502fe67f880cd1fe67c0f84d224a53ee55", 16)
	salt, _ := new(big.Int).SetString("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16)
	utxo1 := NewFungibleNullifier(big.NewInt(10), privateKey, salt, &hash.PoseidonHasher{})

	_, err := utxo1.CalculateIndex()
	assert.EqualError(t, err, "inputs values not inside Finite Field")
}
