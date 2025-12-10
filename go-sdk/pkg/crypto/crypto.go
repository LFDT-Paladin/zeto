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
	"math/big"

	"github.com/hyperledger-labs/zeto/go-sdk/internal/crypto"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/crypto/hash"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/utxo/core"
	"github.com/iden3/go-iden3-crypto/babyjub"
)

// NewSalt generates a new random salt in the range of [0, MAX) where MAX is the order of the BabyJub curve.
// This ensures that the salt is a valid scalar for the curve.
func NewSalt() *big.Int {
	return crypto.NewSalt()
}

func NewEncryptionNonce() *big.Int {
	return crypto.NewEncryptionNonce()
}

func PoseidonEncrypt(msg []*big.Int, key []*big.Int, nonce *big.Int) ([]*big.Int, error) {
	return crypto.PoseidonEncrypt(msg, key, nonce)
}

func PoseidonDecrypt(ciphertext []*big.Int, key []*big.Int, nonce *big.Int, length int) ([]*big.Int, error) {
	return crypto.PoseidonDecrypt(ciphertext, key, nonce, length)
}

func GenerateECDHSharedSecret(privKey *babyjub.PrivateKey, pubKey *babyjub.PublicKey) *babyjub.Point {
	return crypto.GenerateECDHSharedSecret(privKey, pubKey)
}

func BytesToBits(data []byte) []uint8 {
	return crypto.BytesToBits(data)
}

func BitsToBytes(bits []uint8) ([]byte, error) {
	return crypto.BitsToBytes(bits)
}

func RecoverMlkemCiphertextBytes(ciphertext []string) ([]byte, error) {
	return crypto.RecoverMlkemCiphertextBytes(ciphertext)
}

func PublicKeyFromSeed(seed []byte) (*babyjub.Point, error) {
	return crypto.PublicKeyFromSeed(seed)
}

func NewPoseidonHasher() core.Hasher {
	return &hash.PoseidonHasher{}
}

func NewKeccak256Hasher() core.Hasher {
	return &hash.Keccak256Hasher{}
}
