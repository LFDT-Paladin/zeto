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

package utxo

import (
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/hyperledger-labs/zeto/go-sdk/pkg/utxo/core"
	"github.com/iden3/go-iden3-crypto/babyjub"
)

type nonFungible struct {
	TokenId  *big.Int
	TokenUri string
	Owner    *babyjub.PublicKey
	Salt     *big.Int
	hasher   core.Hasher
}

func NewNonFungible(tokenId *big.Int, tokenUri string, owner *babyjub.PublicKey, salt *big.Int, hasher core.Hasher) core.UTXO {
	return &nonFungible{
		TokenId:  tokenId,
		TokenUri: tokenUri,
		Owner:    owner,
		Salt:     salt,
		hasher:   hasher,
	}
}

func (f *nonFungible) GetHash() (*big.Int, error) {
	tokenUriHash, err := HashTokenUri(f.TokenUri)
	if err != nil {
		return nil, err
	}
	hash, err := f.hasher.Hash([]*big.Int{f.TokenId, tokenUriHash, f.Salt, f.Owner.X, f.Owner.Y})
	if err != nil {
		return nil, err
	}
	return hash, nil
}

// the "Owner" is the private key that must be properly hashed and trimmed to be
// compatible with the BabyJub curve.
// Reference: https://github.com/iden3/circomlib/blob/master/test/babyjub.js#L103
type nonFungibleNullifier struct {
	TokenId  *big.Int
	TokenUri string
	Owner    *big.Int
	Salt     *big.Int
	hasher   core.Hasher
}

func NewNonFungibleNullifier(tokenId *big.Int, tokenUri string, owner *big.Int, salt *big.Int, hasher core.Hasher) core.UTXO {
	return &nonFungibleNullifier{
		TokenId:  tokenId,
		TokenUri: tokenUri,
		Owner:    owner,
		Salt:     salt,
		hasher:   hasher,
	}
}

func (f *nonFungibleNullifier) GetHash() (*big.Int, error) {
	tokenUriHash, err := HashTokenUri(f.TokenUri)
	if err != nil {
		return nil, err
	}
	hash, err := f.hasher.Hash([]*big.Int{f.TokenId, tokenUriHash, f.Salt, f.Owner})
	if err != nil {
		return nil, err
	}
	return hash, nil
}

func HashTokenUri(tokenUri string) (*big.Int, error) {
	hash := sha256.New()
	_, err := hash.Write([]byte(tokenUri))
	if err != nil {
		return nil, err
	}
	v := new(big.Int).SetBytes(hash.Sum(nil))

	// to fit the result within the range of the Finite Field used in the poseidon hash,
	// use 253 bit long numbers. we need to remove the most significant three bits.
	// first print the binary representation of the big int with padding to 256 bits
	binStr := fmt.Sprintf("%0256b", v)
	// then remove the most significant three bits
	binStr = binStr[3:]
	// finally parse the binary string back to big int
	v, ok := v.SetString(binStr, 2)
	if !ok {
		return nil, fmt.Errorf("failed to parse binary string")
	}
	return v, nil
}
