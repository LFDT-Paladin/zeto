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
	"math/big"

	"github.com/hyperledger-labs/zeto/go-sdk/pkg/utxo/core"
	"github.com/iden3/go-iden3-crypto/babyjub"
)

type fungible struct {
	Amount *big.Int
	Owner  *babyjub.PublicKey
	Salt   *big.Int
	hasher core.Hasher
}

func NewFungible(amount *big.Int, owner *babyjub.PublicKey, salt *big.Int, hasher core.Hasher) core.UTXO {
	return &fungible{
		Amount: amount,
		Owner:  owner,
		Salt:   salt,
		hasher: hasher,
	}
}

func (f *fungible) GetHash() (*big.Int, error) {
	hash, err := f.hasher.Hash([]*big.Int{f.Amount, f.Salt, f.Owner.X, f.Owner.Y})
	if err != nil {
		return nil, err
	}
	return hash, nil
}

// the "Owner" is the private key that must be properly hashed and trimmed to be
// compatible with the BabyJub curve.
// Reference: https://github.com/iden3/circomlib/blob/master/test/babyjub.js#L103
type fungibleNullifier struct {
	Amount *big.Int
	Owner  *big.Int
	Salt   *big.Int
	hasher core.Hasher
}

func NewFungibleNullifier(amount *big.Int, owner *big.Int, salt *big.Int, hasher core.Hasher) core.UTXO {
	return &fungibleNullifier{
		Amount: amount,
		Owner:  owner,
		Salt:   salt,
		hasher: hasher,
	}
}

func (f *fungibleNullifier) GetHash() (*big.Int, error) {
	hash, err := f.hasher.Hash([]*big.Int{f.Amount, f.Salt, f.Owner})
	if err != nil {
		return nil, err
	}
	return hash, nil
}
