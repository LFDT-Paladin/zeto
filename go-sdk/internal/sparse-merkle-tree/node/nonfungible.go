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

	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/core"
	coreUTXO "github.com/hyperledger-labs/zeto/go-sdk/pkg/utxo"
	apicore "github.com/hyperledger-labs/zeto/go-sdk/pkg/utxo/core"
	"github.com/iden3/go-iden3-crypto/babyjub"
)

type nonFungibleNode struct {
	TokenId  *big.Int
	TokenUri string
	Owner    *babyjub.PublicKey
	Salt     *big.Int
	hasher   apicore.Hasher
}

func NewNonFungible(tokenId *big.Int, tokenUri string, owner *babyjub.PublicKey, salt *big.Int, hasher apicore.Hasher) *nonFungibleNode {
	return &nonFungibleNode{
		TokenId:  tokenId,
		TokenUri: tokenUri,
		Owner:    owner,
		Salt:     salt,
		hasher:   hasher,
	}
}

func (f *nonFungibleNode) CalculateIndex() (core.NodeIndex, error) {
	u := coreUTXO.NewNonFungible(f.TokenId, f.TokenUri, f.Owner, f.Salt, f.hasher)
	hash, err := u.GetHash()
	if err != nil {
		return nil, err
	}
	return NewNodeIndexFromBigInt(hash, f.hasher)
}

func (f *nonFungibleNode) GetHasher() apicore.Hasher {
	return f.hasher
}

// the "Owner" is the private key that must be properly hashed and trimmed to be
// compatible with the BabyJub curve.
// Reference: https://github.com/iden3/circomlib/blob/master/test/babyjub.js#L103
type nonFungibleNullifierNode struct {
	TokenId  *big.Int
	TokenUri string
	Owner    *big.Int
	Salt     *big.Int
	hasher   apicore.Hasher
}

func NewNonFungibleNullifier(tokenId *big.Int, tokenUri string, owner *big.Int, salt *big.Int, hasher apicore.Hasher) *nonFungibleNullifierNode {
	return &nonFungibleNullifierNode{
		TokenId:  tokenId,
		TokenUri: tokenUri,
		Owner:    owner,
		Salt:     salt,
		hasher:   hasher,
	}
}

func (f *nonFungibleNullifierNode) CalculateIndex() (core.NodeIndex, error) {
	u := coreUTXO.NewNonFungibleNullifier(f.TokenId, f.TokenUri, f.Owner, f.Salt, f.hasher)
	hash, err := u.GetHash()
	if err != nil {
		return nil, err
	}
	return NewNodeIndexFromBigInt(hash, f.hasher)
}

func (f *nonFungibleNullifierNode) GetHasher() apicore.Hasher {
	return f.hasher
}
