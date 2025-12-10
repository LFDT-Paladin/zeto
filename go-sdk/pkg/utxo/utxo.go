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

	"github.com/hyperledger-labs/zeto/go-sdk/internal/utxo"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/utxo/core"
	"github.com/iden3/go-iden3-crypto/babyjub"
)

func NewFungible(amount *big.Int, owner *babyjub.PublicKey, salt *big.Int, hasher core.Hasher) core.UTXO {
	return utxo.NewFungible(amount, owner, salt, hasher)
}

func NewNonFungible(tokenId *big.Int, tokenUri string, owner *babyjub.PublicKey, salt *big.Int, hasher core.Hasher) core.UTXO {
	return utxo.NewNonFungible(tokenId, tokenUri, owner, salt, hasher)
}

func NewFungibleNullifier(amount *big.Int, owner *big.Int, salt *big.Int, hasher core.Hasher) core.UTXO {
	return utxo.NewFungibleNullifier(amount, owner, salt, hasher)
}

func NewNonFungibleNullifier(tokenId *big.Int, tokenUri string, owner *big.Int, salt *big.Int, hasher core.Hasher) core.UTXO {
	return utxo.NewNonFungibleNullifier(tokenId, tokenUri, owner, salt, hasher)
}

func HashTokenUri(tokenUri string) (*big.Int, error) {
	return utxo.HashTokenUri(tokenUri)
}
