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

	"github.com/hyperledger-labs/zeto/go-sdk/internal/sparse-merkle-tree/node"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/sparse-merkle-tree/utils"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/core"
	apicore "github.com/hyperledger-labs/zeto/go-sdk/pkg/utxo/core"
	"github.com/iden3/go-iden3-crypto/babyjub"
)

func NewEmptyNode() core.Node {
	return node.NewEmptyNode()
}

// the Indexable object captures the private state data of the node,
// which is used to calculate the hash of the node index.
// the value parameter is optional. if "nil", the index hash is used in the
// place of the value when calculating the node reference hash (aka "node key").
func NewLeafNode(i core.Indexable, v *big.Int, hasher apicore.Hasher) (core.Node, error) {
	return node.NewLeafNode(i, v, hasher)
}

func NewBranchNode(leftChild, rightChild core.NodeRef, hasher apicore.Hasher) (core.Node, error) {
	return node.NewBranchNode(leftChild, rightChild, hasher)
}

func NewNodeIndexFromBigInt(i *big.Int, hasher apicore.Hasher) (core.NodeIndex, error) {
	return node.NewNodeIndexFromBigInt(i, hasher)
}

// NewNodeIndexFromHex creates a new NodeIndex from a hex string that
// represents the index in big-endian format.
func NewNodeIndexFromHex(h string) (core.NodeIndex, error) {
	return node.NewNodeIndexFromHex(h)
}

func NewFungible(amount *big.Int, owner *babyjub.PublicKey, salt *big.Int, hasher apicore.Hasher) core.Indexable {
	return node.NewFungible(amount, owner, salt, hasher)
}

func NewNonFungible(tokenId *big.Int, tokenUri string, owner *babyjub.PublicKey, salt *big.Int, hasher apicore.Hasher) core.Indexable {
	return node.NewNonFungible(tokenId, tokenUri, owner, salt, hasher)
}

func NewFungibleNullifier(amount *big.Int, owner *big.Int, salt *big.Int, hasher apicore.Hasher) core.Indexable {
	return node.NewFungibleNullifier(amount, owner, salt, hasher)
}

func NewNonFungibleNullifier(tokenId *big.Int, tokenUri string, owner *big.Int, salt *big.Int, hasher apicore.Hasher) core.Indexable {
	return node.NewNonFungibleNullifier(tokenId, tokenUri, owner, salt, hasher)
}

func NewIndexOnly(index core.NodeIndex) core.Indexable {
	return utils.NewIndexOnly(index)
}
