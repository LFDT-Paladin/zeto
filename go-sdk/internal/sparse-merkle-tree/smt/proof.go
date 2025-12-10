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

package smt

import (
	"fmt"
	"math/big"

	"github.com/hyperledger-labs/zeto/go-sdk/internal/sparse-merkle-tree/node"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/core"
	apicore "github.com/hyperledger-labs/zeto/go-sdk/pkg/utxo/core"
)

// Proof defines the required elements for a MT proof of existence or
// non-existence.
type proof struct {
	existence    bool
	siblings     []core.NodeRef
	depth        uint
	existingNode core.Node
	// nonEmptySiblings is a bitmap of non-empty Siblings found in Siblings. This helps
	// to save space in the proof, by not having to carry around empty nodes.
	nonEmptySiblings []byte
	hasher           apicore.Hasher
}

func (p *proof) IsExistenceProof() bool {
	return p.existence
}

func (p *proof) Siblings() []core.NodeRef {
	return p.siblings
}

func (p *proof) Depth() uint {
	return p.depth
}

func (p *proof) ExistingNode() core.Node {
	return p.existingNode
}

func (p *proof) MarkNonEmptySibling(level uint) {
	desiredByteLength := level/8 + 1
	if len(p.nonEmptySiblings) <= int(desiredByteLength) {
		// the bitmap is not big enough, resize it
		newBytes := make([]byte, desiredByteLength)
		if len(p.nonEmptySiblings) == 0 {
			p.nonEmptySiblings = newBytes
		} else {
			copy(newBytes, p.nonEmptySiblings)
			p.nonEmptySiblings = newBytes
		}
	}
	setBitBigEndian(p.nonEmptySiblings, level)
}

func (p *proof) IsNonEmptySibling(level uint) bool {
	return isBitOnBigEndian(p.nonEmptySiblings, level)
}

func (p *proof) AllSiblings() []core.NodeRef {
	sibIdx := 0
	siblings := []core.NodeRef{}
	for level := 0; level < int(p.depth); level++ {
		if p.IsNonEmptySibling(uint(level)) {
			siblings = append(siblings, p.siblings[sibIdx])
			sibIdx++
		} else {
			siblings = append(siblings, node.ZERO_INDEX)
		}
	}
	return siblings
}

// getPath returns the binary path, from the root to the leaf.
func (p *proof) getPath(index core.NodeIndex) []bool {
	path := make([]bool, p.depth)
	for n := 0; n < int(p.depth); n++ {
		path[n] = index.IsBitOne(uint(n))
	}
	return path
}

// ToCircomVerifierProof enhances the generic merkle proof with additional
// signals required by the circuit for Sparse Merkle Tree proof verification:
// https://github.com/iden3/circomlib/blob/master/circuits/smt/smtverifier.circom
func (p *proof) ToCircomVerifierProof(k, v *big.Int, rootKey core.NodeRef, levels int) (*core.CircomVerifierProof, error) {
	var cp core.CircomVerifierProof
	cp.Root = rootKey
	cp.Siblings = p.AllSiblings()
	if p.existingNode != nil {
		cp.OldKey = p.existingNode.Index()
		cp.OldValue = p.existingNode.Value()
		if cp.OldValue == nil {
			cp.OldValue = p.existingNode.Index().BigInt()
		}
	} else {
		cp.OldKey = node.ZERO_INDEX
		cp.OldValue = big.NewInt(0)
	}
	var err error
	cp.Key, err = node.NewNodeIndexFromBigInt(k, p.hasher)
	if err != nil {
		return nil, err
	}
	cp.Value, err = node.NewNodeIndexFromBigInt(v, p.hasher)
	if err != nil {
		return nil, err
	}
	if p.existence {
		cp.Fnc = 0 // inclusion
	} else {
		cp.Fnc = 1 // non inclusion
	}
	// returns the full siblings compatible with circom
	// Add the rest of empty levels to the siblings
	for i := len(cp.Siblings); i < levels+1; i++ {
		cp.Siblings = append(cp.Siblings, node.ZERO_INDEX)
	}
	return &cp, nil
}

// VerifyProof verifies the Merkle Proof for the entry and root.
func VerifyProof(rootKey core.NodeRef, p core.Proof, leafNode core.Node) bool {
	rootFromProof, err := calculateRootFromProof(p.(*proof), leafNode)
	if err != nil {
		return false
	}
	return rootKey.Equal(rootFromProof)
}

// CalculateRootFromProof calculates the root that would correspond to a tree whose
// siblings are the ones in the proof with the leaf node
func calculateRootFromProof(proof *proof, leafNode core.Node) (core.NodeRef, error) {
	sibIdx := len(proof.siblings) - 1
	var midKey core.NodeRef
	if proof.existence {
		midKey = leafNode.Ref()
	} else {
		if proof.existingNode == nil {
			midKey = node.ZERO_INDEX
		} else {
			if leafNode.Index().Equal(proof.existingNode.Index()) {
				return nil, fmt.Errorf("non-existence proof being checked but the target node is found in the proof")
			}
			midKey = proof.existingNode.Ref()
		}
	}
	path := proof.getPath(leafNode.Index())
	var siblingKey core.NodeRef
	for level := int(proof.depth) - 1; level >= 0; level-- {
		if proof.IsNonEmptySibling(uint(level)) {
			siblingKey = proof.siblings[sibIdx]
			sibIdx--
		} else {
			siblingKey = node.ZERO_INDEX
		}
		if path[level] { // go right
			branchNode, err := node.NewBranchNode(siblingKey, midKey, proof.hasher)
			if err != nil {
				return nil, err
			}
			midKey = branchNode.Ref()
		} else { // go left
			branchNode, err := node.NewBranchNode(midKey, siblingKey, proof.hasher)
			if err != nil {
				return nil, err
			}
			midKey = branchNode.Ref()
		}
	}
	return midKey, nil
}

// isBitOnBigEndian tests whether the bit n in bitmap is 1, in Big Endian.
func isBitOnBigEndian(bitmap []byte, n uint) bool {
	byteIdxToCheck := n / 8
	return bitmap[byteIdxToCheck]&(1<<(n%8)) != 0
}

// setBitBigEndian sets the bit n in the bitmap to 1, in Big Endian.
func setBitBigEndian(bitmap []byte, n uint) {
	byteIdxToSet := n / 8
	bitmap[byteIdxToSet] |= 1 << (n % 8)
}
