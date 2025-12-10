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
	"math/big"
	"strconv"
	"sync"

	"github.com/hyperledger-labs/zeto/go-sdk/internal/log"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/sparse-merkle-tree/node"
	"github.com/hyperledger-labs/zeto/go-sdk/internal/sparse-merkle-tree/utils"
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/core"
	apicore "github.com/hyperledger-labs/zeto/go-sdk/pkg/utxo/core"
)

// MAX_TREE_HEIGHT is the maximum number of levels of the sparse merkle tree.
// This is determined by the number of bits in the index of a leaf node.
const MAX_TREE_HEIGHT = 256

type sparseMerkleTree struct {
	sync.RWMutex
	db        core.Storage
	rootKey   core.NodeRef
	maxLevels int
	hasher    apicore.Hasher
}

func NewMerkleTree(db core.Storage, maxLevels int) (core.SparseMerkleTree, error) {
	if maxLevels <= 0 || maxLevels > MAX_TREE_HEIGHT {
		return nil, ErrMaxLevelsNotInRange
	}
	mt := sparseMerkleTree{db: db, maxLevels: maxLevels, hasher: db.GetHasher()}

	root, err := mt.db.GetRootNodeRef()
	if err == core.ErrNotFound {
		mt.rootKey = node.ZERO_INDEX
		err = mt.db.UpsertRootNodeRef(mt.rootKey)
		if err != nil {
			return nil, err
		}
		return &mt, nil
	} else if err != nil {
		return nil, err
	}
	mt.rootKey = root
	return &mt, nil
}

func (mt *sparseMerkleTree) Root() core.NodeRef {
	mt.RLock()
	defer mt.RUnlock()
	return mt.rootKey
}

// AddLeaf adds a new leaf node into the MerkleTree. It starts from the root node
func (mt *sparseMerkleTree) AddLeaf(node core.Node) error {
	mt.Lock()
	defer mt.Unlock()

	idx := node.Index()
	path := idx.ToPath(mt.maxLevels)

	// find the lowest level of the tree that can accommodate this new leaf node
	// by its unique index. This is done by traversing the tree from the root node
	// down through the levels until a unique path is found. It doesn't necessarily
	// use up all the bits in the index's path. As soon as a unique path is found,
	// which may be only the first few bits of the index, the new leaf node is added.
	// One or more branch nodes may be created to accommodate the new leaf node.
	batch, err := mt.db.BeginTx()
	if err != nil {
		return err
	}
	newRootKey, err := mt.addLeaf(batch, node, mt.rootKey, 0, path)
	if err != nil {
		log.L().Errorf("Error adding leaf node %s: %v, rolling back", node.Ref().Hex(), err)
		_ = batch.Rollback()
		return err
	}
	mt.rootKey = newRootKey

	// update the root node index in the storage
	log.L().Infof("Upserting root node index to %s", mt.rootKey.Hex())
	err = batch.UpsertRootNodeRef(mt.rootKey)
	if err != nil {
		log.L().Errorf("Error upserting root node %s: %v, rolling back", mt.rootKey.Hex(), err)
		_ = batch.Rollback()
		return err
	}
	log.L().Infof("Committing batch operations for adding leaf node %s", node.Ref().Hex())
	err = batch.Commit()
	if err != nil {
		log.L().Errorf("Error committing batch operations for adding leaf node %s: %v", node.Ref().Hex(), err)
		err = batch.Rollback()
		if err != nil {
			log.L().Errorf("Error rolling back batch operations for adding leaf node %s: %v", node.Ref().Hex(), err)
		}
		return err
	}
	return nil
}

// GetNode gets a node by key from the merkle tree. Empty nodes are not stored in the
// tree: they are all the same and assumed to always exist.
func (mt *sparseMerkleTree) GetNode(key core.NodeRef) (core.Node, error) {
	mt.RLock()
	defer mt.RUnlock()
	return mt.getNode(key)
}

// GenerateProofs generates a list of proofs of existence (or non-existence) of the provided
// leaf nodes that are represented by their indexes. An optional Merkle tree root can be provided.
// If rootKey is not provided, the current Merkle tree root is used
func (mt *sparseMerkleTree) GenerateProofs(keys []*big.Int, rootKey core.NodeRef) ([]core.Proof, []*big.Int, error) {
	mt.RLock()
	defer mt.RUnlock()

	merkleProofs := make([]core.Proof, len(keys))
	foundValues := make([]*big.Int, len(keys))
	for i, key := range keys {
		proof, value, err := mt.generateProof(key, rootKey)
		if err != nil {
			return nil, nil, err
		}
		merkleProofs[i] = proof
		foundValues[i] = value
	}

	return merkleProofs, foundValues, nil
}

func (mt *sparseMerkleTree) generateProof(key *big.Int, rootKey core.NodeRef) (core.Proof, *big.Int, error) {
	p := &proof{hasher: mt.hasher}
	var siblingKey core.NodeRef

	kHash, err := node.NewNodeIndexFromBigInt(key, mt.hasher)
	if err != nil {
		return nil, nil, err
	}
	path := kHash.ToPath(mt.maxLevels)
	if rootKey == nil {
		rootKey = mt.rootKey
	}
	nextKey := rootKey
	for p.depth = 0; p.depth < uint(mt.maxLevels); p.depth++ {
		n, err := mt.getNode(nextKey)
		if err != nil {
			return nil, nil, err
		}
		switch n.Type() {
		case core.NodeTypeEmpty:
			return p, big.NewInt(0), nil
		case core.NodeTypeLeaf:
			idx := n.Index()
			value := n.Value()
			if value == nil {
				value = idx.BigInt()
			}
			if kHash.Equal(idx) {
				p.existence = true
				// in our nodes, the value is the same as the index
				return p, value, nil
			}
			// We found a leaf whose entry didn't match the node index
			p.existingNode, err = node.NewLeafNode(utils.NewIndexOnly(idx), n.Value(), mt.hasher)
			if err != nil {
				return nil, nil, err
			}
			// returning a non-inclusion proof
			return p, value, nil
		case core.NodeTypeBranch:
			if path[p.depth] { // go right
				nextKey = n.RightChild()
				siblingKey = n.LeftChild()
			} else { // go left
				nextKey = n.LeftChild()
				siblingKey = n.RightChild()
			}
		default:
			return nil, nil, ErrInvalidNodeFound
		}

		if !siblingKey.Equal(node.ZERO_INDEX) {
			p.MarkNonEmptySibling(uint(p.depth))
			p.siblings = append(p.siblings, siblingKey)
		}
	}
	return nil, nil, ErrReachedMaxLevel
}

// must be called from inside a read lock
func (mt *sparseMerkleTree) getNode(key core.NodeRef) (core.Node, error) {
	if key.IsZero() {
		return node.NewEmptyNode(), nil
	}
	node, err := mt.db.GetNode(key)
	if err != nil {
		return nil, err
	}
	return node, nil
}

// must be called from inside a write lock
// addLeaf adds a new LeafNode to the MerkleTree. It starts with the current node.
//   - if the current node is empty, it adds the new leaf node at that location.
//   - if the current node is a leaf node, it means there's an existing node that shares
//     the same index, because it hasn't fully utilized the bits of the index. We will
//     extend the path of both the existing node and the new node, using more bits of the
//     index, until the paths of the two nodes diverge, at which point they will be created
//     as children of a new branch node.
//   - if the current node is a branch node, it will continue traversing the tree, using the
//     next bit of the new node's index to determine which child to go down to.
func (mt *sparseMerkleTree) addLeaf(batch core.Transaction, newLeaf core.Node, currentNodeRef core.NodeRef, level int, path []bool) (core.NodeRef, error) {
	log.WithLogField("level", strconv.Itoa(level)).Debugf("Adding leaf node %s", newLeaf.Ref().Hex())
	if level > mt.maxLevels-1 {
		// we have exhausted all levels but could not find a unique path for the new leaf.
		// this happens when two leaf nodes have the same beginning bits of the index, of
		// length of the maxLevels value.
		return nil, ErrReachedMaxLevel
	}

	var nextKey core.NodeRef
	currentNode, err := mt.getNode(currentNodeRef)
	if err != nil {
		return nil, err
	}
	switch currentNode.Type() {
	case core.NodeTypeEmpty:
		// We have searched to a level and have found a position in the
		// index's path where the tree is empty. This means we have found
		// the node that doesn't exist yet. We can add the new leaf node here
		log.WithLogField("level", strconv.Itoa(level)).Debugf("Found empty slot, inserting leaf node %s", newLeaf.Ref().Hex())
		return mt.addNode(batch, newLeaf)
	case core.NodeTypeLeaf:
		nIndex := currentNode.Index()
		// Check if leaf node found contains the leaf node we are
		// trying to add
		newLeafIndex := newLeaf.Index()
		if nIndex.Equal(newLeafIndex) {
			return nil, ErrNodeIndexAlreadyExists
		}
		// we found a leaf node that shares the same index as the new leaf node.
		// but we still have more bits in the index to use. We need to extend the
		// path of the existing leaf node and the new leaf node until they diverge.
		pathOldLeaf := nIndex.ToPath(mt.maxLevels)
		log.WithLogField("level", strconv.Itoa(level)).Debug("Found occupied slot, extending path")
		return mt.extendPath(batch, newLeaf, currentNode, level, path, pathOldLeaf)
	case core.NodeTypeBranch:
		// We need to go deeper, continue traversing the tree, left or
		// right depending on path
		var newBranchNode core.Node
		if path[level] { // go right
			log.WithLogField("level", strconv.Itoa(level)).Debug("Found branch node, going right")
			nextKey, err = mt.addLeaf(batch, newLeaf, currentNode.RightChild(), level+1, path)
			if err != nil {
				return nil, err
			}
			// replace the branch node with the new branch node, which now has a new right child
			newBranchNode, err = node.NewBranchNode(currentNode.LeftChild(), nextKey, mt.hasher)
		} else { // go left
			log.WithLogField("level", strconv.Itoa(level)).Debug("Found branch node, going left")
			nextKey, err = mt.addLeaf(batch, newLeaf, currentNode.LeftChild(), level+1, path)
			if err != nil {
				return nil, err
			}
			// replace the branch node with the new branch node, which now has a new left child
			newBranchNode, err = node.NewBranchNode(nextKey, currentNode.RightChild(), mt.hasher)
		}
		if err != nil {
			return nil, err
		}
		// persist the updated branch node
		log.WithLogField("level", strconv.Itoa(level)).Debugf("Inserting new branch node %s (leftChild=%s, rightChild=%s)", newBranchNode.Ref().Hex(), newBranchNode.LeftChild().Hex(), newBranchNode.RightChild().Hex())
		return mt.addNode(batch, newBranchNode)
	default:
		return nil, ErrInvalidNodeFound
	}
}

// must be called from inside a write lock
// addNode adds a node into the MT.  Empty nodes are not stored in the tree;
// they are all the same and assumed to always exist.
func (mt *sparseMerkleTree) addNode(batch core.Transaction, n core.Node) (core.NodeRef, error) {
	if n.Type() == core.NodeTypeEmpty {
		return n.Ref(), nil
	}
	k := n.Ref()
	err := batch.InsertNode(n)
	return k, err
}

// must be called from inside a write lock
// extendPath extends the path of two leaf nodes, which share the same beginnging part of
// their indexes, until their paths diverge, creating ancestor branch nodes as needed.
func (mt *sparseMerkleTree) extendPath(batch core.Transaction, newLeaf core.Node, oldLeaf core.Node, level int, pathNewLeaf []bool, pathOldLeaf []bool) (core.NodeRef, error) {
	if level > mt.maxLevels-2 {
		return nil, ErrReachedMaxLevel
	}
	var newBranchNode core.Node
	if pathNewLeaf[level] == pathOldLeaf[level] {
		// If the next bit of the new leaf node's index is the same as the
		// next bit of the existing leaf node's index, we need to further extend
		// the path of both nodes.
		log.WithLogField("level", strconv.Itoa(level)).Debug("Found occupied slot, extending path")
		nextKey, err := mt.extendPath(batch, newLeaf, oldLeaf, level+1, pathNewLeaf, pathOldLeaf)
		if err != nil {
			return nil, err
		}
		if pathNewLeaf[level] {
			// the new branch node returned is on the right
			newBranchNode, err = node.NewBranchNode(node.ZERO_INDEX, nextKey, mt.hasher)
		} else {
			// the new branch node returned is on the left
			newBranchNode, err = node.NewBranchNode(nextKey, node.ZERO_INDEX, mt.hasher)
		}
		if err != nil {
			return nil, err
		}
		// persist the new branch node. and return the key of the new branch node
		log.WithLogField("level", strconv.Itoa(level)).Debugf("Inserting new branch node %s (leftChild=%s, rightChild=%s)", newBranchNode.Ref().Hex(), newBranchNode.LeftChild().Hex(), newBranchNode.RightChild().Hex())
		return mt.addNode(batch, newBranchNode)
	}

	// at the current level, the two nodes finally diverges. We can now create a
	// new branch node with the two leaf nodes as children.
	oldLeafRef := oldLeaf.Ref()
	newLeafRef := newLeaf.Ref()

	var err error
	if pathNewLeaf[level] {
		// the new leaf node is on the right
		newBranchNode, err = node.NewBranchNode(oldLeafRef, newLeafRef, mt.hasher)
	} else {
		// the new leaf node is on the left
		newBranchNode, err = node.NewBranchNode(newLeafRef, oldLeafRef, mt.hasher)
	}
	if err != nil {
		return nil, err
	}
	// We can add newLeaf to the DB now. We don't need to add oldLeaf because it's
	// already in the DB.
	log.WithLogField("level", strconv.Itoa(level)).Debugf("Inserting new leaf node %s", newLeaf.Ref().Hex())
	_, err = mt.addNode(batch, newLeaf)
	if err != nil {
		return nil, err
	}
	// finally don't forget to add the new branch node that is the parent of
	// the new leaf node to the DB. We also return this new branch node's key
	// to allow the caller to create branch nodes as needed.
	log.WithLogField("level", strconv.Itoa(level)).Debugf("Inserting new branch node %s (leftChild=%s, rightChild=%s)", newBranchNode.Ref().Hex(), newBranchNode.LeftChild().Hex(), newBranchNode.RightChild().Hex())
	return mt.addNode(batch, newBranchNode)
}
