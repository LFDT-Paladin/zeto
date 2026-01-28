// Copyright © 2025 Kaleido, Inc.
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
pragma solidity ^0.8.27;

import {IZetoConstants, MAX_SMT_DEPTH} from "../interfaces/izeto.sol";
import {IZetoLockable} from "../interfaces/izeto_lockable.sol";
import {IZetoStorage} from "../interfaces/izeto_storage.sol";
import {Commonlib} from "../common/common.sol";
import {Util} from "../common/util.sol";
import {SmtLib} from "@iden3/contracts/contracts/lib/SmtLib.sol";
import {IHasher} from "@iden3/contracts/contracts/interfaces/IHasher.sol";
import {PoseidonHasher} from "@iden3/contracts/contracts/lib/hash/PoseidonHasher.sol";
import {PoseidonUnit3L} from "@iden3/contracts/contracts/lib/Poseidon.sol";

contract NullifierStorage is IZetoStorage, IZetoConstants, IZetoLockable {
    // used for tracking regular (unlocked) UTXOs
    SmtLib.Data internal _commitmentsTree;
    // used for locked UTXOs tracking. multi-step transaction flows that require counterparties
    // to upload proofs. To protect the party that uploads their proof first,
    // and prevent any other party from utilizing the uploaded proof to execute
    // a transaction, the input UTXOs or nullifiers can be locked and only usable
    // by the same party that did the locking.
    SmtLib.Data internal _lockedCommitmentsTree;
    using SmtLib for SmtLib.Data;
    mapping(uint256 => bool) private _nullifiers;

    error UTXORootNotFound(uint256 root);

    constructor() {
        _commitmentsTree.initialize(MAX_SMT_DEPTH);
        _lockedCommitmentsTree.initialize(MAX_SMT_DEPTH);
        IHasher hasher = new PoseidonHasher();
        _commitmentsTree.setHasher(hasher);
        _lockedCommitmentsTree.setHasher(hasher);
    }

    function validateInputs(
        uint256[] calldata inputs,
        bool inputsLocked
    ) public view {
        // sort the nullifiers to detect duplicates
        uint256[] memory sortedInputs = Util.sortCommitments(inputs);

        // Check the inputs are all unspent
        for (uint256 i = 0; i < sortedInputs.length; ++i) {
            if (sortedInputs[i] == 0) {
                // skip the zero inputs
                continue;
            }
            if (i > 0 && sortedInputs[i] == sortedInputs[i - 1]) {
                revert UTXODuplicate(sortedInputs[i]);
            }
            if (_nullifiers[sortedInputs[i]] == true) {
                revert UTXOAlreadySpent(sortedInputs[i]);
            }
        }
    }

    function validateOutputs(uint256[] calldata outputs) public view {
        // sort the outputs to detect duplicates
        uint256[] memory sortedOutputs = Util.sortCommitments(outputs);

        // Check the outputs are all new UTXOs
        for (uint256 i = 0; i < sortedOutputs.length; ++i) {
            if (sortedOutputs[i] == 0) {
                // skip the zero outputs
                continue;
            }
            if (i > 0 && sortedOutputs[i] == sortedOutputs[i - 1]) {
                revert UTXODuplicate(sortedOutputs[i]);
            }
            // check the unlocked commitments tree
            bool existsInTree = exists(sortedOutputs[i]);
            if (existsInTree) {
                revert UTXOAlreadyOwned(sortedOutputs[i]);
            }
        }
    }

    function validateRoot(
        uint256 root,
        bool isLocked
    ) public view returns (bool) {
        // Check if the root has existed before. It does not need to be the latest root.
        // Our SMT is append-only, so if the root has existed before, and the merklet proof
        // is valid, then the leaves still exist in the tree.
        if (isLocked && !_lockedCommitmentsTree.rootExists(root)) {
            revert UTXORootNotFound(root);
        } else if (!isLocked && !_commitmentsTree.rootExists(root)) {
            revert UTXORootNotFound(root);
        }

        return true;
    }

    function getRoot() public view returns (uint256) {
        return _commitmentsTree.getRoot();
    }

    function getRootForLocked() public view returns (uint256) {
        return _lockedCommitmentsTree.getRoot();
    }

    function processInputs(
        uint256[] calldata nullifiers,
        bool inputsLocked
    ) public {
        for (uint256 i = 0; i < nullifiers.length; ++i) {
            if (nullifiers[i] != 0) {
                _nullifiers[nullifiers[i]] = true;
            }
        }
    }

    function processOutputs(uint256[] calldata outputs) public {
        for (uint256 i = 0; i < outputs.length; ++i) {
            if (outputs[i] != 0) {
                _commitmentsTree.addLeaf(outputs[i], outputs[i]);
            }
        }
    }

    function processLockedOutputs(
        uint256[] calldata lockedOutputs,
        address delegate
    ) public {
        for (uint256 i = 0; i < lockedOutputs.length; ++i) {
            if (lockedOutputs[i] != 0) {
                _lockedCommitmentsTree.addLeaf(
                    lockedOutputs[i],
                    uint256(uint160(delegate))
                );
            }
        }
    }

    // the call must perform the necessary checks to ensure the call is valid
    // such as checking the sender is the current delegate
    function delegateLock(
        uint256[] calldata utxos,
        address delegate,
        bytes calldata data
    ) public {
        for (uint256 i = 0; i < utxos.length; ++i) {
            if (utxos[i] == 0) {
                continue;
            }
            _lockedCommitmentsTree.addLeaf(
                utxos[i],
                uint256(uint160(delegate))
            );
        }
    }

    function locked(uint256 utxo) public view returns (bool, address) {
        return existsAsLocked(utxo);
    }

    function spent(uint256 utxo) public view returns (UTXOStatus) {
        // by design, the contract does not know this
        return UTXOStatus.UNKNOWN;
    }

    // check the existence of a UTXO in either the unlocked or locked commitments tree
    function exists(uint256 utxo) internal view returns (bool) {
        bool existsInTree = everExistedAsUnlocked(utxo);
        if (!existsInTree) {
            (bool existsInLockedTree, address currentDelegate) = existsAsLocked(
                utxo
            );
            return existsInLockedTree;
        }
        return true;
    }

    // check the existence of a UTXO in the commitments tree. we take a shortcut
    // by checking the list of nodes by their node hash, because the commitments
    // tree is append-only, no updates or deletions are allowed. As a result, all
    // nodes in the list are valid leaf nodes, aka there are no orphaned nodes.
    function everExistedAsUnlocked(uint256 utxo) internal view returns (bool) {
        uint256 nodeHash = Util.getLeafNodeHash(utxo, utxo);
        SmtLib.Node memory node = _commitmentsTree.getNode(nodeHash);
        return node.nodeType != SmtLib.NodeType.EMPTY;
    }

    // check the existence of a locked UTXO in the locked commitments tree. Because
    // this tree allows updates to an existing leaf node, we need to check the node
    // by its index (the utxo hash), rather than the node hash, using the getProof()
    // function.
    function existsAsLocked(
        uint256 utxo
    ) internal view returns (bool, address) {
        SmtLib.Proof memory proof = _lockedCommitmentsTree.getProof(utxo);
        return (proof.existence, address(uint160(proof.value)));
    }
}
