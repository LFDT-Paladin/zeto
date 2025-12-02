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
import {IZetoStorage} from "../interfaces/izeto_storage.sol";
import {Commonlib} from "../common/common.sol";
import {Util} from "../common/util.sol";
import {SmtLib} from "@iden3/contracts/lib/SmtLib.sol";
import {PoseidonUnit3L} from "@iden3/contracts/lib/Poseidon.sol";
import {BaseStorage} from "./base.sol";

contract NullifierStorage is BaseStorage {
    // used for tracking regular (unlocked) UTXOs
    // locked UTXOs are tracked in the base storage
    SmtLib.Data internal _commitmentsTree;
    using SmtLib for SmtLib.Data;

    mapping(uint256 => bool) private _nullifiers;

    error UTXORootNotFound(uint256 root);

    constructor() {
        _commitmentsTree.initialize(MAX_SMT_DEPTH);
    }

    function validateInputs(
        uint256[] calldata inputs,
        bool inputsLocked
    ) public view override {
        if (inputsLocked) {
            // locked inputs are regular UTXOs (rather than nullifiers)
            // and are validated in the base storage
            super.validateInputs(inputs, inputsLocked);
            return;
        }

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

    function validateOutputs(uint256[] calldata outputs) public view override {
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

    function validateRoot(uint256 root) public view override returns (bool) {
        // Check if the root has existed before. It does not need to be the latest root.
        // Our SMT is append-only, so if the root has existed before, and the merklet proof
        // is valid, then the leaves still exist in the tree.
        if (!_commitmentsTree.rootExists(root)) {
            revert UTXORootNotFound(root);
        }

        return true;
    }

    function getRoot() public view override returns (uint256) {
        return _commitmentsTree.getRoot();
    }

    function processInputs(
        uint256[] calldata nullifiers,
        bool inputsLocked
    ) public override {
        if (inputsLocked) {
            // locked inputs are regular UTXOs (rather than nullifiers)
            // and are processed in the base storage
            super.processInputs(nullifiers, inputsLocked);
            return;
        }

        for (uint256 i = 0; i < nullifiers.length; ++i) {
            if (nullifiers[i] != 0) {
                _nullifiers[nullifiers[i]] = true;
            }
        }
    }

    function processOutputs(uint256[] calldata outputs) public override {
        for (uint256 i = 0; i < outputs.length; ++i) {
            if (outputs[i] != 0) {
                _commitmentsTree.addLeaf(outputs[i], outputs[i]);
            }
        }
    }

    function spent(uint256 utxo) public view override returns (UTXOStatus) {
        // by design, the contract does not know this
        return UTXOStatus.UNKNOWN;
    }

    // check the existence of a UTXO in either the unlocked or locked commitments storage
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

    function existsAsLocked(
        uint256 utxo
    ) internal view returns (bool, address) {
        (bool locked, address delegate) = super.locked(utxo);
        if (locked) {
            return (true, delegate);
        }
        bool known = super.spent(utxo) != UTXOStatus.UNKNOWN;
        return (known, address(0));
    }
}
