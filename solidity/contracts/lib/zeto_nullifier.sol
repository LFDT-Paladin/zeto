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
pragma solidity ^0.8.27;

import {Commonlib} from "./common.sol";
import {IZeto} from "./interfaces/izeto.sol";
import {MAX_SMT_DEPTH} from "./interfaces/izeto.sol";
import {IZetoLockable} from "./interfaces/izeto_lockable.sol";
import {ZetoCommon} from "./zeto_common.sol";
import {SmtLib} from "@iden3/contracts/contracts/lib/SmtLib.sol";
import {PoseidonHasher} from "@iden3/contracts/contracts/lib/hash/PoseidonHasher.sol";
import {IHasher} from "@iden3/contracts/contracts/interfaces/IHasher.sol";
import {PoseidonUnit3L} from "@iden3/contracts/contracts/lib/Poseidon.sol";
import {console} from "hardhat/console.sol";

/// @title A sample base implementation of a Zeto based token contract with nullifiers
/// @author Kaleido, Inc.
/// @dev Implements common functionalities of Zeto based tokens using nullifiers
abstract contract ZetoNullifier is IZeto, IZetoLockable, ZetoCommon {
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
    IHasher private _hasher;

    error UTXORootNotFound(uint256 root);

    function __ZetoNullifier_init(
        string memory name_,
        string memory symbol_,
        address initialOwner
    ) internal onlyInitializing {
        __ZetoCommon_init(name_, symbol_, initialOwner);
        _commitmentsTree.initialize(MAX_SMT_DEPTH);
        _lockedCommitmentsTree.initialize(MAX_SMT_DEPTH);
        _hasher = new PoseidonHasher();
        _commitmentsTree.setHasher(_hasher);
        _lockedCommitmentsTree.setHasher(_hasher);
    }

    function validateTransactionProposal(
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        uint256 root,
        bool isLocked
    ) internal view returns (bool) {
        validateNullifiers(nullifiers);
        validateOutputs(outputs);
        validateRoot(root, isLocked);

        return true;
    }

    function validateNullifiers(
        uint256[] memory nullifiers
    ) internal view returns (bool) {
        // sort the nullifiers to detect duplicates
        uint256[] memory sortedInputs = sortCommitments(nullifiers);

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

    function validateOutputs(
        uint256[] memory outputs
    ) internal view returns (bool) {
        // sort the outputs to detect duplicates
        uint256[] memory sortedOutputs = sortCommitments(outputs);

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
    ) internal view returns (bool) {
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

    function processInputsAndOutputs(
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        uint256[] memory lockedOutputs,
        address delegate
    ) internal {
        processNullifiers(nullifiers);
        processOutputs(outputs);
        processLockedOutputs(lockedOutputs, delegate);
    }

    function processNullifiers(uint256[] memory nullifiers) internal {
        for (uint256 i = 0; i < nullifiers.length; ++i) {
            if (nullifiers[i] != 0) {
                _nullifiers[nullifiers[i]] = true;
            }
        }
    }

    function processOutputs(uint256[] memory outputs) internal {
        for (uint256 i = 0; i < outputs.length; ++i) {
            if (outputs[i] != 0) {
                _commitmentsTree.addLeaf(outputs[i], outputs[i]);
            }
        }
    }

    function processLockedOutputs(
        uint256[] memory lockedOutputs,
        address delegate
    ) internal {
        for (uint256 i = 0; i < lockedOutputs.length; ++i) {
            if (lockedOutputs[i] != 0) {
                _lockedCommitmentsTree.addLeaf(
                    lockedOutputs[i],
                    uint256(uint160(delegate))
                );
            }
        }
    }

    // This function is used to mint new UTXOs, as an example implementation,
    // which is only callable by the owner.
    function _mint(
        uint256[] memory utxos,
        bytes calldata data
    ) internal virtual {
        validateOutputs(utxos);
        processOutputs(utxos);
        emit UTXOMint(utxos, msg.sender, data);
    }

    // This function is used to burn the owner's UTXOs
    function _burn(
        uint256[] memory nullifiers,
        uint256 output,
        uint256 root,
        bytes calldata data
    ) internal virtual {
        validateNullifiers(nullifiers);
        uint256[] memory outputStates = new uint256[](1);
        outputStates[0] = output;
        validateOutputs(outputStates);
        validateRoot(root, false);

        emit UTXOBurn(nullifiers, output, msg.sender, data);
    }

    function getRoot() public view returns (uint256) {
        return _commitmentsTree.getRoot();
    }

    function getRootForLocked() public view returns (uint256) {
        return _lockedCommitmentsTree.getRoot();
    }

    // Locks the UTXOs so that they can only be spent by submitting the appropriate
    // proof from the Eth account designated as the "delegate". This function
    // should be called by escrow contracts that will use uploaded proofs
    // to execute transactions, in order to prevent the proof from being used
    // by parties other than the escrow contract.
    // Assumes that the outputs and locked outputs are already validated to be new UTXOs.
    function _lock(
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        uint256[] memory lockedOutputs,
        address delegate,
        bytes calldata data
    ) internal {
        for (uint256 i = 0; i < outputs.length; ++i) {
            if (outputs[i] == 0) {
                // skip the zero outputs
                continue;
            }
            _commitmentsTree.addLeaf(outputs[i], outputs[i]);
        }

        // Check the locked outputs are all new UTXOs
        for (uint256 i = 0; i < lockedOutputs.length; ++i) {
            if (lockedOutputs[i] == 0) {
                // skip the zero outputs
                continue;
            }
            _lockedCommitmentsTree.addLeaf(
                lockedOutputs[i],
                uint256(uint160(delegate))
            );
        }

        emit UTXOsLocked(
            nullifiers,
            outputs,
            lockedOutputs,
            delegate,
            msg.sender,
            data
        );
    }

    // move the ability to spend the locked UTXOs to the delegate account.
    // The sender must be the current delegate.
    function delegateLock(
        uint256[] memory utxos,
        address delegate,
        bytes calldata data
    ) public {
        for (uint256 i = 0; i < utxos.length; ++i) {
            if (utxos[i] == 0) {
                continue;
            }
            bool existsInTree;
            address currentDelegate;
            (existsInTree, currentDelegate) = existsAsLocked(
                utxos[i],
                msg.sender
            );
            if (!existsInTree) {
                revert UTXONotLocked(utxos[i]);
            }
            if (currentDelegate != msg.sender) {
                revert NotLockDelegate(utxos[i], delegate, msg.sender);
            }
            _lockedCommitmentsTree.addLeaf(
                utxos[i],
                uint256(uint160(delegate))
            );
        }

        emit LockDelegateChanged(utxos, msg.sender, delegate, data);
    }

    function locked(
        uint256 utxo,
        address delegate
    ) public view returns (bool, address) {
        return existsAsLocked(utxo, delegate);
    }

    function getLeafNodeHash(
        uint256 index,
        uint256 value
    ) internal pure returns (uint256) {
        uint256[3] memory params = [index, value, uint256(1)];
        return PoseidonUnit3L.poseidon(params);
    }

    // check the existence of a UTXO in either the unlocked or locked commitments tree
    function exists(uint256 utxo) internal view returns (bool) {
        bool existsInTree = everExistedAsUnlocked(utxo);
        if (!existsInTree) {
            return everExistedAsLocked(utxo);
        }
        return existsInTree;
    }

    // check the existence of a UTXO in the commitments tree. we take a shortcut
    // by checking the list of nodes by their node hash, because the commitments
    // tree is append-only, no updates or deletions are allowed. As a result, all
    // nodes in the list are valid leaf nodes, aka there are no orphaned nodes.
    function everExistedAsUnlocked(uint256 utxo) internal view returns (bool) {
        uint256 nodeHash = getLeafNodeHash(utxo, utxo);
        SmtLib.Node memory node = _commitmentsTree.getNode(nodeHash);
        return node.nodeType != SmtLib.NodeType.EMPTY;
    }

    // check if an UTXO has ever existed in the locked commitments tree. Because
    // this tree allows updates to an existing leaf node, we check the node by its
    // merkle proof
    function everExistedAsLocked(uint256 utxo) internal view returns (bool) {
        SmtLib.Proof memory proof = _lockedCommitmentsTree.getProof(utxo);
        return proof.existence;
    }

    // check the existence of a locked UTXO in the locked commitments tree. Because
    // this tree allows updates to an existing leaf node, we need to check the node
    // by its merkle proof, which is built from the current tree and disregards the
    // orphaned nodes after updates.
    function existsAsLocked(
        uint256 utxo,
        address delegate
    ) internal view returns (bool, address) {
        SmtLib.Proof memory proof = _lockedCommitmentsTree.getProof(utxo);
        return (
            proof.existence && proof.value == uint256(uint160(delegate)),
            address(uint160(proof.value))
        );
    }
}
