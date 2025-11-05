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

import {IZetoConstants} from "../interfaces/izeto.sol";
import {IZetoLockable} from "../interfaces/izeto_lockable.sol";
import {IZetoStorage} from "../interfaces/izeto_storage.sol";
import {Commonlib} from "../common/common.sol";
import {Util} from "../common/util.sol";

contract BaseStorage is IZetoStorage, IZetoConstants {
    // tracks all the regular (unlocked) UTXOs
    mapping(uint256 => UTXOStatus) internal _utxos;
    // used for tracking locked UTXOs. multi-step transaction flows that require counterparties
    // to upload proofs. To protect the party that uploads their proof first,
    // and prevent any other party from utilizing the uploaded proof to execute
    // a transaction, the input UTXOs or nullifiers can be locked and only usable
    // by the same party that did the locking.
    mapping(uint256 => UTXOStatus) internal _lockedUtxos;
    mapping(uint256 => address) internal delegates;

    function validateInputs(
        uint256[] calldata inputs,
        bool inputsLocked
    ) public view virtual {
        // sort the inputs to detect duplicates
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
            if (
                _lockedUtxos[sortedInputs[i]] == UTXOStatus.UNKNOWN &&
                _utxos[sortedInputs[i]] == UTXOStatus.UNKNOWN
            ) {
                revert UTXONotMinted(sortedInputs[i]);
            }
            if (
                _lockedUtxos[sortedInputs[i]] == UTXOStatus.SPENT ||
                _utxos[sortedInputs[i]] == UTXOStatus.SPENT
            ) {
                revert UTXOAlreadySpent(sortedInputs[i]);
            }
            if (
                !inputsLocked &&
                _lockedUtxos[sortedInputs[i]] == UTXOStatus.UNSPENT
            ) {
                revert IZetoLockable.AlreadyLocked(sortedInputs[i]);
            }
        }
    }

    function validateOutputs(uint256[] calldata outputs) public view virtual {
        // sort the outputs to detect duplicates
        uint256[] memory sortedOutputs = Util.sortCommitments(outputs);

        // Check for duplicate outputs
        for (uint256 i = 0; i < sortedOutputs.length; ++i) {
            uint256 output = sortedOutputs[i];
            if (output == 0) {
                // skip the zero outputs
                continue;
            }
            if (i > 0 && output == sortedOutputs[i - 1]) {
                revert UTXODuplicate(output);
            }
            // check the outputs are all new - looking in the locked and unlocked UTXOs
            if (
                _utxos[output] == UTXOStatus.SPENT ||
                _lockedUtxos[output] == UTXOStatus.SPENT
            ) {
                revert UTXOAlreadySpent(output);
            } else if (
                _utxos[output] == UTXOStatus.UNSPENT ||
                _lockedUtxos[output] == UTXOStatus.UNSPENT
            ) {
                revert UTXOAlreadyOwned(output);
            }
        }
    }

    // Only needed for the nullifier based implementation
    function validateRoot(uint256 root) public view virtual returns (bool) {
        revert("Not implemented");
    }

    // Only needed for the nullifier based implementation
    function getRoot() public view virtual returns (uint256) {
        revert("Not implemented");
    }

    function processInputs(
        uint256[] calldata inputs,
        bool inputsLocked
    ) public virtual {
        mapping(uint256 => UTXOStatus) storage utxos = inputsLocked
            ? _lockedUtxos
            : _utxos;
        // consume the input UTXOs
        for (uint256 i = 0; i < inputs.length; ++i) {
            if (inputs[i] != 0) {
                utxos[inputs[i]] = UTXOStatus.SPENT;
            }
        }
    }

    function processOutputs(uint256[] calldata outputs) public virtual {
        for (uint256 i = 0; i < outputs.length; ++i) {
            if (outputs[i] != 0) {
                _utxos[outputs[i]] = UTXOStatus.UNSPENT;
            }
        }
    }

    function processLockedOutputs(
        uint256[] calldata lockedOutputs,
        address delegate
    ) public {
        // put the locked UTXOs into the locked UTXO tree as UNSPENT
        for (uint256 i = 0; i < lockedOutputs.length; ++i) {
            if (lockedOutputs[i] != 0) {
                _lockedUtxos[lockedOutputs[i]] = UTXOStatus.UNSPENT;
            }
        }
        // set the delegate of the locked UTXOs
        for (uint256 i = 0; i < lockedOutputs.length; ++i) {
            if (lockedOutputs[i] == 0) {
                continue;
            }
            delegates[lockedOutputs[i]] = delegate;
        }
    }

    // the call must perform the necessary checks to ensure the call is valid
    // such as checking the sender is the current delegate
    function delegateLock(
        uint256[] calldata utxos,
        address newDelegate,
        bytes calldata data
    ) public {
        for (uint256 i = 0; i < utxos.length; ++i) {
            if (utxos[i] == 0) {
                continue;
            }
            delegates[utxos[i]] = newDelegate;
        }
    }

    function locked(uint256 utxo) public view returns (bool, address) {
        if (_lockedUtxos[utxo] == UTXOStatus.UNSPENT) {
            return (true, delegates[utxo]);
        }
        return (false, address(0));
    }

    function spent(uint256 utxo) public view virtual returns (UTXOStatus) {
        if (
            _utxos[utxo] == UTXOStatus.SPENT ||
            _lockedUtxos[utxo] == UTXOStatus.SPENT
        ) {
            return UTXOStatus.SPENT;
        } else if (
            _utxos[utxo] == UTXOStatus.UNSPENT ||
            _lockedUtxos[utxo] == UTXOStatus.UNSPENT
        ) {
            return UTXOStatus.UNSPENT;
        }
        return UTXOStatus.UNKNOWN;
    }
}
