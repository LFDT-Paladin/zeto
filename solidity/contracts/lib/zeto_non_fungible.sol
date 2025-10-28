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

import {ZetoCommon} from "./zeto_common.sol";
import {Commonlib} from "./common/common.sol";
import {IZetoInitializable} from "./interfaces/izeto_initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IZetoStorage} from "./interfaces/izeto_storage.sol";

/// @title A sample implementation of a Zeto based non-fungible token with anonymity and no encryption
/// @author Kaleido, Inc.
/// @dev The proof has the following statements:
///        - The sender owns the private key whose public key is part of the pre-image of the input UTXOs commitments
///          (aka the sender is authorized to spend the input UTXOs)
///        - The input UTXOs and output UTXOs are valid in terms of obeying mass conservation rules
contract ZetoNonFungible is ZetoCommon {
    function __ZetoNonFungible_init(
        string calldata name,
        string calldata symbol,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers,
        IZetoStorage storage_
    ) public onlyInitializing {
        __ZetoCommon_init(name, symbol, initialOwner, verifiers, storage_);
    }

    /**
     * @dev the main function of the contract.
     *
     * @param input The UTXO to be spent by the transaction.
     * @param output The new UTXO to generate, for future transactions to spend.
     * @param proof A zero knowledge proof that the submitter is authorized to spend the inputs, and
     *      that the outputs are valid in terms of obeying mass conservation rules.
     *
     * Emits a {UTXOTransfer} event.
     */
    function transfer(
        uint256 input,
        uint256 output,
        bytes calldata proof,
        bytes calldata data
    ) public {
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = input;
        uint256[] memory outputs = new uint256[](1);
        outputs[0] = output;
        uint256[] memory lockedOutputs;
        validateTransactionProposal(
            inputs,
            outputs,
            lockedOutputs,
            proof,
            false
        );

        (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        ) = constructPublicInputs(inputs, outputs, proof, false);
        verifyProof(proofStruct, publicInputs, false, false);
        processInputsAndOutputs(inputs, outputs, false);
        emit UTXOTransfer(inputs, outputs, msg.sender, data);
    }

    /**
     * @dev the main function of the contract.
     *
     * @param input The UTXO to be spent by the transaction.
     * @param output The new UTXO to generate, for future transactions to spend.
     * @param proof A zero knowledge proof that the submitter is authorized to spend the inputs, and
     *      that the outputs are valid in terms of obeying mass conservation rules.
     *
     * Emits a {UTXOTransfer} event.
     */
    function transferLocked(
        uint256 input,
        uint256 output,
        bytes calldata proof,
        bytes calldata data
    ) public {
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = input;
        uint256[] memory outputs = new uint256[](1);
        outputs[0] = output;
        uint256[] memory lockedOutputs;
        validateTransactionProposal(
            inputs,
            outputs,
            lockedOutputs,
            proof,
            true
        );

        // construct the public inputs
        (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        ) = constructPublicInputs(inputs, outputs, proof, true);
        verifyProof(proofStruct, publicInputs, false, true);
        processInputsAndOutputs(inputs, outputs, true);
        emit UTXOTransfer(inputs, outputs, msg.sender, data);
    }

    /**
     * @dev lock the intended outputs
     *
     * @param input The UTXO to be spent by the transaction.
     * @param lockedOutput The UTXO to be locked.
     * @param proof A zero knowledge proof that the submitter is authorized to spend the input, and
     *      that the locked output is valid in terms of obeying mass conservation rules.
     * @param delegate The delegate of the locked output.
     * @param data Additional data to be passed to the lock function.
     *
     * Emits a {UTXOLocked} event.
     */
    function lock(
        uint256 input,
        uint256 lockedOutput,
        bytes calldata proof,
        address delegate,
        bytes calldata data
    ) public {
        uint256[] memory inputs = new uint256[](1);
        inputs[0] = input;
        uint256[] memory outputs;
        uint256[] memory lockedOutputs = new uint256[](1);
        lockedOutputs[0] = lockedOutput;
        validateTransactionProposal(
            inputs,
            outputs,
            lockedOutputs,
            proof,
            false
        );

        // construct the public inputs
        (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        ) = constructPublicInputsForLock(inputs, outputs, lockedOutputs, proof);
        verifyProof(proofStruct, publicInputs, false, false);
        processInputsAndOutputs(inputs, outputs, false);
        processLockedOutputs(lockedOutputs, delegate);

        emit UTXOLocked(
            inputs,
            lockedOutputs,
            outputs,
            msg.sender,
            delegate,
            data
        );
    }

    /**
     * @dev unlock the intended outputs
     *
     * @param input The UTXO to be spent by the transaction.
     * @param output The new UTXO to generate, for future transactions to spend.
     * @param proof A zero knowledge proof that the submitter is authorized to spend the input, and
     *      that the locked output is valid in terms of obeying mass conservation rules.
     * @param data Additional data to be passed to the unlock function.
     *
     * Emits a {UTXOTransfer} event.
     */
    function unlock(
        uint256 input,
        uint256 output,
        bytes calldata proof,
        bytes calldata data
    ) public {
        transferLocked(input, output, proof, data);
    }

    /**
     * @dev move the ability to spend the locked UTXOs to the delegate account.
     *      The sender must be the current delegate.
     *
     * @param utxo The locked UTXO to update the delegate of.
     * @param delegate The new delegate.
     * @param data Additional data to be passed to the delegateLock function.
     *
     * Emits a {LockDelegateChanged} event.
     */
    function delegateLock(
        uint256 utxo,
        address delegate,
        bytes calldata data
    ) public {
        (bool isLocked, address currentDelegate) = locked(utxo);
        if (!isLocked) {
            revert UTXONotLocked(utxo);
        }
        if (currentDelegate != msg.sender) {
            revert NotLockDelegate(utxo, currentDelegate, msg.sender);
        }
        uint256[] memory utxos = new uint256[](1);
        utxos[0] = utxo;
        _storage.delegateLock(utxos, delegate, data);
        emit LockDelegateChanged(utxos, msg.sender, delegate, data);
    }
}
