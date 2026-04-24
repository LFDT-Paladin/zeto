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
import {IZetoInitializable} from "./interfaces/IZetoInitializable.sol";
import {IZetoStorage} from "./interfaces/IZetoStorage.sol";

/// @title A sample base implementation of a Zeto based non-fungible token contract
/// @author Kaleido, Inc.
/// @dev The proof has the following statements:
///        - The sender owns the private key whose public key is part of the pre-image of the input UTXOs commitments
///          (aka the sender is authorized to spend the input UTXOs)
///        - The input UTXOs and output UTXOs are valid in terms of obeying mass conservation rules
///
///      Unlike the fungible siblings, this base does NOT implement the
///      {IZetoLockableCapability} lock lifecycle. The historical
///      {IZetoLockable} stack used on `main` was removed when the
///      lockable interface was redesigned (see `ILockableCapability` /
///      `IZetoLockableCapability`); porting that lifecycle to the new
///      stack for non-fungible tokens would require building a
///      `ZetoNonFungibleLockable` mixin paralleling `ZetoFungible`, and
///      is intentionally left out of this revival to keep the diff
///      bounded. Concrete NF tokens (e.g. {Zeto_NfAnon},
///      {Zeto_NfAnonNullifier}) therefore expose only `mint` and
///      `transfer` for now; locking can be added in a subsequent change
///      without affecting the on-disk storage layout (the 50-slot
///      `__gap` reserved here is sized so a future Lockable mixin can
///      claim slots without shifting descendant layouts).
abstract contract ZetoNonFungible is ZetoCommon {
    /// @dev Reserved storage to allow new state variables to be added in
    ///      future upgrades of this contract. Sized at 50 slots, matching
    ///      the OpenZeppelin upgradeable convention. When a new state
    ///      variable is added here, decrement the gap by the equivalent
    ///      number of slots so descendants' layouts stay stable.
    uint256[50] private __gap;

    function __ZetoNonFungible_init(
        string calldata name_,
        string calldata symbol_,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers,
        IZetoStorage storage_
    ) internal onlyInitializing {
        __ZetoCommon_init(name_, symbol_, initialOwner, verifiers, storage_);
    }

    /**
     * @dev Single-input/single-output transfer.
     *
     * @param input The UTXO to be spent by the transaction.
     * @param output The new UTXO to generate, for future transactions to spend.
     * @param proof A zero knowledge proof that the submitter is authorized to spend the input, and
     *      that the output is valid in terms of obeying mass conservation rules.
     * @param data Opaque data appended to the {UTXOTransfer} event for off-chain consumers.
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
}
