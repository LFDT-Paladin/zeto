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

import {ZetoLockable} from "./zeto_lockable.sol";
import {Commonlib} from "./common/common.sol";
import {IZetoInitializable} from "./interfaces/IZetoInitializable.sol";
import {IZetoStorage} from "./interfaces/IZetoStorage.sol";

/// @title A sample base implementation of a Zeto based non-fungible
///        token contract.
/// @author Kaleido, Inc.
/// @dev The proof has the following statements:
///        - The sender owns the private key whose public key is part of the pre-image of the input UTXOs commitments
///          (aka the sender is authorized to spend the input UTXOs)
///        - The input UTXOs and output UTXOs are valid in terms of obeying mass conservation rules
///
///      Inherits {ZetoLockable} so the create/update/delegate/spend/
///      cancel lock lifecycle is shared with the fungible siblings via
///      a single implementation. The two ZK-circuit-shaped hooks
///      ({_doLockTransition} and {_transferLocked}) are overridden here
///      to match the NF circuit's fixed 1-in/1-out shape — there is no
///      input/output padding and no batch verifier path.
abstract contract ZetoNonFungible is ZetoLockable {
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
     * @param output The new UTXO to generate, for future transactions
     *      to spend.
     * @param proof A zero knowledge proof that the submitter is
     *      authorized to spend the input, and that the output is valid
     *      in terms of obeying mass conservation rules.
     * @param data Opaque data appended to the {UTXOTransfer} event for
     *      off-chain consumers.
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

    // ------------------------------------------------------------------
    // ZetoLockable hook overrides — non-fungible flavour.
    //
    // The NF circuits are fixed 1-in/1-out (or 1-in/1-locked-out for
    // create-lock, 1-locked-in/1-out for spend/cancel), so there is no
    // padding step and the batch-verifier path is never selected.
    //
    // Caller-supplied `args` are validated by ZetoLockable to be
    // {ZetoCreateLockArgs}/{ZetoSpendLockArgs}; this hook trusts that
    // shape and additionally enforces that the array sizes match the
    // NF circuit (single input plus a single locked or unlocked
    // output).
    // ------------------------------------------------------------------

    /// @dev Thrown when an NF lock-lifecycle call is invoked with an
    ///      input/output array shape that does not match the fixed
    ///      1-in/1-out circuit. Catching this at the contract layer
    ///      gives a typed revert before the proof verifier would fail
    ///      with a generic {InvalidProof}.
    error InvalidNonFungibleArity(
        uint256 inputs,
        uint256 outputs,
        uint256 lockedOutputs
    );

    function _doLockTransition(
        ZetoCreateLockArgs memory args
    ) internal override {
        // NF createLock: spend exactly one unlocked input and produce
        // exactly one locked output. There is no regular (unlocked)
        // output for NF lock creation — a single token cannot be split.
        if (
            args.inputs.length != 1 ||
            args.outputs.length != 0 ||
            args.lockedOutputs.length != 1
        ) {
            revert InvalidNonFungibleArity(
                args.inputs.length,
                args.outputs.length,
                args.lockedOutputs.length
            );
        }

        validateTransactionProposal(
            args.inputs,
            args.outputs,
            args.lockedOutputs,
            args.proof,
            false
        );

        // The circuit treats the locked output as the "output"; combine
        // for the public-inputs construction.
        uint256[] memory allOutputs = new uint256[](1);
        allOutputs[0] = args.lockedOutputs[0];

        (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        ) = constructPublicInputs(args.inputs, allOutputs, args.proof, false);
        verifyProof(proofStruct, publicInputs, false, false);

        processInputsAndOutputs(args.inputs, args.outputs, false);
        processLockedOutputs(args.lockedOutputs);
        // The freshly-locked output starts under the lock creator as
        // both owner and spender; record that on the per-UTXO
        // projection so {locked} can report it without a reverse lookup.
        _setLockDelegates(args.lockedOutputs, msg.sender);
    }

    function _transferLocked(
        bytes32 /* lockId */,
        uint256[] memory lockedInputs,
        uint256[] memory lockedOutputs,
        uint256[] memory outputs,
        bytes memory proof,
        bytes memory /* data */
    ) internal override {
        // NF spend/cancel: consume exactly one locked input and produce
        // exactly one output. The output may be either a regular
        // unlocked UTXO (the typical spend case) or a fresh locked UTXO
        // (e.g. re-lock under a new spender via cancel-then-create).
        if (
            lockedInputs.length != 1 ||
            lockedOutputs.length + outputs.length != 1
        ) {
            revert InvalidNonFungibleArity(
                lockedInputs.length,
                outputs.length,
                lockedOutputs.length
            );
        }

        validateTransactionProposal(
            lockedInputs,
            outputs,
            lockedOutputs,
            proof,
            true
        );

        // The circuit treats locked and unlocked outputs identically, so
        // both feed `constructPublicInputs` via the same single-element
        // `allOutputs` array.
        uint256[] memory allOutputs = new uint256[](1);
        allOutputs[0] = lockedOutputs.length == 1
            ? lockedOutputs[0]
            : outputs[0];

        (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        ) = constructPublicInputs(lockedInputs, allOutputs, proof, true);
        verifyProof(proofStruct, publicInputs, false, true);

        // Storage-side bookkeeping keeps the two ledgers strictly
        // disjoint: the unlocked output (if any) goes through
        // `processOutputs`, the locked output (if any) goes through
        // `processLockedOutputs`. Mirroring `_doLockTransition` here
        // avoids the locked-output being recorded as both unlocked and
        // locked, which would let it be spent twice (once via the
        // unlocked path, once via the lockable path).
        processInputsAndOutputs(lockedInputs, outputs, true);
        processLockedOutputs(lockedOutputs);
        // Any newly-locked output produced by this spend defaults to
        // the current spender as its delegate. (When `lockedOutputs` is
        // empty -- the common case -- this is a no-op.)
        _setLockDelegates(lockedOutputs, msg.sender);
    }
}

/// @dev ERC-7201 (`erc7201:zeto.storage.ZetoNonFungible`).
library ZetoNonFungibleStorage {
    struct Layout {
        uint256 __reserved;
    }

    bytes32 private constant STORAGE_LOCATION =
        0x70f918cef12f78aa293f0474363ccfa2a5e8bbdc86def1d4dd7d861fb8e6f600;

    function layout() internal pure returns (Layout storage $) {
        assembly {
            $.slot := STORAGE_LOCATION
        }
    }
}
