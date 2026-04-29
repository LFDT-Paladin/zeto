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

import {IGroth16Verifier} from "./interfaces/IZetoVerifier.sol";
import {IZetoInitializable} from "./interfaces/IZetoInitializable.sol";
import {IZetoLockableCapability} from "./interfaces/IZetoLockableCapability.sol";
import {Commonlib} from "./common/common.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {ZetoLockable} from "./zeto_lockable.sol";
import {IZetoStorage} from "./interfaces/IZetoStorage.sol";

/// @title A sample implementation of a base Zeto fungible token contract
/// @author Kaleido, Inc.
/// @dev Adds the ERC20-backed deposit/withdraw lifecycle and a multi-input
///      {transfer} flow on top of the lock-aware {ZetoLockable} base.
///
///      The lock-lifecycle plumbing (state, modifiers, external entry
///      points, views) lives in {ZetoLockable}; this contract supplies
///      only the two ZK-circuit-shaped hooks
///      ({_doLockTransition} and {_transferLocked}) that pad
///      inputs/outputs to the next supported batch size before
///      {constructPublicInputs}.
///
///      Inherits {ReentrancyGuardUpgradeable} so that {deposit} and
///      {withdraw}, which perform external ERC20 transfers, are
///      protected from reentrant calls (defense-in-depth on top of the
///      checks-effects-interactions ordering enforced inside those
///      functions).
abstract contract ZetoFungible is ZetoLockable, ReentrancyGuardUpgradeable {
    using SafeERC20 for IERC20;

    /// @dev Emitted when {setERC20} successfully binds the backing
    ///      ERC20. Indexed by the new token address so subscribers can
    ///      filter.
    event ERC20Set(address indexed erc20);

    /// @dev Thrown when {setERC20} is called with the zero address.
    error ZeroERC20Address();

    /// @dev Thrown when {setERC20} is called after the backing ERC20
    ///      has already been bound. {setERC20} is one-shot: once a
    ///      Zeto contract is paired with an ERC20, that pairing is
    ///      permanent for the lifetime of the proxy. This protects
    ///      depositors from having their backing token rug-pulled out
    ///      from under existing UTXOs.
    error ERC20AlreadySet(address current);

    /// @dev Deposit / withdraw verifiers and ERC20 pairing live in
    ///      {ZetoFungibleStorage} (ERC-7201 namespace `zeto.storage.ZetoFungible`).

    /// @dev Initializer should only ever be called from a derived
    ///      contract's own `initializer`-guarded entrypoint, so the
    ///      `internal` visibility prevents external poking of the
    ///      lifecycle on a partially-initialized proxy.
    function __ZetoFungible_init(
        string calldata name_,
        string calldata symbol_,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers,
        IZetoStorage storage_
    ) internal onlyInitializing {
        __ZetoCommon_init(name_, symbol_, initialOwner, verifiers, storage_);
        __ReentrancyGuard_init();
        ZetoFungibleStorage.Layout storage $ = ZetoFungibleStorage.layout();
        $.depositVerifier = verifiers.depositVerifier;
        $.withdrawVerifier = verifiers.withdrawVerifier;
        $.batchWithdrawVerifier = verifiers.batchWithdrawVerifier;
    }

    /**
     * @dev Bind the ERC20 token that this Zeto contract will interact
     *      with for {deposit} and {withdraw}. One-shot: a subsequent
     *      call reverts with {ERC20AlreadySet}.
     *
     *      Rationale: depositors trust that the asset backing their
     *      UTXOs is stable for the lifetime of the contract. Letting
     *      the owner swap the backing ERC20 after deposits exist would
     *      let them silently change what `withdraw` pays out. Making
     *      this one-shot removes that vector entirely while still
     *      allowing the operator to wire up the pairing post-deployment.
     *
     * @param erc20 The ERC20 token to be used. Must be non-zero.
     *
     * Emits {ERC20Set}.
     */
    function setERC20(IERC20 erc20) public onlyOwner {
        if (address(erc20) == address(0)) {
            revert ZeroERC20Address();
        }
        ZetoFungibleStorage.Layout storage $ = ZetoFungibleStorage.layout();
        if (address($.erc20Token) != address(0)) {
            revert ERC20AlreadySet(address($.erc20Token));
        }
        $.erc20Token = erc20;
        emit ERC20Set(address(erc20));
    }

    /**
     * @dev the main function of the contract, which transfers values from one account (represented by Babyjubjub public keys)
     *      to one or more receiver accounts (also represented by Babyjubjub public keys). One of the two nullifiers may be zero
     *      if the transaction only needs one UTXO to be spent. Equally one of the two outputs may be zero if the transaction
     *      only needs to create one new UTXO.
     *
     * @param inputs Array of nullifiers that are secretly bound to UTXOs to be spent by the transaction.
     * @param outputs Array of new UTXOs to generate, for future transactions to spend.
     * @param proof A zero knowledge proof that the submitter is authorized to spend the inputs, and
     *      that the outputs are valid in terms of obeying mass conservation rules.
     *
     * Emits a {UTXOTransfer} event.
     */
    function transfer(
        uint256[] calldata inputs,
        uint256[] calldata outputs,
        bytes calldata proof,
        bytes calldata data
    ) public virtual {
        uint256[] memory lockedOutputs;
        validateTransactionProposal(
            inputs,
            outputs,
            lockedOutputs,
            proof,
            false
        );
        // Check and pad commitments
        (
            uint256[] memory paddedInputs,
            uint256[] memory paddedOutputs
        ) = checkAndPadCommitments(inputs, outputs);
        // construct the public inputs for the proof verification
        (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        ) = constructPublicInputs(paddedInputs, paddedOutputs, proof, false);
        bool isBatch = (inputs.length > 2 || outputs.length > 2);
        verifyProof(proofStruct, publicInputs, isBatch, false);
        processInputsAndOutputs(paddedInputs, paddedOutputs, false);

        emitTransferEvent(inputs, outputs, proof, data);
    }

    // ------------------------------------------------------------------
    // ZetoLockable hook overrides — fungible flavour pads inputs and
    // outputs to the next supported batch size before constructing the
    // public-inputs array.
    // ------------------------------------------------------------------

    function _doLockTransition(
        ZetoCreateLockArgs memory args
    ) internal override {
        validateTransactionProposal(
            args.inputs,
            args.outputs,
            args.lockedOutputs,
            args.proof,
            false
        );

        // Combine the locked outputs and the regular outputs because the
        // circuits do not differentiate them.
        uint256[] memory allOutputs = new uint256[](
            args.lockedOutputs.length + args.outputs.length
        );
        for (uint256 i = 0; i < args.lockedOutputs.length; i++) {
            allOutputs[i] = args.lockedOutputs[i];
        }
        for (uint256 i = 0; i < args.outputs.length; i++) {
            allOutputs[args.lockedOutputs.length + i] = args.outputs[i];
        }

        (
            uint256[] memory paddedInputs,
            uint256[] memory paddedOutputs
        ) = checkAndPadCommitments(args.inputs, allOutputs);

        (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        ) = constructPublicInputs(
                paddedInputs,
                paddedOutputs,
                args.proof,
                false
            );

        bool isBatch = (paddedInputs.length > 2 ||
            args.outputs.length > 2 ||
            args.lockedOutputs.length > 2);
        verifyProof(proofStruct, publicInputs, isBatch, false);

        processInputsAndOutputs(paddedInputs, args.outputs, false);
        processLockedOutputs(args.lockedOutputs);
        // The freshly-locked outputs all start under the lock creator
        // as both owner and spender; record that on the per-UTXO
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
        validateTransactionProposal(
            lockedInputs,
            outputs,
            lockedOutputs,
            proof,
            true
        );
        // combine the locked outputs and the outputs, because the
        // circuits do not care about the difference between locked and
        // unlocked outputs
        uint256[] memory allOutputs = new uint256[](
            lockedOutputs.length + outputs.length
        );
        for (uint256 i = 0; i < lockedOutputs.length; i++) {
            allOutputs[i] = lockedOutputs[i];
        }
        for (uint256 i = 0; i < outputs.length; i++) {
            allOutputs[lockedOutputs.length + i] = outputs[i];
        }
        // Check and pad inputs and outputs based on the max size
        (
            uint256[] memory paddedInputs,
            uint256[] memory paddedOutputs
        ) = checkAndPadCommitments(lockedInputs, allOutputs);
        // construct the public inputs for the proof verification
        (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        ) = constructPublicInputs(paddedInputs, paddedOutputs, proof, true);
        bool isBatch = (lockedInputs.length > 2 || allOutputs.length > 2);
        verifyProof(proofStruct, publicInputs, isBatch, true);
        processInputsAndOutputs(paddedInputs, paddedOutputs, true);
        processLockedOutputs(lockedOutputs);
        // Any newly-locked outputs produced by this spend default to the
        // current spender as their delegate. (When `lockedOutputs` is
        // empty -- the common case -- this is a no-op.)
        _setLockDelegates(lockedOutputs, msg.sender);
    }

    /**
     * @dev Deposit ERC20 tokens into the Zeto contract.
     *
     * @param amount The amount of ERC20 tokens to be deposited.
     * @param outputs The UTXOs to be minted.
     * @param proof The proof of the deposit.
     * @param data Additional data to be passed to the deposit function.
     *
     * Emits a {UTXOMint} event.
     */
    function deposit(
        uint256 amount,
        uint256[] calldata outputs,
        bytes calldata proof,
        bytes calldata data
    ) public nonReentrant {
        // ---- Checks ----
        validateOutputs(outputs);

        // verifies that the output UTXOs match the claimed value
        // to be deposited
        (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        ) = constructPublicInputsForDeposit(amount, outputs, proof);
        if (
            !ZetoFungibleStorage.layout().depositVerifier.verify(
                proofStruct.pA,
                proofStruct.pB,
                proofStruct.pC,
                publicInputs
            )
        ) {
            revert InvalidProof();
        }

        // ---- Effects ----
        // Mint the UTXOs (commits the new outputs to storage and emits
        // {UTXOMint}) before the external ERC20 call. This ensures that
        // any reentrant call into this contract triggered by the ERC20
        // transfer observes the new outputs as already-committed and
        // cannot replay them.
        _mint(outputs, data);

        // ---- Interactions ----
        // SafeERC20 handles non-standard tokens that return no value on
        // success and reverts cleanly when the underlying call fails or
        // returns false.
        ZetoFungibleStorage.layout().erc20Token.safeTransferFrom(
            msg.sender,
            address(this),
            amount
        );
    }

    /**
     * @dev Withdraw ERC20 tokens from the Zeto contract.
     *
     * @param amount The amount of ERC20 tokens to be withdrawn.
     * @param inputs The UTXOs to be spent.
     * @param output The UTXO to be minted.
     * @param proof The proof of the withdrawal.
     * @param data Additional data to be passed to the withdrawal
     *      function.
     *
     * Emits a {UTXOWithdraw} event.
     */
    function withdraw(
        uint256 amount,
        uint256[] calldata inputs,
        uint256 output,
        bytes calldata proof,
        bytes calldata data
    ) public nonReentrant {
        uint256[] memory outputs = new uint256[](1);
        outputs[0] = output;
        uint256[] memory lockedOutputs;

        // ---- Checks ----
        validateTransactionProposal(
            inputs,
            outputs,
            lockedOutputs,
            proof,
            false
        );
        // Check and pad inputs and outputs based on the max size
        (
            uint256[] memory paddedInputs,
            uint256[] memory paddedOutputs
        ) = checkAndPadCommitments(inputs, outputs);
        (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        ) = constructPublicInputsForWithdraw(
                amount,
                paddedInputs,
                output,
                proof
            );
        ZetoFungibleStorage.Layout storage $ = ZetoFungibleStorage.layout();
        IGroth16Verifier verifier = (inputs.length > 2)
            ? $.batchWithdrawVerifier
            : $.withdrawVerifier;
        if (
            !verifier.verify(
                proofStruct.pA,
                proofStruct.pB,
                proofStruct.pC,
                publicInputs
            )
        ) {
            revert InvalidProof();
        }

        // ---- Effects ----
        // Mark the input nullifiers as spent and commit the
        // change-output before performing the external ERC20 transfer.
        // Following checks-effects-interactions ensures a callback-style
        // ERC20 cannot re-enter and double-spend the same nullifiers.
        processInputsAndOutputs(paddedInputs, paddedOutputs, false);

        // ---- Interactions ----
        // SafeERC20 handles non-standard tokens that return no value on
        // success and reverts cleanly when the underlying call fails or
        // returns false.
        ZetoFungibleStorage.layout().erc20Token.safeTransfer(
            msg.sender,
            amount
        );

        // Emitted after the transfer so that the on-chain event order
        // remains ERC20.Transfer → UTXOWithdraw, matching listeners and
        // tests built before the CEI reorder. Event emission is a pure
        // log and does not affect security; the nullifier state was
        // already committed above.
        emit UTXOWithdraw(amount, inputs, output, msg.sender, data);
    }

    function emitTransferEvent(
        uint256[] memory inputs,
        uint256[] memory outputs,
        bytes memory proof,
        bytes memory data
    ) internal virtual {
        emit UTXOTransfer(inputs, outputs, msg.sender, data);
    }

    // this is a utility function that constructs the public inputs for a proof of a deposit() call.
    // specific implementations of this function may be overridden by each token implementation
    function constructPublicInputsForDeposit(
        uint256 amount,
        uint256[] memory outputs,
        bytes memory proof
    ) public virtual returns (uint256[] memory, Commonlib.Proof memory) {
        Commonlib.Proof memory proofStruct = abi.decode(
            proof,
            (Commonlib.Proof)
        );
        // construct the public inputs
        uint256[] memory extra = extraInputsForDeposit();
        uint256[] memory publicInputs = new uint256[](3 + extra.length);
        publicInputs[0] = amount;
        publicInputs[1] = outputs[0];
        publicInputs[2] = outputs[1];
        for (uint256 i = 0; i < extra.length; i++) {
            publicInputs[3 + i] = extra[i];
        }

        return (publicInputs, proofStruct);
    }

    function extraInputsForDeposit()
        internal
        view
        virtual
        returns (uint256[] memory)
    {
        return new uint256[](0);
    }

    // this is a utility function that constructs the public inputs for a proof of a withdraw() call.
    // specific implementations of this function may be overridden by each token implementation
    function constructPublicInputsForWithdraw(
        uint256 amount,
        uint256[] memory inputs,
        uint256 output,
        bytes memory proof
    ) internal virtual returns (uint256[] memory, Commonlib.Proof memory) {
        Commonlib.Proof memory proofStruct = abi.decode(
            proof,
            (Commonlib.Proof)
        );
        uint256 size = (inputs.length + 1 + 1); // inputs, output, and amount

        uint256[] memory publicInputs = new uint256[](size);
        uint256 piIndex = 0;

        // copy output amount
        publicInputs[piIndex++] = amount;

        // copy input commitments
        for (uint256 i = 0; i < inputs.length; i++) {
            publicInputs[piIndex++] = inputs[i];
        }

        // copy output commitment
        publicInputs[piIndex++] = output;

        return (publicInputs, proofStruct);
    }
}

/// @dev ERC-7201 (`erc7201:zeto.storage.ZetoFungible`): deposit/withdraw verifiers
///      and ERC20 pairing for this abstract contract.
library ZetoFungibleStorage {
    struct Layout {
        IGroth16Verifier depositVerifier;
        IGroth16Verifier withdrawVerifier;
        IGroth16Verifier batchWithdrawVerifier;
        IERC20 erc20Token;
    }

    bytes32 private constant STORAGE_LOCATION =
        0x502fd05a4212f6b786ff372127438db29bf1c676e6268e59ca1feb2fae998d00;

    function layout() internal pure returns (Layout storage $) {
        assembly {
            $.slot := STORAGE_LOCATION
        }
    }
}
