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

import {Commonlib} from "../lib/common/common.sol";
import {Zeto_AnonNullifier} from "../zeto_anon_nullifier.sol";
import {ILockableCapability} from "../lib/interfaces/ILockableCapability.sol";
import {IZetoLockableCapability} from "../lib/interfaces/IZetoLockableCapability.sol";

/// @title zkEscrow2
/// @author Kaleido, Inc.
/// @notice Sample on-chain escrow built on top of {Zeto_AnonNullifier},
///         the nullifier-based fungible Zeto token. The escrow flow is
///         identical to {zkEscrow1} (see that contract for a step-by-step
///         description); the only difference is that the underlying token
///         consumes its locked inputs as **raw UTXO hashes** under the
///         locked-input verifier rather than as nullifiers.
///
///         The {checkAndPadCommitments} +
///         {constructPublicSignalsAndVerifyProof} pair handles both
///         flavours uniformly via the `inputsLocked=true` flag, so this
///         escrow does not need a different proof-shaping path from
///         {zkEscrow1}; it just talks to a different token.
contract zkEscrow2 {
    enum PaymentStatus {
        UNKNOWN, // default value for empty payment slots
        INITIATED,
        APPROVED,
        COMPLETED,
        CANCELLED
    }

    struct Payment {
        bytes32 lockId;
        uint256[] outputs;
        bytes proof;
        PaymentStatus status;
    }

    mapping(uint256 => Payment) public payments;
    uint256 inflightCount;

    Zeto_AnonNullifier public zeto;

    event PaymentInitiated(
        uint256 paymentId,
        bytes32 lockId,
        uint256[] outputs,
        bytes data
    );
    event PaymentApproved(uint256 paymentId, bytes data);
    event PaymentCompleted(uint256 paymentId, bytes data);

    constructor(address zetoAddress) {
        zeto = Zeto_AnonNullifier(zetoAddress);
    }

    /// @notice Record a new escrowed payment against an existing lock.
    /// @dev    See {zkEscrow1.initiatePayment} for the rationale on
    ///         requiring `info.spender == address(this)` instead of any
    ///         caller-provided delegate parameter.
    function initiatePayment(
        bytes32 lockId,
        uint256[] memory outputs,
        bytes calldata data
    ) public {
        ILockableCapability.LockInfo memory info = zeto.getLock(lockId);
        require(info.spender == address(this), "Escrow is not the spender");
        inflightCount++;
        bytes memory emptyProof;
        payments[inflightCount] = Payment(
            lockId,
            outputs,
            emptyProof,
            PaymentStatus.INITIATED
        );
        emit PaymentInitiated(inflightCount, lockId, outputs, data);
    }

    /// @notice Verify the spend ZK proof for an initiated payment.
    /// @dev    The locked inputs are read fresh from
    ///         {Zeto_AnonNullifier.getLockedInputs} so that the verifier
    ///         sees the same array {Zeto_AnonNullifier} will use during
    ///         {spendLock} downstream. For nullifier tokens these are raw
    ///         UTXO hashes (not nullifiers): see
    ///         {Zeto_AnonNullifier.constructPublicInputs}'s
    ///         `inputsLocked` branch for the public-inputs layout.
    function approvePayment(
        uint256 paymentId,
        bytes calldata proof,
        bytes calldata data
    ) public {
        Payment storage payment = payments[paymentId];
        require(
            payment.status == PaymentStatus.INITIATED,
            "Payment not initiated"
        );
        uint256[] memory lockedInputs = zeto.getLockedInputs(payment.lockId);
        (
            uint256[] memory paddedInputs,
            uint256[] memory paddedOutputs
        ) = zeto.checkAndPadCommitments(lockedInputs, payment.outputs);
        require(
            zeto.constructPublicSignalsAndVerifyProof(
                paddedInputs,
                paddedOutputs,
                proof,
                true
            ),
            "Invalid proof"
        );
        payment.proof = proof;
        payment.status = PaymentStatus.APPROVED;
        emit PaymentApproved(paymentId, data);
    }

    /// @notice Forward the approved spend proof to
    ///         {Zeto_AnonNullifier.spendLock}. After this returns the lock
    ///         is consumed, the locked UTXOs are marked spent on the
    ///         underlying nullifier storage, and the unlocked outputs are
    ///         appended to the regular commitments tree.
    function completePayment(uint256 paymentId, bytes calldata data) public {
        Payment storage payment = payments[paymentId];
        require(
            payment.status == PaymentStatus.APPROVED,
            "Payment not approved"
        );
        IZetoLockableCapability.ZetoSpendLockArgs
            memory spendArgs = IZetoLockableCapability.ZetoSpendLockArgs({
                txId: bytes32(paymentId),
                lockedOutputs: new uint256[](0),
                outputs: payment.outputs,
                proof: payment.proof,
                data: ""
            });
        zeto.spendLock(payment.lockId, abi.encode(spendArgs), "");
        payment.status = PaymentStatus.COMPLETED;
        emit PaymentCompleted(paymentId, data);
    }
}
