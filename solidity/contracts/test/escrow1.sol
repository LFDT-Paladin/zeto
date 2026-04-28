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
import {Zeto_Anon} from "../zeto_anon.sol";
import {ILockableCapability} from "../lib/interfaces/ILockableCapability.sol";
import {IZetoLockableCapability} from "../lib/interfaces/IZetoLockableCapability.sol";

/// @title zkEscrow1
/// @author Kaleido, Inc.
/// @notice Sample on-chain escrow built on top of {Zeto_Anon} that brokers a
///         payment between a payer and a payee using the new
///         {ILockableCapability} lifecycle.
///
///         Lifecycle of a single escrowed payment:
///           1. The payer calls {Zeto_Anon.createLock} to lock one or more
///              UTXOs they own. The payer is initially both the lock owner
///              and spender.
///           2. The payer calls {Zeto_Anon.delegateLock} naming this escrow
///              as the new spender. From this point on, only this escrow
///              can spend or cancel the lock.
///           3. The payer (or anyone) calls {initiatePayment} on this
///              escrow with the lockId and the proposed unlocked output
///              UTXOs. The escrow asserts it is the current spender of the
///              lock before recording the payment.
///           4. An authorised approver calls {approvePayment} with a ZK
///              proof attesting that `(lockedInputs, outputs)` is a valid
///              transition under {Zeto_Anon}'s circuit. The escrow stores
///              the proof but does not yet consume the lock.
///           5. Anyone (typically the payee) calls {completePayment}. The
///              escrow forwards the stored proof to {Zeto_Anon.spendLock},
///              which consumes the locked inputs and mints the unlocked
///              outputs to their recipients in a single atomic step.
///
///         Notes on the new lock model:
///           * The escrow does NOT choose the locked inputs at approval
///             or completion time. They are pinned by `_locks[lockId]`
///             inside {Zeto_Anon} at create-time, so "spending lock A
///             always consumes lock A's UTXOs" is a hard contract
///             invariant rather than a soft hash check on user-supplied
///             arrays.
///           * The escrow likewise does not choose `lockedOutputs` (it
///             always sends them empty); the spend completes by minting
///             plain unlocked UTXOs to the recipients.
contract zkEscrow1 {
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
        PaymentStatus status;
        bytes proof;
    }

    mapping(uint256 => Payment) public payments;
    uint256 inflightCount;

    Zeto_Anon public zeto;

    event PaymentInitiated(
        uint256 paymentId,
        bytes32 lockId,
        uint256[] outputs,
        bytes data
    );
    event PaymentApproved(uint256 paymentId, bytes data);
    event PaymentCompleted(uint256 paymentId, bytes data);

    constructor(address zetoAddress) {
        zeto = Zeto_Anon(zetoAddress);
    }

    /// @notice Record a new escrowed payment against an existing lock.
    /// @dev    The escrow MUST already be the current spender of the lock
    ///         (the payer must have called {Zeto_Anon.delegateLock} naming
    ///         this contract as the new spender before calling here).
    ///         The locked inputs themselves are not stored on the
    ///         payment; they are read fresh from {Zeto_Anon.getLockedInputs}
    ///         at approval and completion time so the escrow always
    ///         operates on the lock's storage-pinned content.
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
            PaymentStatus.INITIATED,
            emptyProof
        );
        emit PaymentInitiated(inflightCount, lockId, outputs, data);
    }

    /// @notice Verify the spend ZK proof for an initiated payment and
    ///         move the payment into the APPROVED state.
    /// @dev    The verification mirrors what {Zeto_Anon._transferLocked}
    ///         would do later (same {checkAndPadCommitments} + locked-input
    ///         verifier path), so a successful approval here guarantees
    ///         that {completePayment} will not revert on proof grounds.
    function approvePayment(
        uint256 paymentId,
        bytes memory proof,
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

    /// @notice Forward the approved spend proof to {Zeto_Anon.spendLock}.
    /// @dev    Encodes the {IZetoLockableCapability.ZetoSpendLockArgs}
    ///         payload from `payment` and invokes `spendLock(lockId, ...)`
    ///         as the lock's current spender. After this call returns the
    ///         lock is consumed, the locked UTXOs are marked spent on the
    ///         underlying Zeto storage, and the unlocked outputs are
    ///         emitted to their recipients.
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
