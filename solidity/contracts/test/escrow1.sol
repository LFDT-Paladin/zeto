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

/// @title A sample on-chain implementation of an escrow contract using Zeto tokens
/// @author Kaleido, Inc.
/// @dev Implements escrow based payment flows with Zeto_Anon tokens
contract zkEscrow1 {
    enum PaymentStatus {
        UNKNOWN, // this is the default value for the empty payment slots
        INITIATED,
        APPROVED,
        COMPLETED,
        CANCELLED
    }

    struct Payment {
        uint256[] lockedInputs;
        uint256[] outputs;
        PaymentStatus status;
        bytes proof;
    }

    mapping(uint256 => Payment) public payments;
    uint256 inflightCount;

    Zeto_Anon public zeto;

    event PaymentInitiated(
        uint256 paymentId,
        uint256[] lockedInputs,
        uint256[] outputs,
        bytes data
    );
    event PaymentApproved(uint256 paymentId, bytes data);
    event PaymentCompleted(uint256 paymentId, bytes data);

    constructor(address zetoAddress) {
        zeto = Zeto_Anon(zetoAddress);
    }

    function initiatePayment(
        uint256[] memory lockedInputs,
        uint256[] memory outputs,
        bytes calldata data
    ) public {
        for (uint256 i = 0; i < lockedInputs.length; i++) {
            (bool isLocked, address currentDelegate) = zeto.locked(
                lockedInputs[i]
            );
            require(isLocked, "Input not locked");
            require(currentDelegate == address(this), "Not lock delegate");
        }
        inflightCount++;
        bytes memory emptyProof;
        payments[inflightCount] = Payment(
            lockedInputs,
            outputs,
            PaymentStatus.INITIATED,
            emptyProof
        );
        emit PaymentInitiated(inflightCount, lockedInputs, outputs, data);
    }

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
        (payment.lockedInputs, payment.outputs) = zeto.checkAndPadCommitments(
            payment.lockedInputs,
            payment.outputs
        );
        require(
            zeto.constructPublicSignalsAndVerifyProof(
                payment.lockedInputs,
                payment.outputs,
                proof,
                true
            ),
            "Invalid proof"
        );
        payment.proof = proof;
        payment.status = PaymentStatus.APPROVED;
        emit PaymentApproved(paymentId, data);
    }

    function completePayment(uint256 paymentId, bytes calldata data) public {
        Payment storage payment = payments[paymentId];
        require(
            payment.status == PaymentStatus.APPROVED,
            "Payment not approved"
        );
        uint256[] memory lockedOutputs;
        zeto.transferLocked(
            payment.lockedInputs,
            lockedOutputs,
            payment.outputs,
            payment.proof,
            "0x"
        );
        payment.status = PaymentStatus.COMPLETED;
        emit PaymentCompleted(paymentId, data);
    }
}
