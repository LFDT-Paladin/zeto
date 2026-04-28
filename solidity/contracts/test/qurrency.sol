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

import {Groth16Verifier_AnonNullifierQurrencyTransfer} from "../verifiers/verifier_anon_nullifier_qurrency_transfer.sol";
import {Commonlib} from "../lib/common/common.sol";

/// @title TestVerifierQurrency
/// @notice Thin standalone wrapper around the
///         {Groth16Verifier_AnonNullifierQurrencyTransfer} verifier so that
///         its 48-element public-input signature can be exercised in
///         isolation, without dragging in the full {Zeto_AnonNullifierQurrency}
///         token. Useful for end-to-end ML-KEM payload tests where we need
///         to confirm the snarkjs proof matches what the on-chain verifier
///         expects, decoupled from token bookkeeping.
contract TestVerifierQurrency {
    Groth16Verifier_AnonNullifierQurrencyTransfer verifier;

    bool public lastSuccess = false;

    constructor() {
        verifier = new Groth16Verifier_AnonNullifierQurrencyTransfer();
    }

    function verifyProof(
        Commonlib.Proof memory proof,
        uint256[48] memory publicInputs
    ) public returns (bool) {
        bool result = verifier.verifyProof(
            proof.pA,
            proof.pB,
            proof.pC,
            publicInputs
        );
        lastSuccess = result;
        require(result, "Verification failed");
        return result;
    }
}
