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

pragma solidity >=0.7.0 <0.9.0;

import {Verifier_AnonNullifierKycTransferLockedBatch} from "./impl/anon_nullifier_kyc_transferLocked_batch.sol";

contract Groth16Verifier_AnonNullifierKycTransferLockedBatch is
    Verifier_AnonNullifierKycTransferLockedBatch
{
    function verify(
        uint[2] calldata _pA,
        uint[2][2] calldata _pB,
        uint[2] calldata _pC,
        uint[] calldata _pubSignals
    ) public view returns (bool) {
        uint256[21] memory fixedSizeInputs;
        for (uint256 i = 0; i < fixedSizeInputs.length; i++) {
            fixedSizeInputs[i] = _pubSignals[i];
        }
        return this.verifyProof(_pA, _pB, _pC, fixedSizeInputs);
    }
}
