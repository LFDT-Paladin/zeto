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

import {IGroth16Verifier} from "./IZetoVerifier.sol";

interface IZetoInitializable {
    struct VerifiersInfo {
        IGroth16Verifier verifier;
        IGroth16Verifier depositVerifier;
        IGroth16Verifier withdrawVerifier;
        IGroth16Verifier lockVerifier;
        IGroth16Verifier burnVerifier;
        IGroth16Verifier batchVerifier;
        IGroth16Verifier batchWithdrawVerifier;
        IGroth16Verifier batchLockVerifier;
        IGroth16Verifier batchBurnVerifier;
    }

    function initialize(
        string calldata name,
        string calldata symbol,
        address initialOwner,
        VerifiersInfo calldata verifiersInfo
    ) external;
}
