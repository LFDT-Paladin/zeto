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

import {Arrays} from "@openzeppelin/contracts/utils/Arrays.sol";
import {PoseidonUnit3L} from "@iden3/contracts/contracts/lib/Poseidon.sol";

library Util {
    function sortCommitments(
        uint256[] memory utxos
    ) internal pure returns (uint256[] memory) {
        uint256[] memory sorted = new uint256[](utxos.length);
        for (uint256 i = 0; i < utxos.length; ++i) {
            sorted[i] = utxos[i];
        }
        sorted = Arrays.sort(sorted);
        return sorted;
    }

    function getLeafNodeHash(
        uint256 index,
        uint256 value
    ) internal pure returns (uint256) {
        uint256[3] memory params = [index, value, uint256(1)];
        return PoseidonUnit3L.poseidon(params);
    }
}
