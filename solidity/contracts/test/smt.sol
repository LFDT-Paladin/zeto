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

import {SmtLib} from "@iden3/contracts/contracts/lib/SmtLib.sol";
import {PoseidonUnit3L} from "@iden3/contracts/contracts/lib/Poseidon.sol";

// test ground for better understanding of the SmtLib library implementation
contract TestSmt {
    using SmtLib for SmtLib.Data;

    SmtLib.Data tree;

    constructor() {
        tree.initialize(10);
    }

    function insert(uint256 key, uint256 value) public {
        tree.addLeaf(key, value);
    }

    function get(
        uint256 key,
        uint256 value
    ) public view returns (SmtLib.Node memory) {
        uint256 nodeHash = getLeafNodeHash(key, value);
        SmtLib.Node memory node = tree.getNode(nodeHash);
        return node;
    }

    function getProof(uint256 key) public view returns (SmtLib.Proof memory) {
        SmtLib.Proof memory proof = tree.getProof(key);
        return proof;
    }

    function root() public view returns (uint256) {
        return tree.getRoot();
    }

    function getLeafNodeHash(
        uint256 index,
        uint256 value
    ) internal pure returns (uint256) {
        uint256[3] memory params = [index, value, uint256(1)];
        return PoseidonUnit3L.poseidon(params);
    }
}
