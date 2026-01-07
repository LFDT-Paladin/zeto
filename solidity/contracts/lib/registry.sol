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

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {SmtLib} from "@iden3/contracts/contracts/lib/SmtLib.sol";
import {PoseidonUnit2L, PoseidonUnit3L} from "@iden3/contracts/contracts/lib/Poseidon.sol";
import {Commonlib} from "./common.sol";
import {IZeto} from "./interfaces/izeto.sol";
import {IZetoKyc} from "./interfaces/izeto_kyc.sol";

uint256 constant MAX_SMT_DEPTH = 64;

/// @title A sample on-chain implementation of a KYC registry
/// @dev The registry uses a Sparse Merkle Tree to store the
///   Zeto accounts (Babyjubjub keys), so that transaction
///   submitters can generate proofs of membership for the
///   accounts in a privacy-preserving manner.
/// @author Kaleido, Inc.
abstract contract Registry is OwnableUpgradeable, IZetoKyc {
    SmtLib.Data internal _publicKeysTree;
    using SmtLib for SmtLib.Data;

    error AlreadyRegistered(uint256[2]);

    function __Registry_init() internal onlyInitializing {
        _publicKeysTree.initialize(MAX_SMT_DEPTH);
    }

    function register(
        uint256[2] memory publicKey,
        bytes calldata data
    ) public onlyOwner {
        _register(publicKey, data);
    }

    /// @dev returns whether the given public key is registered
    /// @param publicKey The Babyjubjub public key to check
    /// @return bool whether the given public key is included in the registry
    function isRegistered(
        uint256[2] memory publicKey
    ) public view returns (bool) {
        uint256 nodeKey = _getIdentitiesLeafNodeKey(publicKey);
        SmtLib.Node memory node = _publicKeysTree.getNode(nodeKey);
        return node.nodeType != SmtLib.NodeType.EMPTY;
    }

    function getIdentitiesRoot() public view returns (uint256) {
        return _publicKeysTree.getRoot();
    }

    /// @dev Register a new Zeto account
    /// @param publicKey The public Babyjubjub key to register
    function _register(
        uint256[2] memory publicKey,
        bytes calldata data
    ) internal {
        uint256 nodeHash = _getIdentitiesLeafNodeHash(publicKey);
        SmtLib.Node memory node = _publicKeysTree.getNode(nodeHash);
        if (node.nodeType != SmtLib.NodeType.EMPTY) {
            revert AlreadyRegistered(publicKey);
        }
        _publicKeysTree.addLeaf(nodeHash, nodeHash);
        emit IdentityRegistered(publicKey, data);
    }

    function _getIdentitiesLeafNodeHash(
        uint256[2] memory publicKey
    ) internal pure returns (uint256) {
        return PoseidonUnit2L.poseidon(publicKey);
    }

    function _getIdentitiesLeafNodeKey(
        uint256[2] memory publicKey
    ) internal pure returns (uint256) {
        uint256 nodeHash = PoseidonUnit2L.poseidon(publicKey);
        uint256[3] memory params = [nodeHash, nodeHash, uint256(1)];
        return PoseidonUnit3L.poseidon(params);
    }
}
