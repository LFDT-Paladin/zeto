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

import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {SmtLib} from "@iden3/contracts/contracts/lib/SmtLib.sol";
import {PoseidonHasher} from "@iden3/contracts/contracts/lib/hash/PoseidonHasher.sol";
import {PoseidonUnit2L, PoseidonUnit3L} from "@iden3/contracts/contracts/lib/Poseidon.sol";
import {MAX_SMT_DEPTH} from "./interfaces/IZeto.sol";
import {IZetoKyc} from "./interfaces/IZetoKyc.sol";

/// @title A sample on-chain implementation of a KYC registry
/// @author Kaleido, Inc.
/// @dev The registry uses a Sparse Merkle Tree to store the
///   Zeto accounts (Babyjubjub keys), so that transaction
///   submitters can generate proofs of membership for the
///   accounts in a privacy-preserving manner.
///
///   Mixed into KYC-aware concrete tokens (e.g. {Zeto_AnonNullifierKyc})
///   so that those tokens can expose `register`/`isRegistered` and
///   contribute the identities tree's root as an additional public input
///   to the transfer/deposit ZK circuits via the inheriting token's
///   {extraInputs}/{extraInputsForDeposit} overrides.
///
///   Inherits {Ownable2StepUpgradeable} (rather than the simpler
///   {OwnableUpgradeable}) so that the diamond formed when this mixin is
///   composed with a token that already inherits {ZetoCommon}, which is
///   itself {Ownable2StepUpgradeable}, resolves cleanly: both branches of
///   the inheritance graph reach `transferOwnership`/`_transferOwnership`
///   through the same {Ownable2StepUpgradeable} implementation, so no
///   leaf-level override is required. The Ownable initialization itself
///   is performed once by the token's `__ZetoCommon_init`; the Registry
///   initializer only needs to set up the SMT.
abstract contract Registry is Ownable2StepUpgradeable, IZetoKyc {
    SmtLib.Data internal _publicKeysTree;
    using SmtLib for SmtLib.Data;

    /// @dev Reserved storage to allow new state variables to be added in
    ///      future upgrades of this mixin without shifting the storage
    ///      layout of inheriting contracts. The {SmtLib.Data} struct
    ///      itself is upgrade-stable, but additional bookkeeping (e.g.
    ///      issuer attestations, revocation lists) may need to be added
    ///      later. Sized at 50 slots, matching the OpenZeppelin
    ///      upgradeable convention.
    uint256[50] private __gap;

    /// @dev Thrown by {register} when the supplied public key is already
    ///      a member of the identities tree.
    error AlreadyRegistered(uint256[2] publicKey);

    /// @dev Internal-only so it can only be called from a derived
    ///      contract's own `initializer`-guarded entrypoint.
    function __Registry_init() internal onlyInitializing {
        _publicKeysTree.initialize(MAX_SMT_DEPTH);
        _publicKeysTree.setHasher(new PoseidonHasher());
    }

    /**
     * @dev Register a new Zeto account.
     * @param publicKey The public Babyjubjub key to register.
     * @param data Opaque off-chain correlation data appended to the
     *             {IdentityRegistered} event.
     *
     * Emits an {IdentityRegistered} event.
     */
    function register(
        uint256[2] calldata publicKey,
        bytes calldata data
    ) public onlyOwner {
        _register(publicKey, data);
    }

    /**
     * @dev Returns whether the given public key is registered.
     * @param publicKey The Babyjubjub public key to check.
     */
    function isRegistered(
        uint256[2] calldata publicKey
    ) public view returns (bool) {
        uint256 nodeKey = _getIdentitiesLeafNodeKey(publicKey);
        SmtLib.Node memory node = _publicKeysTree.getNode(nodeKey);
        return node.nodeType != SmtLib.NodeType.EMPTY;
    }

    /**
     * @dev Returns the root of the identities tree. This is contributed as
     *      an extra public input to the transfer / deposit circuits in
     *      KYC-aware token contracts via {extraInputs}.
     */
    function getIdentitiesRoot() public view returns (uint256) {
        return _publicKeysTree.getRoot();
    }

    function _register(
        uint256[2] calldata publicKey,
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
        uint256[2] calldata publicKey
    ) internal pure returns (uint256) {
        return PoseidonUnit2L.poseidon(publicKey);
    }

    function _getIdentitiesLeafNodeKey(
        uint256[2] calldata publicKey
    ) internal pure returns (uint256) {
        uint256 nodeHash = PoseidonUnit2L.poseidon(publicKey);
        uint256[3] memory params = [nodeHash, nodeHash, uint256(1)];
        return PoseidonUnit3L.poseidon(params);
    }
}
