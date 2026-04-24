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

import {Zeto_AnonNullifier} from "./zeto_anon_nullifier.sol";
import {Registry} from "./lib/registry.sol";
import {IZetoInitializable} from "./lib/interfaces/IZetoInitializable.sol";

/// @title A sample implementation of a Zeto based fungible token with
///        anonymity, history masking via nullifiers, and KYC enforcement.
/// @author Kaleido, Inc.
/// @notice Decimals: this token uses **4** decimals, inherited from
///         {ZetoCommon.decimals}. Indexers and UIs reading this contract
///         directly should treat balances accordingly.
/// @dev The proof has the following statements:
///        - each value in the output commitments must be a positive number in the range 0 ~ (2\*\*40 - 1)
///        - the sum of the nullified values match the sum of output values
///        - the hashes in the input and output match the hash(value, salt, owner public key) formula
///        - the sender possesses the private BabyJubjub key, whose public key is part of the pre-image of the input commitment hashes, which match the corresponding nullifiers
///        - the nullifiers represent input commitments that are included in a Sparse Merkle Tree represented by the root hash
///        - the input/output owners are members of the {Registry}'s identities tree
///
///      The {extraInputs} / {extraInputsForDeposit} overrides surface the
///      identities tree's root as an additional public input to the
///      transfer / deposit circuits, which is what wires KYC enforcement
///      into the same proof system used for value conservation.
contract Zeto_AnonNullifierKyc is Zeto_AnonNullifier, Registry {
    /// @dev Lock the implementation contract on construction. The parent
    ///      {Zeto_AnonNullifier} already does this via its own constructor
    ///      (which Solidity invokes as part of every leaf's deployment),
    ///      but we restate it here so the H-2 protection survives any
    ///      future refactor that changes the inheritance graph.
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        string calldata name,
        string calldata symbol,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers
    ) public override initializer {
        __ZetoAnonNullifier_init(name, symbol, initialOwner, verifiers);
        __Registry_init();
    }

    function extraInputs() internal view override returns (uint256[] memory) {
        uint256[] memory extras = new uint256[](1);
        extras[0] = getIdentitiesRoot();
        return extras;
    }

    function extraInputsForDeposit()
        internal
        view
        override
        returns (uint256[] memory)
    {
        uint256[] memory extras = new uint256[](1);
        extras[0] = getIdentitiesRoot();
        return extras;
    }
}
