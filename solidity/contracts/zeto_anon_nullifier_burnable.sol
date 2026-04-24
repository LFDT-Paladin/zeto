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

import {IZetoInitializable} from "./lib/interfaces/IZetoInitializable.sol";
import {Zeto_AnonNullifier} from "./zeto_anon_nullifier.sol";
import {ZetoFungibleBurnableNullifier} from "./lib/zeto_fungible_burn_nullifier.sol";
import {Commonlib} from "./lib/common/common.sol";
import {ZetoCommon} from "./lib/zeto_common.sol";

/// @title A sample implementation of a Zeto based fungible token with
///        anonymity, history masking via nullifiers, and {burn} support.
/// @author Kaleido, Inc.
/// @notice Decimals: this token uses **4** decimals, inherited from
///         {ZetoCommon.decimals}. Indexers and UIs reading this contract
///         directly should treat balances accordingly.
/// @dev The transfer proof has the following statements:
///        - each value in the output commitments must be a positive number in the range 0 ~ (2\*\*40 - 1)
///        - the sum of the nullified values match the sum of output values
///        - the hashes in the input and output match the hash(value, salt, owner public key) formula
///        - the sender possesses the private BabyJubjub key, whose public key is part of the pre-image of the input commitment hashes, which match the corresponding nullifiers
///        - the nullifiers represent input commitments that are included in a Sparse Merkle Tree represented by the root hash
///
///      The burn proof has the analogous statements with the output side
///      collapsed to a single remainder commitment.
///
///      Composes {Zeto_AnonNullifier} (transfer + lock lifecycle) with
///      {ZetoFungibleBurnableNullifier} (burn entry point). Both base
///      paths converge on the abstract {ZetoCommon.constructPublicInputs}
///      hook, so this leaf contract must explicitly disambiguate the
///      override; it simply forwards to {Zeto_AnonNullifier}'s
///      implementation, which is the same proof layout used for both
///      unlocked transfers and the locked-input spend flow inherited from
///      {ZetoFungible}.
///
///      Unlike the pre-{ILockableCapability} version, there is no longer a
///      separate `constructPublicInputsForLock` hook to override; the lock
///      lifecycle now reuses {constructPublicInputs} with `inputsLocked = true`.
contract Zeto_AnonNullifierBurnable is
    Zeto_AnonNullifier,
    ZetoFungibleBurnableNullifier
{
    /// @dev Lock the implementation contract on construction. The parent
    ///      {Zeto_AnonNullifier} already does this via its own constructor
    ///      (which Solidity invokes as part of every leaf's deployment),
    ///      but we restate it here so the H-2 protection survives any
    ///      future refactor that changes the inheritance graph.
    ///      `_disableInitializers()` is idempotent, so the duplicate call
    ///      is a harmless no-op.
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
        __ZetoFungibleBurnableNullifier_init(
            verifiers.burnVerifier,
            verifiers.batchBurnVerifier
        );
    }

    function constructPublicInputs(
        uint256[] memory inputs,
        uint256[] memory outputs,
        bytes memory proof,
        bool inputsLocked
    )
        internal
        override(Zeto_AnonNullifier, ZetoCommon)
        returns (uint256[] memory, Commonlib.Proof memory)
    {
        return
            Zeto_AnonNullifier.constructPublicInputs(
                inputs,
                outputs,
                proof,
                inputsLocked
            );
    }
}
