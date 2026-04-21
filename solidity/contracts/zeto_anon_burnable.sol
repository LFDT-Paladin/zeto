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

import {IZetoInitializable} from "./lib/interfaces/izeto_initializable.sol";
import {Zeto_Anon} from "./zeto_anon.sol";
import {ZetoFungibleBurnable} from "./lib/zeto_fungible_burn.sol";
import {Commonlib} from "./lib/common/common.sol";
import {ZetoCommon} from "./lib/zeto_common.sol";

/// @title A sample implementation of a Zeto based fungible token with
///        anonymity, no encryption, and {burn} support.
/// @author Kaleido, Inc.
/// @dev The transfer proof has the following statements:
///        - each value in the output commitments must be a positive number in the range 0 ~ (2\*\*40 - 1)
///        - the sum of the input values match the sum of output values
///        - the hashes in the input and output match the `hash(value, salt, owner public key)` formula
///        - the sender possesses the private BabyJubjub key, whose public key is part of the pre-image of the input commitment hashes
///
///      The burn proof has the analogous statements with the output side
///      collapsed to a single remainder commitment.
///
///      Composes {Zeto_Anon} (transfer + lock lifecycle) with
///      {ZetoFungibleBurnable} (burn entry point). Both base paths converge
///      on the abstract {ZetoCommon.constructPublicInputs} hook, so this
///      leaf contract must explicitly disambiguate the override; it simply
///      forwards to {Zeto_Anon}'s implementation, which is the same proof
///      layout used for both unlocked transfers and the locked-input spend
///      flow inherited from {ZetoFungible}.
///
///      Unlike the pre-{ILockableCapability} version, there is no longer a
///      separate `constructPublicInputsForLock` hook to override; the lock
///      lifecycle now reuses {constructPublicInputs} with `inputsLocked = true`.
contract Zeto_AnonBurnable is Zeto_Anon, ZetoFungibleBurnable {
    function initialize(
        string calldata name,
        string calldata symbol,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers
    ) public override initializer {
        __ZetoAnon_init(name, symbol, initialOwner, verifiers);
        __ZetoFungibleBurnable_init(
            verifiers.burnVerifier,
            verifiers.batchBurnVerifier
        );
    }

    function constructPublicInputs(
        uint256[] memory inputs,
        uint256[] memory outputs,
        bytes memory proof,
        bool isLocked
    )
        internal
        view
        override(Zeto_Anon, ZetoCommon)
        returns (uint256[] memory, Commonlib.Proof memory)
    {
        return
            Zeto_Anon.constructPublicInputs(inputs, outputs, proof, isLocked);
    }
}
