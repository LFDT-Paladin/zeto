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

import {ZetoFungibleBase} from "./lib/zeto_fungible_base.sol";
import {Commonlib} from "./lib/common/common.sol";
import {IZetoInitializable} from "./lib/interfaces/izeto_initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title A sample implementation of a Zeto based fungible token with anonymity and no encryption
/// @author Kaleido, Inc.
/// @dev The proof has the following statements:
///        - each value in the output commitments must be a positive number in the range 0 ~ (2\*\*40 - 1)
///        - the sum of the input values match the sum of output values
///        - the hashes in the input and output match the `hash(value, salt, owner public key)` formula
///        - the sender possesses the private BabyJubjub key, whose public key is part of the pre-image of the input commitment hashes
///
///      Implements the {IZetoLockableCapability} lifecycle (createLock /
///      updateLock / delegateLock / spendLock / cancelLock) by inheriting
///      {ZetoFungibleBase}, the non-nullifier sibling of
///      {ZetoFungibleNullifier}. Both siblings funnel locked-input spends
///      through the same `constructPublicInputs(_, _, _, inputsLocked=true)`
///      hook implemented below; for the anon (non-nullifier) circuit the
///      proof and public-input layout is identical regardless of
///      `inputsLocked`, since neither a nullifier merkle root nor an
///      enabled-flags vector is part of the witness.
contract Zeto_Anon is ZetoFungibleBase, UUPSUpgradeable {
    /// @dev Reserved storage to allow new state variables to be added in
    ///      future upgrades of this contract. Even though Zeto_Anon is a
    ///      concrete (leaf) contract today, reserving a gap keeps the door
    ///      open for further specialization (e.g. embedding a burnable or
    ///      encrypted variant in a derived contract) without breaking
    ///      storage compatibility for live deployments.
    uint256[50] private __gap;

    /// @dev Lock the implementation contract on construction so that
    ///      {initialize} can only ever run on a proxy. Without this,
    ///      anyone could call {initialize} directly on the deployed
    ///      implementation, become its owner, and then `upgradeTo(any)`
    ///      via {_authorizeUpgrade} (the OZ "implementation takeover"
    ///      pattern, CVE-2022-35961 family). See OpenZeppelin's
    ///      `Initializable._disableInitializers` for the rationale.
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        string calldata name,
        string calldata symbol,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers
    ) public virtual initializer {
        __ZetoAnon_init(name, symbol, initialOwner, verifiers);
    }

    function __ZetoAnon_init(
        string calldata name_,
        string calldata symbol_,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers
    ) internal onlyInitializing {
        __ZetoFungibleBase_init(name_, symbol_, initialOwner, verifiers);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    /**
     * @dev Construct the public-inputs vector for the anon circuit.
     *
     *      For Zeto_Anon the proof layout is the same in both the unlocked
     *      `transfer` flow and the locked-input `_transferLocked` flow that
     *      runs inside {spendLock} and {cancelLock}: the witness is just
     *      `inputs ++ outputs`. We therefore ignore `inputsLocked` here and
     *      let `ZetoCommon.verifyProof` pick the right verifier
     *      (`_verifier` vs `_lockVerifier`) based on the same flag. The two
     *      verifiers are typically wired to the same Groth16 verifier
     *      contract for this token (see scripts/tokens/Zeto_Anon.ts) so the
     *      flag is purely a routing concern at this layer.
     */
    function constructPublicInputs(
        uint256[] memory inputs,
        uint256[] memory outputs,
        bytes memory proof,
        bool /* inputsLocked */
    )
        internal
        view
        virtual
        override
        returns (uint256[] memory, Commonlib.Proof memory)
    {
        Commonlib.Proof memory proofStruct = abi.decode(
            proof,
            (Commonlib.Proof)
        );
        uint256 size = inputs.length + outputs.length;
        uint256[] memory publicInputs = new uint256[](size);
        uint256 piIndex = 0;
        for (uint256 i = 0; i < inputs.length; i++) {
            publicInputs[piIndex++] = inputs[i];
        }
        for (uint256 i = 0; i < outputs.length; i++) {
            publicInputs[piIndex++] = outputs[i];
        }

        return (publicInputs, proofStruct);
    }
}
