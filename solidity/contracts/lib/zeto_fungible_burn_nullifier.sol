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

import {IGroth16Verifier} from "./interfaces/IZetoVerifier.sol";
import {ZetoFungibleNullifier} from "./zeto_fungible_nullifier.sol";
import {Commonlib} from "./common/common.sol";

/// @title A feature implementation of a Zeto fungible token burn contract for nullifier-based variants
/// @author Kaleido, Inc.
/// @dev Mixed-in alongside {ZetoFungibleNullifier} to add a {burn} entry
///      point that destroys a set of input nullifiers and produces a single
///      output UTXO holding the remainder. The burn proof attests that the
///      pre-image UTXOs sum to `output + burn_amount` while preserving
///      owner-side range and ownership invariants and proving membership
///      against the historical SMT `root`.
///
///      This is the nullifier-flow companion to {ZetoFungibleBurnable}.
///      Unlike that contract:
///        - inputs are nullifiers, not UTXOs;
///        - the SMT `root` is a separate `burn` argument (not encoded in the
///          proof bytes), so `burn` validates it explicitly;
///        - the locking lifecycle is unaffected by burning because
///          {NullifierStorage.validateInputs} (called from {_burn}) only
///          accepts unspent nullifiers, and locked UTXOs live in a disjoint
///          part of the ledger.
abstract contract ZetoFungibleBurnableNullifier is ZetoFungibleNullifier {
    IGroth16Verifier internal _burnVerifier;
    IGroth16Verifier internal _batchBurnVerifier;

    /// @dev Reserved storage to allow new state variables to be added in
    ///      future upgrades of this mixin without shifting the storage
    ///      layout of inheriting contracts (e.g. Zeto_AnonNullifierBurnable).
    ///      Sized so that `<state slots> + __gap.length == 50`, matching
    ///      the OpenZeppelin upgradeable convention.
    uint256[48] private __gap;

    /// @dev Internal-only so it can only be called from a derived
    ///      contract's own `initializer`-guarded entrypoint.
    function __ZetoFungibleBurnableNullifier_init(
        IGroth16Verifier burnVerifier,
        IGroth16Verifier batchBurnVerifier
    ) internal onlyInitializing {
        _burnVerifier = burnVerifier;
        _batchBurnVerifier = batchBurnVerifier;
    }

    /**
     * @dev Construct the burn-circuit public-inputs vector. Layout:
     *        [nullifiers..., root, enabled-flags..., output]
     *      where `enabled-flags[i]` is 1 if `nullifiers[i] != 0` else 0,
     *      mirroring the convention used in
     *      {Zeto_AnonNullifier.constructPublicInputs}.
     */
    function constructBurnPublicInputs(
        uint256[] memory nullifiers,
        uint256 output,
        uint256 root
    ) internal pure returns (uint256[] memory publicInputs) {
        publicInputs = new uint256[](nullifiers.length * 2 + 2);
        uint256 piIndex = 0;

        for (uint256 i = 0; i < nullifiers.length; i++) {
            publicInputs[piIndex++] = nullifiers[i];
        }
        publicInputs[piIndex++] = root;
        for (uint256 i = 0; i < nullifiers.length; i++) {
            publicInputs[piIndex++] = (nullifiers[i] == 0) ? 0 : 1;
        }
        publicInputs[piIndex] = output;

        return publicInputs;
    }

    /**
     * @dev Burn a set of nullifier-pre-image UTXOs, leaving a single output
     *      UTXO that holds the remainder.
     * @param nullifiers The nullifiers of the input UTXOs being burned.
     * @param output The single output UTXO holding the remainder.
     * @param root The historical SMT root the proof is committed against.
     *             Validated against the on-chain root history before state
     *             transitions are applied.
     * @param proof The Groth16 proof attesting to value conservation,
     *              owner-side range/ownership invariants, and membership of
     *              the input UTXOs in the SMT identified by `root`.
     * @param data Opaque data appended to the {UTXOBurn} event for off-chain
     *             consumers (e.g. correlation ids).
     *
     * Emits a {UTXOBurn} event.
     */
    function burn(
        uint256[] calldata nullifiers,
        uint256 output,
        uint256 root,
        Commonlib.Proof calldata proof,
        bytes calldata data
    ) public virtual {
        uint256[] memory publicInputs = constructBurnPublicInputs(
            nullifiers,
            output,
            root
        );

        IGroth16Verifier verifier = (nullifiers.length > 2)
            ? _batchBurnVerifier
            : _burnVerifier;
        if (!verifier.verify(proof.pA, proof.pB, proof.pC, publicInputs)) {
            revert InvalidProof();
        }

        _burn(nullifiers, output, root, data);
    }

    /**
     * @dev Validate inputs/outputs/root, then transition state and emit the
     *      {UTXOBurn} event. Marked virtual so concrete tokens can wrap
     *      with additional bookkeeping if needed.
     *
     *      Unlike the historical implementation on `main`, this consumes
     *      the nullifiers via {processInputs} and inserts the output UTXO
     *      into the SMT via {processOutputs}; without those calls the
     *      burned UTXOs would remain spendable and the remainder UTXO
     *      would not be a member of the tree.
     */
    function _burn(
        uint256[] memory nullifiers,
        uint256 output,
        uint256 root,
        bytes calldata data
    ) internal virtual {
        validateInputs(nullifiers, false);
        uint256[] memory outputStates = new uint256[](1);
        outputStates[0] = output;
        validateOutputs(outputStates);
        validateRoot(root);

        processInputs(nullifiers, false);
        processOutputs(outputStates);

        emit UTXOBurn(nullifiers, output, msg.sender, data);
    }
}
