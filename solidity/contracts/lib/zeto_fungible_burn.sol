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
import {ZetoFungibleBase} from "./zeto_fungible_base.sol";
import {Commonlib} from "./common/common.sol";

/// @title A feature implementation of a Zeto fungible token burn contract
/// @author Kaleido, Inc.
/// @dev Mixed-in alongside {ZetoFungibleBase} (the non-nullifier sibling of
///      {ZetoFungibleNullifier}) to add a {burn} entry point that destroys a
///      set of input UTXOs and produces a single output UTXO holding the
///      remainder. The burn proof attests that the inputs sum to
///      `output + burn_amount` while preserving owner-side range and
///      ownership invariants.
///
///      The locking lifecycle is unaffected by burning: locked UTXOs cannot
///      be supplied as inputs because {validateInputs} (called from {_burn})
///      rejects locked entries via the underlying {BaseStorage} ledger.
abstract contract ZetoFungibleBurnable is ZetoFungibleBase {
    /// @dev Internal-only so it can only be called from a derived
    ///      contract's own `initializer`-guarded entrypoint.
    function __ZetoFungibleBurnable_init(
        IGroth16Verifier burnVerifier,
        IGroth16Verifier batchBurnVerifier
    ) internal onlyInitializing {
        ZetoFungibleBurnableStorage.Layout storage $ = ZetoFungibleBurnableStorage
            .layout();
        $.burnVerifier = burnVerifier;
        $.batchBurnVerifier = batchBurnVerifier;
    }

    /**
     * @dev Burn a set of inputs, leaving a single output UTXO that holds the
     *      remainder.
     * @param inputs The input UTXOs to burn.
     * @param output The single output UTXO holding the remainder.
     * @param proof The Groth16 proof attesting to value conservation and
     *              owner-side range/ownership invariants.
     * @param data Opaque data appended to the {UTXOBurn} event for off-chain
     *             consumers (e.g. correlation ids).
     *
     * Emits a {UTXOBurn} event.
     */
    function burn(
        uint256[] calldata inputs,
        uint256 output,
        Commonlib.Proof calldata proof,
        bytes calldata data
    ) public virtual {
        uint256[] memory publicInputs = new uint256[](inputs.length + 1);
        for (uint256 i = 0; i < inputs.length; i++) {
            publicInputs[i] = inputs[i];
        }
        publicInputs[inputs.length] = output;

        ZetoFungibleBurnableStorage.Layout storage $ = ZetoFungibleBurnableStorage
            .layout();
        IGroth16Verifier verifier = (inputs.length > 2)
            ? $.batchBurnVerifier
            : $.burnVerifier;
        if (!verifier.verify(proof.pA, proof.pB, proof.pC, publicInputs)) {
            revert InvalidProof();
        }

        _burn(inputs, output, data);
    }

    /// @dev Validate inputs/outputs, then transition state and emit the
    ///      {UTXOBurn} event. Marked virtual so concrete tokens can wrap
    ///      with additional bookkeeping if needed.
    function _burn(
        uint256[] memory inputs,
        uint256 output,
        bytes calldata data
    ) internal virtual {
        validateInputs(inputs, false);
        uint256[] memory outputStates = new uint256[](1);
        outputStates[0] = output;
        validateOutputs(outputStates);
        processInputs(inputs, false);
        processOutputs(outputStates);
        emit UTXOBurn(inputs, output, msg.sender, data);
    }
}

/// @dev ERC-7201 (`erc7201:zeto.storage.ZetoFungibleBurnable`).
library ZetoFungibleBurnableStorage {
    struct Layout {
        IGroth16Verifier burnVerifier;
        IGroth16Verifier batchBurnVerifier;
    }

    bytes32 private constant STORAGE_LOCATION =
        0x99d1a11894f655177598fbad145350332923053ddb779beb1721e5203b8acf00;

    function layout() internal pure returns (Layout storage $) {
        assembly {
            $.slot := STORAGE_LOCATION
        }
    }
}
