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

import {ZetoNonFungibleNullifier} from "./lib/zeto_non_fungible_nullifier.sol";
import {Commonlib} from "./lib/common/common.sol";
import {IZetoInitializable} from "./lib/interfaces/IZetoInitializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title A sample implementation of a Zeto based non-fungible token with
///        anonymity and history masking via nullifiers.
/// @author Kaleido, Inc.
/// @notice Decimals: this token uses **4** decimals, inherited from
///         {ZetoCommon.decimals}. NFT integrators rarely consult
///         `decimals()` but it is preserved for ABI symmetry with the
///         fungible siblings.
/// @dev The proof has the following statements:
///        - The sender owns the private key whose public key is part of the pre-image of the input UTXO commitment
///          (which corresponds to the nullifier).
///        - The nullifier represents an input commitment included in a Sparse Merkle Tree represented by the root hash.
///        - The output UTXO commitment is well-formed.
///
///      Two public-inputs layouts are produced depending on whether the
///      transition is consuming an unlocked input (a nullifier proven
///      against the unlocked-commitments SMT) or a locked input (a raw
///      UTXO hash whose locked status is verified by the storage layer
///      itself):
///        - unlocked: `[nullifier, root, output]` -> verified by
///          {Groth16Verifier_NfAnonNullifierTransfer}.
///        - locked:   `[input, output]`           -> verified by the
///          simpler {Groth16Verifier_NfAnon}.
///      This mirrors how {Zeto_AnonNullifier} reuses the non-nullifier
///      verifier for its lock path. The locked branch does not require
///      a Merkle inclusion proof because the contract has already
///      validated the input via {NullifierStorage.validateInputs} (it
///      defers to {BaseStorage.validateInputs} when `inputsLocked`).
contract Zeto_NfAnonNullifier is ZetoNonFungibleNullifier, UUPSUpgradeable {
    /// @dev Lock the implementation contract on construction.
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        string calldata name,
        string calldata symbol,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers
    ) public initializer {
        __ZetoNonFungibleNullifier_init(name, symbol, initialOwner, verifiers);
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// @dev Public-inputs layout depends on `inputsLocked`:
    ///        - !inputsLocked: `[nullifier, root, output]` paired with the
    ///          `nf_anon_nullifier_transfer` circuit. The proof carries
    ///          `(uint256 root, Commonlib.Proof)`; the root is decoded
    ///          and validated here so that `validateTransactionProposal`
    ///          does not need to pre-decode the proof.
    ///        - inputsLocked:  `[input, output]` paired with the simpler
    ///          `nf_anon` circuit. No root: the storage layer has
    ///          already verified the input is in `_lockedUtxos`, so we
    ///          do not re-prove inclusion in a locked-SMT. The proof
    ///          payload is just `Commonlib.Proof`.
    function constructPublicInputs(
        uint256[] memory inputs,
        uint256[] memory outputs,
        bytes memory proof,
        bool inputsLocked
    )
        internal
        view
        override
        returns (uint256[] memory, Commonlib.Proof memory)
    {
        if (inputsLocked) {
            Commonlib.Proof memory proofStruct = abi.decode(
                proof,
                (Commonlib.Proof)
            );
            uint256[] memory publicInputs = new uint256[](2);
            publicInputs[0] = inputs[0];
            publicInputs[1] = outputs[0];
            return (publicInputs, proofStruct);
        }

        (uint256 root, Commonlib.Proof memory proofStruct) = abi.decode(
            proof,
            (uint256, Commonlib.Proof)
        );
        validateRoot(root);

        uint256[] memory publicInputs = new uint256[](3);
        publicInputs[0] = inputs[0];
        publicInputs[1] = root;
        publicInputs[2] = outputs[0];
        return (publicInputs, proofStruct);
    }
}

/// @dev ERC-7201 (`erc7201:zeto.storage.Zeto_NfAnonNullifier`).
library Zeto_NfAnonNullifierStorage {
    struct Layout {
        uint256 __reserved;
    }

    bytes32 private constant STORAGE_LOCATION =
        0xb42e743e63c75bf1f2c05ab181e1371afad8f4114706ec6cfc12171a24893700;

    function layout() internal pure returns (Layout storage $) {
        assembly {
            $.slot := STORAGE_LOCATION
        }
    }
}
