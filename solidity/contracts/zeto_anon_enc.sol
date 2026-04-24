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

import {Commonlib} from "./lib/common/common.sol";
import {IZetoInitializable} from "./lib/interfaces/IZetoInitializable.sol";
import {Zeto_Anon} from "./zeto_anon.sol";

/// @title A sample implementation of a Zeto based fungible token with
///        anonymity and encryption (no nullifier history masking).
/// @author Kaleido, Inc.
/// @notice Decimals: this token uses **4** decimals, inherited from
///         {ZetoCommon.decimals}. Indexers and UIs reading this contract
///         directly should treat balances accordingly.
/// @dev The proof has the following statements:
///        - each value in the output commitments must be a positive number in the range 0 ~ (2\*\*40 - 1)
///        - the sum of the input values match the sum of output values
///        - the hashes in the input and output match the hash(value, salt, owner public key) formula
///        - the sender possesses the private BabyJubjub key, whose public key is part of the pre-image of the input commitment hashes
///        - the encrypted value in the output is derived from the receiver's UTXO value and encrypted with a shared secret using
///          the ECDH protocol between the sender and receiver (this guarantees data availability for the receiver)
///
///      Composes {Zeto_Anon} (transfer + ILockableCapability lifecycle) with
///      an encryption-aware {emitTransferEvent}/{constructPublicInputs}
///      override. The proof bytes carry the additional encryption metadata
///      (ECDH public key, encryption nonce, encrypted values) and a
///      Groth16 proof; we decode them in the public-inputs builder so the
///      circuit verifies the encryption commitments alongside value
///      conservation.
contract Zeto_AnonEnc is Zeto_Anon {
    /// @dev Lock the implementation contract on construction. The parent
    ///      {Zeto_Anon} already does this via its own constructor (which
    ///      Solidity invokes as part of every leaf's deployment), but we
    ///      restate it here so the H-2 protection survives any future
    ///      refactor that changes the inheritance graph.
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        string calldata name,
        string calldata symbol,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers
    ) public virtual override initializer {
        __ZetoAnon_init(name, symbol, initialOwner, verifiers);
    }

    function emitTransferEvent(
        uint256[] memory inputs,
        uint256[] memory outputs,
        bytes memory proof,
        bytes memory data
    ) internal virtual override {
        (
            uint256 encryptionNonce,
            uint256[2] memory ecdhPublicKey,
            uint256[] memory encryptedValues,

        ) = abi.decode(
                proof,
                (uint256, uint256[2], uint256[], Commonlib.Proof)
            );
        emit UTXOTransferWithEncryptedValues(
            inputs,
            outputs,
            encryptionNonce,
            ecdhPublicKey,
            encryptedValues,
            msg.sender,
            data
        );
    }

    /// @dev Layout of `proof` (ABI-encoded tuple):
    ///        (uint256 encryptionNonce,
    ///         uint256[2] ecdhPublicKey,
    ///         uint256[] encryptedValues,
    ///         Commonlib.Proof groth16Proof)
    ///
    ///      `inputsLocked` is ignored: the encryption circuit's public-input
    ///      layout is identical regardless of whether the inputs were
    ///      previously locked, since the lock state is enforced at the
    ///      Zeto layer (via {ZetoFungible}) rather than inside the circuit.
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
        (
            uint256 encryptionNonce,
            uint256[2] memory ecdhPublicKey,
            uint256[] memory encryptedValues,
            Commonlib.Proof memory proofStruct
        ) = abi.decode(
                proof,
                (uint256, uint256[2], uint256[], Commonlib.Proof)
            );

        // Layout: ecdhPublicKey ++ encryptedValues ++ inputs ++ outputs ++ encryptionNonce
        uint256 size = ecdhPublicKey.length +
            encryptedValues.length +
            inputs.length +
            outputs.length +
            1;
        uint256[] memory publicInputs = new uint256[](size);
        uint256 piIndex = 0;
        for (uint256 i = 0; i < ecdhPublicKey.length; ++i) {
            publicInputs[piIndex++] = ecdhPublicKey[i];
        }
        for (uint256 i = 0; i < encryptedValues.length; ++i) {
            publicInputs[piIndex++] = encryptedValues[i];
        }
        for (uint256 i = 0; i < inputs.length; i++) {
            publicInputs[piIndex++] = inputs[i];
        }
        for (uint256 i = 0; i < outputs.length; i++) {
            publicInputs[piIndex++] = outputs[i];
        }
        publicInputs[piIndex++] = encryptionNonce;

        return (publicInputs, proofStruct);
    }
}
