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

import {PoseidonUnit5L} from "@iden3/contracts/contracts/lib/Poseidon.sol";
import {IZeto} from "./lib/interfaces/izeto.sol";
import {MAX_BATCH} from "./lib/interfaces/izeto.sol";
import {Groth16Verifier_Deposit} from "./verifiers/verifier_deposit.sol";
import {Groth16Verifier_WithdrawNullifier} from "./verifiers/verifier_withdraw_nullifier.sol";
import {Groth16Verifier_WithdrawNullifierBatch} from "./verifiers/verifier_withdraw_nullifier_batch.sol";
import {Groth16Verifier_AnonNullifierQurrencyTransfer} from "./verifiers/verifier_anon_nullifier_qurrency_transfer.sol";
// import {Groth16Verifier_AnonNullifierTransferLocked} from "./verifiers/verifier_anon_nullifier_transferLocked.sol";
import {Groth16Verifier_AnonNullifierQurrencyTransferBatch} from "./verifiers/verifier_anon_nullifier_qurrency_transfer_batch.sol";
// import {Groth16Verifier_AnonNullifierTransferLockedBatch} from "./verifiers/verifier_anon_nullifier_transferLocked_batch.sol";
import {ZetoNullifier} from "./lib/zeto_nullifier.sol";
import {ZetoFungibleWithdrawWithNullifiers} from "./lib/zeto_fungible_withdraw_nullifier.sol";
import {Commonlib} from "./lib/common.sol";
import {IZetoInitializable} from "./lib/interfaces/izeto_initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {console} from "hardhat/console.sol";

uint256 constant INPUT_SIZE = 9;
// uint256 constant INPUT_SIZE_LOCKED = 8;
uint256 constant BATCH_INPUT_SIZE = 33;

// uint256 constant BATCH_INPUT_SIZE_LOCKED = 32;

/// @title A sample implementation of a Zeto based fungible token with anonymity and history masking
/// @author Kaleido, Inc.
/// @dev The proof has the following statements:
///        - each value in the output commitments must be a positive number in the range 0 ~ (2\*\*40 - 1)
///        - the sum of the nullified values match the sum of output values
///        - the hashes in the input and output match the hash(value, salt, owner public key) formula
///        - the sender possesses the private BabyJubjub key, whose public key is part of the pre-image of the input commitment hashes, which match the corresponding nullifiers
///        - the nullifiers represent input commitments that are included in a Sparse Merkle Tree represented by the root hash
contract Zeto_AnonNullifierQurrency is
    IZeto,
    IZetoInitializable,
    ZetoNullifier,
    ZetoFungibleWithdrawWithNullifiers,
    UUPSUpgradeable
{
    Groth16Verifier_AnonNullifierQurrencyTransfer internal _verifier;
    Groth16Verifier_AnonNullifierQurrencyTransferBatch internal _batchVerifier;

    // Groth16Verifier_AnonNullifierTransferLocked internal _lockVerifier;
    // Groth16Verifier_AnonNullifierTransferLockedBatch
    //     internal _batchLockVerifier;

    function initialize(
        string memory name,
        string memory symbol,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers
    ) public initializer {
        __ZetoNullifier_init(name, symbol, initialOwner);
        __ZetoFungibleWithdrawWithNullifiers_init(
            (Groth16Verifier_Deposit)(verifiers.depositVerifier),
            (Groth16Verifier_WithdrawNullifier)(verifiers.withdrawVerifier),
            (Groth16Verifier_WithdrawNullifierBatch)(
                verifiers.batchWithdrawVerifier
            )
        );
        _verifier = (Groth16Verifier_AnonNullifierQurrencyTransfer)(
            verifiers.verifier
        );
        // _lockVerifier = (Groth16Verifier_AnonNullifierTransferLocked)(
        //     verifiers.lockVerifier
        // );
        _batchVerifier = (Groth16Verifier_AnonNullifierQurrencyTransferBatch)(
            verifiers.batchVerifier
        );
        // _batchLockVerifier = (Groth16Verifier_AnonNullifierTransferLockedBatch)(
        //     verifiers.batchLockVerifier
        // );
    }

    function _authorizeUpgrade(address) internal override onlyOwner {}

    function constructPublicInputs(
        uint[2] memory computed_hashes,
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        uint256 root,
        uint256 size,
        bool locked
    ) internal view returns (uint256[] memory publicInputs) {
        publicInputs = new uint256[](size);
        // copy computed hashes
        publicInputs[0] = computed_hashes[0];
        publicInputs[1] = computed_hashes[1];
        uint256 piIndex = 2;
        // copy input commitments
        for (uint256 i = 0; i < nullifiers.length; i++) {
            publicInputs[piIndex++] = nullifiers[i];
        }
        // when verifying locked transfers, additional public input
        // for the lock delegate
        if (locked) {
            publicInputs[piIndex++] = uint256(uint160(msg.sender));
        }
        // copy root
        publicInputs[piIndex++] = root;

        // populate enables
        for (uint256 i = 0; i < nullifiers.length; i++) {
            publicInputs[piIndex++] = (nullifiers[i] == 0) ? 0 : 1;
        }

        // copy output commitments
        for (uint256 i = 0; i < outputs.length; i++) {
            publicInputs[piIndex++] = outputs[i];
        }

        return publicInputs;
    }

    /**
     * @dev the main function of the contract.
     *
     * @param nullifiers Array of nullifiers that are secretly bound to UTXOs to be spent by the transaction.
     * @param outputs Array of new UTXOs to generate, for future transactions to spend.
     * @param root The root hash of the Sparse Merkle Tree that contains the nullifiers.
     * @param proof A zero knowledge proof that the submitter is authorized to spend the inputs, and
     *      that the outputs are valid in terms of obeying mass conservation rules.
     *
     * Emits a {UTXOTransfer} event.
     */
    function transfer(
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        uint256 root,
        bytes memory ciphertext,
        Commonlib.Proof calldata proof,
        bytes calldata data
    ) public returns (bool) {
        nullifiers = checkAndPadCommitments(nullifiers);
        outputs = checkAndPadCommitments(outputs);
        validateTransactionProposal(nullifiers, outputs, root, false);
        uint[2] memory computed_pubSignals = calculateHash(ciphertext);
        verifyProof(computed_pubSignals, nullifiers, outputs, root, proof);
        uint256[] memory empty;
        processInputsAndOutputs(nullifiers, outputs, empty, address(0));

        uint256[] memory nullifierArray = new uint256[](nullifiers.length);
        uint256[] memory outputArray = new uint256[](outputs.length);
        for (uint256 i = 0; i < nullifiers.length; ++i) {
            nullifierArray[i] = nullifiers[i];
            outputArray[i] = outputs[i];
        }
        emit UTXOTransfer(nullifierArray, outputArray, msg.sender, data);
        return true;
    }

    // function transferLocked(
    //     uint256[] memory nullifiers,
    //     uint256[] memory outputs,
    //     uint256 root,
    //     Commonlib.Proof calldata proof,
    //     bytes calldata data
    // ) public returns (bool) {
    //     nullifiers = checkAndPadCommitments(nullifiers);
    //     outputs = checkAndPadCommitments(outputs);
    //     validateTransactionProposal(nullifiers, outputs, root, true);
    //     verifyProofLocked(nullifiers, outputs, root, proof);
    //     uint256[] memory empty;
    //     processInputsAndOutputs(nullifiers, outputs, empty, address(0));

    //     uint256[] memory nullifierArray = new uint256[](nullifiers.length);
    //     uint256[] memory outputArray = new uint256[](outputs.length);
    //     for (uint256 i = 0; i < nullifiers.length; ++i) {
    //         nullifierArray[i] = nullifiers[i];
    //         outputArray[i] = outputs[i];
    //     }
    //     emit UTXOTransfer(nullifierArray, outputArray, msg.sender, data);
    //     return true;
    // }

    function deposit(
        uint256 amount,
        uint256[] memory outputs,
        Commonlib.Proof calldata proof,
        bytes calldata data
    ) public {
        _deposit(amount, outputs, proof);
        _mint(outputs, data);
    }

    function withdraw(
        uint256 amount,
        uint256[] memory nullifiers,
        uint256 output,
        uint256 root,
        Commonlib.Proof calldata proof,
        bytes calldata data
    ) public {
        uint256[] memory outputs = new uint256[](nullifiers.length);
        outputs[0] = output;
        // Check and pad inputs and outputs based on the max size
        nullifiers = checkAndPadCommitments(nullifiers);
        outputs = checkAndPadCommitments(outputs);
        validateTransactionProposal(nullifiers, outputs, root, false);
        _withdrawWithNullifiers(amount, nullifiers, output, root, proof);
        uint256[] memory empty;
        processInputsAndOutputs(nullifiers, outputs, empty, address(0));
        emit UTXOWithdraw(amount, nullifiers, output, msg.sender, data);
    }

    function mint(
        uint256[] memory utxos,
        bytes calldata data
    ) public onlyOwner {
        _mint(utxos, data);
    }

    // function lock(
    //     uint256[] memory nullifiers,
    //     uint256[] memory outputs,
    //     uint256[] memory lockedOutputs,
    //     uint256 root,
    //     Commonlib.Proof calldata proof,
    //     address delegate,
    //     bytes calldata data
    // ) public {
    //     // merge the outputs and lockedOutputs and do a regular transfer
    //     uint256[] memory allOutputs = new uint256[](
    //         outputs.length + lockedOutputs.length
    //     );
    //     for (uint256 i = 0; i < outputs.length; i++) {
    //         allOutputs[i] = outputs[i];
    //     }
    //     for (uint256 i = 0; i < lockedOutputs.length; i++) {
    //         allOutputs[outputs.length + i] = lockedOutputs[i];
    //     }
    //     nullifiers = checkAndPadCommitments(nullifiers);
    //     allOutputs = checkAndPadCommitments(allOutputs);
    //     validateTransactionProposal(nullifiers, allOutputs, root, false);
    //     verifyProof(nullifiers, allOutputs, root, proof);

    //     spendNullifiers(nullifiers);

    //     // lock the intended outputs
    //     _lock(nullifiers, outputs, lockedOutputs, delegate, data);
    // }

    // function unlock(
    //     uint256[] memory nullifiers,
    //     uint256[] memory outputs,
    //     uint256 root,
    //     Commonlib.Proof calldata proof,
    //     bytes calldata data
    // ) public {
    //     transferLocked(nullifiers, outputs, root, proof, data);
    // }

    function verifyProof(
        uint[2] memory computed_hashes,
        uint256[] memory nullifiers,
        uint256[] memory outputs,
        uint256 root,
        Commonlib.Proof calldata proof
    ) public view returns (bool) {
        if (nullifiers.length > 2 || outputs.length > 2) {
            uint256[] memory publicInputs = constructPublicInputs(
                computed_hashes,
                nullifiers,
                outputs,
                root,
                BATCH_INPUT_SIZE,
                false
            );
            // construct the public inputs for verifier
            uint256[BATCH_INPUT_SIZE] memory fixedSizeInputs;
            for (uint256 i = 0; i < fixedSizeInputs.length; i++) {
                fixedSizeInputs[i] = publicInputs[i];
            }
            // Check the proof using batchVerifier
            require(
                _batchVerifier.verifyProof(
                    proof.pA,
                    proof.pB,
                    proof.pC,
                    fixedSizeInputs
                ),
                "Invalid proof (batch)"
            );
        } else {
            uint256[] memory publicInputs = constructPublicInputs(
                computed_hashes,
                nullifiers,
                outputs,
                root,
                INPUT_SIZE,
                false
            );
            // construct the public inputs for verifier
            uint256[INPUT_SIZE] memory fixedSizeInputs;
            for (uint256 i = 0; i < fixedSizeInputs.length; i++) {
                fixedSizeInputs[i] = publicInputs[i];
            }
            // Check the proof
            require(
                _verifier.verifyProof(
                    proof.pA,
                    proof.pB,
                    proof.pC,
                    fixedSizeInputs
                ),
                "Invalid proof"
            );
        }
        return true;
    }

    // function verifyProofLocked(
    //     uint256[] memory nullifiers,
    //     uint256[] memory outputs,
    //     uint256 root,
    //     Commonlib.Proof calldata proof
    // ) public view returns (bool) {
    //     if (nullifiers.length > 2 || outputs.length > 2) {
    //         uint256[] memory publicInputs = constructPublicInputs(
    //             nullifiers,
    //             outputs,
    //             root,
    //             BATCH_INPUT_SIZE_LOCKED,
    //             true
    //         );
    //         // construct the public inputs for batchVerifier
    //         uint256[BATCH_INPUT_SIZE_LOCKED] memory fixedSizeInputs;
    //         for (uint256 i = 0; i < fixedSizeInputs.length; i++) {
    //             fixedSizeInputs[i] = publicInputs[i];
    //         }

    //         // Check the proof using batchVerifier
    //         require(
    //             _batchLockVerifier.verifyProof(
    //                 proof.pA,
    //                 proof.pB,
    //                 proof.pC,
    //                 fixedSizeInputs
    //             ),
    //             "Invalid proof"
    //         );
    //     } else {
    //         uint256[] memory publicInputs = constructPublicInputs(
    //             nullifiers,
    //             outputs,
    //             root,
    //             INPUT_SIZE_LOCKED,
    //             true
    //         );
    //         // construct the public inputs for verifier
    //         uint256[INPUT_SIZE_LOCKED] memory fixedSizeInputs;
    //         for (uint256 i = 0; i < fixedSizeInputs.length; i++) {
    //             fixedSizeInputs[i] = publicInputs[i];
    //         }
    //         // Check the proof
    //         require(
    //             _lockVerifier.verifyProof(
    //                 proof.pA,
    //                 proof.pB,
    //                 proof.pC,
    //                 fixedSizeInputs
    //             ),
    //             "Invalid proof"
    //         );
    //     }
    //     return true;
    // }

    function calculateHash(
        bytes memory ciphertext
    ) internal view returns (uint[2] memory) {
        bytes memory ret = new bytes(32); // return is a simple 0 or 1
        bool ok;
        uint256 result;
        bytes memory ct = new bytes(768);
        for (uint i = 0; i < ct.length; i++) {
            ct[i] = ciphertext[i];
        }
        assembly {
            ok := staticcall(
                gas(),
                0x02,
                add(ct, 0x20),
                768,
                add(ret, 0x20),
                0x20
            )
            result := mload(add(ret, 0x20))
        }
        require(ok, "hash failed");

        bytes32 hash = bytes32(result);
        uint[2] memory computed_pubSignals;
        // Calculate h0: sum of the first 16 bytes
        for (uint i = 0; i < 16; i++) {
            computed_pubSignals[0] += uint256(uint8(hash[i])) * (1 << (8 * i));
        }
        // Calculate h1: sum of the next 16 bytes
        for (uint i = 16; i < 32; i++) {
            computed_pubSignals[1] +=
                uint256(uint8(hash[i])) *
                (1 << (8 * (i - 16)));
        }
        return computed_pubSignals;
    }
}
