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

import {Commonlib} from "./common/common.sol";
import {IZeto, MAX_BATCH} from "./interfaces/izeto.sol";
import {IZetoLockable} from "./interfaces/izeto_lockable.sol";
import {IGroth16Verifier} from "./interfaces/izeto_verifier.sol";
import {IZetoInitializable} from "./interfaces/izeto_initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Util} from "./common/util.sol";
import {IZetoStorage} from "./interfaces/izeto_storage.sol";

/// @title A sample base implementation of a Zeto based token contract
/// @author Kaleido, Inc.
/// @dev Implements common functionalities of Zeto based tokens
abstract contract ZetoCommon is IZeto, IZetoLockable, OwnableUpgradeable {
    string private _name;
    string private _symbol;

    IZetoStorage internal _storage;

    IGroth16Verifier internal _verifier;
    IGroth16Verifier internal _batchVerifier;
    IGroth16Verifier internal _lockVerifier;
    IGroth16Verifier internal _batchLockVerifier;

    function __ZetoCommon_init(
        string calldata name_,
        string calldata symbol_,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers,
        IZetoStorage storage_
    ) internal onlyInitializing {
        __Ownable_init(initialOwner);
        _name = name_;
        _symbol = symbol_;
        _verifier = verifiers.verifier;
        _lockVerifier = verifiers.lockVerifier;
        _batchVerifier = verifiers.batchVerifier;
        _batchLockVerifier = verifiers.batchLockVerifier;
        _storage = storage_;
    }

    /**
     * @dev Returns the name of the token.
     */
    function name() public view virtual returns (string memory) {
        return _name;
    }

    /**
     * @dev Returns the symbol of the token, usually a shorter version of the
     * name.
     */
    function symbol() public view virtual returns (string memory) {
        return _symbol;
    }

    /**
     * @dev Returns the number of decimals used to get its user representation.
     * For example, if `decimals` equals `2`, a balance of `505` tokens should
     * be displayed to a user as `5.05` (`505 / 10 ** 2`).
     *
     * Tokens usually opt for a value of 18, imitating the relationship between
     * Ether and Wei. But Zeto uses 4 as the default, based on its target use cases
     * in CBDCs and tokenized commercial money. The default value can be overridden.
     *
     * NOTE: This information is only used for _display_ purposes: it in
     * no way affects any of the arithmetic of the contract, or the ZKP circuits.
     */
    function decimals() public view virtual returns (uint8) {
        return 4;
    }

    /**
     * @dev This function is used to mint new UTXOs, as an example implementation,
     * which is only callable by the owner.
     *
     * @param utxos Array of UTXOs to be minted.
     * @param data Additional data to be passed to the mint function.
     *
     * Emits a {UTXOMint} event.
     */
    function mint(
        uint256[] calldata utxos,
        bytes calldata data
    ) public virtual onlyOwner {
        _mint(utxos, data);
    }

    /**
     * @dev construct the public inputs and verify the proof. it's a utility function useful for situations
     *  like an escrow contract orchestrating locking and settlement flows
     *
     * @param inputs Array of UTXOs to be spent by the transaction.
     * @param outputs Array of new UTXOs to generate, for future transactions to spend.
     * @param proof A zero knowledge proof that the submitter is authorized to spend the inputs, and
     *      that the outputs are valid in terms of obeying mass conservation rules.
     * @param inputsLocked Whether the inputs are locked.
     *
     * @return True if the proof is valid, false otherwise.
     */
    function constructPublicSignalsAndVerifyProof(
        uint256[] memory inputs,
        uint256[] memory outputs,
        bytes memory proof,
        bool inputsLocked
    ) public returns (bool) {
        (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        ) = constructPublicInputs(inputs, outputs, proof, inputsLocked);
        bool isBatch = inputs.length > 2 || outputs.length > 2;
        verifyProof(proofStruct, publicInputs, isBatch, inputsLocked);
        return true;
    }

    function _mint(
        uint256[] memory utxos,
        bytes calldata data
    ) internal virtual {
        validateOutputs(utxos);
        processOutputs(utxos);
        emit UTXOMint(utxos, msg.sender, data);
    }

    function checkAndPadCommitments(
        uint256[] memory inputs,
        uint256[] memory outputs
    ) public pure returns (uint256[] memory, uint256[] memory) {
        uint256 len = (inputs.length > outputs.length)
            ? inputs.length
            : outputs.length;

        // Check if inputs or outputs exceed batchMax and revert with custom error if necessary
        if (len > MAX_BATCH) {
            revert UTXOArrayTooLarge(MAX_BATCH);
        }

        // Ensure both arrays are padded to the same length
        uint256 maxLength;

        // By default all tokens supports at least a circuit with 2 inputs and 2 outputs
        // which has a shorter proof generation time and should cover most use cases.
        // In addition, tokens can support circuits with bigger inputs
        if (len > 2) {
            // check whether a batch circuit is required
            maxLength = MAX_BATCH; // Pad both to batchMax if one has more than 2 items
        } else {
            maxLength = 2; // Otherwise, pad both to 2
        }

        // Pad commitments to the determined maxLength
        inputs = Commonlib.padUintArray(inputs, maxLength, 0);
        outputs = Commonlib.padUintArray(outputs, maxLength, 0);

        return (inputs, outputs);
    }

    // this is a utility function that constructs the public inputs for a proof.
    // specific implementations of this function are provided by each token implementation
    function constructPublicInputs(
        uint256[] memory inputs,
        uint256[] memory outputs,
        bytes memory proof,
        bool inputsLocked
    )
        internal
        virtual
        returns (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        )
    {}

    // this is a utility function that constructs the public inputs for a proof of a lock() call.
    // specific implementations of this function are provided by each token implementation
    function constructPublicInputsForLock(
        uint256[] memory inputs,
        uint256[] memory outputs,
        uint256[] memory lockedOutputs,
        bytes memory proof
    )
        internal
        virtual
        returns (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        )
    {}

    function validateTransactionProposal(
        uint256[] memory inputs,
        uint256[] memory outputs,
        uint256[] memory lockedOutputs,
        bytes memory proof,
        bool inputsLocked
    ) internal view virtual {
        uint256[] memory allOutputs = new uint256[](
            outputs.length + lockedOutputs.length
        );
        for (uint256 i = 0; i < outputs.length; i++) {
            allOutputs[i] = outputs[i];
        }
        for (uint256 i = 0; i < lockedOutputs.length; i++) {
            allOutputs[outputs.length + i] = lockedOutputs[i];
        }
        validateInputs(inputs, inputsLocked);
        validateOutputs(allOutputs);
    }

    function validateInputs(
        uint256[] memory inputs,
        bool inputsLocked
    ) internal view virtual {
        _storage.validateInputs(inputs, inputsLocked);
    }

    function validateOutputs(uint256[] memory outputs) internal view virtual {
        _storage.validateOutputs(outputs);
    }

    function validateRoot(
        uint256 root,
        bool inputsLocked
    ) internal view virtual {
        _storage.validateRoot(root, inputsLocked);
    }

    function getRoot() public view virtual returns (uint256) {
        return _storage.getRoot();
    }

    function getRootForLocked() public view virtual returns (uint256) {
        return _storage.getRootForLocked();
    }

    function processInputsAndOutputs(
        uint256[] memory inputs,
        uint256[] memory outputs,
        bool inputsLocked
    ) internal virtual {
        processInputs(inputs, inputsLocked);
        processOutputs(outputs);
    }

    function processInputs(
        uint256[] memory inputs,
        bool inputsLocked
    ) internal virtual {
        _storage.processInputs(inputs, inputsLocked);
    }

    function processOutputs(uint256[] memory outputs) internal virtual {
        _storage.processOutputs(outputs);
    }

    function processLockedOutputs(
        uint256[] memory lockedOutputs,
        address delegate
    ) internal virtual {
        for (uint256 i = 0; i < lockedOutputs.length; ++i) {
            if (lockedOutputs[i] == 0) {
                continue;
            }
            (bool isLocked, address currentDelegate) = locked(lockedOutputs[i]);
            if (isLocked) {
                // if the UTXO is locked, check if the sender is the current delegate
                if (currentDelegate != msg.sender) {
                    revert NotLockDelegate(
                        lockedOutputs[i],
                        currentDelegate,
                        msg.sender
                    );
                }
            }
        }
        _storage.processLockedOutputs(lockedOutputs, delegate);
    }

    function verifyProof(
        Commonlib.Proof memory proof,
        uint256[] memory publicInputs,
        bool isBatch,
        bool inputsLocked
    ) public view returns (bool) {
        IGroth16Verifier verifier = inputsLocked
            ? (isBatch ? _batchLockVerifier : _lockVerifier)
            : (isBatch ? _batchVerifier : _verifier);
        require(
            verifier.verify(proof.pA, proof.pB, proof.pC, publicInputs),
            "Invalid proof"
        );
        return true;
    }

    function spent(uint256 utxo) public view returns (IZetoStorage.UTXOStatus) {
        return _storage.spent(utxo);
    }

    function locked(uint256 utxo) public view returns (bool, address) {
        return _storage.locked(utxo);
    }
}
