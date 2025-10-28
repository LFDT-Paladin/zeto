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

import {IGroth16Verifier} from "./interfaces/izeto_verifier.sol";
import {IZetoInitializable} from "./interfaces/izeto_initializable.sol";
import {Commonlib} from "./common/common.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ZetoCommon} from "./zeto_common.sol";
import {IZetoStorage} from "./interfaces/izeto_storage.sol";

/// @title A sample implementation of a base Zeto fungible token contract
/// @author Kaleido, Inc.
/// @dev Defines the verifier library for checking UTXOs against a claimed value.
abstract contract ZetoFungible is ZetoCommon {
    // _depositVerifier library for checking UTXOs against a claimed value.
    // this can be used in the optional deposit calls to verify that
    // the UTXOs match the deposited value
    IGroth16Verifier internal _depositVerifier;
    // nullifierVerifier library for checking nullifiers against a claimed value.
    // this can be used in the optional withdraw calls to verify that the nullifiers
    // match the withdrawn value
    IGroth16Verifier internal _withdrawVerifier;
    IGroth16Verifier internal _batchWithdrawVerifier;

    IERC20 internal _erc20;

    function __ZetoFungible_init(
        string calldata name_,
        string calldata symbol_,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers,
        IZetoStorage storage_
    ) public onlyInitializing {
        __ZetoCommon_init(name_, symbol_, initialOwner, verifiers, storage_);
        _depositVerifier = verifiers.depositVerifier;
        _withdrawVerifier = verifiers.withdrawVerifier;
        _batchWithdrawVerifier = verifiers.batchWithdrawVerifier;
    }

    /**
     * @dev Set the ERC20 token that this Zeto contract will interact with.
     *
     * @param erc20 The ERC20 token to be used.
     */
    function setERC20(IERC20 erc20) public onlyOwner {
        _erc20 = erc20;
    }

    /**
     * @dev the main function of the contract, which transfers values from one account (represented by Babyjubjub public keys)
     *      to one or more receiver accounts (also represented by Babyjubjub public keys). One of the two nullifiers may be zero
     *      if the transaction only needs one UTXO to be spent. Equally one of the two outputs may be zero if the transaction
     *      only needs to create one new UTXO.
     *
     * @param inputs Array of nullifiers that are secretly bound to UTXOs to be spent by the transaction.
     * @param outputs Array of new UTXOs to generate, for future transactions to spend.
     * @param proof A zero knowledge proof that the submitter is authorized to spend the inputs, and
     *      that the outputs are valid in terms of obeying mass conservation rules.
     *
     * Emits a {UTXOTransfer} event.
     */
    function transfer(
        uint256[] calldata inputs,
        uint256[] calldata outputs,
        bytes calldata proof,
        bytes calldata data
    ) public virtual {
        uint256[] memory lockedOutputs;
        validateTransactionProposal(
            inputs,
            outputs,
            lockedOutputs,
            proof,
            false
        );
        // Check and pad commitments
        (
            uint256[] memory paddedInputs,
            uint256[] memory paddedOutputs
        ) = checkAndPadCommitments(inputs, outputs);
        // construct the public inputs for the proof verification
        (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        ) = constructPublicInputs(paddedInputs, paddedOutputs, proof, false);
        bool isBatch = (inputs.length > 2 || outputs.length > 2);
        verifyProof(proofStruct, publicInputs, isBatch, false);
        processInputsAndOutputs(paddedInputs, paddedOutputs, false);

        emitTransferEvent(inputs, outputs, proof, data);
    }

    /**
     * @dev transfer funds that have been previously locked by the sender. The submitted must
     * be the current delegate of the locked UTXOs.
     *
     * @param lockedInputs Array of UTXOs to be spent by the transaction, they must be locked.
     * @param outputs Array of new UTXOs to generate, for future transactions to spend. They are unlocked.
     * @param proof A zero knowledge proof that the submitter is authorized to spend the inputs, and
     *      that the outputs are valid in terms of obeying mass conservation rules.
     *
     * Emits a {UTXOTransfer} event.
     */
    function transferLocked(
        uint256[] calldata lockedInputs,
        uint256[] calldata lockedOutputs,
        uint256[] calldata outputs,
        bytes calldata proof,
        bytes calldata data
    ) public virtual {
        _transferLocked(lockedInputs, lockedOutputs, outputs, proof, data);
    }

    /**
     * @dev lock funds that have been previously unlocked by the sender. The submitted must
     * be the current delegate of the locked UTXOs.
     *
     * @param inputs Array of UTXOs to be spent by the transaction, they must be unlocked.
     * @param outputs Array of new UTXOs to generate, for future transactions to spend. They are locked.
     * @param lockedOutputs Array of UTXOs to be locked by the transaction.
     * @param proof A zero knowledge proof that the submitter is authorized to spend the inputs, and
     *      that the outputs are valid in terms of obeying mass conservation rules.
     * @param delegate The delegate of the locked UTXOs.
     * @param data Additional data to be passed to the lock function.
     *
     * Emits a {UTXOLocked} event.
     */
    function lock(
        uint256[] calldata inputs,
        uint256[] calldata outputs,
        uint256[] calldata lockedOutputs,
        bytes calldata proof,
        address delegate,
        bytes calldata data
    ) public {
        validateTransactionProposal(
            inputs,
            outputs,
            lockedOutputs,
            proof,
            false
        );

        // combine the locked outputs and the outputs, because the circuits
        // do not care about the difference between locked and unlocked outputs
        uint256[] memory allOutputs = new uint256[](
            lockedOutputs.length + outputs.length
        );
        for (uint256 i = 0; i < lockedOutputs.length; i++) {
            allOutputs[i] = lockedOutputs[i];
        }
        for (uint256 i = 0; i < outputs.length; i++) {
            allOutputs[lockedOutputs.length + i] = outputs[i];
        }
        // Check and pad inputs and outputs based on the max size
        (
            uint256[] memory paddedInputs,
            uint256[] memory paddedOutputs
        ) = checkAndPadCommitments(inputs, allOutputs);

        // construct the public inputs for the proof verification
        (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        ) = constructPublicInputs(paddedInputs, paddedOutputs, proof, false);

        bool isBatch = (paddedInputs.length > 2 ||
            outputs.length > 2 ||
            lockedOutputs.length > 2);
        verifyProof(proofStruct, publicInputs, isBatch, false);

        processInputsAndOutputs(paddedInputs, outputs, false);
        processLockedOutputs(lockedOutputs, delegate);

        emit UTXOLocked(
            inputs,
            lockedOutputs,
            outputs,
            msg.sender,
            delegate,
            data
        );
    }

    /**
     * @dev unlock funds that have been previously locked by the sender. The submitted must
     * be the current delegate of the locked UTXOs.
     *
     * @param nullifiers Array of nullifiers that are secretly bound to UTXOs to be spent by the transaction.
     * @param outputs Array of new UTXOs to generate, for future transactions to spend. They are unlocked.
     * @param proof A zero knowledge proof that the submitter is authorized to spend the inputs, and
     *      that the outputs are valid in terms of obeying mass conservation rules.
     * @param data Additional data to be passed to the unlock function.
     *
     * Emits a {UTXOTransfer} event.
     */
    function unlock(
        uint256[] calldata nullifiers,
        uint256[] calldata outputs,
        bytes calldata proof,
        bytes calldata data
    ) public {
        uint256[] memory lockedOutputs;
        _transferLocked(nullifiers, lockedOutputs, outputs, proof, data);
    }

    /**
     * @dev move the ability to spend the locked UTXOs to the delegate account.
     *      The sender must be the current delegate.
     *
     * @param utxos The locked UTXO to update the delegate of.
     * @param delegate The new delegate.
     * @param data Additional data to be passed to the delegateLock function.
     *
     * Emits a {LockDelegateChanged} event.
     */
    function delegateLock(
        uint256[] calldata utxos,
        address delegate,
        bytes calldata data
    ) public {
        for (uint256 i = 0; i < utxos.length; i++) {
            (bool isLocked, address currentDelegate) = locked(utxos[i]);
            if (!isLocked) {
                revert UTXONotLocked(utxos[i]);
            }
            if (currentDelegate != msg.sender) {
                revert NotLockDelegate(utxos[i], currentDelegate, msg.sender);
            }
        }
        _storage.delegateLock(utxos, delegate, data);
        emit LockDelegateChanged(utxos, msg.sender, delegate, data);
    }

    /**
     * @dev Deposit ERC20 tokens into the Zeto contract.
     *
     * @param amount The amount of ERC20 tokens to be deposited.
     * @param outputs The UTXOs to be minted.
     * @param proof The proof of the deposit.
     * @param data Additional data to be passed to the deposit function.
     *
     * Emits a {UTXOMint} event.
     */
    function deposit(
        uint256 amount,
        uint256[] calldata outputs,
        bytes calldata proof,
        bytes calldata data
    ) public {
        validateOutputs(outputs);

        // verifies that the output UTXOs match the claimed value
        // to be deposited
        (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        ) = constructPublicInputsForDeposit(amount, outputs, proof);
        // Check the proof
        require(
            _depositVerifier.verify(
                proofStruct.pA,
                proofStruct.pB,
                proofStruct.pC,
                publicInputs
            ),
            "Invalid proof"
        );

        require(
            _erc20.transferFrom(msg.sender, address(this), amount),
            "Failed to transfer ERC20 tokens"
        );
        _mint(outputs, data);
    }

    /**
     * @dev Withdraw ERC20 tokens from the Zeto contract.
     *
     * @param amount The amount of ERC20 tokens to be withdrawn.
     * @param inputs The UTXOs to be spent.
     * @param output The UTXO to be minted.
     * @param proof The proof of the withdrawal.
     * @param data Additional data to be passed to the withdrawal function.
     *
     * Emits a {UTXOWithdraw} event.
     */
    function withdraw(
        uint256 amount,
        uint256[] calldata inputs,
        uint256 output,
        bytes calldata proof,
        bytes calldata data
    ) public {
        uint256[] memory outputs = new uint256[](1);
        outputs[0] = output;
        uint256[] memory lockedOutputs;
        validateTransactionProposal(
            inputs,
            outputs,
            lockedOutputs,
            proof,
            false
        );
        // Check and pad inputs and outputs based on the max size
        (
            uint256[] memory paddedInputs,
            uint256[] memory paddedOutputs
        ) = checkAndPadCommitments(inputs, outputs);
        (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        ) = constructPublicInputsForWithdraw(
                amount,
                paddedInputs,
                output,
                proof
            );
        // Check the proof
        IGroth16Verifier verifier = (inputs.length > 2)
            ? _batchWithdrawVerifier
            : _withdrawVerifier;
        require(
            verifier.verify(
                proofStruct.pA,
                proofStruct.pB,
                proofStruct.pC,
                publicInputs
            ),
            "Invalid proof"
        );

        require(
            _erc20.transfer(msg.sender, amount),
            "Failed to transfer ERC20 tokens"
        );

        processInputsAndOutputs(paddedInputs, paddedOutputs, false);
        emit UTXOWithdraw(amount, inputs, output, msg.sender, data);
    }

    function emitTransferEvent(
        uint256[] memory inputs,
        uint256[] memory outputs,
        bytes memory proof,
        bytes memory data
    ) internal virtual {
        emit UTXOTransfer(inputs, outputs, msg.sender, data);
    }

    function emitTransferLockedEvent(
        uint256[] memory lockedInputs,
        uint256[] memory lockedOutputs,
        uint256[] memory outputs,
        bytes memory proof,
        bytes memory data
    ) internal virtual {
        emit UTXOTransferLocked(
            lockedInputs,
            lockedOutputs,
            outputs,
            msg.sender,
            data
        );
    }

    function _transferLocked(
        uint256[] memory lockedInputs,
        uint256[] memory lockedOutputs,
        uint256[] memory outputs,
        bytes memory proof,
        bytes memory data
    ) internal virtual {
        validateTransactionProposal(
            lockedInputs,
            outputs,
            lockedOutputs,
            proof,
            true
        );
        // combine the locked outputs and the outputs, because the circuits
        // do not care about the difference between locked and unlocked outputs
        uint256[] memory allOutputs = new uint256[](
            lockedOutputs.length + outputs.length
        );
        for (uint256 i = 0; i < lockedOutputs.length; i++) {
            allOutputs[i] = lockedOutputs[i];
        }
        for (uint256 i = 0; i < outputs.length; i++) {
            allOutputs[lockedOutputs.length + i] = outputs[i];
        }
        // Check and pad inputs and outputs based on the max size
        (
            uint256[] memory paddedInputs,
            uint256[] memory paddedOutputs
        ) = checkAndPadCommitments(lockedInputs, allOutputs);

        // construct the public inputs for the proof verification
        (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        ) = constructPublicInputs(paddedInputs, paddedOutputs, proof, true);
        bool isBatch = (lockedInputs.length > 2 || allOutputs.length > 2);
        verifyProof(proofStruct, publicInputs, isBatch, true);
        processInputsAndOutputs(paddedInputs, paddedOutputs, true);
        processLockedOutputs(lockedOutputs, msg.sender);

        emitTransferLockedEvent(
            lockedInputs,
            lockedOutputs,
            outputs,
            proof,
            data
        );
    }

    // this is a utility function that constructs the public inputs for a proof of a deposit() call.
    // specific implementations of this function may be overridden by each token implementation
    function constructPublicInputsForDeposit(
        uint256 amount,
        uint256[] memory outputs,
        bytes memory proof
    ) public virtual returns (uint256[] memory, Commonlib.Proof memory) {
        Commonlib.Proof memory proofStruct = abi.decode(
            proof,
            (Commonlib.Proof)
        );
        // construct the public inputs
        uint256[] memory extra = extraInputsForDeposit();
        uint256[] memory publicInputs = new uint256[](3 + extra.length);
        publicInputs[0] = amount;
        publicInputs[1] = outputs[0];
        publicInputs[2] = outputs[1];
        for (uint256 i = 0; i < extra.length; i++) {
            publicInputs[3 + i] = extra[i];
        }

        return (publicInputs, proofStruct);
    }

    function extraInputsForDeposit()
        internal
        view
        virtual
        returns (uint256[] memory)
    {
        return new uint256[](0);
    }

    // this is a utility function that constructs the public inputs for a proof of a withdraw() call.
    // specific implementations of this function may be overridden by each token implementation
    function constructPublicInputsForWithdraw(
        uint256 amount,
        uint256[] memory inputs,
        uint256 output,
        bytes memory proof
    ) internal virtual returns (uint256[] memory, Commonlib.Proof memory) {
        Commonlib.Proof memory proofStruct = abi.decode(
            proof,
            (Commonlib.Proof)
        );
        uint256 size = (inputs.length + 1 + 1); // inputs, output, and amount

        uint256[] memory publicInputs = new uint256[](size);
        uint256 piIndex = 0;

        // copy output amount
        publicInputs[piIndex++] = amount;

        // copy input commitments
        for (uint256 i = 0; i < inputs.length; i++) {
            publicInputs[piIndex++] = inputs[i];
        }

        // copy output commitment
        publicInputs[piIndex++] = output;

        return (publicInputs, proofStruct);
    }
}
