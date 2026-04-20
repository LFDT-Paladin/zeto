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
import {IZetoLockableCapability} from "./interfaces/izeto_lockable_capability.sol";
import {Commonlib} from "./common/common.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ZetoCommon} from "./zeto_common.sol";
import {IZetoStorage} from "./interfaces/izeto_storage.sol";

/// @title A sample implementation of a base Zeto fungible token contract
/// @author Kaleido, Inc.
/// @dev Defines the verifier library for checking UTXOs against a claimed value.
///      Implements {IZetoLockableCapability} (which extends ILockableCapability)
///      to provide the create/update/delegate/spend/cancel lock lifecycle.
abstract contract ZetoFungible is ZetoCommon, IZetoLockableCapability {
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

    // Stored lock state, indexed by lockId.
    struct ZetoLockInfo {
        address owner;
        address spender;
        bytes32 spendCommitment;
        bytes32 cancelCommitment;
        // The locked content: the lockedOutputs from createLock, which become
        // the locked inputs for spendLock/cancelLock.
        uint256[] lockedInputs;
    }

    mapping(bytes32 => ZetoLockInfo) internal _locks;
    mapping(bytes32 => bool) internal _txIds;

    modifier lockActive(bytes32 lockId) {
        if (_locks[lockId].owner == address(0)) {
            revert LockNotActive(lockId);
        }
        _;
    }

    modifier onlySpender(bytes32 lockId) {
        address spender = _locks[lockId].spender;
        if (spender != msg.sender) {
            revert LockUnauthorized(lockId, spender, msg.sender);
        }
        _;
    }

    function _useTxId(bytes32 txId) internal {
        if (_txIds[txId]) {
            revert DuplicateTransaction(txId);
        }
        _txIds[txId] = true;
    }

    function _checkDelegate(uint256[] memory utxos) internal view {
        for (uint256 i = 0; i < utxos.length; i++) {
            (bool isLocked, address currentDelegate) = locked(utxos[i]);
            if (!isLocked) {
                revert NotLocked(utxos[i]);
            }
            if (currentDelegate != msg.sender) {
                revert NotLockDelegate(utxos[i], currentDelegate, msg.sender);
            }
        }
    }

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

    // ------------------------------------------------------------------
    // ILockableCapability lifecycle
    // ------------------------------------------------------------------

    /// @inheritdoc IZetoLockableCapability
    function computeLockId(
        bytes calldata createArgs
    ) external view override returns (bytes32) {
        ZetoCreateLockArgs memory args = abi.decode(
            createArgs,
            (ZetoCreateLockArgs)
        );
        return _computeLockId(args.txId);
    }

    function _computeLockId(bytes32 txId) internal view returns (bytes32) {
        return keccak256(abi.encode(address(this), msg.sender, txId));
    }

    /// @inheritdoc IZetoLockableCapability
    function computeUnlockHash(
        uint256[] calldata lockedInputs,
        uint256[] calldata lockedOutputs,
        uint256[] calldata outputs,
        bytes calldata data
    ) external pure override returns (bytes32) {
        return _buildUnlockHash(lockedInputs, lockedOutputs, outputs, data);
    }

    /**
     * @dev Create a new lock by spending unlocked inputs and producing the
     *      locked content. See {ILockableCapability.createLock} for the
     *      generic semantics; the Zeto-specific payload is {ZetoCreateLockArgs}.
     *
     * Emits {LockCreated} (generic) and {ZetoLockCreated} (Zeto-specific).
     */
    function createLock(
        bytes calldata createArgs,
        bytes32 spendCommitment,
        bytes32 cancelCommitment,
        bytes calldata data
    ) external override returns (bytes32) {
        ZetoCreateLockArgs memory args = abi.decode(
            createArgs,
            (ZetoCreateLockArgs)
        );

        bytes32 lockId = _computeLockId(args.txId);
        if (_locks[lockId].owner != address(0)) {
            revert DuplicateLock(lockId);
        }
        _useTxId(args.txId);

        // Verify the ZK proof and consume inputs / produce locked outputs.
        _doLockTransition(args);

        ZetoLockInfo storage lock = _locks[lockId];
        lock.owner = msg.sender;
        lock.spender = msg.sender;
        lock.spendCommitment = spendCommitment;
        lock.cancelCommitment = cancelCommitment;
        lock.lockedInputs = args.lockedOutputs;

        emit LockCreated(
            lockId,
            msg.sender,
            msg.sender,
            spendCommitment,
            cancelCommitment,
            data
        );
        emit ZetoLockCreated(
            args.txId,
            lockId,
            msg.sender,
            args.inputs,
            args.outputs,
            args.lockedOutputs,
            args.proof,
            data
        );

        return lockId;
    }

    /**
     * @dev Update the spend/cancel commitments on an active, owner-controlled
     *      lock. Mirrors the previous prepareUnlock flow but with full-update
     *      semantics: both commitments are replaced atomically.
     *
     * Emits {LockUpdated} and {ZetoLockUpdated}.
     */
    function updateLock(
        bytes32 lockId,
        bytes calldata updateArgs,
        bytes32 spendCommitment,
        bytes32 cancelCommitment,
        bytes calldata data
    ) external override lockActive(lockId) {
        ZetoLockInfo storage lock = _locks[lockId];
        if (lock.spender != lock.owner) {
            revert LockImmutable(lockId);
        }
        if (msg.sender != lock.owner) {
            revert LockUnauthorized(lockId, lock.spender, msg.sender);
        }

        ZetoUpdateLockArgs memory args = abi.decode(
            updateArgs,
            (ZetoUpdateLockArgs)
        );
        _useTxId(args.txId);

        lock.spendCommitment = spendCommitment;
        lock.cancelCommitment = cancelCommitment;

        emit LockUpdated(
            lockId,
            msg.sender,
            spendCommitment,
            cancelCommitment,
            data
        );
        emit ZetoLockUpdated(args.txId, lockId, msg.sender, data);
    }

    /**
     * @dev Delegate spending authority for the lock. The previous spender's
     *      authority over the locked UTXOs is also moved at the storage layer
     *      so that subsequent locked-input transactions are routed correctly.
     *
     * Emits {LockDelegated} and {ZetoLockDelegated}.
     */
    function delegateLock(
        bytes32 lockId,
        bytes calldata delegateArgs,
        address newSpender,
        bytes calldata data
    ) external override lockActive(lockId) onlySpender(lockId) {
        ZetoDelegateLockArgs memory args = abi.decode(
            delegateArgs,
            (ZetoDelegateLockArgs)
        );
        _useTxId(args.txId);

        ZetoLockInfo storage lock = _locks[lockId];
        address previousSpender = lock.spender;
        lock.spender = newSpender;

        _storage.delegateLock(lock.lockedInputs, newSpender, data);

        emit LockDelegated(lockId, previousSpender, newSpender, data);
        emit ZetoLockDelegated(
            args.txId,
            lockId,
            previousSpender,
            newSpender,
            data
        );
    }

    /**
     * @dev Spend the lock by executing the committed unlock operation.
     *      If `spendCommitment` is non-zero, the supplied spendArgs MUST hash
     *      to it.
     *
     * Emits {LockSpent} and {ZetoLockSpent}.
     */
    function spendLock(
        bytes32 lockId,
        bytes calldata spendArgs,
        bytes calldata data
    ) external virtual override lockActive(lockId) onlySpender(lockId) {
        ZetoSpendLockArgs memory args = abi.decode(
            spendArgs,
            (ZetoSpendLockArgs)
        );

        ZetoLockInfo memory lock = _locks[lockId];
        _consumeLock(lockId, lock, lock.spendCommitment, args);

        emit LockSpent(lockId, msg.sender, data);
        emit ZetoLockSpent(
            args.txId,
            lockId,
            msg.sender,
            args.lockedInputs,
            args.lockedOutputs,
            args.outputs,
            args.proof,
            data
        );
    }

    /**
     * @dev Cancel the lock by executing the committed cancellation operation.
     *      If `cancelCommitment` is non-zero, the supplied cancelArgs MUST hash
     *      to it.
     *
     * Emits {LockCancelled} and {ZetoLockCancelled}.
     */
    function cancelLock(
        bytes32 lockId,
        bytes calldata cancelArgs,
        bytes calldata data
    ) external virtual override lockActive(lockId) onlySpender(lockId) {
        ZetoSpendLockArgs memory args = abi.decode(
            cancelArgs,
            (ZetoSpendLockArgs)
        );

        ZetoLockInfo memory lock = _locks[lockId];
        _consumeLock(lockId, lock, lock.cancelCommitment, args);

        emit LockCancelled(lockId, msg.sender, data);
        emit ZetoLockCancelled(
            args.txId,
            lockId,
            msg.sender,
            args.lockedInputs,
            args.lockedOutputs,
            args.outputs,
            args.proof,
            data
        );
    }

    // ------------------------------------------------------------------
    // ILockableCapability views
    // ------------------------------------------------------------------

    function getLock(
        bytes32 lockId
    ) external view override lockActive(lockId) returns (LockInfo memory) {
        ZetoLockInfo storage lock = _locks[lockId];
        return
            LockInfo({
                owner: lock.owner,
                spender: lock.spender,
                spendCommitment: lock.spendCommitment,
                cancelCommitment: lock.cancelCommitment
            });
    }

    function isLockActive(
        bytes32 lockId
    ) external view override returns (bool) {
        return _locks[lockId].owner != address(0);
    }

    function getLockContent(
        bytes32 lockId
    )
        external
        view
        override
        lockActive(lockId)
        returns (bytes memory content)
    {
        return abi.encode(_locks[lockId].lockedInputs);
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    function _doLockTransition(ZetoCreateLockArgs memory args) internal {
        validateTransactionProposal(
            args.inputs,
            args.outputs,
            args.lockedOutputs,
            args.proof,
            false
        );

        // Combine the locked outputs and the regular outputs because the
        // circuits do not differentiate them.
        uint256[] memory allOutputs = new uint256[](
            args.lockedOutputs.length + args.outputs.length
        );
        for (uint256 i = 0; i < args.lockedOutputs.length; i++) {
            allOutputs[i] = args.lockedOutputs[i];
        }
        for (uint256 i = 0; i < args.outputs.length; i++) {
            allOutputs[args.lockedOutputs.length + i] = args.outputs[i];
        }

        (
            uint256[] memory paddedInputs,
            uint256[] memory paddedOutputs
        ) = checkAndPadCommitments(args.inputs, allOutputs);

        (
            uint256[] memory publicInputs,
            Commonlib.Proof memory proofStruct
        ) = constructPublicInputs(paddedInputs, paddedOutputs, args.proof, false);

        bool isBatch = (paddedInputs.length > 2 ||
            args.outputs.length > 2 ||
            args.lockedOutputs.length > 2);
        verifyProof(proofStruct, publicInputs, isBatch, false);

        processInputsAndOutputs(paddedInputs, args.outputs, false);
        processLockedOutputs(args.lockedOutputs, msg.sender);
    }

    function _consumeLock(
        bytes32 lockId,
        ZetoLockInfo memory lock,
        bytes32 expectedHash,
        ZetoSpendLockArgs memory args
    ) internal {
        // Length check (full content check happens via the storage layer).
        if (lock.lockedInputs.length != args.lockedInputs.length) {
            revert NotLocked(0);
        }

        _useTxId(args.txId);

        if (expectedHash != 0) {
            bytes32 actualHash = _buildUnlockHash(
                args.lockedInputs,
                args.lockedOutputs,
                args.outputs,
                args.data
            );
            if (actualHash != expectedHash) {
                revert InvalidUnlockHash(expectedHash, actualHash);
            }
        }

        _transferLocked(
            lockId,
            args.lockedInputs,
            args.lockedOutputs,
            args.outputs,
            args.proof,
            args.data
        );

        delete _locks[lockId];
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

    function _buildUnlockHash(
        uint256[] memory lockedInputs,
        uint256[] memory lockedOutputs,
        uint256[] memory outputs,
        bytes memory data
    ) internal pure returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    keccak256(abi.encodePacked(lockedInputs)),
                    keccak256(abi.encodePacked(lockedOutputs)),
                    keccak256(abi.encodePacked(outputs)),
                    keccak256(data)
                )
            );
    }

    function _transferLocked(
        bytes32 lockId,
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
