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
import {IZeto, MAX_BATCH} from "./interfaces/IZeto.sol";
import {IGroth16Verifier} from "./interfaces/IZetoVerifier.sol";
import {IZetoInitializable} from "./interfaces/IZetoInitializable.sol";
import {Ownable2StepUpgradeable} from "@openzeppelin/contracts-upgradeable/access/Ownable2StepUpgradeable.sol";
import {Util} from "./common/util.sol";
import {IZetoStorage} from "./interfaces/IZetoStorage.sol";

/// @title A sample base implementation of a Zeto based token contract
/// @author Kaleido, Inc.
/// @dev Implements common functionalities of Zeto based tokens.
///
///      Ownership uses {Ownable2StepUpgradeable}: the current owner cannot
///      transfer ownership in a single call. {transferOwnership} stages a
///      pending owner that the candidate must accept by calling
///      {acceptOwnership}. This eliminates the "fat-finger to the wrong
///      address" risk of single-step transfer for accounts that, in this
///      contract, can mint, configure verifiers (via upgrades), bind the
///      backing ERC20 (via {ZetoFungible.setERC20}), and authorize UUPS
///      upgrades on the concrete tokens.
///
///      Operators are nonetheless STRONGLY advised to assign ownership to
///      a multisig (e.g. Gnosis Safe) or a timelock-governed account, since
///      the privileges above are still concentrated in a single role.
abstract contract ZetoCommon is IZeto, Ownable2StepUpgradeable {
    /// @dev Thrown when the supplied Groth16 proof fails verification.
    ///      Replaces the previous `require(..., "Invalid proof")` strings
    ///      so callers can match a typed error in their error decoders.
    error InvalidProof();

    string private _name;
    string private _symbol;

    IZetoStorage internal _storage;

    IGroth16Verifier internal _verifier;
    IGroth16Verifier internal _batchVerifier;
    IGroth16Verifier internal _lockVerifier;
    IGroth16Verifier internal _batchLockVerifier;

    /// @dev Reserved storage to allow new state variables to be added in
    ///      future upgrades of this contract without shifting the storage
    ///      layout of inheriting contracts. Sized at 50 slots, matching the
    ///      OpenZeppelin upgradeable convention. When a new state variable
    ///      is added to ZetoCommon, decrement the gap by the equivalent
    ///      number of slots so that descendants' layouts remain stable.
    uint256[50] private __gap;

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

    function validateRoot(uint256 root) internal view virtual {
        _storage.validateRoot(root);
    }

    function getRoot() public view virtual returns (uint256) {
        return _storage.getRoot();
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

    /**
     * @dev Forward freshly-minted locked outputs to storage.
     *
     *      Callers reach this function only after `validateOutputs` has been
     *      invoked (via {validateTransactionProposal} in the lock-creation
     *      flow), which already rejects any output that is known to storage
     *      as locked or unlocked (revert {UTXOAlreadyOwned} /
     *      {UTXOAlreadySpent}). It is therefore an invariant at this point
     *      that none of the `lockedOutputs` already exist as locked.
     *
     *      The storage layer no longer tracks who can spend a locked UTXO;
     *      the Zeto contract on top owns that state (e.g.
     *      `_locks[lockId].spender` in `ZetoFungible`-style lockable
     *      capabilities). Subclasses that implement a lock model are
     *      responsible for recording the spender for each locked output
     *      after calling this function.
     */
    function processLockedOutputs(
        uint256[] memory lockedOutputs
    ) internal virtual {
        _storage.processLockedOutputs(lockedOutputs);
    }

    /**
     * @dev Verify a Groth16 proof against the appropriate verifier for the
     *      requested flavour (regular vs batch, locked-input vs unlocked).
     *
     *      Reverts with {InvalidProof} on failure. The boolean return value
     *      is preserved for ABI compatibility with existing off-chain
     *      callers, and is always `true` when the call returns: a `false`
     *      verification result is never observed.
     */
    function verifyProof(
        Commonlib.Proof memory proof,
        uint256[] memory publicInputs,
        bool isBatch,
        bool inputsLocked
    ) public view returns (bool) {
        IGroth16Verifier verifier = inputsLocked
            ? (isBatch ? _batchLockVerifier : _lockVerifier)
            : (isBatch ? _batchVerifier : _verifier);
        if (!verifier.verify(proof.pA, proof.pB, proof.pC, publicInputs)) {
            revert InvalidProof();
        }
        return true;
    }

    function spent(uint256 utxo) public view returns (IZetoStorage.UTXOStatus) {
        return _storage.spent(utxo);
    }

    /**
     * @dev Return whether `utxo` is currently locked, plus the address
     *      authorized to spend it.
     *
     *      The base implementation returns `address(0)` for the spender
     *      because `ZetoCommon` itself does not implement any lock model.
     *      Subclasses that DO implement a lock model (e.g. `ZetoFungible`
     *      via `IZetoLockableCapability`) MUST override this to return the
     *      spender for the lock that owns `utxo`.
     */
    function locked(uint256 utxo) public view virtual returns (bool, address) {
        return (_storage.locked(utxo), address(0));
    }
}
