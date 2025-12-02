// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Minimal interface for a lockable contract, used by escrow
// contracts to interact with the lockable functionality of privacy tokens
interface ILockable {
    struct UnlockOperationData {
        // Array of zero or more new states to generate, for future transactions to spend
        uint256[] outputs;
        // Array of zero or more locked states to generate, which will be tied to the lockId
        uint256[] lockedOutputs;
        // zk proof or other type of certificates to demonstrate validity of the unlock operation
        bytes proof;
        // app-specific data associated with the unlock operation
        bytes data;
    }

    function unlock(
        bytes32 lockId,
        UnlockOperationData calldata settle
    ) external;

    function rollbackLock(
        bytes32 lockId,
        UnlockOperationData calldata rollback
    ) external;
}
