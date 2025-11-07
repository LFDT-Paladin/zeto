// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Minimal interface for a lockable contract, used by escrow
// contracts to interact with the lockable functionality of privacy tokens
interface ILockable {
    function settleLock(bytes32 lockId, bytes calldata data) external;

    function rollbackLock(bytes32 lockId, bytes calldata data) external;
}
