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

import {IZetoLockableCapability} from "./IZetoLockableCapability.sol";

/**
 * @title IZetoLockHooks
 * @dev Callback surface invoked by {ZetoLockableLib} (via `address(this)`)
 *      so circuit-specific lock transitions stay in the embedding token
 *      while shared lock lifecycle logic lives in the external library.
 */
interface IZetoLockHooks {
    /// @dev Thrown when a hook is invoked by an address other than `address(this)`.
    error NotSelf(address caller);

    function zetoLockDoLockTransition(
        IZetoLockableCapability.ZetoCreateLockArgs calldata args
    ) external;

    function zetoLockTransferLocked(
        bytes32 lockId,
        uint256[] calldata lockedInputs,
        uint256[] calldata lockedOutputs,
        uint256[] calldata outputs,
        bytes calldata proof,
        bytes calldata data
    ) external;
}
