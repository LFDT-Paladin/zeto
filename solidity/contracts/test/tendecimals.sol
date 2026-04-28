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

import {Zeto_Anon} from "../zeto_anon.sol";
import {IZetoInitializable} from "../lib/interfaces/IZetoInitializable.sol";

/// @title TenDecimals
/// @notice Test sibling of {Zeto_Anon} that overrides {decimals} to 10.
///         Confirms that downstream extensions can change the decimals
///         exposed by the inherited {ZetoCommon.decimals} view (default 4)
///         without otherwise altering the token. The {initialize} override
///         is required because {Zeto_Anon.initialize} is `virtual` —
///         re-declaring it here keeps it callable on the proxy and
///         locks the implementation otherwise unchanged.
contract TenDecimals is Zeto_Anon {
    function decimals() public pure override returns (uint8) {
        return 10;
    }

    function initialize(
        string calldata name,
        string calldata symbol,
        address initialOwner,
        IZetoInitializable.VerifiersInfo calldata verifiers
    ) public override initializer {
        __ZetoAnon_init(name, symbol, initialOwner, verifiers);
    }
}
