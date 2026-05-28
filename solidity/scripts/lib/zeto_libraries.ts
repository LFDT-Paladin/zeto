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

/** Hardhat library link map for Zeto token implementations. */
export function withZetoLockableLib(
  zetoLockableLib: { target: string },
  extra: Record<string, string> = {},
): Record<string, string> {
  return {
    ZetoLockableLib: zetoLockableLib.target,
    ...extra,
  };
}

export function smtLibraries(deps: {
  smtLib: { target: string };
  poseidon2: { target: string };
  poseidon3: { target: string };
  poseidon5?: { target: string };
  poseidon6?: { target: string };
}): Record<string, string> {
  const libs: Record<string, string> = {
    SmtLib: deps.smtLib.target,
    PoseidonUnit2L: deps.poseidon2.target,
    PoseidonUnit3L: deps.poseidon3.target,
  };
  if (deps.poseidon5) {
    libs.PoseidonUnit5L = deps.poseidon5.target;
  }
  if (deps.poseidon6) {
    libs.PoseidonUnit6L = deps.poseidon6.target;
  }
  return libs;
}
