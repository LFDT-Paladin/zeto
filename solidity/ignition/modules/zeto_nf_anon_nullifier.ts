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

import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import { SmtLibModule } from "./lib/deps";

const VerifierModule = buildModule(
  "Groth16Verifier_NfAnonNullifierTransfer",
  (m) => {
    const verifier = m.contract("Groth16Verifier_NfAnonNullifierTransfer", []);
    return { verifier };
  },
);

const LockVerifierModule = buildModule(
  "Groth16Verifier_NfAnonNullifierTransferLocked",
  (m) => {
    const verifier = m.contract(
      "Groth16Verifier_NfAnonNullifierTransferLocked",
      [],
    );
    return { verifier };
  },
);

export default buildModule("Zeto_NfAnonNullifier", (m) => {
  const { smtLib, poseidon2, poseidon3 } = m.useModule(SmtLibModule);
  const { verifier } = m.useModule(VerifierModule);
  const { verifier: lockVerifier } = m.useModule(LockVerifierModule);

  return { verifier, lockVerifier, smtLib, poseidon2, poseidon3 };
});
