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
import { SmtLibModule, ZetoLockableLibModule } from "./lib/deps";

const VerifierModule = buildModule(
  "Groth16Verifier_NfAnonNullifierTransfer",
  (m) => {
    const verifier = m.contract("Groth16Verifier_NfAnonNullifierTransfer", []);
    return { verifier };
  },
);

// Locked-input transition for the NF nullifier token reuses the simple
// {Groth16Verifier_NfAnon} verifier, mirroring how Zeto_AnonNullifier
// reuses {Groth16Verifier_Anon} for its lock path. In the new
// {ILockableCapability} architecture the locked-UTXO ledger is a flat
// mapping (no Merkle tree, no per-UTXO delegate SMT), so the proof for
// a locked-input spend collapses to the same `[input, output]` shape as
// the non-nullifier NF transfer. The historical
// `Groth16Verifier_NfAnonNullifierTransferLocked` (which baked the
// locked-SMT inclusion + delegate-binding into the proof) is no longer
// needed and intentionally not deployed.
const LockVerifierModule = buildModule("Groth16Verifier_NfAnon", (m) => {
  const verifier = m.contract("Groth16Verifier_NfAnon", []);
  return { verifier };
});

export default buildModule("Zeto_NfAnonNullifier", (m) => {
  const { zetoLockableLib } = m.useModule(ZetoLockableLibModule);
  const { smtLib, poseidon2, poseidon3 } = m.useModule(SmtLibModule);
  const { verifier } = m.useModule(VerifierModule);
  const { verifier: lockVerifier } = m.useModule(LockVerifierModule);

  return { verifier, lockVerifier, smtLib, poseidon2, poseidon3, zetoLockableLib };
});
