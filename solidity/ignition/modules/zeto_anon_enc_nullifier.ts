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
import {
  SmtLibModule,
  DepositVerifierModule,
  WithdrawNullifierVerifierModule,
  BatchWithdrawNullifierVerifierModule,
} from "./lib/deps";

const VerifierModule = buildModule("Groth16Verifier_AnonEncNullifier", (m) => {
  const verifier = m.contract("Groth16Verifier_AnonEncNullifier", []);
  return { verifier };
});

const BatchVerifierModule = buildModule(
  "Groth16Verifier_AnonEncNullifierBatch",
  (m) => {
    const verifier = m.contract("Groth16Verifier_AnonEncNullifierBatch", []);
    return { verifier };
  },
);

// Locked-input transfers reuse the plain {Groth16Verifier_AnonEnc} verifier
// (the same one the non-nullifier {Zeto_AnonEnc} token uses for its
// regular transfers), NOT a nullifier-aware verifier.
//
// Rationale: under the new ILockableCapability storage, locked UTXOs are
// kept in a flat per-lock mapping keyed by lockId — there is no SMT for
// locked UTXOs and the locked-input proof has no nullifier history to
// bind against. {Zeto_AnonEncNullifier.constructPublicInputs(...,
// inputsLocked = true)} reflects this by emitting public inputs as
// `[ecdhPublicKey, encryptedValues, inputCommitments, outputCommitments,
// encryptionNonce]` — exactly what `Groth16Verifier_AnonEnc` expects.
// The encryption witness (ECDH key + encrypted blob) still applies because
// the receiver still needs data availability for the post-spend outputs.
const LockVerifierModule = buildModule("Groth16Verifier_AnonEnc", (m) => {
  const verifier = m.contract("Groth16Verifier_AnonEnc", []);
  return { verifier };
});

// Batched (10-in / 10-out) twin of {LockVerifierModule}. Same rationale.
const BatchLockVerifierModule = buildModule(
  "Groth16Verifier_AnonEncBatch",
  (m) => {
    const verifier = m.contract("Groth16Verifier_AnonEncBatch", []);
    return { verifier };
  },
);

export default buildModule("Zeto_AnonEncNullifier", (m) => {
  const { smtLib, poseidon2, poseidon3 } = m.useModule(SmtLibModule);
  const { verifier } = m.useModule(VerifierModule);
  const { verifier: lockVerifier } = m.useModule(LockVerifierModule);
  const { verifier: batchVerifier } = m.useModule(BatchVerifierModule);
  const { verifier: batchLockVerifier } = m.useModule(BatchLockVerifierModule);
  const { verifier: depositVerifier } = m.useModule(DepositVerifierModule);
  const { verifier: withdrawVerifier } = m.useModule(
    WithdrawNullifierVerifierModule,
  );
  const { verifier: batchWithdrawVerifier } = m.useModule(
    BatchWithdrawNullifierVerifierModule,
  );

  return {
    depositVerifier,
    withdrawVerifier,
    verifier,
    lockVerifier,
    batchVerifier,
    batchLockVerifier,
    batchWithdrawVerifier,
    smtLib,
    poseidon2,
    poseidon3,
  };
});
