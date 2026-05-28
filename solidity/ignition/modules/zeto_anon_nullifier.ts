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
  ZetoLockableLibModule,
} from "./lib/deps";

const VerifierModule = buildModule(
  "Groth16Verifier_AnonNullifierTransfer",
  (m) => {
    const verifier = m.contract("Groth16Verifier_AnonNullifierTransfer", []);
    return { verifier };
  },
);

// Locked-input transfers reuse the plain {Groth16Verifier_Anon} verifier
// (the same one the non-nullifier {Zeto_Anon} token uses for its regular
// transfers), NOT a nullifier-aware verifier.
//
// Rationale: under the new ILockableCapability storage, locked UTXOs are
// kept in a flat per-lock mapping keyed by lockId. Previously they were
// shadowed in a dedicated locked-state Sparse Merkle Tree (separate from
// the unlocked-UTXO SMT) so that the locked-input proof could assert
// SMT membership against a locked-state root; that secondary tree has
// been removed. As a result, settling a lock now consumes the locked
// UTXOs by their raw commitment hashes (the on-chain mapping enforces
// single-spend semantics — a lock can only be cleared once), so the
// proof has no nullifiers and no SMT membership to bind against. That
// matches exactly what the simpler `anon` circuit asserts: hash + sum +
// owner-key derivation over input/output commitments.
//
// The corresponding contract code path is
// {Zeto_AnonNullifier.constructPublicInputs(..., inputsLocked = true)},
// which emits public inputs as `[inputCommitments, outputCommitments]`
// — exactly the layout `Groth16Verifier_Anon` expects.
const LockVerifierModule = buildModule(
  "Groth16Verifier_Anon",
  (m) => {
    const verifier = m.contract(
      "Groth16Verifier_Anon",
      [],
    );
    return { verifier };
  },
);

const BatchVerifierModule = buildModule(
  "Groth16Verifier_AnonNullifierTransferBatch",
  (m) => {
    const verifier = m.contract(
      "Groth16Verifier_AnonNullifierTransferBatch",
      [],
    );
    return { verifier };
  },
);

// Batched (10-in / 10-out) twin of {LockVerifierModule}. Same rationale:
// locked-input settlements consume raw UTXO commitments — not nullifiers
// — so the lock-side verifier is the plain `anon_batch` one, not the
// nullifier-aware `anon_nullifier_transfer_batch`.
const BatchLockVerifierModule = buildModule(
  "Groth16Verifier_AnonBatch",
  (m) => {
    const verifier = m.contract(
      "Groth16Verifier_AnonBatch",
      [],
    );
    return { verifier };
  },
);

export default buildModule("Zeto_AnonNullifier", (m) => {
  const { zetoLockableLib } = m.useModule(ZetoLockableLibModule);
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
    zetoLockableLib,
  };
});
