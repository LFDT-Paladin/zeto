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

const VerifierModule = buildModule(
  "Groth16Verifier_AnonEncNullifierNonRepudiation",
  (m) => {
    const verifier = m.contract(
      "Groth16Verifier_AnonEncNullifierNonRepudiation",
      [],
    );
    return { verifier };
  },
);

const BatchVerifierModule = buildModule(
  "Groth16Verifier_AnonEncNullifierNonRepudiationBatch",
  (m) => {
    const verifier = m.contract(
      "Groth16Verifier_AnonEncNullifierNonRepudiationBatch",
      [],
    );
    return { verifier };
  },
);

export default buildModule("Zeto_AnonEncNullifierNonRepudiation", (m) => {
  const { smtLib, poseidon2, poseidon3 } = m.useModule(SmtLibModule);
  const { verifier } = m.useModule(VerifierModule);
  const { verifier: batchVerifier } = m.useModule(BatchVerifierModule);
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
    batchVerifier,
    batchWithdrawVerifier,
    smtLib,
    poseidon2,
    poseidon3,
  };
});
