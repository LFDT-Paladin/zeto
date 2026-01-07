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
import { poseidonContract } from "circomlibjs";
import { Artifact } from "hardhat/types";

export const SmtLibModule = buildModule("SmtLib", (m) => {
  const poseidon2 = m.library("Poseidon2", PoseidonArtifact(2));
  const poseidon3 = m.library("Poseidon3", PoseidonArtifact(3));
  const poseidon5 = m.library("Poseidon5", PoseidonArtifact(5));
  const poseidon6 = m.library("Poseidon6", PoseidonArtifact(6));
  const smtLib = m.contract("SmtLib", []);
  return { smtLib, poseidon2, poseidon3, poseidon5, poseidon6 };
});

export const DepositVerifierModule = buildModule(
  "Groth16Verifier_Deposit",
  (m) => {
    const verifier = m.contract("Groth16Verifier_Deposit", []);
    return { verifier };
  },
);

export const WithdrawNullifierVerifierModule = buildModule(
  "Groth16Verifier_WithdrawNullifier",
  (m) => {
    const verifier = m.contract("Groth16Verifier_WithdrawNullifier", []);
    return { verifier };
  },
);
export const BatchWithdrawNullifierVerifierModule = buildModule(
  "Groth16Verifier_WithdrawNullifierBatch",
  (m) => {
    const verifier = m.contract("Groth16Verifier_WithdrawNullifierBatch", []);
    return { verifier };
  },
);

export const WithdrawVerifierModule = buildModule(
  "Groth16Verifier_Withdraw",
  (m) => {
    const verifier = m.contract("Groth16Verifier_Withdraw", []);
    return { verifier };
  },
);
export const BatchWithdrawVerifierModule = buildModule(
  "Groth16Verifier_WithdrawBatch",
  (m) => {
    const verifier = m.contract("Groth16Verifier_WithdrawBatch", []);
    return { verifier };
  },
);

function PoseidonArtifact(param: number): Artifact {
  const abi = poseidonContract.generateABI(param);
  const bytecode = poseidonContract.createCode(param);
  const artifact: Artifact = {
    _format: "hh-sol-artifact-1",
    contractName: `Poseidon${param}`,
    sourceName: "",
    abi: abi,
    bytecode: bytecode,
    deployedBytecode: "", // "0x"-prefixed hex string
    linkReferences: {},
    deployedLinkReferences: {},
  };
  return artifact;
}
