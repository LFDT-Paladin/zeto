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

import { readFileSync } from "fs";
import * as path from "path";
import crypto from "crypto";
import { AbiCoder, BigNumberish } from "ethers";
import { groth16 } from "snarkjs";
import { loadCircuit, encodeProof, tokenUriHash } from "zeto-js";
import { User, UTXO, ZERO_UTXO } from "./lib/utils";
import { formatPrivKeyForBabyJub, stringifyBigInts } from "maci-crypto";

function provingKeysRoot() {
  const PROVING_KEYS_ROOT = process.env.PROVING_KEYS_ROOT;
  if (!PROVING_KEYS_ROOT) {
    throw new Error("PROVING_KEYS_ROOT env var is not set");
  }
  return PROVING_KEYS_ROOT;
}

export function loadProvingKeys(type: string) {
  const provingKeyFile = path.join(provingKeysRoot(), `${type}.zkey`);
  const verificationKey = JSON.parse(
    new TextDecoder().decode(
      readFileSync(path.join(provingKeysRoot(), `${type}-vkey.json`)),
    ),
  );
  return {
    provingKeyFile,
    verificationKey,
  };
}

export function inflateUtxos(outputUtxos: UTXO[]) {
  const desiredLength = outputUtxos.length > 2 ? 10 : 2;
  const inflatedOutputUtxos = [...outputUtxos];
  for (let i = 0; i < desiredLength - outputUtxos.length; i++) {
    inflatedOutputUtxos.push(ZERO_UTXO);
  }
  return inflatedOutputUtxos;
}

export function inflateOwners(owners: User[]) {
  const desiredLength = owners.length > 2 ? 10 : 2;
  const inflatedOwners = [...owners];
  for (let i = 0; i < desiredLength - owners.length; i++) {
    inflatedOwners.push(owners[0]); // use a random owner for the extra utxos
  }
  return inflatedOwners;
}

export async function prepareDepositProof(signer: User, outputs: [UTXO, UTXO]) {
  const outputCommitments: [BigNumberish, BigNumberish] = [
    outputs[0].hash,
    outputs[1].hash,
  ] as [BigNumberish, BigNumberish];
  const outputValues = [
    BigInt(outputs[0].value || 0),
    BigInt(outputs[1].value || 0),
  ];
  const outputSalts = [
    BigInt(outputs[0].salt || 0n),
    BigInt(outputs[1].salt || 0n),
  ];
  const outputOwnerPublicKeys: [
    [BigNumberish, BigNumberish],
    [BigNumberish, BigNumberish],
  ] = [
    signer.babyJubPublicKey,
    outputs[1].hash ? signer.babyJubPublicKey : [0n, 0n],
  ] as [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]];

  const inputObj = {
    outputCommitments,
    outputValues,
    outputSalts,
    outputOwnerPublicKeys,
  };

  const circuit = await loadCircuit("deposit");
  const { provingKeyFile } = loadProvingKeys("deposit");

  const startWitnessCalculation = Date.now();
  const witness = await circuit.calculateWTNSBin(inputObj, true);
  const timeWithnessCalculation = Date.now() - startWitnessCalculation;

  const startProofGeneration = Date.now();
  const { proof, publicSignals } = (await groth16.prove(
    provingKeyFile,
    witness,
  )) as { proof: BigNumberish[]; publicSignals: BigNumberish[] };
  const timeProofGeneration = Date.now() - startProofGeneration;

  console.log(
    `Witness calculation time: ${timeWithnessCalculation}ms. Proof generation time: ${timeProofGeneration}ms.`,
  );

  const encodedProof = encodeProof(proof);
  return {
    outputCommitments,
    encodedProof,
  };
}

export async function prepareDepositKycProof(
  signer: User,
  outputs: [UTXO, UTXO],
  identitiesRoot: BigInt,
  identitiesMerkleProof: BigInt[][],
) {
  const outputCommitments: [BigNumberish, BigNumberish] = [
    outputs[0].hash,
    outputs[1].hash,
  ] as [BigNumberish, BigNumberish];
  const outputValues = [
    BigInt(outputs[0].value || 0),
    BigInt(outputs[1].value || 0),
  ];
  const outputSalts = [
    BigInt(outputs[0].salt || 0n),
    BigInt(outputs[1].salt || 0n),
  ];
  const outputOwnerPublicKeys: [
    [BigNumberish, BigNumberish],
    [BigNumberish, BigNumberish],
  ] = [
    signer.babyJubPublicKey,
    outputs[1].hash ? signer.babyJubPublicKey : [0n, 0n],
  ] as [[BigNumberish, BigNumberish], [BigNumberish, BigNumberish]];

  const inputObj = {
    outputCommitments,
    outputValues,
    outputSalts,
    outputOwnerPublicKeys,
    identitiesRoot,
    identitiesMerkleProof,
  };

  const circuit = await loadCircuit("deposit_kyc");
  const { provingKeyFile } = loadProvingKeys("deposit_kyc");

  const startWitnessCalculation = Date.now();
  const witness = await circuit.calculateWTNSBin(inputObj, true);
  const timeWithnessCalculation = Date.now() - startWitnessCalculation;

  const startProofGeneration = Date.now();
  const { proof, publicSignals } = (await groth16.prove(
    provingKeyFile,
    witness,
  )) as { proof: BigNumberish[]; publicSignals: BigNumberish[] };
  const timeProofGeneration = Date.now() - startProofGeneration;

  console.log(
    `Witness calculation time: ${timeWithnessCalculation}ms. Proof generation time: ${timeProofGeneration}ms.`,
  );

  const encodedProof = encodeProof(proof);
  return {
    outputCommitments,
    encodedProof,
  };
}

export async function prepareWithdrawProof(
  signer: User,
  inputs: UTXO[],
  output: UTXO,
) {
  const inputCommitments: BigNumberish[] = inputs.map(
    (input) => input.hash,
  ) as BigNumberish[];
  const inputValues = inputs.map((input) => BigInt(input.value || 0n));
  const inputSalts = inputs.map((input) => input.salt || 0n);
  const outputCommitments: [BigNumberish] = [output.hash] as [BigNumberish];
  const outputValues = [BigInt(output.value || 0n)];
  const outputOwnerPublicKeys: [[BigNumberish, BigNumberish]] = [
    signer.babyJubPublicKey,
  ] as [[BigNumberish, BigNumberish]];

  const inputObj = {
    inputCommitments,
    inputValues,
    inputSalts,
    inputOwnerPrivateKey: signer.formattedPrivateKey,
    outputCommitments,
    outputValues,
    outputSalts: [output.salt || 0n],
    outputOwnerPublicKeys,
  };

  let circuit = await loadCircuit("withdraw");
  let { provingKeyFile } = loadProvingKeys("withdraw");
  if (inputCommitments.length > 2) {
    circuit = await loadCircuit("withdraw_batch");
    ({ provingKeyFile } = loadProvingKeys("withdraw_batch"));
  }

  const startWitnessCalculation = Date.now();
  const witness = await circuit.calculateWTNSBin(inputObj, true);
  const timeWithnessCalculation = Date.now() - startWitnessCalculation;

  const startProofGeneration = Date.now();
  const { proof, publicSignals } = (await groth16.prove(
    provingKeyFile,
    witness,
  )) as { proof: BigNumberish[]; publicSignals: BigNumberish[] };
  const timeProofGeneration = Date.now() - startProofGeneration;

  console.log(
    `Witness calculation time: ${timeWithnessCalculation}ms. Proof generation time: ${timeProofGeneration}ms.`,
  );

  const encodedProof = encodeProof(proof);
  return {
    inputCommitments,
    outputCommitments,
    encodedProof,
  };
}

export async function prepareNullifierWithdrawProof(
  signer: User,
  inputs: UTXO[],
  _nullifiers: UTXO[],
  output: UTXO,
  root: BigInt,
  merkleProof: BigInt[][],
) {
  const nullifiers = _nullifiers.map(
    (nullifier) => nullifier.hash,
  ) as BigNumberish[];
  const inputCommitments: BigNumberish[] = inputs.map(
    (input) => input.hash,
  ) as BigNumberish[];
  const inputValues = inputs.map((input) => BigInt(input.value || 0n));
  const inputSalts = inputs.map((input) => input.salt || 0n);
  const outputCommitments: [BigNumberish] = [output.hash] as [BigNumberish];
  const outputValues = [BigInt(output.value || 0n)];
  const outputOwnerPublicKeys: [[BigNumberish, BigNumberish]] = [
    signer.babyJubPublicKey,
  ] as [[BigNumberish, BigNumberish]];

  const inputObj = {
    nullifiers,
    inputCommitments,
    inputValues,
    inputSalts,
    inputOwnerPrivateKey: signer.formattedPrivateKey,
    root,
    enabled: nullifiers.map((n) => (n !== 0n ? 1 : 0)),
    merkleProof,
    outputCommitments,
    outputValues,
    outputSalts: [output.salt || 0n],
    outputOwnerPublicKeys,
  };
  let circuit = await loadCircuit("withdraw_nullifier");
  let { provingKeyFile } = loadProvingKeys("withdraw_nullifier");
  if (inputCommitments.length > 2) {
    circuit = await loadCircuit("withdraw_nullifier_batch");
    ({ provingKeyFile } = loadProvingKeys("withdraw_nullifier_batch"));
  }

  const startWitnessCalculation = Date.now();
  const witness = await circuit.calculateWTNSBin(inputObj, true);
  const timeWithnessCalculation = Date.now() - startWitnessCalculation;

  const startProofGeneration = Date.now();
  const { proof, publicSignals } = (await groth16.prove(
    provingKeyFile,
    witness,
  )) as { proof: BigNumberish[]; publicSignals: BigNumberish[] };
  const timeProofGeneration = Date.now() - startProofGeneration;

  console.log(
    `Witness calculation time: ${timeWithnessCalculation}ms. Proof generation time: ${timeProofGeneration}ms.`,
  );

  const encodedProof = encodeProof(proof);
  return {
    nullifiers,
    outputCommitments,
    encodedProof,
  };
}

export async function prepareBurnProof(
  signer: User,
  inputs: UTXO[],
  output: UTXO,
) {
  const inputCommitments: BigNumberish[] = inputs.map(
    (input) => input.hash,
  ) as BigNumberish[];
  const inputValues = inputs.map((input) => BigInt(input.value || 0n));
  const inputSalts = inputs.map((input) => input.salt || 0n);

  const inputObj = {
    inputCommitments,
    inputValues,
    inputSalts,
    ownerPrivateKey: signer.formattedPrivateKey,
    outputCommitment: [output.hash],
    outputValue: [BigInt(output.value || 0n)],
    outputSalt: [output.salt || 0n],
  };

  let circuit = await loadCircuit("burn");
  let { provingKeyFile } = loadProvingKeys("burn");
  if (inputCommitments.length > 2) {
    circuit = await loadCircuit("burn_batch");
    ({ provingKeyFile } = loadProvingKeys("burn_batch"));
  }

  const startWitnessCalculation = Date.now();
  const witness = await circuit.calculateWTNSBin(inputObj, true);
  const timeWithnessCalculation = Date.now() - startWitnessCalculation;

  const startProofGeneration = Date.now();
  const { proof, publicSignals } = (await groth16.prove(
    provingKeyFile,
    witness,
  )) as { proof: BigNumberish[]; publicSignals: BigNumberish[] };
  const timeProofGeneration = Date.now() - startProofGeneration;

  console.log(
    `Witness calculation time: ${timeWithnessCalculation}ms. Proof generation time: ${timeProofGeneration}ms.`,
  );

  const encodedProof = encodeProof(proof);
  return {
    inputCommitments,
    outputCommitment: output.hash,
    encodedProof,
  };
}

export async function prepareNullifierBurnProof(
  signer: User,
  inputs: UTXO[],
  output: UTXO,
  _nullifiers: UTXO[],
  root: BigInt,
  merkleProof: BigInt[][],
) {
  const nullifiers = _nullifiers.map(
    (nullifier) => nullifier.hash,
  ) as BigNumberish[];
  const inputCommitments: BigNumberish[] = inputs.map(
    (input) => input.hash,
  ) as BigNumberish[];
  const inputValues = inputs.map((input) => BigInt(input.value || 0n));
  const inputSalts = inputs.map((input) => input.salt || 0n);

  const inputObj = {
    nullifiers,
    inputCommitments,
    inputValues,
    inputSalts,
    ownerPrivateKey: signer.formattedPrivateKey,
    root,
    enabled: nullifiers.map((n) => (n !== 0n ? 1 : 0)),
    merkleProof,
    outputCommitment: output.hash,
    outputValue: BigInt(output.value || 0n),
    outputSalt: output.salt || 0n,
  };

  let circuit = await loadCircuit("burn_nullifier");
  let { provingKeyFile } = loadProvingKeys("burn_nullifier");
  if (inputCommitments.length > 2) {
    circuit = await loadCircuit("burn_nullifier_batch");
    ({ provingKeyFile } = loadProvingKeys("burn_nullifier_batch"));
  }

  const startWitnessCalculation = Date.now();
  const witness = await circuit.calculateWTNSBin(inputObj, true);
  const timeWithnessCalculation = Date.now() - startWitnessCalculation;

  const startProofGeneration = Date.now();
  const { proof, publicSignals } = (await groth16.prove(
    provingKeyFile,
    witness,
  )) as { proof: BigNumberish[]; publicSignals: BigNumberish[] };
  const timeProofGeneration = Date.now() - startProofGeneration;

  console.log(
    `Witness calculation time: ${timeWithnessCalculation}ms. Proof generation time: ${timeProofGeneration}ms.`,
  );

  const encodedProof = encodeProof(proof);
  return {
    nullifiers,
    inputCommitments,
    outputCommitment: output.hash,
    encodedProof,
  };
}

export function encodeToBytesForDeposit(proof: any) {
  return new AbiCoder().encode(
    ["tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC)"],
    [proof],
  );
}

export function encodeToBytesForWithdraw(root: any, proof: any) {
  return new AbiCoder().encode(
    ["uint256 root", "tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC)"],
    [root, proof],
  );
}
