// Copyright © 2024 Kaleido, Inc.
//
// SPDX-License-Identifier: Apache-2.0
//
// ZK helpers for the `anon_nullifier_transfer` circuit family ({Zeto_AnonNullifier}
// unlocked-input transfers and createLock). Extracted so escrow and other suites
// can use them without importing the full `zeto_anon_nullifier.ts` Hardhat module.

import { AbiCoder, BigNumberish, ethers } from "ethers";
import { encodeProof } from "zeto-js";
import { groth16 } from "snarkjs";
import { User, UTXO, logger } from "./utils";

/**
 * Build a Groth16 proof for an unlocked-input nullifier transfer (merkle-backed).
 */
export async function prepareProof(
  circuit: any,
  provingKey: any,
  signer: User,
  inputs: UTXO[],
  _nullifiers: UTXO[],
  outputs: UTXO[],
  root: BigInt,
  merkleProof: BigInt[][],
  owners: User[],
  lockDelegate?: string,
) {
  const nullifiers = _nullifiers.map((nullifier) => nullifier.hash) as [
    BigNumberish,
    BigNumberish,
  ];
  const inputCommitments: BigNumberish[] = inputs.map(
    (input) => input.hash,
  ) as BigNumberish[];
  const inputValues = inputs.map((input) => BigInt(input.value || 0n));
  const inputSalts = inputs.map((input) => input.salt || 0n);
  const outputCommitments: BigNumberish[] = outputs.map(
    (output) => output.hash,
  ) as BigNumberish[];
  const outputValues = outputs.map((output) => BigInt(output.value || 0n));
  const outputOwnerPublicKeys: BigNumberish[][] = owners.map(
    (owner) => owner.babyJubPublicKey,
  ) as BigNumberish[][];

  const startWitnessCalculation = Date.now();
  const inputObj: Record<string, unknown> = {
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
    outputSalts: outputs.map((output) => output.salt || 0n),
    outputOwnerPublicKeys,
  };
  if (lockDelegate) {
    inputObj["lockDelegate"] = ethers.toBigInt(lockDelegate);
  }

  const witness = await circuit.calculateWTNSBin(inputObj, true);
  const timeWithnessCalculation = Date.now() - startWitnessCalculation;

  const startProofGeneration = Date.now();
  const { proof } = (await groth16.prove(provingKey, witness)) as {
    proof: BigNumberish[];
    publicSignals: BigNumberish[];
  };
  const timeProofGeneration = Date.now() - startProofGeneration;

  logger.debug(
    `Witness calculation time: ${timeWithnessCalculation}ms. Proof generation time: ${timeProofGeneration}ms.`,
  );

  const encodedProof = encodeProof(proof);
  return encodedProof;
}

/** ABI encoding for nullifier transfer proofs: root prefix + Groth16 tuple. */
export function encodeToBytes(root: any, proof: any) {
  return new AbiCoder().encode(
    ["uint256 root", "tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC)"],
    [root, proof],
  );
}
