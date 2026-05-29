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

import { ethers, network } from "hardhat";
import {
  Signer,
  BigNumberish,
  ContractTransactionReceipt,
  AbiCoder,
} from "ethers";
import { expect } from "chai";
import { loadCircuit, encodeProof, Poseidon } from "zeto-js";
import { groth16 } from "snarkjs";
import { stringifyBigInts } from "maci-crypto";
import { Merkletree, InMemoryDB, str2Bytes } from "@iden3/js-merkletree";
import {
  User,
  UTXO,
  newUser,
  newUTXO,
  newNullifier,
  parseUTXOEvents,
  ZERO_UTXO,
} from "./lib/utils";
import {
  loadProvingKeys,
  prepareDepositProof,
  prepareNullifierWithdrawProof,
  encodeToBytesForDeposit,
  encodeToBytesForWithdraw,
} from "./utils";
import { Zeto_AnonNullifier } from "../typechain-types";
import { deployZeto } from "./lib/deploy";
const USDC_SEPOLIA_ADDRESS = "0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238";
const TRANSFER_AMOUNT = 1000; // 0.001000 UDSC

describe("Shield USDC balances, transact in privacy, and withdraw back to USDC", function () {
  let deployer: Signer;
  let Alice: User;
  let Alice2: User; // Alice2 is used to withdraw back to USDC
  let Bob: User;
  let usdc: any;
  let zeto: Zeto_AnonNullifier;
  let circuit: any, provingKey: any;
  let smtAlice: Merkletree;
  let smtBob: Merkletree;

  let utxo1: UTXO;
  let utxo2: UTXO;
  let utxo3: UTXO;

  let txResult1: ContractTransactionReceipt | null;

  before(async function () {
    this.timeout(600000);
    let [a, b, c] = await ethers.getSigners();
    deployer = a;
    Alice = await newUser(a);
    Alice2 = await newUser(b);
    Bob = await newUser(c);

    ({ zeto, erc20: usdc } = await deployZeto("Zeto_AnonNullifier"));

    circuit = await loadCircuit("anon_nullifier_transfer");
    ({ provingKeyFile: provingKey } = loadProvingKeys(
      "anon_nullifier_transfer",
    ));

    const storage1 = new InMemoryDB(str2Bytes(""));
    smtAlice = new Merkletree(storage1, true, 64);

    const storage2 = new InMemoryDB(str2Bytes(""));
    smtBob = new Merkletree(storage2, true, 64);
  });

  it("Alice shields some USDC balance into the Zeto contract, and get Zeto tokens of the same value", async function () {
    const balance = await usdc.balanceOf(Alice.ethAddress);
    expect(balance).to.be.gt(TRANSFER_AMOUNT);
    const tx1 = await usdc
      .connect(Alice.signer)
      .approve(zeto.target, TRANSFER_AMOUNT);
    await tx1.wait();

    // Alice proposes the output UTXOs to shield her USDC balance
    utxo1 = newUTXO(TRANSFER_AMOUNT, Alice);
    const { outputCommitments, encodedProof } = await prepareDepositProof(
      Alice,
      [utxo1, ZERO_UTXO],
    );
    const tx2 = await zeto
      .connect(Alice.signer)
      .deposit(
        TRANSFER_AMOUNT,
        outputCommitments,
        encodeToBytesForDeposit(encodedProof),
        "0x",
      );
    await tx2.wait();

    // Alice locally tracks the UTXOs inside the Sparse Merkle Tree
    await smtAlice.add(utxo1.hash, utxo1.hash);

    // Bob also tracks the UTXOs inside the Sparse Merkle Tree
    // by using the UTXO events emitted by the Zeto contract
    await smtBob.add(utxo1.hash, utxo1.hash);
  });

  it("Alice transfers some Zeto tokens to Bob", async function () {
    // Alice generates the nullifiers for the UTXOs to be spent
    const nullifier1 = newNullifier(utxo1, Alice);

    // Alice generates inclusion proofs for the UTXOs to be spent
    const root = await smtAlice.root();
    const proof1 = await smtAlice.generateCircomVerifierProof(utxo1.hash, root);
    const proof2 = await smtAlice.generateCircomVerifierProof(0n, root);
    const merkleProofs = [
      proof1.siblings.map((s) => s.bigInt()),
      proof2.siblings.map((s) => s.bigInt()),
    ];

    // Alice proposes the output UTXOs for the transfer to Bob
    utxo2 = newUTXO(TRANSFER_AMOUNT / 2, Bob);
    utxo3 = newUTXO(TRANSFER_AMOUNT / 2, Alice);

    // Alice transfers her UTXOs to Bob
    ({ txResult: txResult1 } = await doTransfer(
      Alice,
      [utxo1, ZERO_UTXO],
      [nullifier1, ZERO_UTXO],
      [utxo2, utxo3],
      root.bigInt(),
      merkleProofs,
      [Bob, Alice],
    ));

    // Alice locally tracks the UTXOs inside the Sparse Merkle Tree
    await smtAlice.add(utxo2.hash, utxo2.hash);
    await smtAlice.add(utxo3.hash, utxo3.hash);

    // Bob also tracks the UTXOs inside the Sparse Merkle Tree
    // by using the UTXO events emitted by the Zeto contract
    await smtBob.add(utxo2.hash, utxo2.hash);
    await smtBob.add(utxo3.hash, utxo3.hash);
  });

  it("Bob constructs the UTXO's local private states", async function () {
    // Bob parses the UTXOs from the onchain event
    const events = parseUTXOEvents(zeto, txResult1!);

    // Bob uses the information received from Alice to reconstruct the UTXO sent to him
    const receivedValue = utxo2.value!;
    const receivedSalt = utxo2.salt;
    const incomingUTXOs: any = events[0].outputs;
    const hash = Poseidon.poseidon4([
      BigInt(receivedValue),
      receivedSalt,
      Bob.babyJubPublicKey[0],
      Bob.babyJubPublicKey[1],
    ]);
    // per convention, the first UTXO in the event is the one sent to the receiver (Bob)
    expect(incomingUTXOs[0]).to.equal(hash);

    // now that the received values have been verified,
    // Bob uses them to construct the local UTXO with the private state
    const bobLocalUTXO = newUTXO(receivedValue, Bob, receivedSalt);

    // Bob can add the private state to his local state storage
    console.log(
      `Bob's local UTXO: ${JSON.stringify(stringifyBigInts(bobLocalUTXO))}`,
    );
  });

  it("Alice withdraws the Zeto tokens back to USDC into a different wallet she owns", async function () {
    const balance1 = await usdc.balanceOf(Alice.ethAddress);

    // Alice generates the nullifiers for the UTXOs to be spent
    const nullifier1 = newNullifier(utxo3, Alice);

    // Alice generates inclusion proofs for the UTXOs to be spent
    let root = await smtAlice.root();
    const proof1 = await smtAlice.generateCircomVerifierProof(utxo3.hash, root);
    const proof2 = await smtAlice.generateCircomVerifierProof(0n, root);
    const merkleProofs = [
      proof1.siblings.map((s) => s.bigInt()),
      proof2.siblings.map((s) => s.bigInt()),
    ];

    // Alice proposes the output ERC20 tokens for the remainder after withdrawal
    const withdrawChangesUTXO = newUTXO(0, Alice);

    const { nullifiers, outputCommitments, encodedProof } =
      await prepareNullifierWithdrawProof(
        Alice,
        [utxo3, ZERO_UTXO],
        [nullifier1, ZERO_UTXO],
        withdrawChangesUTXO,
        root.bigInt(),
        merkleProofs,
      );

    // Alice withdraws her UTXOs to ERC20 tokens, using her other wallet address,
    // Alice2, to receive the USDC tokens. This essentially makes Zeto a mixer,
    // as Alice can withdraw the USDC tokens to a different address than the one
    // she used to shield the USDC tokens. Other parties can not link the
    // original USDC tokens to the withdrawn USDC tokens, because the public key
    // information behind the UTXO is unknown to other parties.
    const tx = await zeto.connect(Alice2.signer).withdraw(
      TRANSFER_AMOUNT / 2, // the amount to withdraw
      nullifiers,
      outputCommitments[0],
      encodeToBytesForWithdraw(root.bigInt(), encodedProof),
      "0x",
    );
    await tx.wait();

    // Alice checks her ERC20 balance
    const balance2 = await usdc.balanceOf(Alice.ethAddress);
    expect(balance1).to.be.equal(balance2);
    const balance3 = await usdc.balanceOf(Alice2.ethAddress);
    expect(balance3).to.be.equal(TRANSFER_AMOUNT / 2);
  });

  async function doTransfer(
    signer: User,
    inputs: UTXO[],
    _nullifiers: UTXO[],
    outputs: UTXO[],
    root: BigInt,
    merkleProofs: BigInt[][],
    owners: User[],
  ) {
    let nullifiers: BigNumberish[];
    let outputCommitments: BigNumberish[];
    let encodedProof: any;
    const result = await prepareProof(
      signer,
      inputs,
      _nullifiers,
      outputs,
      root,
      merkleProofs,
      owners,
    );
    nullifiers = _nullifiers.map(
      (nullifier) => nullifier.hash,
    ) as BigNumberish[];
    outputCommitments = result.outputCommitments;
    encodedProof = result.encodedProof;

    const txResult = await sendTx(
      signer,
      nullifiers,
      outputCommitments,
      root,
      encodedProof,
    );
    // add the clear text value so that it can be used by tests to compare with the decrypted value
    return {
      txResult,
      expectedPlainText: outputs.reduce((acc, o, i) => {
        acc.push(BigInt(o.value || 0n) as BigNumberish);
        acc.push((o.salt || 0n) as BigNumberish);
        return acc;
      }, [] as BigNumberish[]),
    };
  }

  async function sendTx(
    signer: User,
    nullifiers: BigNumberish[],
    outputCommitments: BigNumberish[],
    root: BigNumberish,
    encodedProof: any,
  ) {
    const startTx = Date.now();
    let tx: any;
    tx = await zeto.connect(signer.signer).transfer(
      nullifiers.filter((ic) => ic !== 0n), // trim off empty utxo hashes to check padding logic for batching works
      outputCommitments.filter((oc) => oc !== 0n), // trim off empty utxo hashes to check padding logic for batching works
      encodeToBytes(root, encodedProof),
      "0x",
    );
    const results: ContractTransactionReceipt | null = await tx.wait();
    console.log(
      `Time to execute transaction: ${Date.now() - startTx}ms. Gas used: ${results?.gasUsed}`,
    );
    return results;
  }

  async function prepareProof(
    signer: User,
    inputs: UTXO[],
    _nullifiers: UTXO[],
    outputs: UTXO[],
    root: BigInt,
    merkleProof: BigInt[][],
    owners: User[],
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
    const inputObj: any = {
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

    const witness = await circuit.calculateWTNSBin(inputObj, true);
    const timeWithnessCalculation = Date.now() - startWitnessCalculation;

    const startProofGeneration = Date.now();
    const { proof, publicSignals } = (await groth16.prove(
      provingKey,
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
});

function encodeToBytes(root: any, proof: any) {
  return new AbiCoder().encode(
    ["uint256 root", "tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC)"],
    [root, proof],
  );
}
