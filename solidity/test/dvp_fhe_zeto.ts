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

import { ethers, fhevm, network } from "hardhat";
import { FhevmType } from '@fhevm/hardhat-plugin';
import { Signer, encodeBytes32String, ZeroHash, ContractTransactionReceipt } from "ethers";
import { expect } from "chai";
import { Merkletree, InMemoryDB, str2Bytes } from "@iden3/js-merkletree";
import { loadCircuit } from "zeto-js";

process.env.SKIP_ZETO_TESTS = "true";
import { prepareProof, encodeToBytes } from "./zeto_anon_nullifier";
import {
  UTXO,
  User,
  newUser,
  newUTXO,
  newNullifier,
  doMint,
  ZERO_UTXO,
  parseUTXOEvents,
} from "./lib/utils";
import { deployZeto } from "./lib/deploy";
import { loadProvingKeys, deployAtomIntance, create2Salt, calculateAtomAddress } from "./utils";

describe("DvP flows between fungible and non-fungible tokens based on Zeto with anonymity without encryption or nullifiers", function () {
  // users interacting with each other in the DvP transactions
  let Deployer: User;
  let Alice: User;
  let Bob: User;

  // instances of the contracts
  let zkPayment: any;
  let fheERC20Contract: any;
  let atomInstanceAddress: string;

  // payment UTXOs to be minted and transferred
  let payment1: UTXO;
  let payment2: UTXO;

  // other variables
  let smtAlice: Merkletree;
  let smtAliceForLocked: Merkletree;

  let circuit: any;
  let circuitForLocked: any;
  let provingKey: string;
  let provingKeyForLocked: string;

  before(async function () {
    if (network.name !== "hardhat") {
      // accommodate for longer block times on public networks
      this.timeout(120000);
    }
    let [deployer, a, b] = await ethers.getSigners();
    Deployer = await newUser(deployer);
    Alice = await newUser(a);
    Bob = await newUser(b);

    const storage1 = new InMemoryDB(str2Bytes(""));
    smtAlice = new Merkletree(storage1, true, 64);

    const storage2 = new InMemoryDB(str2Bytes(""));
    smtAliceForLocked = new Merkletree(storage2, true, 64);

    ({ zeto: zkPayment } = await deployZeto("Zeto_AnonNullifier"));
    console.log(`ZK Payment contract deployed at ${zkPayment.target}`);
    circuit = await loadCircuit("anon_nullifier_transfer");
    ({ provingKeyFile: provingKey } = loadProvingKeys(
      "anon_nullifier_transfer",
    ));
    circuitForLocked = await loadCircuit("anon_nullifier_transferLocked");
    ({ provingKeyFile: provingKeyForLocked } = loadProvingKeys(
      "anon_nullifier_transferLocked",
    ));

    const factory = await ethers.getContractFactory("FheERC20");
    fheERC20Contract = await factory.connect(Deployer.signer).deploy();
    console.log(`FHE ERC20 contract deployed at ${fheERC20Contract.target}`);
  });

  it("mint to Alice some payment tokens", async function () {
    payment1 = newUTXO(100, Alice);
    payment2 = newUTXO(20, Alice);
    const result = await doMint(zkPayment, Deployer.signer, [payment1, payment2]);
    await smtAlice.add(payment1.hash, payment1.hash);
    await smtAlice.add(payment2.hash, payment2.hash);

    // simulate Alice and Bob listening to minting events and updating his local merkle tree
    for (const log of result.logs) {
      const event = zkPayment.interface.parseLog(log as any);
      expect(event.args.outputs.length).to.equal(2);
    }

    let root = await smtAlice.root();
    let onchainRoot = await zkPayment.getRoot();
    expect(root.string()).to.equal(onchainRoot.toString());
  });

  it("mint to Bob some FHE ERC20 tokens", async function () {
    const encryptedInput = await fhevm
      .createEncryptedInput(fheERC20Contract.target, Deployer.ethAddress)
      .add64(1000)
      .encrypt();

    const tx = await fheERC20Contract.connect(Deployer.signer).mint(Bob.ethAddress, encryptedInput.handles[0], encryptedInput.inputProof);
    await tx.wait();

    // check the balance of Alice
    const balance = await fheERC20Contract.confidentialBalanceOf(Bob.signer);
    await expect(
      fhevm.userDecryptEuint(FhevmType.euint64, balance, fheERC20Contract.target, Bob.signer),
    ).to.eventually.equal(1000);
  });

  describe("Trade flow between Alice (using Zeto tokens) and Bob (using FHE ERC20 tokens)", function () {
    let lockedUtxo: UTXO;
    let encodedCallDataAlice: string;
    let encodedCallDataBob: string;
    let sequenceNumber: number;

    before(async function () {
      sequenceNumber = 0;
    });

    it("Alice and Bob agrees on an Atom contract address", async function () {
      atomInstanceAddress = await calculateAtomAddress(sequenceNumber);
      console.log("Calculated Atom contract address", atomInstanceAddress);
    });

    it("Alice locks a UTXO to initiate a trade with Bob", async function () {
      // Alice consumes a Zeto token and locks it
      const nullifier1 = newNullifier(payment1, Alice);
      // The locked UTXO is owned by Alice, who is responsible for generating the proof
      // and giving it to the Atom contract as the delegate.
      lockedUtxo = newUTXO(payment1.value!, Alice);
      const root = await smtAlice.root();
      const proof1 = await smtAlice.generateCircomVerifierProof(
        payment1.hash,
        root,
      );
      const proof2 = await smtAlice.generateCircomVerifierProof(0n, root);
      const merkleProofs = [
        proof1.siblings.map((s) => s.bigInt()),
        proof2.siblings.map((s) => s.bigInt()),
      ];
      const encodedProof = await prepareProof(
        circuit,
        provingKey,
        Alice,
        [payment1, ZERO_UTXO],
        [nullifier1, ZERO_UTXO],
        [lockedUtxo, ZERO_UTXO],
        root.bigInt(),
        merkleProofs,
        [Alice, Alice],
      );

      const tx = await zkPayment.connect(Alice.signer).lock(
        [nullifier1.hash],
        [],
        [lockedUtxo.hash],
        encodeToBytes(root.bigInt(), encodedProof), // encode the root and proof together
        atomInstanceAddress,
        "0x",
      );
      const result: ContractTransactionReceipt | null = await tx.wait();

      // Note that the locked UTXO should NOT be added to the local SMT for UTXOs because it's tracked in a separate SMT onchain
      // we add it to the local SMT for locked UTXOs
      const events = parseUTXOEvents(zkPayment, result!);
      await smtAliceForLocked.add(
        events[0].lockedOutputs[0],
        ethers.toBigInt(events[0].delegate),
      );
    });

    it("Alice prepares a proof to spend the locked state, designating the Atom contract as the delegate", async function () {
      // Alice generates a nullifier for the locked UTXO
      const nullifier1 = newNullifier(lockedUtxo, Alice);
      // Alice generates inclusion proofs for the UTXOs to be spent, as private input to the proof generation
      const root = await smtAliceForLocked.root();
      const proof1 = await smtAliceForLocked.generateCircomVerifierProof(
        lockedUtxo.hash,
        root,
      );
      const proof2 = await smtAliceForLocked.generateCircomVerifierProof(
        0n,
        root,
      );
      const merkleProofs = [
        proof1.siblings.map((s) => s.bigInt()),
        proof2.siblings.map((s) => s.bigInt()),
      ];
      // Alice prepares an output UTXO for Bob as the output of the trade
      const paymentForBob = newUTXO(75, Bob);
      const changeForAlice = newUTXO(25, Alice);
      const encodedProof = await prepareProof(
        circuitForLocked,
        provingKeyForLocked,
        Alice,
        [lockedUtxo, ZERO_UTXO],
        [nullifier1, ZERO_UTXO],
        [paymentForBob, changeForAlice],
        root.bigInt(),
        merkleProofs,
        [Bob, Alice],
        atomInstanceAddress, // the Atom contract will be the delegate
      );
      const nullifiers = [nullifier1.hash];
      const outputCommitments = [paymentForBob.hash, changeForAlice.hash];
      encodedCallDataAlice = zkPayment.interface.encodeFunctionData("transferLocked", [nullifiers, [], outputCommitments, encodeToBytes(root.bigInt(), encodedProof), "0x"]);
    });

    it("Bob makes the Atom contract the operator on the Confidential ERC20 contract", async function () {
      const expirationTimestamp = Math.round(Date.now()) + 60 * 60 * 24; // Now + 24 hours
      const tx = await fheERC20Contract.connect(Bob.signer).setOperator(atomInstanceAddress, expirationTimestamp);
      await tx.wait();

      // Bob trades 50 of his FHE ERC20 tokens to Alice
      const encryptedInput = await fhevm
        .createEncryptedInput(fheERC20Contract.target, atomInstanceAddress)
        .add64(50)
        .encrypt();

      encodedCallDataBob = fheERC20Contract.interface.encodeFunctionData(
        "confidentialTransferFrom(address,address,bytes32,bytes)",
        [Bob.ethAddress, Alice.ethAddress, encryptedInput.handles[0], encryptedInput.inputProof]
      );
    });

    it("Alice and Bob each produce the encoded call data and initialize the Atom contract", async function () {
      const operations = [
        {
          contractAddress: zkPayment.target,
          callData: encodedCallDataAlice,
        },
        {
          contractAddress: fheERC20Contract.target,
          callData: encodedCallDataBob,
        }
      ]
      const deployedAtomAddress = await deployAtomIntance(sequenceNumber, operations);
      expect(deployedAtomAddress).to.equal(atomInstanceAddress);
    });

    it("One of Alice or Bob executes the Atom contract to complete the trade", async function () {
      const atomInstance = await ethers.getContractAt("Atom", atomInstanceAddress);
      if (Math.random() < 0.5) {
        const tx = await atomInstance.connect(Alice.signer).execute();
        await tx.wait();
      } else {
        const tx = await atomInstance.connect(Bob.signer).execute();
        await tx.wait();
      }

      // check the balance of Alice
      const balanceAlice = await fheERC20Contract.confidentialBalanceOf(Alice.signer);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint64, balanceAlice, fheERC20Contract.target, Alice.signer),
      ).to.eventually.equal(50);

      // check the balance of Bob
      const balanceBob = await fheERC20Contract.confidentialBalanceOf(Bob.signer);
      await expect(
        fhevm.userDecryptEuint(FhevmType.euint64, balanceBob, fheERC20Contract.target, Bob.signer),
      ).to.eventually.equal(950);
    });
  });
}).timeout(600000);
