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

import { ethers, ignition, network } from "hardhat";
import { Signer, encodeBytes32String, ZeroHash, ContractTransactionReceipt } from "ethers";
import { expect } from "chai";
import { Merkletree, InMemoryDB, str2Bytes } from "@iden3/js-merkletree";
import { loadCircuit } from "zeto-js";
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
import { loadProvingKeys } from "./utils";

describe("DvP flows between fungible and non-fungible tokens based on Zeto with anonymity without encryption or nullifiers", function () {
  // users interacting with each other in the DvP transactions
  let Alice: User;
  let Bob: User;

  // instances of the contracts
  let zkPayment: any;

  // payment UTXOs to be minted and transferred
  let payment1: UTXO;
  let payment2: UTXO;

  // other variables
  let deployer: Signer;
  let smtAlice: Merkletree;
  let smtAliceForLocked: Merkletree;

  let circuit: any;
  let provingKey: string;

  before(async function () {
    if (network.name !== "hardhat") {
      // accommodate for longer block times on public networks
      this.timeout(120000);
    }
    let [d, a, b, c] = await ethers.getSigners();
    deployer = d;
    Alice = await newUser(a);
    Bob = await newUser(b);

    const storage1 = new InMemoryDB(str2Bytes(""));
    smtAlice = new Merkletree(storage1, true, 64);

    const storage2 = new InMemoryDB(str2Bytes(""));
    smtAliceForLocked = new Merkletree(storage2, true, 64);

    ({ deployer, zeto: zkPayment } = await deployZeto("Zeto_AnonNullifier"));
    console.log(`ZK Payment contract deployed at ${zkPayment.target}`);
    circuit = await loadCircuit("anon_nullifier_transfer");
    ({ provingKeyFile: provingKey } = loadProvingKeys(
      "anon_nullifier_transfer",
    ));
  });

  it("mint to Alice some payment tokens", async function () {
    payment1 = newUTXO(10, Alice);
    payment2 = newUTXO(20, Alice);
    const result = await doMint(zkPayment, deployer, [payment1, payment2]);

    // simulate Alice and Bob listening to minting events and updating his local merkle tree
    for (const log of result.logs) {
      const event = zkPayment.interface.parseLog(log as any);
      expect(event.args.outputs.length).to.equal(2);
    }
  });

  describe("lock -> delegate -> transfer flow", function () {
    let lockedUtxo: UTXO;

    it("Alice locks a UTXO to Bob and makes the DvP contract as the delegate ", async function () {
      const nullifier1 = newNullifier(payment1, Alice);
      lockedUtxo = newUTXO(payment1.value!, Bob);
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
        [Bob, Bob],
      );

      const tx = await zkPayment.connect(Alice.signer).lock(
        [nullifier1.hash],
        [],
        [lockedUtxo.hash],
        encodeToBytes(root.bigInt(), encodedProof), // encode the root and proof together
        Alice.ethAddress, // make Alice the delegate who can spend the state (if she has the right proof)
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

    it("Alice delegates the lock to Charlie", async function () {
      const tx = await zeto
        .connect(Alice.signer)
        .delegateLock([lockedUtxo2.hash], Charlie.ethAddress, "0x");
      const result = await tx.wait();
      const events = parseUTXOEvents(zeto, result);
      // this should update the existing leaf node value from address of Alice to Charlie
      await smtBobForLocked.update(
        events[0].lockedOutputs[0],
        ethers.toBigInt(events[0].newDelegate),
      );
    });

    it("onchain SMT root for the locked UTXOs should be equal to the offchain SMT root", async function () {
      const root = await smtBobForLocked.root();
      const onchainRoot = await zeto.getRootForLocked();
      expect(root.string()).to.equal(onchainRoot.toString());
    });

    it("an invalid delegate can NOT use the proper proof to spend the locked state", async function () {
      // Bob generates inclusion proofs for the UTXOs to be spent, as private input to the proof generation
      const nullifier1 = newNullifier(lockedUtxo2, Bob);
      const root = await smtBobForLocked.root();
      const proof1 = await smtBobForLocked.generateCircomVerifierProof(
        lockedUtxo2.hash,
        root,
      );
      const proof2 = await smtBobForLocked.generateCircomVerifierProof(
        0n,
        root,
      );
      const merkleProofs = [
        proof1.siblings.map((s) => s.bigInt()),
        proof2.siblings.map((s) => s.bigInt()),
      ];
      // Bob proposes the output UTXOs, attempting to transfer the locked UTXO to Alice
      const utxo1 = newUTXO(1, Alice);
      utxo11 = newUTXO(4, Bob);

      const encodedProof = await prepareProof(
        circuitForLocked,
        provingKeyForLocked,
        Bob,
        [lockedUtxo2, ZERO_UTXO],
        [nullifier1, ZERO_UTXO],
        [utxo1, utxo11],
        root.bigInt(),
        merkleProofs,
        [Alice, Bob],
        Charlie.ethAddress, // current lock delegate
      );
      const nullifiers = [nullifier1.hash];

      // Charlie NOT being the delegate can NOT spend the locked state
      // using the proof generated by the trade counterparty (Bob in this case)
      await expect(
        sendTx(
          Eva,
          nullifiers,
          [utxo1.hash, utxo11.hash],
          root.bigInt(),
          encodedProof,
          true,
        ),
      ).to.be.rejectedWith("Invalid proof");
    });

    it("Charlie can use the proper proof to spend the locked state", async function () {
      // Bob generates inclusion proofs for the UTXOs to be spent, as private input to the proof generation
      const nullifier1 = newNullifier(lockedUtxo2, Bob);
      const root = await smtBobForLocked.root();
      const proof1 = await smtBobForLocked.generateCircomVerifierProof(
        lockedUtxo2.hash,
        root,
      );
      const proof2 = await smtBobForLocked.generateCircomVerifierProof(
        0n,
        root,
      );
      const merkleProofs = [
        proof1.siblings.map((s) => s.bigInt()),
        proof2.siblings.map((s) => s.bigInt()),
      ];
      // Bob proposes the output UTXOs, attempting to transfer the locked UTXO to Alice
      const utxo1 = newUTXO(1, Alice);
      utxo11 = newUTXO(4, Bob);

      const encodedProof = await prepareProof(
        circuitForLocked,
        provingKeyForLocked,
        Bob,
        [lockedUtxo2, ZERO_UTXO],
        [nullifier1, ZERO_UTXO],
        [utxo1, utxo11],
        root.bigInt(),
        merkleProofs,
        [Alice, Bob],
        Charlie.ethAddress, // current lock delegate
      );
      const nullifiers = [nullifier1.hash];

      // Charlie (in reality this is usually a contract that orchestrates a trade flow) can spend the locked state
      // using the proof generated by the trade counterparty (Bob in this case)
      await expect(
        sendTx(
          Charlie,
          nullifiers,
          [utxo1.hash, utxo11.hash],
          root.bigInt(),
          encodedProof,
          true,
        ),
      ).to.be.fulfilled;

      // Alice and Bob keep the local SMT in sync
      await smtAlice.add(utxo1.hash, utxo1.hash);
      await smtAlice.add(utxo11.hash, utxo11.hash);
      await smtBob.add(utxo1.hash, utxo1.hash);
      await smtBob.add(utxo11.hash, utxo11.hash);
    });
  });
}).timeout(600000);
