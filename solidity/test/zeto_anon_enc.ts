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
  ContractTransactionReceipt,
  Signer,
  BigNumberish,
  AbiCoder,
} from "ethers";
import { expect } from "chai";
import {
  loadCircuit,
  poseidonDecrypt,
  encodeProof,
  Poseidon,
  newEncryptionNonce,
} from "zeto-js";
import { groth16 } from "snarkjs";
import {
  genKeypair,
  formatPrivKeyForBabyJub,
  genEcdhSharedKey,
  stringifyBigInts,
} from "maci-crypto";
import {
  User,
  UTXO,
  newUser,
  newUTXO,
  doMint,
  ZERO_UTXO,
  parseUTXOEvents,
} from "./lib/utils";
import {
  loadProvingKeys,
  prepareDepositProof,
  prepareWithdrawProof,
  encodeToBytesForDeposit,
} from "./utils";
import { deployZeto } from "./lib/deploy";

const poseidonHash = Poseidon.poseidon4;

describe("Zeto based fungible token with anonymity and encryption", function () {
  let deployer: Signer;
  let Alice: User;
  let Bob: User;
  let Charlie: User;
  let erc20: any;
  let zeto: any;
  let utxo100: UTXO;
  let utxo1: UTXO;
  let utxo2: UTXO;
  let utxo3: UTXO;
  let utxo4: UTXO;
  let circuit: any, provingKey: any;
  let batchCircuit: any, batchProvingKey: any;

  before(async function () {
    if (network.name !== "hardhat") {
      // accommodate for longer block times on public networks
      this.timeout(120000);
    }
    let [d, a, b, c] = await ethers.getSigners();
    deployer = d;
    Alice = await newUser(a);
    Bob = await newUser(b);
    Charlie = await newUser(c);

    ({ deployer, zeto, erc20 } = await deployZeto("Zeto_AnonEnc"));

    circuit = await loadCircuit("anon_enc");
    ({ provingKeyFile: provingKey } = loadProvingKeys("anon_enc"));
    batchCircuit = await loadCircuit("anon_enc_batch");
    ({ provingKeyFile: batchProvingKey } = loadProvingKeys("anon_enc_batch"));
  });

  it("(batch) mint to Alice and batch transfer 10 UTXOs honestly to Bob & Charlie then withdraw should succeed", async function () {
    // first mint the tokens for batch testing
    const inputUtxos = [];
    for (let i = 0; i < 10; i++) {
      // mint 10 utxos
      inputUtxos.push(newUTXO(1, Alice));
    }
    await doMint(zeto, deployer, inputUtxos);

    const aliceUTXOsToBeWithdrawn = [
      newUTXO(1, Alice),
      newUTXO(1, Alice),
      newUTXO(1, Alice),
    ];
    // Alice proposes the output UTXOs, 1 utxo to bob, 1 utxo to charlie and 3 utxos to alice
    const _bOut1 = newUTXO(6, Bob);
    const _bOut2 = newUTXO(1, Charlie);

    const outputUtxos = [_bOut1, _bOut2, ...aliceUTXOsToBeWithdrawn];
    const outputOwners = [Bob, Charlie, Alice, Alice, Alice];
    const inflatedOutputUtxos = [...outputUtxos];
    const inflatedOutputOwners = [...outputOwners];
    for (let i = 0; i < 10 - outputUtxos.length; i++) {
      inflatedOutputUtxos.push(ZERO_UTXO);
      inflatedOutputOwners.push(Bob);
    }

    // Alice transfers UTXOs to Bob
    const result = await doTransfer(
      Alice,
      inputUtxos,
      inflatedOutputUtxos,
      inflatedOutputOwners,
    );

    const events = parseUTXOEvents(zeto, result.txResult!);
    const event = events[0];
    expect(event.inputs).to.deep.equal(inputUtxos.map((i) => i.hash));
    const incomingUTXOs: any = event.outputs;
    const ecdhPublicKey = event.ecdhPublicKey;

    // check the non-empty output hashes are correct
    for (let i = 0; i < outputUtxos.length; i++) {
      const utxoOwner = outputOwners[i];
      const sharedKey = genEcdhSharedKey(
        utxoOwner.babyJubPrivateKey,
        ecdhPublicKey,
      );
      const plainText = poseidonDecrypt(
        event.encryptedValues.slice(4 * i, 4 * i + 4),
        sharedKey,
        event.encryptionNonce,
        2,
      );
      expect(plainText).to.deep.equal(
        result.expectedPlainText.slice(2 * i, 2 * i + 2),
      );
      const hash = poseidonHash([
        BigInt(plainText[0]),
        plainText[1],
        utxoOwner.babyJubPublicKey[0],
        utxoOwner.babyJubPublicKey[1],
      ]);
      expect(incomingUTXOs[i]).to.equal(hash);
    }

    // mint sufficient balance in Zeto contract address for Alice to withdraw
    const mintTx = await erc20.connect(deployer).mint(zeto, 3);
    await mintTx.wait();
    const startingBalance = await erc20.balanceOf(Alice.ethAddress);

    // Alice generates the nullifiers for the UTXOs to be spent
    const inflatedWithdrawInputs = [...aliceUTXOsToBeWithdrawn];

    // Alice generates inclusion proofs for the UTXOs to be spent

    for (let i = aliceUTXOsToBeWithdrawn.length; i < 10; i++) {
      inflatedWithdrawInputs.push(ZERO_UTXO);
    }
    const { inputCommitments, outputCommitments, encodedProof } =
      await prepareWithdrawProof(Alice, inflatedWithdrawInputs, ZERO_UTXO);

    // Alice withdraws her UTXOs to ERC20 tokens
    const tx = await zeto
      .connect(Alice.signer)
      .withdraw(
        3,
        inputCommitments,
        outputCommitments[0],
        encodeToBytesForWithdraw(encodedProof),
        "0x",
      );
    await tx.wait();

    // Alice checks her ERC20 balance
    const endingBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(endingBalance - startingBalance).to.be.equal(3);
  });

  it("mint ERC20 tokens to Alice to deposit to Zeto should succeed", async function () {
    const startingBalance = await erc20.balanceOf(Alice.ethAddress);
    const tx = await erc20.connect(deployer).mint(Alice.ethAddress, 100);
    await tx.wait();
    const endingBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(endingBalance - startingBalance).to.be.equal(100);

    const tx1 = await erc20.connect(Alice.signer).approve(zeto.target, 100);
    await tx1.wait();

    utxo100 = newUTXO(100, Alice);
    const utxo0 = newUTXO(0, Alice);
    const { outputCommitments, encodedProof } = await prepareDepositProof(
      Alice,
      [utxo100, utxo0],
    );
    const tx2 = await zeto
      .connect(Alice.signer)
      .deposit(
        100,
        outputCommitments,
        encodeToBytesForDeposit(encodedProof),
        "0x",
      );
    await tx2.wait();
  }).timeout(60000);

  it("mint to Alice and transfer UTXOs honestly to Bob should succeed", async function () {
    const startingBalance = await erc20.balanceOf(Alice.ethAddress);
    // first the authority mints UTXOs to Alice
    utxo1 = newUTXO(10, Alice);
    utxo2 = newUTXO(20, Alice);
    await doMint(zeto, deployer, [utxo1, utxo2]);

    // check the private mint activity is not exposed in the ERC20 contract
    const afterMintBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(afterMintBalance).to.equal(startingBalance);

    // Alice proposes the output UTXOs
    const _utxo1 = newUTXO(25, Bob);
    utxo4 = newUTXO(5, Alice, _utxo1.salt);

    // Alice transfers UTXOs to Bob
    const result = await doTransfer(
      Alice,
      [utxo1, utxo2],
      [_utxo1, utxo4],
      [Bob, Alice],
    );

    // check the private transfer activity is not exposed in the ERC20 contract
    const afterTransferBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(afterTransferBalance).to.equal(startingBalance);

    // Bob uses the information in the event to recover the incoming UTXO
    // first obtain the UTXO from the transaction event
    const events = parseUTXOEvents(zeto, result.txResult!);
    const event = events[0];
    expect(event.inputs).to.deep.equal([utxo1.hash, utxo2.hash]);
    expect(event.outputs).to.deep.equal([_utxo1.hash, utxo4.hash]);
    const incomingUTXOs: any = event.outputs;

    const ecdhPublicKey = event.ecdhPublicKey;
    // Bob reconstructs the shared key using his private key and ephemeral public key

    const sharedKey = genEcdhSharedKey(Bob.babyJubPrivateKey, ecdhPublicKey);
    const plainText = poseidonDecrypt(
      event.encryptedValues.slice(0, 4),
      sharedKey,
      event.encryptionNonce,
      2,
    );
    expect(plainText).to.deep.equal(result.expectedPlainText.slice(0, 2));
    // Bob verifies that the UTXO constructed from the decrypted values matches the UTXO from the event
    const hash = poseidonHash([
      BigInt(plainText[0]),
      plainText[1],
      Bob.babyJubPublicKey[0],
      Bob.babyJubPublicKey[1],
    ]);
    expect(hash).to.equal(incomingUTXOs[0]);

    // simulate Bob using the decrypted values to construct the UTXO received from the transaction
    utxo3 = newUTXO(Number(plainText[0]), Bob, plainText[1]);
  });

  it("Bob transfers UTXOs, previously received from Alice, honestly to Charlie should succeed", async function () {
    // propose the output UTXOs
    const _utxo1 = newUTXO(25, Charlie);
    // Bob should be able to spend the UTXO that was reconstructed from the previous transaction
    await doTransfer(
      Bob,
      [utxo3, ZERO_UTXO],
      [_utxo1, ZERO_UTXO],
      [Charlie, Bob],
    );
  });

  it("Alice withdraws her UTXOs to ERC20 tokens should succeed", async function () {
    const startingBalance = await erc20.balanceOf(Alice.ethAddress);
    // Alice proposes the output ERC20 tokens
    const outputCommitment = newUTXO(20, Alice);

    const { inputCommitments, outputCommitments, encodedProof } =
      await prepareWithdrawProof(Alice, [utxo100, ZERO_UTXO], outputCommitment);

    // Alice withdraws her UTXOs to ERC20 tokens
    const tx = await zeto
      .connect(Alice.signer)
      .withdraw(
        80,
        inputCommitments,
        outputCommitments[0],
        encodeToBytesForWithdraw(encodedProof),
        "0x",
      );
    await tx.wait();

    // Alice checks her ERC20 balance
    const endingBalance = await erc20.balanceOf(Alice.ethAddress);
    expect(endingBalance - startingBalance).to.be.equal(80);
  });

  describe("failure cases", function () {
    // the following failure cases rely on the hardhat network
    // to return the details of the errors. This is not possible
    // on non-hardhat networks
    if (network.name !== "hardhat") {
      return;
    }

    it("Alice attempting to withdraw spent UTXOs should fail", async function () {
      // Alice proposes the output ERC20 tokens
      const outputCommitment = newUTXO(90, Alice);

      const { inputCommitments, outputCommitments, encodedProof } =
        await prepareWithdrawProof(
          Alice,
          [utxo100, ZERO_UTXO],
          outputCommitment,
        );

      await expect(
        zeto
          .connect(Alice.signer)
          .withdraw(
            10,
            inputCommitments,
            outputCommitments[0],
            encodeToBytesForWithdraw(encodedProof),
            "0x",
          ),
      ).rejectedWith("UTXOAlreadySpent");
    });

    it("mint existing unspent UTXOs should fail", async function () {
      await expect(doMint(zeto, deployer, [utxo4])).rejectedWith(
        "UTXOAlreadyOwned",
      );
    });

    it("mint existing spent UTXOs should fail", async function () {
      await expect(doMint(zeto, deployer, [utxo1])).rejectedWith(
        "UTXOAlreadySpent",
      );
    });

    it("transfer non-existing UTXOs should fail", async function () {
      const nonExisting1 = newUTXO(10, Alice);
      const nonExisting2 = newUTXO(20, Alice, nonExisting1.salt);
      await expect(
        doTransfer(
          Alice,
          [nonExisting1, nonExisting2],
          [nonExisting1, nonExisting2],
          [Alice, Alice],
        ),
      ).rejectedWith("UTXONotMinted");
    });

    it("transfer spent UTXOs should fail (double spend protection)", async function () {
      // create outputs
      const _utxo1 = newUTXO(25, Bob);
      const _utxo2 = newUTXO(5, Alice);
      await expect(
        doTransfer(Alice, [utxo1, utxo2], [_utxo1, _utxo2], [Bob, Alice]),
      ).rejectedWith("UTXOAlreadySpent");
    });

    it("spend by using the same UTXO as both inputs should fail", async function () {
      // mint a new UTXO to Bob
      const _utxo1 = newUTXO(20, Bob);
      await doMint(zeto, deployer, [_utxo1]);

      const _utxo2 = newUTXO(25, Alice);
      const _utxo3 = newUTXO(15, Bob);
      await expect(
        doTransfer(Bob, [_utxo1, _utxo1], [_utxo2, _utxo3], [Alice, Bob]),
      ).rejectedWith(`UTXODuplicate(${_utxo1.hash.toString()}`);
    });
  });

  // describe("lockStates() tests", function () {
  //   it("lockStates() should succeed when using unlocked states", async function () {
  //     const { commitments, encodedProof } = await prepareLockProof(Alice, [utxo4, ZERO_UTXO]);

  //     const tx = await zeto.connect(Alice.signer).lockStates(
  //       commitments.filter((ic) => ic !== 0n), // trim off empty utxo hashes to check padding logic for batching works
  //       encodedProof,
  //       Bob.ethAddress, // make Bob the delegate who can spend the state (if she has the right proof)
  //       "0x",
  //     );
  //     const results = await tx.wait();
  //     console.log(`Method transfer() complete. Gas used: ${results?.gasUsed}`);
  //   });

  //   it("lockStates() should fail when trying to lock as non-delegate", async function () {
  //     if (network.name !== "hardhat") {
  //       return;
  //     }

  //     // Bob is the owner of the UTXO, so he can generate the right proof
  //     const { commitments, encodedProof } = await prepareLockProof(Alice, [utxo4, ZERO_UTXO]);

  //     // but he's no longer the delegate (Alice is) to spend the state
  //     await expect(zeto.connect(Alice.signer).lockStates(
  //       commitments.filter((ic) => ic !== 0n), // trim off empty utxo hashes to check padding logic for batching works
  //       encodedProof,
  //       Alice.ethAddress,
  //       "0x",
  //     )).rejectedWith(`UTXOAlreadyLocked(${utxo4.hash.toString()})`);
  //   });

  //   it("the original owner can NOT spend the locked state", async function () {
  //     const utxo8 = newUTXO(5, Charlie);
  //     const ephemeralKeypair = genKeypair();
  //     await expect(doTransfer(Alice, [utxo4, ZERO_UTXO], [utxo8, ZERO_UTXO], [Charlie, Alice])).to.be.rejectedWith("UTXOAlreadyLocked");
  //   });

  //   it("the original owner can NOT withdraw the locked state", async function () {
  //     const utxo8 = newUTXO(0, Alice);
  //     const { inputCommitments, outputCommitments, encodedProof } =
  //       await prepareWithdrawProof(Alice, [utxo4, ZERO_UTXO], utxo8);

  //     await expect(zeto
  //       .connect(Alice.signer)
  //       .withdraw(5, inputCommitments, outputCommitments[0], encodedProof, "0x")).to.be.rejectedWith("UTXOAlreadyLocked");
  //   });

  //   it("the designated delegate can use the proper proof to spend the locked state", async function () {
  //     const utxo8 = newUTXO(5, Charlie);
  //     const ephemeralKeypair = genKeypair();
  //     const { inputCommitments, outputCommitments, encodedProof, encryptedValues, encryptionNonce } = await prepareProof(Alice, [utxo4, ZERO_UTXO], [utxo8, ZERO_UTXO], [Charlie, Alice], ephemeralKeypair.privKey);
  //     // Bob (in reality this is usually a contract that orchestrates a trade flow) can spend the locked state
  //     // using the proof generated by the trade counterparty (Alice in this case)
  //     await expect(sendTx(Bob, inputCommitments, outputCommitments, encryptedValues, encryptionNonce, encodedProof, ephemeralKeypair.pubKey)).to.be.fulfilled;
  //   });
  // });

  async function doTransfer(
    signer: User,
    inputs: UTXO[],
    outputs: UTXO[],
    owners: User[],
  ) {
    let inputCommitments: BigNumberish[];
    let outputCommitments: BigNumberish[];
    let encryptedValues: BigNumberish[];
    let encryptionNonce: BigNumberish;
    let encodedProof: any;
    const ephemeralKeypair = genKeypair();
    const result = await prepareProof(
      signer,
      inputs,
      outputs,
      owners,
      ephemeralKeypair.privKey,
    );
    inputCommitments = result.inputCommitments;
    outputCommitments = result.outputCommitments;
    encodedProof = result.encodedProof;
    encryptedValues = result.encryptedValues;
    encryptionNonce = result.encryptionNonce;

    const txResult = await sendTx(
      signer,
      inputCommitments,
      outputCommitments,
      encryptedValues,
      encryptionNonce,
      encodedProof,
      ephemeralKeypair.pubKey,
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

  async function prepareProof(
    signer: User,
    inputs: UTXO[],
    outputs: UTXO[],
    owners: User[],
    ephemeralPrivateKey: BigInt,
  ) {
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
    const encryptionNonce: BigNumberish = newEncryptionNonce() as BigNumberish;
    const encryptInputs = stringifyBigInts({
      encryptionNonce,
      ecdhPrivateKey: formatPrivKeyForBabyJub(ephemeralPrivateKey),
    });

    let circuitToUse = circuit;
    let provingKeyToUse = provingKey;
    let isBatch = false;
    if (inputCommitments.length > 2 || outputCommitments.length > 2) {
      isBatch = true;
      circuitToUse = batchCircuit;
      provingKeyToUse = batchProvingKey;
    }
    const startWitnessCalculation = Date.now();
    const witness = await circuitToUse.calculateWTNSBin(
      {
        inputCommitments,
        inputValues,
        inputSalts,
        inputOwnerPrivateKey: formatPrivKeyForBabyJub(signer.babyJubPrivateKey),
        outputCommitments,
        outputValues,
        outputSalts: outputs.map((output) => output.salt || 0n),
        outputOwnerPublicKeys,
        ...encryptInputs,
      },
      true,
    );
    const timeWitnessCalculation = Date.now() - startWitnessCalculation;

    const startProofGeneration = Date.now();
    const { proof, publicSignals } = (await groth16.prove(
      provingKeyToUse,
      witness,
    )) as { proof: BigNumberish[]; publicSignals: BigNumberish[] };
    const timeProofGeneration = Date.now() - startProofGeneration;
    console.log(
      `Witness calculation time: ${timeWitnessCalculation}ms, Proof generation time: ${timeProofGeneration}ms`,
    );

    // console.log(publicSignals);
    const encodedProof = encodeProof(proof);
    const encryptedValues = isBatch
      ? publicSignals.slice(2, 42)
      : publicSignals.slice(2, 10);
    return {
      inputCommitments,
      outputCommitments,
      encryptedValues,
      encryptionNonce,
      encodedProof,
    };
  }

  async function sendTx(
    signer: User,
    inputCommitments: BigNumberish[],
    outputCommitments: BigNumberish[],
    encryptedValues: BigNumberish[],
    encryptionNonce: BigNumberish,
    encodedProof: any,
    ecdhPublicKey: BigInt[],
  ) {
    const tx = await zeto.connect(signer.signer).transfer(
      inputCommitments.filter((ic) => ic !== 0n), // trim off empty utxo hashes to check padding logic for batching works
      outputCommitments.filter((oc) => oc !== 0n), // trim off empty utxo hashes to check padding logic for batching works
      encodeToBytes(
        encryptionNonce,
        ecdhPublicKey,
        encryptedValues,
        encodedProof,
      ),
      "0x",
    );
    const results: ContractTransactionReceipt | null = await tx.wait();

    for (const input of inputCommitments) {
      if (input === 0n) continue;
      expect(await zeto.spent(input)).to.equal(2n);
    }
    for (const output of outputCommitments) {
      if (output === 0n) continue;
      expect(await zeto.spent(output)).to.equal(1n);
    }
    console.log(`Method transfer() complete. Gas used: ${results?.gasUsed}`);

    return results;
  }
});

function encodeToBytes(
  encryptionNonce: any,
  ecdhPublicKey: any,
  encryptedValues: any,
  proof: any,
) {
  const bytes = new AbiCoder().encode(
    [
      "uint256 encryptionNonce",
      "uint256[2] ecdhPublicKey",
      "uint256[] encryptedValues",
      "tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC)",
    ],
    [encryptionNonce, ecdhPublicKey, encryptedValues, proof],
  );
  console.log("Encryption nonce:", encryptionNonce);
  console.log("ECDH public key:", ecdhPublicKey);
  console.log("Encrypted values:", encryptedValues);
  console.log("Proof:", proof);
  console.log("Encoded proof:", bytes);
  return bytes;
}

function encodeToBytesForWithdraw(proof: any) {
  return new AbiCoder().encode(
    ["tuple(uint256[2] pA, uint256[2][2] pB, uint256[2] pC)"],
    [proof],
  );
}
