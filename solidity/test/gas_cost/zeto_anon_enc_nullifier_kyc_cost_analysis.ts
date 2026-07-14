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
import fs from "fs";
import path from "path";
import { ethers, network } from "hardhat";
import { ContractTransactionReceipt, Signer, BigNumberish } from "ethers";
import { expect } from "chai";
import { loadCircuit, encodeProof, newEncryptionNonce, kycHash } from "zeto-js";
import { groth16 } from "snarkjs";
import {
  genKeypair,
  formatPrivKeyForBabyJub,
  stringifyBigInts,
} from "maci-crypto";
import AsyncLock from "async-lock";
const lock = new AsyncLock();
import { Merkletree, InMemoryDB, str2Bytes } from "@iden3/js-merkletree";
import {
  UTXO,
  User,
  newUser,
  newUTXO,
  newNullifier,
  doMint,
  doDeposit,
  doWithdraw,
  ZERO_UTXO,
  parseRegistryEvents,
} from "../lib/utils";
import {
  loadProvingKeys,
  prepareDepositProof,
  prepareNullifierWithdrawProof,
} from "../utils";
import { deployZeto } from "../lib/deploy";

const TOTAL_AMOUNT = parseInt(process.env.TOTAL_ROUNDS || "1000");
const TX_CONCURRENCY = parseInt(process.env.TX_CONCURRENCY || "1");
const UTXO_PER_TX = 10;

describe.skip("(Gas cost analysis) Zeto based fungible token with anonymity using nullifiers and encryption with KYC", function () {
  let deployer: Signer;
  let Alice: User;
  let Bob: User;
  let Charlie: User;
  let erc20: any;
  let zeto: any;
  const atMostHalfAmount = Math.floor(TOTAL_AMOUNT / 2);
  const atLeastHalfAmount = atMostHalfAmount + (TOTAL_AMOUNT % 2);
  const mintCount =
    Math.floor(atLeastHalfAmount / UTXO_PER_TX) +
    (atLeastHalfAmount % UTXO_PER_TX !== 0 ? 1 : 0);
  let unspentAliceUTXOs: UTXO[] = [];
  let unspentBobUTXOs: UTXO[] = [];
  let mintGasCostHistory: number[] = [];
  let depositGasCostHistory: number[] = [];
  let transferGasCostHistory: number[] = [];
  let withdrawGasCostHistory: number[] = [];
  let circuit: any, provingKey: any;
  let batchCircuit: any, batchProvingKey: any;
  let smtAlice: Merkletree;
  let smtBob: Merkletree;
  let smtKyc: Merkletree;
  const transferCount =
    Math.floor(TOTAL_AMOUNT / UTXO_PER_TX) +
    (TOTAL_AMOUNT % UTXO_PER_TX !== 0 ? 1 : 0);

  const date = new Date();
  const reportPrefix = date.toISOString();

  before(async function () {
    if (network.name !== "hardhat") {
      // accommodate for longer block times on public networks
      this.timeout(120000);
    }
    let [d, a, b, c, e] = await ethers.getSigners();
    deployer = d;
    Alice = await newUser(a);
    Bob = await newUser(b);
    Charlie = await newUser(c);

    ({ deployer, zeto, erc20 } = await deployZeto("Zeto_AnonEncNullifierKyc"));

    const tx2 = await zeto.connect(deployer).register(Alice.babyJubPublicKey);
    const result1 = await tx2.wait();
    const tx3 = await zeto.connect(deployer).register(Bob.babyJubPublicKey);
    const result2 = await tx3.wait();
    const tx4 = await zeto.connect(deployer).register(Charlie.babyJubPublicKey);
    const result3 = await tx4.wait();

    const storage1 = new InMemoryDB(str2Bytes("alice"));
    smtAlice = new Merkletree(storage1, true, 64);

    const storage2 = new InMemoryDB(str2Bytes("bob"));
    smtBob = new Merkletree(storage2, true, 64);

    const storage3 = new InMemoryDB(str2Bytes("kyc"));
    smtKyc = new Merkletree(storage3, true, 10);

    const publicKey1 = parseRegistryEvents(zeto, result1);
    await smtKyc.add(kycHash(publicKey1), kycHash(publicKey1));
    const publicKey2 = parseRegistryEvents(zeto, result2);
    await smtKyc.add(kycHash(publicKey2), kycHash(publicKey2));
    const publicKey3 = parseRegistryEvents(zeto, result3);
    await smtKyc.add(kycHash(publicKey3), kycHash(publicKey3));

    circuit = await loadCircuit("anon_enc_nullifier_kyc");
    ({ provingKeyFile: provingKey } = loadProvingKeys(
      "anon_enc_nullifier_kyc"
    ));
    batchCircuit = await loadCircuit("anon_enc_nullifier_kyc_batch");
    ({ provingKeyFile: batchProvingKey } = loadProvingKeys(
      "anon_enc_nullifier_kyc_batch"
    ));
  });

  after(function () {
    // console.log(`Mint costs: ${mintGasCostHistory.join(',')}`);
    // console.log(`Deposit costs: ${depositGasCostHistory.join(',')}`);
    // console.log(`Transfer costs: ${transferGasCostHistory.join(',')}`);
    // console.log(`Withdraw costs: ${withdrawGasCostHistory.join(',')}`);
  });

  describe(`Transfer ${TOTAL_AMOUNT} tokens (half from deposit, half from mint) from single address to another`, function () {
    before(async function () {
      const root = await smtAlice.root();
      const onchainRoot = await zeto.getRoot();
      expect(onchainRoot).to.equal(0n);
      expect(root.string()).to.equal(onchainRoot.toString());
      const startingBalance = await erc20.balanceOf(Alice.ethAddress);
      const tx = await erc20
        .connect(deployer)
        .mint(Alice.ethAddress, atMostHalfAmount); // mint to alice the amount of token that can be deposited
      await tx.wait();

      const endingBalance = await erc20.balanceOf(Alice.ethAddress);
      expect(endingBalance - startingBalance).to.be.equal(atMostHalfAmount);
      console.log(
        `ERC20 successfully minted ${atMostHalfAmount} to Alice for deposit`
      );
      const tx1 = await erc20
        .connect(Alice.signer)
        .approve(zeto.target, atMostHalfAmount);
      await tx1.wait();

      const startingBalanceDep = await erc20.balanceOf(zeto.target);
      const txDep = await erc20
        .connect(deployer)
        .mint(zeto.target, atLeastHalfAmount); // mint to zeto contract the amount of token that can be minted
      await txDep.wait();
      const endingBalanceDep = await erc20.balanceOf(zeto.target);
      expect(endingBalanceDep - startingBalanceDep).to.be.equal(
        atLeastHalfAmount
      );
    });

    it(`Alice deposit ${atMostHalfAmount} token`, async function () {
      let promises = [];
      for (let i = 0; i < atMostHalfAmount; i++) {
        promises.push(
          (async () => {
            const utxoSingle = newUTXO(1, Alice);
            const { outputCommitments, encodedProof } =
              await prepareDepositProof(Alice, utxoSingle);
            await doDeposit(
              zeto,
              Alice.signer,
              1,
              outputCommitments[0],
              encodedProof,
              depositGasCostHistory
            );
            await smtAlice.add(utxoSingle.hash, utxoSingle.hash);
            await smtBob.add(utxoSingle.hash, utxoSingle.hash);
            unspentAliceUTXOs.push(utxoSingle);
          })()
        );

        // If we reach the concurrency limit, wait for the current batch to finish
        if (promises.length >= TX_CONCURRENCY) {
          await Promise.all(promises);
          promises = []; // Reset promises for the next batch
        }
      }

      // Run any remaining promises that didn’t fill the batch
      if (promises.length > 0) {
        await Promise.all(promises);
      }
      writeGasCostsToCSV(
        `${reportPrefix}deposit_gas_costs.csv`,
        depositGasCostHistory
      );
    }).timeout(6000000000000);

    it(`Zeto mint ${atLeastHalfAmount} token to Alice in ${mintCount} txs`, async function () {
      let promises = [];
      for (let i = 0; i < mintCount; i++) {
        promises.push(
          (async () => {
            const mintUTXOs = [];
            for (let j = 0; j < UTXO_PER_TX; j++) {
              if (
                i !== mintCount - 1 ||
                atLeastHalfAmount % UTXO_PER_TX === 0 ||
                j < atLeastHalfAmount % UTXO_PER_TX
              ) {
                const _new_utxo = newUTXO(1, Alice);
                mintUTXOs.push(_new_utxo);
                await smtAlice.add(_new_utxo.hash, _new_utxo.hash);
                await smtBob.add(_new_utxo.hash, _new_utxo.hash);
                unspentAliceUTXOs.push(_new_utxo);
              }
            }

            await doMint(zeto, deployer, mintUTXOs, mintGasCostHistory);
          })()
        );

        // If we reach the concurrency limit, wait for the current batch to finish
        if (promises.length >= TX_CONCURRENCY) {
          await Promise.all(promises);
          promises = []; // Reset promises for the next batch
        }
      }
      // Run any remaining promises that didn’t fill the batch
      if (promises.length > 0) {
        await Promise.all(promises);
      }
      writeGasCostsToCSV(
        `${reportPrefix}mint_gas_costs.csv`,
        mintGasCostHistory
      );
    }).timeout(6000000000000);

    it(`Alice transfer ${TOTAL_AMOUNT} tokens to Bob in ${transferCount} txs`, async function () {
      const utxosRoot = await smtAlice.root(); // get the root before all transfer and use it for all the proofs
      let promises = [];
      // Alice generates inclusion proofs for the identities in the transaction
      const identitiesRoot = await smtKyc.root();
      const proof3 = await smtKyc.generateCircomVerifierProof(
        kycHash(Alice.babyJubPublicKey),
        identitiesRoot
      );
      const proof4 = await smtKyc.generateCircomVerifierProof(
        kycHash(Bob.babyJubPublicKey),
        identitiesRoot
      );
      const identityMerkleProofs = [
        proof3.siblings.map((s) => s.bigInt()), // identity proof for the sender (Alice)
      ];

      const batchSize = UTXO_PER_TX > 2 ? 10 : 2;

      for (let i = 0; i < batchSize; i++) {
        identityMerkleProofs.push(proof4.siblings.map((s) => s.bigInt())); // identity proof for the output utxos (Bob)
      }

      for (let i = 0; i < transferCount; i++) {
        promises.push(
          (async () => {
            const _inUtxos = [];
            const _outUtxos = [];
            const _mtps = [];
            const _nullifiers = [];
            for (let j = 0; j < UTXO_PER_TX; j++) {
              if (
                i !== transferCount - 1 ||
                unspentAliceUTXOs.length % UTXO_PER_TX === 0 ||
                j < unspentAliceUTXOs.length % UTXO_PER_TX
              ) {
                const _iUtxo = unspentAliceUTXOs[i * UTXO_PER_TX + j];
                _inUtxos.push(_iUtxo);
                _nullifiers.push(newNullifier(_iUtxo, Alice));
                // Alice generates inclusion proofs for the UTXOs to be spent
                const inProof = await smtAlice.generateCircomVerifierProof(
                  _iUtxo.hash,
                  utxosRoot
                );
                _mtps.push(inProof.siblings.map((s) => s.bigInt()));
                const _oUtox = newUTXO(1, Bob);
                _outUtxos.push(_oUtox);
                unspentBobUTXOs.push(_oUtox);
              } else {
                _inUtxos.push(ZERO_UTXO);
                _nullifiers.push(ZERO_UTXO);
                const inProof = await smtAlice.generateCircomVerifierProof(
                  0n,
                  utxosRoot
                );
                _outUtxos.push(ZERO_UTXO);
                _mtps.push(inProof.siblings.map((s) => s.bigInt()));
              }
            }
            const owners = [];
            for (let i = 0; i < batchSize; i++) {
              owners.push(Bob);
            }

            // Alice transfers her UTXOs to Bob
            await doTransfer(
              Alice,
              _inUtxos,
              _nullifiers,
              _outUtxos,
              utxosRoot.bigInt(),
              _mtps,
              identitiesRoot.bigInt(),
              identityMerkleProofs,
              owners,
              transferGasCostHistory
            );
          })()
        );

        // If we reach the concurrency limit, wait for the current batch to finish
        if (promises.length >= TX_CONCURRENCY) {
          await Promise.all(promises);
          promises = []; // Reset promises for the next batch
        }
      }

      // Run any remaining promises that didn’t fill the batch
      if (promises.length > 0) {
        await Promise.all(promises);
      }

      for (let i = 0; i < unspentBobUTXOs.length; i++) {
        const _oUtox = unspentBobUTXOs[i];
        await smtAlice.add(_oUtox.hash, _oUtox.hash);
        await smtBob.add(_oUtox.hash, _oUtox.hash);
      }
      writeGasCostsToCSV(
        `${reportPrefix}transfer_gas_costs.csv`,
        transferGasCostHistory
      );
    }).timeout(6000000000000);

    it(`Bob withdraw ${TOTAL_AMOUNT} tokens in ${transferCount} transactions`, async function () {
      const startingBalance = await erc20.balanceOf(Bob.ethAddress);

      const root = await smtBob.root();
      let promises = [];
      for (let i = 0; i < transferCount; i++) {
        promises.push(
          (async () => {
            const _inUtxos = [];
            const _mtps = [];
            const _nullifiers = [];
            let amount = 0;
            for (let j = 0; j < UTXO_PER_TX; j++) {
              if (
                i !== transferCount - 1 ||
                unspentBobUTXOs.length % UTXO_PER_TX === 0 ||
                j < unspentBobUTXOs.length % UTXO_PER_TX
              ) {
                amount++;
                const _iUtxo = unspentBobUTXOs[i * UTXO_PER_TX + j];
                _inUtxos.push(_iUtxo);
                _nullifiers.push(newNullifier(_iUtxo, Bob));
                // Alice generates inclusion proofs for the UTXOs to be spent
                const inProof = await smtBob.generateCircomVerifierProof(
                  _iUtxo.hash,
                  root
                );
                _mtps.push(inProof.siblings.map((s) => s.bigInt()));
              } else {
                _inUtxos.push(ZERO_UTXO);
                _nullifiers.push(ZERO_UTXO);
                const inProof = await smtBob.generateCircomVerifierProof(
                  0n,
                  root
                );
                _mtps.push(inProof.siblings.map((s) => s.bigInt()));
              }
            }
            const { nullifiers, outputCommitments, encodedProof } =
              await prepareNullifierWithdrawProof(
                Bob,
                _inUtxos,
                _nullifiers,
                ZERO_UTXO,
                root.bigInt(),
                _mtps
              );

            // Bob withdraws UTXOs to ERC20 tokens
            await doWithdraw(
              zeto,
              Bob.signer,
              amount,
              nullifiers,
              outputCommitments[0],
              root.bigInt(),
              encodedProof,
              withdrawGasCostHistory
            );
          })()
        );

        // If we reach the concurrency limit, wait for the current batch to finish
        if (promises.length >= TX_CONCURRENCY) {
          await Promise.all(promises);
          promises = []; // Reset promises for the next batch
        }
      }
      // Run any remaining promises that didn’t fill the batch
      if (promises.length > 0) {
        await Promise.all(promises);
      }
      writeGasCostsToCSV(
        `${reportPrefix}withdraw_gas_costs.csv`,
        withdrawGasCostHistory
      );
      // Bob checks ERC20 balance
      const endingBalance = await erc20.balanceOf(Bob.ethAddress);
      expect(endingBalance - startingBalance).to.be.equal(TOTAL_AMOUNT);
    }).timeout(6000000000000);
  }).timeout(6000000000000);

  async function doTransfer(
    signer: User,
    inputs: UTXO[],
    _nullifiers: UTXO[],
    outputs: UTXO[],
    utxosRoot: BigInt,
    utxosMerkleProof: BigInt[][],
    identitiesRoot: BigInt,
    identitiesMerkleProof: BigInt[][],
    owners: User[],
    gasHistories: number[]
  ) {
    let nullifiers: BigNumberish[];
    let outputCommitments: BigNumberish[];
    let encryptedValues: BigNumberish[];
    let encryptionNonce: BigNumberish;
    let encodedProof: any;
    const ephemeralKeypair = genKeypair();
    const result = await prepareProof(
      signer,
      inputs,
      _nullifiers,
      outputs,
      utxosRoot,
      utxosMerkleProof,
      identitiesRoot,
      identitiesMerkleProof,
      owners,
      ephemeralKeypair.privKey
    );

    nullifiers = _nullifiers.map((nullifier) => nullifier.hash) as [
      BigNumberish,
      BigNumberish,
    ];
    outputCommitments = result.outputCommitments;
    encodedProof = result.encodedProof;
    encryptedValues = result.encryptedValues;
    encryptionNonce = result.encryptionNonce;

    const txResult = await sendTx(
      signer,
      nullifiers,
      outputCommitments,
      utxosRoot,
      encryptedValues,
      encryptionNonce,
      encodedProof,
      ephemeralKeypair.pubKey
    );
    if (txResult?.gasUsed && Array.isArray(gasHistories)) {
      gasHistories.push(txResult?.gasUsed);
    }
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
    _nullifiers: UTXO[],
    outputs: UTXO[],
    utxosRoot: BigInt,
    utxosMerkleProof: BigInt[][],
    identitiesRoot: BigInt,
    identitiesMerkleProof: BigInt[][],
    owners: User[],
    ephemeralPrivateKey: BigInt
  ) {
    const nullifiers = _nullifiers.map((nullifier) => nullifier.hash) as [
      BigNumberish,
      BigNumberish,
    ];
    const inputCommitments: BigNumberish[] = inputs.map(
      (input) => input.hash
    ) as BigNumberish[];
    const inputValues = inputs.map((input) => BigInt(input.value || 0n));
    const inputSalts = inputs.map((input) => input.salt || 0n);
    const outputCommitments: BigNumberish[] = outputs.map(
      (output) => output.hash
    ) as BigNumberish[];
    const outputValues = outputs.map((output) => BigInt(output.value || 0n));
    const outputOwnerPublicKeys: BigNumberish[][] = owners.map(
      (owner) => owner.babyJubPublicKey
    ) as BigNumberish[][];
    const encryptionNonce: BigNumberish = newEncryptionNonce() as BigNumberish;
    const encryptInputs = stringifyBigInts({
      encryptionNonce,
      ecdhPrivateKey: formatPrivKeyForBabyJub(ephemeralPrivateKey),
    });

    const startWitnessCalculation = Date.now();
    const inputObj = {
      nullifiers,
      inputCommitments,
      inputValues,
      inputSalts,
      inputOwnerPrivateKey: signer.formattedPrivateKey,
      utxosRoot,
      enabled: nullifiers.map((n) => (n !== 0n ? 1 : 0)),
      utxosMerkleProof,
      identitiesRoot,
      identitiesMerkleProof,
      outputCommitments,
      outputValues,
      outputSalts: outputs.map((output) => output.salt || 0n),
      outputOwnerPublicKeys,
      ...encryptInputs,
    };
    let circuitToUse = circuit;
    let provingKeyToUse = provingKey;
    let isBatch = false;
    if (inputCommitments.length > 2 || outputCommitments.length > 2) {
      isBatch = true;
      circuitToUse = batchCircuit;
      provingKeyToUse = batchProvingKey;
    }
    const witness = await lock.acquire("proofGen", async () => {
      // this lock is added for https://github.com/LFDT-Paladin/zeto/issues/80, which only happens for Transfer circuit, not deposit/mint
      return circuitToUse.calculateWTNSBin(inputObj, true);
    });
    const timeWithnessCalculation = Date.now() - startWitnessCalculation;

    const startProofGeneration = Date.now();
    const { proof, publicSignals } = (await groth16.prove(
      provingKeyToUse,
      witness
    )) as { proof: BigNumberish[]; publicSignals: BigNumberish[] };
    const timeProofGeneration = Date.now() - startProofGeneration;

    console.log(
      `Witness calculation time: ${timeWithnessCalculation}ms. Proof generation time: ${timeProofGeneration}ms.`
    );

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
    nullifiers: BigNumberish[],
    outputCommitments: BigNumberish[],
    root: BigNumberish,
    encryptedValues: BigNumberish[],
    encryptionNonce: BigNumberish,
    encodedProof: any,
    ecdhPublicKey: BigInt[]
  ) {
    const startTx = Date.now();
    const tx = await zeto
      .connect(signer.signer)
      .transfer(
        nullifiers,
        outputCommitments,
        root,
        encryptionNonce,
        ecdhPublicKey,
        encryptedValues,
        encodedProof,
        "0x"
      );
    const result: ContractTransactionReceipt | null = await tx.wait();
    console.log(
      `Transfer transaction took: ${Date.now() - startTx}ms. Gas used: ${
        result?.gasUsed
      }`
    );
    return result;
  }
});

function writeGasCostsToCSV(filename: string, gasCosts: number[]) {
  const filePath = path.join(__dirname, filename);

  // Prepare the CSV content
  const csvData = gasCosts.join(",\n") + "\n"; // Each value in a new line

  // Write the CSV content to a file (overwrite if file exists)
  fs.writeFileSync(filePath, "gas_costs,\n" + csvData, "utf8");

  console.log(`Gas costs written to ${filePath}`);
}
