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

import {
  ContractTransactionReceipt,
  Signer,
  BigNumberish,
  AddressLike,
} from "ethers";
import {
  genKeypair,
  formatPrivKeyForBabyJub,
  genEcdhSharedKey,
} from "maci-crypto";
import { Poseidon, newSalt, tokenUriHash } from "zeto-js";

const poseidonHash3 = Poseidon.poseidon3;
const poseidonHash4 = Poseidon.poseidon4;
const poseidonHash5 = Poseidon.poseidon5;

export interface UTXO {
  value?: number;
  tokenId?: number;
  uri?: string;
  hash: BigInt;
  salt?: BigInt;
}

export const ZERO_UTXO: UTXO = { hash: BigInt(0) };

export interface User {
  signer: Signer;
  ethAddress: string;
  babyJubPrivateKey: BigInt;
  babyJubPublicKey: BigInt[];
  formattedPrivateKey: BigInt;
}

export async function newUser(signer: Signer) {
  const { privKey, pubKey } = genKeypair();
  const formattedPrivateKey = formatPrivKeyForBabyJub(privKey);

  return {
    signer,
    ethAddress: await signer.getAddress(),
    babyJubPrivateKey: privKey,
    babyJubPublicKey: pubKey,
    formattedPrivateKey,
  };
}

export function newUTXO(value: number, owner: User, salt?: BigInt): UTXO {
  if (!salt) salt = newSalt();
  const hash = poseidonHash4([
    BigInt(value),
    salt,
    owner.babyJubPublicKey[0],
    owner.babyJubPublicKey[1],
  ]);
  return { value, hash, salt };
}

export function newAssetUTXO(
  tokenId: number,
  uri: string,
  owner: User,
  salt?: BigInt,
): UTXO {
  if (!salt) salt = newSalt();
  const hash = poseidonHash5([
    BigInt(tokenId),
    tokenUriHash(uri),
    salt,
    owner.babyJubPublicKey[0],
    owner.babyJubPublicKey[1],
  ]);
  return { tokenId, uri, hash, salt };
}

export function newNullifier(utxo: UTXO, owner: User): UTXO {
  const hash = poseidonHash3([
    BigInt(utxo.value!),
    utxo.salt,
    owner.formattedPrivateKey,
  ]);
  return { value: utxo.value, hash, salt: utxo.salt };
}

export function newAssetNullifier(utxo: UTXO, owner: User): UTXO {
  const hash = poseidonHash4([
    BigInt(utxo.tokenId!),
    tokenUriHash(utxo.uri),
    utxo.salt,
    owner.formattedPrivateKey,
  ]);
  return { tokenId: utxo.tokenId, uri: utxo.uri, hash, salt: utxo.salt };
}

export async function doMint(
  zetoTokenContract: any,
  minter: Signer,
  outputs: UTXO[],
  gasHistories?: number[],
): Promise<ContractTransactionReceipt> {
  const outputCommitments = outputs.map(
    (output) => output.hash,
  ) as BigNumberish[];
  const tx = await zetoTokenContract
    .connect(minter)
    .mint(outputCommitments, "0x");
  const result = await tx.wait();
  console.log(`Method mint() complete. Gas used: ${result?.gasUsed}`);
  if (result?.gasUsed && Array.isArray(gasHistories)) {
    gasHistories.push(result?.gasUsed);
  }
  return result;
}

export async function doDeposit(
  zetoTokenContract: any,
  depositUser: Signer,
  amount: any,
  commitment: any,
  proof: any,
  gasHistories?: number[],
): Promise<ContractTransactionReceipt> {
  const tx = await zetoTokenContract
    .connect(depositUser)
    .deposit(amount, commitment, proof, "0x");
  const result = await tx.wait();
  console.log(`Method deposit() complete. Gas used: ${result?.gasUsed}`);
  if (result?.gasUsed && Array.isArray(gasHistories)) {
    gasHistories.push(result?.gasUsed);
  }
  return result;
}

export async function doWithdraw(
  zetoTokenContract: any,
  withdrawUser: Signer,
  amount: any,
  nullifiers: any,
  commitment: any,
  root: any,
  proof: any,
  gasHistories?: number[],
): Promise<ContractTransactionReceipt> {
  const tx = await zetoTokenContract
    .connect(withdrawUser)
    .withdraw(amount, nullifiers, commitment, root, proof);
  const result = await tx.wait();
  console.log(`Method withdraw() complete. Gas used: ${result?.gasUsed}`);
  if (result?.gasUsed && Array.isArray(gasHistories)) {
    gasHistories.push(result?.gasUsed);
  }
  return result;
}

export function parseUTXOEvents(
  zetoTokenContract: any,
  result: ContractTransactionReceipt,
) {
  let returnValues: any[] = [];
  for (const log of result.logs || []) {
    const event = zetoTokenContract.interface.parseLog(log as any);
    let e: any;
    if (event?.name === "UTXOTransfer") {
      e = {
        inputs: event?.args.inputs,
        outputs: event?.args.outputs,
        submitter: event?.args.submitter,
      };
    } else if (event?.name === "UTXOTransferLocked") {
      e = {
        lockedInputs: event?.args.lockedInputs,
        lockedOutputs: event?.args.lockedOutputs,
        outputs: event?.args.outputs,
        submitter: event?.args.submitter,
      };
    } else if (event?.name === "UTXOTransferWithEncryptedValues") {
      e = {
        inputs: event?.args.inputs,
        outputs: event?.args.outputs,
        encryptedValues: event?.args.encryptedValues,
        encryptionNonce: event?.args.encryptionNonce,
        submitter: event?.args.submitter,
        ecdhPublicKey: event?.args.ecdhPublicKey,
      };
    } else if (event?.name === "UTXOTransferWithMlkemEncryptedValues") {
      e = {
        inputs: event?.args.inputs,
        outputs: event?.args.outputs,
        encryptedValues: event?.args.encryptedValues,
        encryptionNonce: event?.args.encryptionNonce,
        submitter: event?.args.submitter,
        encapsulatedSharedSecret: event?.args.encapsulatedSharedSecret,
      };
    } else if (event?.name === "UTXOTransferNonRepudiation") {
      e = {
        inputs: event?.args.inputs,
        outputs: event?.args.outputs,
        encryptedValuesForReceiver: event?.args.encryptedValuesForReceiver,
        encryptedValuesForAuthority: event?.args.encryptedValuesForAuthority,
        encryptionNonce: event?.args.encryptionNonce,
        submitter: event?.args.submitter,
        ecdhPublicKey: event?.args.ecdhPublicKey,
      };
    } else if (event?.name === "UTXOMint") {
      e = {
        outputs: event?.args.outputs,
        receivers: event?.args.receivers,
        submitter: event?.args.submitter,
      };
    } else if (event?.name === "TradeCompleted") {
      e = {
        tradeId: event?.args.tradeId,
        trade: event?.args.trade,
      };
    } else if (event?.name === "UTXOLocked") {
      e = {
        outputs: event?.args.outputs,
        lockedOutputs: event?.args.lockedOutputs,
        delegate: event?.args.delegate,
      };
    } else if (event?.name === "LockDelegateChanged") {
      e = {
        lockedOutputs: event?.args.lockedOutputs,
        oldDelegate: event?.args.oldDelegate,
        newDelegate: event?.args.newDelegate,
      };
    } else if (event?.name === "PaymentInitiated") {
      e = {
        paymentId: event?.args.paymentId,
        lockedInputs: event?.args.lockedInputs,
        nullifiers: event?.args.nullifiers,
        outputs: event?.args.outputs,
      };
    } else if (
      event?.name === "PaymentApproved" ||
      event?.name === "PaymentCompleted"
    ) {
      e = {
        paymentId: event?.args.paymentId,
      };
    }
    returnValues.push(e);
  }
  return returnValues;
}

export function parseRegistryEvents(
  registryContract: any,
  result: ContractTransactionReceipt,
) {
  for (const log of result.logs || []) {
    const event = registryContract.interface.parseLog(log as any);
    if (event?.name === "IdentityRegistered") {
      return event?.args.publicKey;
    }
  }
  return null;
}
