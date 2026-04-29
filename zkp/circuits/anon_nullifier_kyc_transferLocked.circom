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
pragma circom 2.2.2;

include "./basetokens/anon_nullifier_kyc__transferLocked_base.circom";

// Locked-input transfer for the KYC nullifier-based token. The new
// ILockableCapability storage tracks locked UTXOs in a flat per-lock
// mapping rather than an SMT, so the proof drops the locked-state
// merkle inputs and the nullifiers. The public-input order matches
// {Zeto_AnonNullifier.constructPublicInputs} for inputsLocked == true:
// [inputCommitments, identitiesRoot, outputCommitments].
component main { public [ inputCommitments, identitiesRoot, outputCommitments ] } = transferLocked(2, 2, 10);
