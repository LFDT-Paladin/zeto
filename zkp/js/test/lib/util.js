// Copyright © 2025 Kaleido, Inc.
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

const { sha3_256, sha3_512 } = require("@noble/hashes/sha3.js");
const testKeyPair = require("../../lib/testKeypair.js");

// copied from node_modules/mlkem/script/src/mlKemBase.js
function h(pk) {
  const hash = sha3_256.create();
  hash.update(pk);
  return hash.digest();
}

function g(m, hpk) {
  const hash = sha3_512.create();
  hash.update(m);
  hash.update(hpk);
  const res = hash.digest();
  return [res.subarray(0, 32), res.subarray(32, 64)];
}

module.exports = {
  testKeyPair,
  h,
  g,
};
