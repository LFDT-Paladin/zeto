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

package integration_test

import (
	"github.com/LFDT-Paladin/zeto/go-sdk/pkg/key-manager/key"
	"github.com/stretchr/testify/assert"
)

func (s *E2ETestSuite) TestKeyManager() {
	keypair := decryptKeyStorev3(s.T())

	keyEntry := key.NewKeyEntryFromPrivateKeyBytes([32]byte(keypair.PrivateKeyBytes()))
	assert.NotNil(s.T(), keyEntry)

	assert.NotNil(s.T(), keyEntry.PrivateKey)
	assert.NotNil(s.T(), keyEntry.PublicKey)
	assert.NotNil(s.T(), keyEntry.PrivateKeyForZkp)
}
