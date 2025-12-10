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

package utils

import (
	"github.com/hyperledger-labs/zeto/go-sdk/pkg/sparse-merkle-tree/core"
	apicore "github.com/hyperledger-labs/zeto/go-sdk/pkg/utxo/core"
)

type IndexOnly struct {
	Index core.NodeIndex
}

func NewIndexOnly(index core.NodeIndex) *IndexOnly {
	return &IndexOnly{
		Index: index,
	}
}

func (f *IndexOnly) CalculateIndex() (core.NodeIndex, error) {
	return f.Index, nil
}

func (f *IndexOnly) GetHasher() apicore.Hasher {
	return f.Index.GetHasher()
}
