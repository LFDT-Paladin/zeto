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

package crypto

import (
	"fmt"
	"math/big"

	"github.com/LFDT-Paladin/smt/pkg/crypto"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/utils"
)

const TWO_POW_128 = "340282366920938463463374607431768211456"

func NewEncryptionNonce() *big.Int {
	// per https://drive.google.com/file/d/1EVrP3DzoGbmzkRmYnyEDcIQcXVU7GlOd/view
	// the encrpition nonce should be in the range [0, 2^128)
	max, _ := new(big.Int).SetString(TWO_POW_128, 10)
	return crypto.NewRandomNumberInRange(max)
}

func BytesToBits(data []byte) []uint8 {
	bits := make([]uint8, len(data)*8)
	for i, b := range data {
		for j := 0; j < 8; j++ {
			// For little-endian bit order within each byte:
			// The j-th bit (0-7) of the current byte 'b'
			// is extracted using a bitwise AND with a left-shifted 1.
			// The result is true if the bit is set, false otherwise.
			bits[i*8+j] = (b >> j) & 1
		}
	}
	return bits
}

func BitsToBytes(bits []uint8) ([]byte, error) {
	if len(bits)%8 != 0 {
		return nil, fmt.Errorf("bits length must be a multiple of 8, got %d", len(bits))
	}
	data := make([]byte, len(bits)/8)
	for i := 0; i < len(bits); i += 8 {
		var b byte
		for j := 0; j < 8; j++ {
			b |= bits[i+j] << j
		}
		data[i/8] = b
	}
	return data, nil
}

func RecoverMlkemCiphertextBytes(ciphertextStrs []string) ([]byte, error) {
	var ciphertextBytes []byte
	for i, str := range ciphertextStrs {
		v, OK := new(big.Int).SetString(str, 10)
		if !OK {
			return nil, fmt.Errorf("failed to parse big.Int from string: %s", str)
		}
		if i < len(ciphertextStrs)-1 {
			if len(v.Bytes()) > 248/8 {
				return nil, fmt.Errorf("expected ciphertext to be up to %d bytes, got %d bytes", 248/8, len(v.Bytes()))
			}
		} else {
			if len(v.Bytes()) > 192/8 {
				return nil, fmt.Errorf("expected last ciphertext to be up to %d bytes, got %d bytes", 192/8, len(v.Bytes()))
			}
		}
		vBytes := v.Bytes()[:]
		reverseSlice(vBytes)
		ciphertextBytes = append(ciphertextBytes, vBytes...)
	}
	return ciphertextBytes, nil
}

// the seed is a 32-byte array, which is trimmed to fit the group order
// and then used to generate a valid EC point.
// This is based on https://datatracker.ietf.org/doc/html/rfc8032#page-13,
// but the SHA-512 step is skipped.
func PublicKeyFromSeed(seed []byte) (*babyjub.Point, error) {
	trimmed := seed[:]
	trimmed[0] = trimmed[0] & 0xf8
	trimmed[31] = trimmed[31] & 0x7f
	trimmed[31] = trimmed[31] | 0x40
	ssBits := BytesToBits(trimmed)[3:]
	ssBits = append(ssBits, []uint8{0, 0, 0}...) // pad to 256 bits
	ssTrimmedBytes, err := BitsToBytes(ssBits)
	if err != nil {
		return nil, fmt.Errorf("failed to convert bits to bytes: %w", err)
	}
	ssBigInt := utils.SetBigIntFromLEBytes(new(big.Int), ssTrimmedBytes)
	ssPoint := babyjub.NewPoint().Mul(ssBigInt, babyjub.B8)
	return ssPoint, nil
}

func reverseSlice(s []byte) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
