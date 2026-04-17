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
	"math/big"
	"testing"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/assert"
)

func TestPoseidonEx(t *testing.T) {
	inputs := []*big.Int{big.NewInt(1234567890), big.NewInt(2345678901), big.NewInt(3456789012), big.NewInt(4567890123)}
	result, err := poseidon.HashEx(inputs, 4)
	assert.NoError(t, err)
	v1, _ := new(big.Int).SetString("11501175702185290676838936720607163128640649954538569247536215022783738807825", 10)
	v2, _ := new(big.Int).SetString("6120530503331008674221484812464542651389744817446661784148353548752694803697", 10)
	v3, _ := new(big.Int).SetString("7124537720832890754896732787915836308362735099852420819626168545145412807782", 10)
	v4, _ := new(big.Int).SetString("1847024135263482697175502194253586321631751560455204108489523026877035496452", 10)
	assert.Equal(t, result, []*big.Int{v1, v2, v3, v4})
}

func TestPoseidonEncrypt(t *testing.T) {
	x, _ := new(big.Int).SetString("2225468530552752510522780019536893048169408270351832766087923920964657502364", 10)
	y, _ := new(big.Int).SetString("18264896395019517559018400396898398442219687903646821466907778802937824776999", 10)
	key := []*big.Int{x, y}
	nonce, _ := new(big.Int).SetString("220373351579243596212522709113509916796", 10)
	msg := []*big.Int{big.NewInt(1234567890), big.NewInt(2345678901)}
	cipherText, err := PoseidonEncrypt(msg, key, nonce)
	assert.NoError(t, err)
	assert.Equal(t, "3623473636383738070031324804097049685564466189577273141109672613904615191520", cipherText[0].Text(10))
	assert.Equal(t, "14192366070411288656840625597415252300006763456323771445497376523077328650161", cipherText[1].Text(10))
	assert.Equal(t, "8948874854696341437962075211230225158124203775185169948359228967178039019393", cipherText[2].Text(10))
	assert.Equal(t, "13654519867376896827561074824557193869787926453227340059166840999629617764240", cipherText[3].Text(10))
}

func TestPoseidonDecrypt(t *testing.T) {
	x, _ := new(big.Int).SetString("2225468530552752510522780019536893048169408270351832766087923920964657502364", 10)
	y, _ := new(big.Int).SetString("18264896395019517559018400396898398442219687903646821466907778802937824776999", 10)
	key := []*big.Int{x, y}
	nonce, _ := new(big.Int).SetString("220373351579243596212522709113509916796", 10)
	c1, _ := new(big.Int).SetString("3623473636383738070031324804097049685564466189577273141109672613904615191520", 10)
	c2, _ := new(big.Int).SetString("14192366070411288656840625597415252300006763456323771445497376523077328650161", 10)
	c3, _ := new(big.Int).SetString("8948874854696341437962075211230225158124203775185169948359228967178039019393", 10)
	c4, _ := new(big.Int).SetString("13654519867376896827561074824557193869787926453227340059166840999629617764240", 10)
	cipherText := []*big.Int{c1, c2, c3, c4}
	msg, err := PoseidonDecrypt(cipherText, key, nonce, 2)
	assert.NoError(t, err)
	assert.Equal(t, "1234567890", msg[0].Text(10))
	assert.Equal(t, "2345678901", msg[1].Text(10))
}

func TestPoseidonEncryptDecryptWithLongMessages_3n(t *testing.T) {
	nonce := NewEncryptionNonce()
	x, _ := new(big.Int).SetString("14104886431895638088879904796248988944763544789684292755064599086710742631244", 10)
	y, _ := new(big.Int).SetString("12567888666920372522142016384715158971908391387943244674769979344082830343251", 10)
	sharedKey := []*big.Int{x, y}

	// Encrypt a message of length 3n and bigger than 3
	msg := []*big.Int{big.NewInt(1234567890), big.NewInt(2345678901), big.NewInt(3456789012), big.NewInt(4567890123), big.NewInt(5678901234), big.NewInt(6789012345)}
	cipherText, err := PoseidonEncrypt(msg, sharedKey, nonce)
	assert.NoError(t, err)
	assert.Equal(t, 7, len(cipherText))

	// Decrypt the message
	decryptedMsg, err := PoseidonDecrypt(cipherText, sharedKey, nonce, 6)
	assert.NoError(t, err)
	assert.Equal(t, 6, len(decryptedMsg))
	assert.Equal(t, "1234567890", decryptedMsg[0].Text(10))
	assert.Equal(t, "2345678901", decryptedMsg[1].Text(10))
	assert.Equal(t, "3456789012", decryptedMsg[2].Text(10))
	assert.Equal(t, "4567890123", decryptedMsg[3].Text(10))
	assert.Equal(t, "5678901234", decryptedMsg[4].Text(10))
	assert.Equal(t, "6789012345", decryptedMsg[5].Text(10))
}

func TestPoseidonEncryptDecryptWithLongMessages_3nPlus1(t *testing.T) {
	nonce := NewEncryptionNonce()
	x, _ := new(big.Int).SetString("14104886431895638088879904796248988944763544789684292755064599086710742631244", 10)
	y, _ := new(big.Int).SetString("12567888666920372522142016384715158971908391387943244674769979344082830343251", 10)
	sharedKey := []*big.Int{x, y}

	// Encrypt a message of length 3n+1 and bigger than 3
	msg := []*big.Int{big.NewInt(1234567890), big.NewInt(2345678901), big.NewInt(3456789012), big.NewInt(4567890123), big.NewInt(5678901234), big.NewInt(6789012345), big.NewInt(7890123456)}
	cipherText, err := PoseidonEncrypt(msg, sharedKey, nonce)
	assert.NoError(t, err)
	assert.Equal(t, 10, len(cipherText))

	// Decrypt the message
	decryptedMsg, err := PoseidonDecrypt(cipherText, sharedKey, nonce, 7)
	assert.NoError(t, err)
	assert.Equal(t, 7, len(decryptedMsg))
	assert.Equal(t, "1234567890", decryptedMsg[0].Text(10))
	assert.Equal(t, "2345678901", decryptedMsg[1].Text(10))
	assert.Equal(t, "3456789012", decryptedMsg[2].Text(10))
	assert.Equal(t, "4567890123", decryptedMsg[3].Text(10))
	assert.Equal(t, "5678901234", decryptedMsg[4].Text(10))
	assert.Equal(t, "6789012345", decryptedMsg[5].Text(10))
	assert.Equal(t, "7890123456", decryptedMsg[6].Text(10))
}

func TestPoseidonEncryptDecryptWithLongMessages_3nPlus2(t *testing.T) {
	nonce := NewEncryptionNonce()
	x, _ := new(big.Int).SetString("14104886431895638088879904796248988944763544789684292755064599086710742631244", 10)
	y, _ := new(big.Int).SetString("12567888666920372522142016384715158971908391387943244674769979344082830343251", 10)
	sharedKey := []*big.Int{x, y}

	// Encrypt a message of length 3n+2 and bigger than 3
	msg := []*big.Int{big.NewInt(1234567890), big.NewInt(2345678901), big.NewInt(3456789012), big.NewInt(4567890123), big.NewInt(5678901234), big.NewInt(6789012345), big.NewInt(7890123456), big.NewInt(8901234567)}
	cipherText, err := PoseidonEncrypt(msg, sharedKey, nonce)
	assert.NoError(t, err)
	assert.Equal(t, 10, len(cipherText))

	// Decrypt the message
	decryptedMsg, err := PoseidonDecrypt(cipherText, sharedKey, nonce, 8)
	assert.NoError(t, err)
	assert.Equal(t, 8, len(decryptedMsg))
	assert.Equal(t, "1234567890", decryptedMsg[0].Text(10))
	assert.Equal(t, "2345678901", decryptedMsg[1].Text(10))
	assert.Equal(t, "3456789012", decryptedMsg[2].Text(10))
	assert.Equal(t, "4567890123", decryptedMsg[3].Text(10))
	assert.Equal(t, "5678901234", decryptedMsg[4].Text(10))
	assert.Equal(t, "6789012345", decryptedMsg[5].Text(10))
	assert.Equal(t, "7890123456", decryptedMsg[6].Text(10))
	assert.Equal(t, "8901234567", decryptedMsg[7].Text(10))
}

func TestPoseidonEncryptFail_WrongKeyLength(t *testing.T) {
	nonce := NewEncryptionNonce()
	x, _ := new(big.Int).SetString("14104886431895638088879904796248988944763544789684292755064599086710742631244", 10)
	y, _ := new(big.Int).SetString("12567888666920372522142016384715158971908391387943244674769979344082830343251", 10)
	sharedKey := []*big.Int{x, y, big.NewInt(0)}

	msg := []*big.Int{big.NewInt(1234567890), big.NewInt(2345678901), big.NewInt(3456789012)}
	_, err := PoseidonEncrypt(msg, sharedKey, nonce)
	assert.EqualError(t, err, "the key must have 2 elements, but got 3")
}

func TestPoseidonDecryptFail_WrongKeyLength(t *testing.T) {
	nonce := NewEncryptionNonce()
	x, _ := new(big.Int).SetString("14104886431895638088879904796248988944763544789684292755064599086710742631244", 10)
	y, _ := new(big.Int).SetString("12567888666920372522142016384715158971908391387943244674769979344082830343251", 10)
	sharedKey := []*big.Int{x, y, big.NewInt(0)}

	cipherText := []*big.Int{big.NewInt(1234567890), big.NewInt(2345678901), big.NewInt(3456789012)}
	_, err := PoseidonDecrypt(cipherText, sharedKey, nonce, 2)
	assert.EqualError(t, err, "the key must have 2 elements, but got 3")
}

func TestPoseidonDecryptFail_WrongCipherTextLength(t *testing.T) {
	nonce := NewEncryptionNonce()
	x, _ := new(big.Int).SetString("14104886431895638088879904796248988944763544789684292755064599086710742631244", 10)
	y, _ := new(big.Int).SetString("12567888666920372522142016384715158971908391387943244674769979344082830343251", 10)
	sharedKey := []*big.Int{x, y}

	cipherText := []*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0)}
	_, err := PoseidonDecrypt(cipherText, sharedKey, nonce, 3)
	assert.EqualError(t, err, "the length of the cipher text must be 3n+1, but got 3")
}

func TestPoseidonDecryptFail_DecryptedPaddingNotZero(t *testing.T) {
	// using the wrong key to decrypt the message to cause the padding to be not zero
	x, _ := new(big.Int).SetString("2225468530552752510522780019536893048169408270351832766087923920964657502364", 10)
	y, _ := new(big.Int).SetString("18264896395019517559018400396898398442219687903646821466907778802937824776999", 10)
	key := []*big.Int{x, y}
	nonce, _ := new(big.Int).SetString("220373351579243596212522709113509916796", 10)
	c1, _ := new(big.Int).SetString("21039212344699161871898848613539390724983078519593720831154100738838838817785", 10)
	c2, _ := new(big.Int).SetString("15977345191053612091391791983324450668689493803418876942389476888978407035452", 10)
	c3, _ := new(big.Int).SetString("5372411734880755416968088645882790397762440240735300976022902570974350057620", 10)
	c4, _ := new(big.Int).SetString("19025632437627264551396791396969817959604751019734376072608658820773266990048", 10)
	c5, _ := new(big.Int).SetString("6160222253936480678964609308357479211911264527083645332807503357507880448565", 10)
	c6, _ := new(big.Int).SetString("20422614434004746360815436868365648789543143774057224246303845550093575638210", 10)
	c7, _ := new(big.Int).SetString("7221629992444548069963332349434479366564733367858828912252976650571445651163", 10)

	cipherText := []*big.Int{c1, c2, c3, c4, c5, c6, c7}
	_, err := PoseidonDecrypt(cipherText, key, nonce, 4)
	assert.EqualError(t, err, "the last two elements of the decrypted text must be 0")

	_, err = PoseidonDecrypt(cipherText, key, nonce, 5)
	assert.EqualError(t, err, "the last element of the decrypted text must be 0")
}

func TestPoseidonDecryptFail_LastCipherTextCheck(t *testing.T) {
	x, _ := new(big.Int).SetString("2225468530552752510522780019536893048169408270351832766087923920964657502364", 10)
	y, _ := new(big.Int).SetString("18264896395019517559018400396898398442219687903646821466907778802937824776999", 10)
	key := []*big.Int{x, y}
	nonce, _ := new(big.Int).SetString("220373351579243596212522709113509916796", 10)
	c1, _ := new(big.Int).SetString("3623473636383738070031324804097049685564466189577273141109672613904615191520", 10)
	c2, _ := new(big.Int).SetString("14192366070411288656840625597415252300006763456323771445497376523077328650161", 10)
	c3, _ := new(big.Int).SetString("8948874854696341437962075211230225158124203775185169948359228967178039019393", 10)
	c4, _ := new(big.Int).SetString("13654519867376896827561074824557193869787926453227340059166840999629617764240", 10)
	c4 = c4.Add(c4, big.NewInt(1))
	cipherText := []*big.Int{c1, c2, c3, c4}
	_, err := PoseidonDecrypt(cipherText, key, nonce, 2)
	assert.EqualError(t, err, "the last element of the cipher text does not match the 2nd element of the state from the last round")
}

func TestPoseidonEncryptFail_NonceTooBig(t *testing.T) {
	nonce := new(big.Int).Lsh(big.NewInt(1), 128)
	x, _ := new(big.Int).SetString("2225468530552752510522780019536893048169408270351832766087923920964657502364", 10)
	y, _ := new(big.Int).SetString("18264896395019517559018400396898398442219687903646821466907778802937824776999", 10)
	sharedKey := []*big.Int{x, y}

	msg := []*big.Int{big.NewInt(1234567890), big.NewInt(2345678901)}
	_, err := PoseidonEncrypt(msg, sharedKey, nonce)
	assert.EqualError(t, err, "the nonce must be less than 2^128, but got 340282366920938463463374607431768211456")
}

func TestPoseidonDecryptFail_NonceTooBig(t *testing.T) {
	nonce := new(big.Int).Lsh(big.NewInt(1), 128)
	x, _ := new(big.Int).SetString("2225468530552752510522780019536893048169408270351832766087923920964657502364", 10)
	y, _ := new(big.Int).SetString("18264896395019517559018400396898398442219687903646821466907778802937824776999", 10)
	sharedKey := []*big.Int{x, y}

	c1, _ := new(big.Int).SetString("3623473636383738070031324804097049685564466189577273141109672613904615191520", 10)
	c2, _ := new(big.Int).SetString("14192366070411288656840625597415252300006763456323771445497376523077328650161", 10)
	c3, _ := new(big.Int).SetString("8948874854696341437962075211230225158124203775185169948359228967178039019393", 10)
	c4, _ := new(big.Int).SetString("13654519867376896827561074824557193869787926453227340059166840999629617764240", 10)
	cipherText := []*big.Int{c1, c2, c3, c4}
	_, err := PoseidonDecrypt(cipherText, sharedKey, nonce, 2)
	assert.EqualError(t, err, "the nonce must be less than 2^128, but got 340282366920938463463374607431768211456")
}

func TestPoseidonDecryptFail_LengthOutOfRange(t *testing.T) {
	nonce := NewEncryptionNonce()
	x, _ := new(big.Int).SetString("2225468530552752510522780019536893048169408270351832766087923920964657502364", 10)
	y, _ := new(big.Int).SetString("18264896395019517559018400396898398442219687903646821466907778802937824776999", 10)
	sharedKey := []*big.Int{x, y}

	c1, _ := new(big.Int).SetString("3623473636383738070031324804097049685564466189577273141109672613904615191520", 10)
	c2, _ := new(big.Int).SetString("14192366070411288656840625597415252300006763456323771445497376523077328650161", 10)
	c3, _ := new(big.Int).SetString("8948874854696341437962075211230225158124203775185169948359228967178039019393", 10)
	c4, _ := new(big.Int).SetString("13654519867376896827561074824557193869787926453227340059166840999629617764240", 10)
	cipherText := []*big.Int{c1, c2, c3, c4}
	_, err := PoseidonDecrypt(cipherText, sharedKey, nonce, 0)
	assert.EqualError(t, err, "the length must be between 1 and 3 (length of cipher text array - 1), but got 0")

	_, err = PoseidonDecrypt(cipherText, sharedKey, nonce, 5)
	assert.EqualError(t, err, "the length must be between 1 and 3 (length of cipher text array - 1), but got 5")
}
