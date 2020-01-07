/*
 * Copyright 2019 The openwallet Authors
 * This file is part of the openwallet library.
 *
 * The openwallet library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The openwallet library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 */

package owcrypt_tester

import (
	"encoding/hex"
	"fmt"
	"github.com/blocktree/go-owcrypt"
	owcryptdev "github.com/blocktree/go-owcrypt-dev"
	"testing"
)

func TestNewowcryptSignatureAll(t *testing.T) {

	tests := []struct {
		name    string
		eccType uint32
	}{
		{name: "ECC_CURVE_SECP256K1", eccType: owcryptdev.ECC_CURVE_SECP256K1},
		{name: "ECC_CURVE_SECP256R1", eccType: owcryptdev.ECC_CURVE_SECP256R1},
		{name: "ECC_CURVE_PRIMEV1", eccType: owcryptdev.ECC_CURVE_PRIMEV1},
		{name: "ECC_CURVE_NIST_P256", eccType: owcryptdev.ECC_CURVE_NIST_P256},
		{name: "ECC_CURVE_SM2_STANDARD", eccType: owcryptdev.ECC_CURVE_SM2_STANDARD},
		{name: "ECC_CURVE_ED25519_NORMAL", eccType: owcryptdev.ECC_CURVE_ED25519_NORMAL},
		{name: "ECC_CURVE_ED25519", eccType: owcryptdev.ECC_CURVE_ED25519},
		{name: "ECC_CURVE_X25519", eccType: owcryptdev.ECC_CURVE_X25519},
	}

	for _, test := range tests {

		for i := 0; i < 1024; i++ {
			priviteKey, err := generateSeed(32)
			if err != nil {
				t.Errorf("generateSeed err: %v", err)
				return
			}

			if test.eccType == owcryptdev.ECC_CURVE_ED25519 || test.eccType == owcryptdev.ECC_CURVE_X25519 {
				priviteKey[0] &= 248
				priviteKey[31] &= 127
				priviteKey[31] |= 64
			}

			msg, err := generateSeed(32)
			if err != nil {
				t.Errorf("generateSeed err: %v", err)
				return
			}

			ID, err := generateSeed(32)
			if err != nil {
				t.Errorf("generateSeed err: %v", err)
				return
			}

			pub, ret := owcryptdev.GenPubkey(priviteKey, test.eccType)
			if ret != owcryptdev.SUCCESS {
				t.Errorf("owcrypt.GenPubkey [%s] failed, privateKey: %s \n", test.name, hex.EncodeToString(priviteKey))
				return
			}
			pubStr := hex.EncodeToString(pub)

			signature, _, ret2 := owcryptdev.Signature(priviteKey, ID, msg, test.eccType)
			if ret2 != owcryptdev.SUCCESS {
				t.Errorf("owcryptdev.Signature [%s] failed, privateKey: %s \n", test.name, hex.EncodeToString(priviteKey))
				return
			}
			signatureStr := hex.EncodeToString(signature)

			verifyNew := owcryptdev.Verify(pub, ID, msg, signature, test.eccType)

			if verifyNew == owcryptdev.FAILURE {

				fmt.Printf("%s \n", test.name)
				fmt.Printf("priviteKey: %s \n", hex.EncodeToString(priviteKey))
				fmt.Printf("msg: %s \n", hex.EncodeToString(msg))
				fmt.Printf("ID: %s \n", hex.EncodeToString(ID))
				fmt.Printf("pub: %s \n", pubStr)
				fmt.Printf("signature: %s \n", signatureStr)

				t.Errorf("test [%s] new failed, signature: %s \n", test.name, signatureStr)
				return
			} else {
				fmt.Printf("test [%s] new passed \n", test.name)
			}

			verifyOld := owcrypt.Verify(pub, ID, uint16(len(ID)), msg, uint16(len(msg)), signature, test.eccType)

			if verifyOld == owcryptdev.FAILURE {

				fmt.Printf("%s \n", test.name)
				fmt.Printf("priviteKey: %s \n", hex.EncodeToString(priviteKey))
				fmt.Printf("msg: %s \n", hex.EncodeToString(msg))
				fmt.Printf("ID: %s \n", hex.EncodeToString(ID))
				fmt.Printf("pub: %s \n", pubStr)
				fmt.Printf("signature: %s \n", signatureStr)

				t.Errorf("test [%s] old failed, signature: %s \n", test.name, signatureStr)
				return
			} else {
				fmt.Printf("test [%s] old passed \n", test.name)
			}

			signatureOld, retOld := owcrypt.Signature(priviteKey, ID, uint16(len(ID)), msg, uint16(len(msg)), test.eccType)
			if retOld != owcryptdev.SUCCESS {
				t.Errorf("owcrypt.Signature [%s] failed, privateKey: %s \n", test.name, hex.EncodeToString(priviteKey))
				return
			}

			signatureOldStr := hex.EncodeToString(signatureOld)

			newVerifyOld := owcryptdev.Verify(pub, ID, msg, signatureOld, test.eccType)

			if newVerifyOld == owcryptdev.FAILURE {

				fmt.Printf("%s \n", test.name)
				fmt.Printf("priviteKey: %s \n", hex.EncodeToString(priviteKey))
				fmt.Printf("msg: %s \n", hex.EncodeToString(msg))
				fmt.Printf("ID: %s \n", hex.EncodeToString(ID))
				fmt.Printf("pub: %s \n", pubStr)
				fmt.Printf("signature: %s \n", signatureOldStr)

				t.Errorf("test new verify [%s] old failed, signature: %s \n", test.name, signatureOldStr)
				return
			} else {
				fmt.Printf("test new verify [%s] old passed \n", test.name)
			}
		}

	}

}

func TestNewowcryptSignature(t *testing.T) {
	name := "ECC_CURVE_ED25519_NORMAL"
	eccType := owcryptdev.ECC_CURVE_ED25519_NORMAL
	priviteKey, _ := hex.DecodeString("d85e52025dc1387385518fe3a08cfbf4a09d96ba6d2a866615fbdc816b9846d5")
	msg, _ := hex.DecodeString("ec97ca639c627b9b82f6598921b123b21be0e9cb3c21d36a90b18a0a16485e46")
	ID, _ := hex.DecodeString("a7189b94872a635728fbfdd1c64ce12d5ccbac2f2995d8501c718f7425a7357a")
	signature, _ := hex.DecodeString("cd403e4931126944c63b5cf5b51a50b82a24e50cfc64f6e7c2ab0c9fa8b9722205e633a8d672dafbd56c58fac0c8d5cb3acac2f79b0d90e08c8249d10988a80f")

	pub, ret := owcryptdev.GenPubkey(priviteKey, eccType)
	if ret != owcryptdev.SUCCESS {
		t.Errorf("owcrypt.GenPubkey [%s] failed, privateKey: %s \n", name, hex.EncodeToString(priviteKey))
		return
	}
	//signature, _, ret2 := owcryptdev.Signature(priviteKey, ID, msg, eccType)
	//if ret2 != owcryptdev.SUCCESS {
	//	t.Errorf("owcryptdev.Signature [%s] failed, privateKey: %s \n", name, hex.EncodeToString(priviteKey))
	//	return
	//}
	pubStr := hex.EncodeToString(pub)
	signatureStr := hex.EncodeToString(signature)

	fmt.Printf("priviteKey: %s \n", hex.EncodeToString(priviteKey))
	fmt.Printf("msg: %s \n", hex.EncodeToString(msg))
	fmt.Printf("ID: %s \n", hex.EncodeToString(ID))
	fmt.Printf("pub: %s \n", pubStr)
	fmt.Printf("signature: %s \n", signatureStr)

	verifyNew := owcryptdev.Verify(pub, ID, msg, signature, eccType)

	if verifyNew == owcryptdev.FAILURE {

		fmt.Printf("%s \n", name)
		fmt.Printf("priviteKey: %s \n", hex.EncodeToString(priviteKey))
		fmt.Printf("msg: %s \n", hex.EncodeToString(msg))
		fmt.Printf("ID: %s \n", hex.EncodeToString(ID))
		fmt.Printf("pub: %s \n", pubStr)
		fmt.Printf("signature: %s \n", signatureStr)

		t.Errorf("test [%s] new failed, signature: %s \n", name, signatureStr)
		return
	} else {
		fmt.Printf("test [%s] new passed \n", name)
	}

	verifyOld := owcrypt.Verify(pub, ID, uint16(len(ID)), msg, uint16(len(msg)), signature, eccType)

	if verifyOld == owcryptdev.FAILURE {

		fmt.Printf("%s \n", name)
		fmt.Printf("priviteKey: %s \n", hex.EncodeToString(priviteKey))
		fmt.Printf("msg: %s \n", hex.EncodeToString(msg))
		fmt.Printf("ID: %s \n", hex.EncodeToString(ID))
		fmt.Printf("pub: %s \n", pubStr)
		fmt.Printf("signature: %s \n", signatureStr)

		t.Errorf("test [%s] old failed, signature: %s \n", name, signatureStr)
		return
	} else {
		fmt.Printf("test [%s] old passed \n", name)
	}
}
