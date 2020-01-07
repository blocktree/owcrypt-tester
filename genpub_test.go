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

func TestGenPubAll(t *testing.T) {

	tests := []struct {
		name    string
		eccType uint32
	}{
		//{name: "ECC_CURVE_SECP256K1", eccType: owcryptdev.ECC_CURVE_SECP256K1},
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
			//fmt.Printf("test [%s] length[%d] begin \n", test.name, i)

			pub1, ret := owcrypt.GenPubkey(priviteKey, test.eccType)
			if ret != owcryptdev.SUCCESS {
				t.Errorf("owcrypt.GenPubkey [%s] failed, privateKey: %s \n", test.name, hex.EncodeToString(priviteKey))
				return
			}
			pub2, ret2 := owcryptdev.GenPubkey(priviteKey, test.eccType)
			if ret2 != owcryptdev.SUCCESS {
				t.Errorf("owcryptdev.GenPubkey [%s] failed, privateKey: %s \n", test.name, hex.EncodeToString(priviteKey))
				return
			}
			pubStr := hex.EncodeToString(pub1)
			pubStr2 := hex.EncodeToString(pub2)

			fmt.Printf("priviteKey: %s \n", hex.EncodeToString(priviteKey))
			fmt.Printf("pub: %s \n", pubStr)
			fmt.Printf("pub2: %s \n", pubStr2)

			if pubStr != pubStr2 {
				t.Errorf("%s result failed, %s : %s \n", test.name, pubStr, pubStr2)
				return
			} else {
				fmt.Printf("test [%s] passed \n", test.name)
			}
		}

	}

}


func TestGenPub(t *testing.T) {
	name := "ECC_CURVE_SECP256R1"
	eccType := owcryptdev.ECC_CURVE_SECP256R1
	priviteKey, _ := hex.DecodeString("c40b79528d69c5e59ececf790e1b869212f6d8112700c5365ae685fdf1205586")
	pub1, ret := owcrypt.GenPubkey(priviteKey, eccType)
	if ret != owcryptdev.SUCCESS {
		t.Errorf("owcrypt.GenPubkey [%s] failed, privateKey: %s \n", name, hex.EncodeToString(priviteKey))
		return
	}
	pub2, ret2 := owcryptdev.GenPubkey(priviteKey, eccType)
	if ret2 != owcryptdev.SUCCESS {
		t.Errorf("owcryptdev.GenPubkey [%s] failed, privateKey: %s \n", name, hex.EncodeToString(priviteKey))
		return
	}
	pubStr := hex.EncodeToString(pub1)
	pubStr2 := hex.EncodeToString(pub2)

	fmt.Printf("priviteKey: %s \n", hex.EncodeToString(priviteKey))
	fmt.Printf("pub: %s \n", pubStr)
	fmt.Printf("pub2: %s \n", pubStr2)

	if pubStr != pubStr2 {
		t.Errorf("%s result failed, %s : %s \n", name, pubStr, pubStr2)
		return
	} else {
		fmt.Printf("test [%s] passed \n", name)
	}

}

