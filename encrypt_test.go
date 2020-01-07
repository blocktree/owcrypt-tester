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

func TestEncryptAll(t *testing.T) {

	tests := []struct {
		name    string
		eccType uint32
	}{
		{name: "ECC_CURVE_SM2_STANDARD", eccType: owcryptdev.ECC_CURVE_SM2_STANDARD},
	}

	for _, test := range tests {

		for i := 0; i < 10240; i++ {
			priviteKey, err := generateSeed(32)
			if err != nil {
				t.Errorf("generateSeed err: %v", err)
				return
			}

			msg, err := generateSeed(1024)
			if err != nil {
				t.Errorf("generateSeed err: %v", err)
				return
			}
			msgStr := hex.EncodeToString(msg)

			pub, ret := owcryptdev.GenPubkey(priviteKey, test.eccType)
			if ret != owcryptdev.SUCCESS {
				t.Errorf("owcrypt.GenPubkey [%s] failed, privateKey: %s \n", test.name, hex.EncodeToString(priviteKey))
				return
			}
			pubStr := hex.EncodeToString(pub)

			cipher, ret2 := owcryptdev.Encryption(pub, msg, test.eccType)
			if ret2 != owcryptdev.SUCCESS {
				t.Errorf("owcryptdev.Encryption [%s] failed, privateKey: %s \n", test.name, hex.EncodeToString(priviteKey))
				return
			}
			cipherStr := hex.EncodeToString(cipher)

			plain, verifyNew := owcryptdev.Decryption(priviteKey, cipher, test.eccType)
			plainStr := hex.EncodeToString(plain)
			if verifyNew == owcryptdev.FAILURE || plainStr != msgStr {

				fmt.Printf("%s \n", test.name)
				fmt.Printf("priviteKey: %s \n", hex.EncodeToString(priviteKey))
				fmt.Printf("pub: %s \n", pubStr)
				fmt.Printf("msg: %s \n", msgStr)
				fmt.Printf("cipher: %s \n", cipherStr)
				fmt.Printf("plain: %s \n", plainStr)

				t.Errorf("test [%s] new decrypt failed \n", test.name)
				return
			} else {
				fmt.Printf("test [%s] new decrypt passed \n", test.name)
			}

			plainOld, verifyOld := owcrypt.Decryption(priviteKey, cipher, test.eccType)
			plainOldStr := hex.EncodeToString(plainOld)
			if verifyOld == owcryptdev.FAILURE || plainOldStr != msgStr {

				fmt.Printf("%s \n", test.name)
				fmt.Printf("priviteKey: %s \n", hex.EncodeToString(priviteKey))
				fmt.Printf("pub: %s \n", pubStr)
				fmt.Printf("msg: %s \n", msgStr)
				fmt.Printf("cipher: %s \n", cipherStr)
				fmt.Printf("plain: %s \n", plainOldStr)

				t.Errorf("test [%s] old decrypt failed \n", test.name)
				return
			} else {
				fmt.Printf("test [%s] old decrypt passed \n", test.name)
			}

			////// old encrypt new decrypt //////

			cipherOld, retOld := owcrypt.Encryption(pub, msg, test.eccType)
			if retOld != owcryptdev.SUCCESS {
				t.Errorf("owcryptdev.Encryption [%s] failed, privateKey: %s \n", test.name, hex.EncodeToString(priviteKey))
				return
			}
			cipherOldStr := hex.EncodeToString(cipherOld)

			plainNew, newVerifyOld := owcrypt.Decryption(priviteKey, cipherOld, test.eccType)
			plainNewStr := hex.EncodeToString(plainNew)
			if newVerifyOld == owcryptdev.FAILURE || plainNewStr != msgStr {

				fmt.Printf("%s \n", test.name)
				fmt.Printf("priviteKey: %s \n", hex.EncodeToString(priviteKey))
				fmt.Printf("pub: %s \n", pubStr)
				fmt.Printf("msg: %s \n", msgStr)
				fmt.Printf("cipher: %s \n", cipherOldStr)
				fmt.Printf("plain: %s \n", plainNewStr)

				t.Errorf("test [%s] old encrypt new decrypt failed \n", test.name)
				return
			} else {
				fmt.Printf("test [%s] old encrypt new decrypt passed \n", test.name)
			}
		}

	}

}


func TestEncrypt(t *testing.T) {
	name := "ECC_CURVE_SM2_STANDARD"
	eccType := owcryptdev.ECC_CURVE_SM2_STANDARD
	priviteKey, _ := hex.DecodeString("c1b517b5668bc9c0adcf05ad3a35278868120e55feb6ebd3bdc913727c44436d")
	msg, _ := hex.DecodeString("8457058a7f71791caab5105de9925869ebff0817277d062759dbae7f503bea4a71f6a4ff2c8d38edba31eb2a2c0b5be985f933001c3a217ad290f116dd4a66a5ea88e3b67ec93587a5586342bdcb704051db4e102b671677f0ffe3af5b7227c7eca5475bde8edfe6b6cebe46d19cbe6ef719299d431bfefc216dfc06f2764b9403b31866551b6b592e25b26601cea8d85d3e6c52a2165773ef0e1acff0bbc7fc2a65b7a05aac54a853c990d2f13925ea83170db654f6bf9a6aaa575ecbcd0e085e935cbe83a2fc6bc159d3c1dc4237cf66f2598dd28fc8afbd8a6b959626f89b390f35db6e16f68545f4c8be00904276bf2ada464bf108080bdddde2b21756400b8b3a0887cbc2ef1eefaa1b194421ce13c4689fcb9b6d5fcaba724395c1093963332284358295727f08a06b2193b841f76ee1dac2bda762df4313db8e12470ccea60225087516b88a4603a3eaaf65944a6d08d776a74c8e5922e7f44a24c8265870a65f0d0a8bacb97440fbcf29c9acc03ea39181da3d360ca489a59223bba962902994658d8ce13d4e1047d30764645daa0865cbb4b8f69141c225b381947b65786fa26e1c46939cd64407f88fa372327de532e2bae7c5e696a854586bca6b30c29ebb2271113d64102024c88abd1d0cf07f7db49a42d2a4271ab019208b165bd5982e5fdee30e154653a33f31ae0d19ae8451e0e8904126240277908f63f4471d50c64b6f59b8f2bef4677387536552aefc7e9b497993992c9de0bb26c5b83a05cb957806921db52c3d7c03d66330e7d7b984c782f343b6c228e272fc035e92dc3bd879b4d22240f26dd239aa16cbb8729f0aa6cfb207af4ffab127e576297cdfad49f4b69f4afebd5000d70ae4630c822d1021578d47c49dc37d29a9462240a106af33973575fdfebc371ef7e5a7d468852079addc7740264717ba49bc56be0bd01bac7c270da4ee15b927eb31e79bc6e97f8622f3c0681799ec18662a6b333490c4824b6de18b0bba455b3a78e3b61c86dd8c46be9b9566e5e8db96f7c126ec3f01ca89f2cfe4c46ea037b73da7b0f8f69829187b0ebb0fe2279642d6aa4087764ad7c44c89c17aba3df534169f0328dd6239e8b137950dcffc43e88509142fdd4059cb7ab8ae6af8f4757fec16f7b680d82246253dc6f156abf8a2af8737545fc690aaf401a67574adee12e5fdcdb1cb74f0ce9e87f65cd2ea0e00ff6317bf08f74157b433d42dd4c639f39bc69b79574345f363a88cccd3b376e8c4b139417602f1d9137d5824fa9ce7fa6ed9b5463c6658a98390ff5c389e8a96215627c7c712f7c52a879e17ecf0cb42f74d7565064ca9679e785dd03d30e3cbbbcb4aac9d99af540c49644a0c74041f2016739b536c3463bac2a9ed8a0dbff379cad83d4d8841279a6100e22883c948ebe09c1882f7105ed2d96a0bb891be47f5fe")
	msgStr := hex.EncodeToString(msg)

	pub, ret := owcryptdev.GenPubkey(priviteKey, eccType)
	if ret != owcryptdev.SUCCESS {
		t.Errorf("owcrypt.GenPubkey [%s] failed, privateKey: %s \n", name, hex.EncodeToString(priviteKey))
		return
	}
	pubStr := hex.EncodeToString(pub)

	cipher, ret2 := owcryptdev.Encryption(pub, msg, eccType)
	if ret2 != owcryptdev.SUCCESS {
		t.Errorf("owcryptdev.Encryption [%s] failed, privateKey: %s \n", name, hex.EncodeToString(priviteKey))
		return
	}
	cipherStr := hex.EncodeToString(cipher)

	plain, verifyNew := owcryptdev.Decryption(priviteKey, cipher, eccType)
	plainStr := hex.EncodeToString(plain)
	if verifyNew == owcryptdev.FAILURE || plainStr != msgStr {

		fmt.Printf("%s \n", name)
		fmt.Printf("priviteKey: %s \n", hex.EncodeToString(priviteKey))
		fmt.Printf("pub: %s \n", pubStr)
		fmt.Printf("msg: %s \n", msgStr)
		fmt.Printf("cipher: %s \n", cipherStr)
		fmt.Printf("plain: %s \n", plainStr)

		t.Errorf("test [%s] new decrypt failed \n", name)
		return
	} else {
		fmt.Printf("test [%s] new decrypt passed \n", name)
	}

	plainOld, verifyOld := owcrypt.Decryption(priviteKey, cipher, eccType)
	plainOldStr := hex.EncodeToString(plainOld)
	if verifyOld == owcryptdev.FAILURE || plainOldStr != msgStr {

		fmt.Printf("%s \n", name)
		fmt.Printf("priviteKey: %s \n", hex.EncodeToString(priviteKey))
		fmt.Printf("pub: %s \n", pubStr)
		fmt.Printf("msg: %s \n", msgStr)
		fmt.Printf("cipher: %s \n", cipherStr)
		fmt.Printf("plain: %s \n", plainOldStr)

		t.Errorf("test [%s] old decrypt failed \n", name)
		return
	} else {
		fmt.Printf("test [%s] old decrypt passed \n", name)
	}

	////// old encrypt new decrypt //////

	cipherOld, retOld := owcrypt.Encryption(pub, msg, eccType)
	if retOld != owcryptdev.SUCCESS {
		t.Errorf("owcryptdev.Encryption [%s] failed, privateKey: %s \n", name, hex.EncodeToString(priviteKey))
		return
	}
	cipherOldStr := hex.EncodeToString(cipherOld)

	plainNew, newVerifyOld := owcrypt.Decryption(priviteKey, cipherOld, eccType)
	plainNewStr := hex.EncodeToString(plainNew)
	if newVerifyOld == owcryptdev.FAILURE || plainNewStr != msgStr {

		fmt.Printf("%s \n", name)
		fmt.Printf("priviteKey: %s \n", hex.EncodeToString(priviteKey))
		fmt.Printf("pub: %s \n", pubStr)
		fmt.Printf("msg: %s \n", msgStr)
		fmt.Printf("cipher: %s \n", cipherOldStr)
		fmt.Printf("plain: %s \n", plainNewStr)

		t.Errorf("test [%s] old encrypt new decrypt failed \n", name)
		return
	} else {
		fmt.Printf("test [%s] old encrypt new decrypt passed \n", name)
	}

}
