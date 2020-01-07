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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/blocktree/go-owcrypt"
	owcryptdev "github.com/blocktree/go-owcrypt-dev"
	"testing"
)

func generateSeed(length int) ([]byte, error) {
	buf := make([]byte, length)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func TestHash(t *testing.T) {

	tests := []struct {
		name     string
		hashType uint32
		digestLen uint16
	}{
		{name: "HASH_ALG_SHA1", hashType: owcryptdev.HASH_ALG_SHA1},
		{name: "HASH_ALG_SHA3_256", hashType: owcryptdev.HASH_ALG_SHA3_256},
		{name: "HASH_ALG_SHA256", hashType: owcryptdev.HASH_ALG_SHA256},
		{name: "HASH_ALG_SHA512", hashType: owcryptdev.HASH_ALG_SHA512},
		{name: "HASH_ALG_MD4", hashType: owcryptdev.HASH_ALG_MD4},
		{name: "HASH_ALG_MD5", hashType: owcryptdev.HASH_ALG_MD5},
		{name: "HASH_ALG_RIPEMD160", hashType: owcryptdev.HASH_ALG_RIPEMD160},
		{name: "HASH_ALG_BLAKE2B", hashType: owcryptdev.HASH_ALG_BLAKE2B, digestLen: 32},
		{name: "HASH_ALG_BLAKE2S", hashType: owcryptdev.HASH_ALG_BLAKE2S, digestLen: 32},
		{name: "HASH_ALG_SM3", hashType: owcryptdev.HASH_ALG_SM3},
		{name: "HASh_ALG_DOUBLE_SHA256", hashType: owcryptdev.HASH_ALG_DOUBLE_SHA256},
		{name: "HASH_ALG_HASH160", hashType: owcryptdev.HASH_ALG_HASH160},
		{name: "HASH_ALG_BLAKE256", hashType: owcryptdev.HASH_ALG_BLAKE256},
		{name: "HASH_ALG_BLAKE512", hashType: owcryptdev.HASH_ALG_BLAKE512},
		{name: "HASH_ALG_KECCAK256", hashType: owcryptdev.HASH_ALG_KECCAK256},
		{name: "HASH_ALG_KECCAK256_RIPEMD160", hashType: owcryptdev.HASH_ALG_KECCAK256_RIPEMD160},
		{name: "HASH_ALG_SHA3_256_RIPEMD160", hashType: owcryptdev.HASH_ALG_SHA3_256_RIPEMD160},
		{name: "HASH_ALG_KECCAK512", hashType: owcryptdev.HASH_ALG_KECCAK512},
		{name: "HASH_ALG_SHA3_512", hashType: owcryptdev.HASH_ALG_SHA3_512},
	}

	for _, test := range tests {

		for i := 128; i <= 1024; i++ {
			plainBit, err := generateSeed(i)
			if err != nil {
				t.Errorf("generateSeed err: %v", err)
				return
			}

			//fmt.Printf("test [%s] length[%d] begin \n", test.name, i)

			hash := owcrypt.Hash(plainBit, test.digestLen, test.hashType)
			hash2 := owcryptdev.Hash(plainBit, test.digestLen, test.hashType)
			hashStr := hex.EncodeToString(hash)
			hashStr2 := hex.EncodeToString(hash2)

			//fmt.Printf("plainBit: %s \n", hex.EncodeToString(plainBit))
			//fmt.Printf("hash: %s \n", hashStr)
			//fmt.Printf("hash2: %s \n", hashStr2)

			if hashStr != hashStr2 {
				t.Errorf("%s result failed, %s : %s \n", test.name, hashStr, hashStr2)
				return
			} else {
				fmt.Printf("test [%s] length[%d] passed \n", test.name, i)
			}
		}
	}

}
