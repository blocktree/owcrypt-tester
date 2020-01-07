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
	owcryptdev "github.com/blocktree/go-owcrypt-dev"
	"testing"
)

func TestKeyAgreement(t *testing.T) {

	for i := 0; i < 102400; i++ {

		eccType := owcryptdev.ECC_CURVE_SM2_STANDARD
		////////////////////////////////////////////////////////////////////发起方 - initiator////////////////////////////////////////////////////////////////////
		//发起方标识符
		IDinitiator, _ := generateSeed(4)
		//发起方私钥
		prikeyInitiator, _ := generateSeed(32)
		//发起方共钥
		pubkeyInitiator, ret := owcryptdev.GenPubkey(prikeyInitiator, eccType)
		if ret != owcryptdev.SUCCESS {
			t.Errorf("owcrypt.GenPubkey failed, privateKey: %s \n", hex.EncodeToString(prikeyInitiator))
			return
		}
		//pubkeyInitiatorStr := hex.EncodeToString(pubkeyInitiator)

		////////////////////////////////////////////////////////////////////响应方 - responder////////////////////////////////////////////////////////////////////
		//响应方标识符
		IDresponder, _ := generateSeed(4)
		//相应方私钥
		prikeyResponder, _ := generateSeed(32)
		//响应方公钥
		pubkeyResponder, ret2 := owcryptdev.GenPubkey(prikeyResponder, eccType)
		if ret2 != owcryptdev.SUCCESS {
			t.Errorf("owcrypt.GenPubkey failed, privateKey: %s \n", hex.EncodeToString(prikeyResponder))
			return
		}

		tmpPrikeyInitiator, tmpPubkeyInitiator := owcryptdev.KeyAgreement_initiator_step1(eccType)

		//1.2 发起方将临时私钥保存在本地，用于第二步操作的输入
		//1.3 发起方将临时公钥发送给响应方来发起协商，同时会指定协商的具体长度

		//第二步：
		//2.1 响应方获得发送方的临时公钥和协商长度，然后开始进行协商计算
		fmt.Println("--------------------------响应方第一步--------------------------")
		retB, tmpPubkeyResponder, S2, SB, retStep1 := owcryptdev.KeyAgreement_responder_step1(IDinitiator[:],
			IDresponder[:],
			prikeyResponder[:],
			pubkeyResponder[:],
			pubkeyInitiator[:],
			tmpPubkeyInitiator[:],
			32,
			eccType)
		if retStep1 != owcryptdev.SUCCESS {

			fmt.Println("发起方产生临时公私钥对，产生结果为：")
			fmt.Println("发起方临时私钥：", hex.EncodeToString(tmpPrikeyInitiator[:]))
			fmt.Println("发起方临时公钥：", hex.EncodeToString(tmpPubkeyInitiator[:]))

			t.Errorf("KeyAgreement_responder_step1 failed \n")
			return

		}

		//2.2 响应方此时获得临时公钥、用于本地校验的S2、用于发送给发起方的校验值SB， 协商结果
		//2.3 响应方将S2和协商保存在本地，用于第二步的校验
		//2.4 响应方将临时公钥和校验值SB发送给发起方

		//第三步：
		//发起方获得响应方的临时公钥和校验值，开始进行协商计算
		fmt.Println("--------------------------发起方第二步--------------------------")
		retA, SA, err := owcryptdev.KeyAgreement_initiator_step2(IDinitiator[:],
			IDresponder[:],
			prikeyInitiator[:],
			pubkeyInitiator[:],
			pubkeyResponder[:],
			tmpPrikeyInitiator[:],
			tmpPubkeyInitiator[:],
			tmpPubkeyResponder[:],
			SB[:],
			32,
			eccType)
		if err != owcryptdev.SUCCESS {

			fmt.Println("响应方产生临时公钥 ：", hex.EncodeToString(tmpPubkeyResponder[:]))
			fmt.Println("响应方本地校验值： ", hex.EncodeToString(S2[:]))
			fmt.Println("响应方发送给发起方的校验值： ", hex.EncodeToString(SB[:]))
			fmt.Println("响应方获得的协商结果： ", hex.EncodeToString(retB[:]))

			t.Errorf("KeyAgreement_initiator_step2 failed \n")
			return
		}

		//此时，发起方已经获得协商结果，如果接口返回SUCCESS，则说明接口内部已经与响应方发来的校验值完成校验
		//即：发起方的协商流程已经完成
		//然后，发起方需要将输出的校验值SA发送给响应方进行校验

		//第四步：
		//响应方拿到发起方发来的最终校验值SA， 与之前本地保存的校验值S2进行比对，返回SUCCESS则响应方协商通过
		fmt.Println("--------------------------响应方第二步--------------------------")
		if owcryptdev.SUCCESS != owcryptdev.KeyAgreement_responder_step2(SA[:], S2[:], eccType) {

			fmt.Println("发起方发送给响应方的校验值： ", hex.EncodeToString(SA[:]))
			fmt.Println("发起方获得的协商结果： ", hex.EncodeToString(retA[:]))

			t.Errorf("KeyAgreement_responder_step2 failed \n")
			return
		} else {
			fmt.Println("响应方校验通过")
		}

		retAStr := hex.EncodeToString(retA)
		retBStr := hex.EncodeToString(retB)

		if retAStr != retBStr {
			fmt.Printf("retA: %s \n", retAStr)
			fmt.Printf("retB: %s \n", retBStr)

			t.Errorf("retA is not equal of retB \n")
			return
		}
	}
}
