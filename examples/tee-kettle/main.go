package main

import (
	"fmt"
	//"os"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/flashbots/suapp-examples/framework"
)

func main() {
	fr := framework.New()
	contract := fr.DeployContract("verify-attestation.sol/VerifyAttestation.json")

	fmt.Println("Remote attestation verification ...")

	var mrenclave [32]byte
	_mrenclave := common.FromHex("0xd0ae774774c2064a60dd92541fcc7cb8b3acdea0d793f3b27a27a44dbf71e75f")
	copy(mrenclave[:], _mrenclave)

	var mrsigner [32]byte
	_mrsigner := common.FromHex("0x83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e")
	copy(mrsigner[:], _mrsigner)

	expectedPayload := common.FromHex(
		"0xa4f1e2de42ade42856a6e7b029432278d76ad1c3e86ceccd6f2f46532861c20c0615a3b4f8a3e283d23c09255e51360e")

	receipt := contract.SendTransaction("verifyTeeKettle", []interface{}{mrenclave, mrsigner, expectedPayload}, nil)
	//fmt.Println("receipt", receipt.Logs[0])

	attestationVerificationEvent := &AttestationVerificationEvent{}
	if err := attestationVerificationEvent.Unpack(receipt.Logs[0]); err != nil {
		panic(err)
	}

	fmt.Println("attestation mrenclave hex", common.Bytes2Hex(attestationVerificationEvent.mrenclave))
	fmt.Println("attestation mrsigner hex", common.Bytes2Hex(attestationVerificationEvent.mrsigner))
	fmt.Println("attestation payload hex (should be kettle address)", common.Bytes2Hex(attestationVerificationEvent.payload))
}

var attestationVerificationEventABI abi.Event

func init() {
	artifact, _ := framework.ReadArtifact("verify-attestation.sol/VerifyAttestation.json")
	attestationVerificationEventABI = artifact.Abi.Events["AttestationVerificationEvent"]
}

type AttestationVerificationEvent struct {
	mrenclave []byte
	mrsigner  []byte
	payload   []byte
}

func (e *AttestationVerificationEvent) Unpack(log *types.Log) error {
	unpacked, err := attestationVerificationEventABI.Inputs.Unpack(log.Data)

	if err != nil {
		return err
	}

	_mrenclave := unpacked[0].([32]byte)
	_mrsigner := unpacked[1].([32]byte)

	e.mrenclave = _mrenclave[:]
	e.mrsigner = _mrsigner[:]
	e.payload = unpacked[2].([]byte)

	return nil
}
