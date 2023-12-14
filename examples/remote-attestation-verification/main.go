package main

import (
	"fmt"
	//"os"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/flashbots/suapp-examples/framework"
)

func main() {
	fr := framework.New()
	contract := fr.DeployContract("remote-attestation-verification.sol/RemoteAttestationVerification.json")
	//contract := fr.DeployContract("onchain-state.sol/OnChainState.json")

	fmt.Println("Remote attestation verification ...")

	receipt := contract.SendTransaction("example", nil, nil)
	fmt.Println("receipt", receipt.Logs[0])

	attestationVerificationEvent := &AttestationVerificationEvent{}
	if err := attestationVerificationEvent.Unpack(receipt.Logs[0]); err != nil {
		panic(err)
	}

	fmt.Println("attestation quote", attestationVerificationEvent.isvEnclaveQuoteBody)
	//val := contract.Call("getAttestationVerificationReport")[0].(string)
	//val := contract.Call("getAttestationVerificationReport")
	//fmt.Println("IAS report verif", val)
	//if val != 1 {
	//	fmt.Printf("expected 1")
	//	os.Exit(1)
	//}
}

var attestationVerificationEventABI abi.Event

func init() {
	artifact, _ := framework.ReadArtifact("remote-attestation-verification.sol/RemoteAttestationVerification.json")
	attestationVerificationEventABI = artifact.Abi.Events["AttestationVerificationEvent"]
}

type AttestationVerificationEvent struct {
	//iasResponse         types.IASResponse
	isvEnclaveQuoteBody string
}

func (e *AttestationVerificationEvent) Unpack(log *types.Log) error {
	unpacked, err := attestationVerificationEventABI.Inputs.Unpack(log.Data)
	if err != nil {
		return err
	}
	//e.iasResponse = unpacked[0].(types.IASResponse)
	e.isvEnclaveQuoteBody = unpacked[1].(string)
	return nil
}
