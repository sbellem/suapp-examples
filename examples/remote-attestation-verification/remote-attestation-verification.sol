// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.8;

import "../../suave-geth/suave/sol/libraries/Suave.sol";
import "forge-std/console.sol";


contract RemoteAttestationVerification {

    event AttestationVerificationEvent (
        Suave.IASResponse iasResponse,
        string isvEnclaveQuoteBody
    );

    function emitAttestationVerification(Suave.IASResponse memory iasResponse) public payable {
        emit AttestationVerificationEvent(iasResponse, iasResponse.body.isvEnclaveQuoteBody);
    }

    function callback() external payable {}

    function getAttestationVerificationReport() external returns (string memory) {
        Suave.IASResponse memory iasResponse = Suave.getAttestationVerificationReport();
        return iasResponse.body.isvEnclaveQuoteBody;
    }

    function example() external payable returns (bytes memory) {
        require(Suave.isConfidential());
        Suave.IASResponse memory iasResponse = Suave.getAttestationVerificationReport();
        console.log(iasResponse.body.isvEnclaveQuoteBody);
        //return abi.encodeWithSelector(this.callback.selector);
        return abi.encodeWithSelector(this.emitAttestationVerification.selector, iasResponse);
    }
}
