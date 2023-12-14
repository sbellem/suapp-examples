// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.8;

import "../../suave-geth/suave/sol/libraries/Suave.sol";
import "forge-std/console.sol";
import { Base64 } from "openzeppelin/utils/Base64.sol";
import { RAVEBase } from "rave/RAVEBase.sol";
import { RAVE } from "rave/RAVE.sol";


contract RemoteAttestationVerification {

    RAVEBase c;

    struct AttestationVerificationData {
        Suave.IASResponse iasResponse;
        string isvEnclaveQuoteBodyBase64;
        bytes isvEnclaveQuoteBodyBytes;
        //bytes payload;
    }

    event AttestationVerificationEvent (
        Suave.IASResponse iasResponse,
        string isvEnclaveQuoteBodyBase64,
        bytes isvEnclaveQuoteBodyBytes
    );
        //bytes payload

    function emitAttestationVerification(AttestationVerificationData memory avd) public payable {
        //bytes memory isvEnclaveQuoteBodyBytes = iasResponse.body.isvEnclaveQuoteBody;
        //string memory isvEnclaveQuoteBodyBase64 = Base64.encode(isvEnclaveQuoteBodyBytes);
        emit AttestationVerificationEvent(
            avd.iasResponse,
            avd.isvEnclaveQuoteBodyBase64,
            avd.isvEnclaveQuoteBodyBytes
            //avd.payload
        );
    }

    function callback() external payable {}

    function getAttestationVerificationReport() external returns (string memory) {
        Suave.IASResponse memory iasResponse = Suave.getAttestationVerificationReport();
        string memory isvEnclaveQuoteBodyBase64 = Base64.encode(iasResponse.body.isvEnclaveQuoteBody);
        return isvEnclaveQuoteBodyBase64;
    }

    function example() external payable returns (bytes memory) {
        require(Suave.isConfidential());
        Suave.IASResponse memory iasResponse = Suave.getAttestationVerificationReport();
        string memory isvEnclaveQuoteBodyBase64 = Base64.encode(iasResponse.body.isvEnclaveQuoteBody);
        console.log(isvEnclaveQuoteBodyBase64);
        //bytes memory gotPayload = verifyRA(iasResponse);
        AttestationVerificationData memory avd;
        avd.iasResponse = iasResponse;
        avd.isvEnclaveQuoteBodyBase64 = isvEnclaveQuoteBodyBase64;
        avd.isvEnclaveQuoteBodyBytes = iasResponse.body.isvEnclaveQuoteBody;
        //avd.payload = gotPayload;
        return abi.encodeWithSelector(this.emitAttestationVerification.selector, avd);
    }


    // test & mocks from Rave
    function run_verifyRemoteAttestation(
        bytes memory report,
        bytes memory sig,
        bytes memory signingMod,
        bytes memory signingExp,
        bytes32 mrenclave,
        bytes32 mrsigner,
        bytes memory expPayload
    ) internal returns (bytes memory) {
        c = new RAVE();
        bytes memory gotPayload = c.verifyRemoteAttestation(report, sig, signingMod, signingExp, mrenclave, mrsigner);
        return gotPayload;
        //assert(keccak256(gotPayload.substring(0, expPayload.length)) == keccak256(expPayload));
    }

    function verifyRA(Suave.IASResponse memory iasResponse) internal returns (bytes memory) {
        bytes memory report = report(iasResponse.body);
        bytes memory sig = sig();
        bytes memory signingMod = signingMod();
        bytes memory signingExp = signingExp();
        bytes32 mrenclave = mrenclave();
        bytes32 mrsigner = mrsigner();
        bytes memory payload = payload();
        bytes memory gotPayload = run_verifyRemoteAttestation(report, sig, signingMod, signingExp, mrenclave, mrsigner, payload);
        return gotPayload;
    }

    function report(Suave.IASResponseBody memory iasResponseBody) internal view returns (bytes memory) {
        // Report is inputted as abi-encoded JSON values
        return abi.encode(
            //"142090828149453720542199954221331392599",
            iasResponseBody.id,
            //"2023-02-15T01:24:57.989456",
            iasResponseBody.timestamp,
            //"4",
            iasResponseBody.version,
            //"EbrM6X6YCH3brjPXT23gVh/I2EG5sVfHYh+S54fb0rrAqVRTiRTOSfLsWSVTZc8wrazGG7oooGoMU7Gj5TEhsvsDIV4aYpvkSk/E3Tsb7CaGd+Iy1cEhLO4GPwdmwt/PXNQQ3htLdy3aNb7iQMrNbiFcdkVdV/tepdezMsSB8Go=",
            iasResponseBody.epidPseudonym,
            //"https://security-center.intel.com",
            iasResponseBody.advisoryURL,
            //"[\"INTEL-SA-00334\",\"INTEL-SA-00615\"]",
            iasResponseBody.advisoryIDs,
            //"SW_HARDENING_NEEDED",
            iasResponseBody.isvEnclaveQuoteStatus,
            // Already Base64 decoded off-chain
            //hex"02000100800c00000d000d000000000042616c98d53c9712639447c9b0e7003f0000000000000000000000000000000014140b07ff800e000000000000000000000000000000000000000000000000000000000000000000000000000000000005000000000000001f00000000000000d0ae774774c2064a60dd92541fcc7cb8b3acdea0d793f3b27a27a44dbf71e75f000000000000000000000000000000000000000000000000000000000000000083d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a4f1e2de42ade42856a6e7b029432278d76ad1c3e86ceccd6f2f46532861c20c0615a3b4f8a3e283d23c09255e51360e00000000000000000000000000000000"
            iasResponseBody.isvEnclaveQuoteBody
        );
    }

    // The leaf x509 signing certificate's signature over the report
    function sig() internal view returns (bytes memory) {
        // base64 decoded signature as hex
        return
        hex"4c15c80ec83f5ebbee20f1be0cf1f7c1850179988442cba027152e01b79474592f2cd526fc8b2b2808b9c6afeaed642061aafa9b92ffcedc7cfbc1418bb9865719ef86c9de9f01bc166cf5f2ce392a70d5cd2017336c8817eaad129ad9ff5dd88eb3ecc26b0d21e04aba01c0bf303ed5e343e85104ea7a6e45514938158358825bf339fbd5116581218575551478e49c0aecfb1eb40c863c4401c44da2aa5634e335512915b38d77c7dc693ee8b9fa41f3bf9d939c1c5e382c010c42da237650c16a3ff4ac504376b215b1fc08f69a3dc0c3d0404f643e42e3078a70db5d61305c87e90ad39968b28e333e24b0887b0f01ace55d647805575fd96648c006abe3";
    }

    //// The leaf x509 signing certificate used to sign the report
    //function signingCert() internal view returns (bytes memory) {
    //    return
    //    hex"308204a130820309a003020102020900d107765d32a3b096300d06092a864886f70d01010b0500307e310b3009060355040613025553310b300906035504080c0243413114301206035504070c0b53616e746120436c617261311a3018060355040a0c11496e74656c20436f72706f726174696f6e3130302e06035504030c27496e74656c20534758204174746573746174696f6e205265706f7274205369676e696e67204341301e170d3136313132323039333635385a170d3236313132303039333635385a307b310b3009060355040613025553310b300906035504080c0243413114301206035504070c0b53616e746120436c617261311a3018060355040a0c11496e74656c20436f72706f726174696f6e312d302b06035504030c24496e74656c20534758204174746573746174696f6e205265706f7274205369676e696e6730820122300d06092a864886f70d01010105000382010f003082010a0282010100a97a2de0e66ea6147c9ee745ac0162686c7192099afc4b3f040fad6de093511d74e802f510d716038157dcaf84f4104bd3fed7e6b8f99c8817fd1ff5b9b864296c3d81fa8f1b729e02d21d72ffee4ced725efe74bea68fbc4d4244286fcdd4bf64406a439a15bcb4cf67754489c423972b4a80df5c2e7c5bc2dbaf2d42bb7b244f7c95bf92c75d3b33fc5410678a89589d1083da3acc459f2704cd99598c275e7c1878e00757e5bdb4e840226c11c0a17ff79c80b15c1ddb5af21cc2417061fbd2a2da819ed3b72b7efaa3bfebe2805c9b8ac19aa346512d484cfc81941e15f55881cc127e8f7aa12300cd5afb5742fa1d20cb467a5beb1c666cf76a368978b50203010001a381a43081a1301f0603551d2304183016801478437b76a67ebcd0af7e4237eb357c3b8701513c300e0603551d0f0101ff0404030206c0300c0603551d130101ff0402300030600603551d1f045930573055a053a051864f687474703a2f2f7472757374656473657276696365732e696e74656c2e636f6d2f636f6e74656e742f43524c2f5347582f4174746573746174696f6e5265706f72745369676e696e6743412e63726c300d06092a864886f70d01010b050003820181006708b61b5c2bd215473e2b46af99284fbb939d3f3b152c996f1a6af3b329bd220b1d3b610f6bce2e6753bded304db21912f385256216cfcba456bd96940be892f5690c260d1ef84f1606040222e5fe08e5326808212a447cfdd64a46e94bf29f6b4b9a721d25b3c4e2f62f58baed5d77c505248f0f801f9fbfb7fd752080095cee80938b339f6dbb4e165600e20e4a718812d49d9901e310a9b51d66c79909c6996599fae6d76a79ef145d9943bf1d3e35d3b42d1fb9a45cbe8ee334c166eee7d32fcdc9935db8ec8bb1d8eb3779dd8ab92b6e387f0147450f1e381d08581fb83df33b15e000a59be57ea94a3a52dc64bdaec959b3464c91e725bbdaea3d99e857e380a23c9d9fb1ef58e9e42d71f12130f9261d7234d6c37e2b03dba40dfdfb13ac4ad8e13fd3756356b6b50015a3ec9580b815d87c2cef715cd28df00bbf2a3c403ebf6691b3f05edd9143803ca085cff57e053eec2f8fea46ea778a68c9be885bc28225bc5f309be4a2b74d3a03945319dd3c7122fed6ff53bb8b8cb3a03c";
    //}

    // The extracted RSA modulus of the leaf x509 signing certificate
    function signingMod() internal view returns (bytes memory) {
        return
        hex"a97a2de0e66ea6147c9ee745ac0162686c7192099afc4b3f040fad6de093511d74e802f510d716038157dcaf84f4104bd3fed7e6b8f99c8817fd1ff5b9b864296c3d81fa8f1b729e02d21d72ffee4ced725efe74bea68fbc4d4244286fcdd4bf64406a439a15bcb4cf67754489c423972b4a80df5c2e7c5bc2dbaf2d42bb7b244f7c95bf92c75d3b33fc5410678a89589d1083da3acc459f2704cd99598c275e7c1878e00757e5bdb4e840226c11c0a17ff79c80b15c1ddb5af21cc2417061fbd2a2da819ed3b72b7efaa3bfebe2805c9b8ac19aa346512d484cfc81941e15f55881cc127e8f7aa12300cd5afb5742fa1d20cb467a5beb1c666cf76a368978b5";
    }

    // The extracted RSA exponent of the leaf x509 signing certificate
    function signingExp() internal view returns (bytes memory) {
        return hex"010001";
    }

    // The expected MRENCLAVE value in this specific report
    function mrenclave() internal view returns (bytes32) {
        return hex"d0ae774774c2064a60dd92541fcc7cb8b3acdea0d793f3b27a27a44dbf71e75f";
    }

    // The expected MRSIGNER value in this specific report
    function mrsigner() internal view returns (bytes32) {
        return hex"83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e";
    }

    // The expected payload value in this specific report
    function payload() internal view returns (bytes memory) {
        // This is a hex-encoded 48 byte BLS public key
        return hex"a4f1e2de42ade42856a6e7b029432278d76ad1c3e86ceccd6f2f46532861c20c0615a3b4f8a3e283d23c09255e51360e";
    }
}
