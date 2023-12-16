// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.8;

import "../../suave-geth/suave/sol/libraries/Suave.sol";
import { BytesUtils } from "ens-contracts/dnssec-oracle/BytesUtils.sol";
import { Test, console } from "forge-std/Test.sol";
import { Base64 } from "openzeppelin/utils/Base64.sol";
import { RAVE } from "rave/RAVE.sol";
import { X509Verifier } from "rave/X509Verifier.sol";


contract VerifyAttestation is Test, RAVE {
    using BytesUtils for *;

    bytes constant intelRootModulus =
        hex"9F3C647EB5773CBB512D2732C0D7415EBB55A0FA9EDE2E649199E6821DB910D53177370977466A6A5E4786CCD2DDEBD4149D6A2F6325529DD10CC98737B0779C1A07E29C47A1AE004948476C489F45A5A15D7AC8ECC6ACC645ADB43D87679DF59C093BC5A2E9696C5478541B979E754B573914BE55D32FF4C09DDF27219934CD990527B3F92ED78FBF29246ABECB71240EF39C2D7107B447545A7FFB10EB060A68A98580219E36910952683892D6A5E2A80803193E407531404E36B315623799AA825074409754A2DFE8F5AFD5FE631E1FC2AF3808906F28A790D9DD9FE060939B125790C5805D037DF56A99531B96DE69DE33ED226CC1207D1042B5C9AB7F404FC711C0FE4769FB9578B1DC0EC469EA1A25E0FF9914886EF2699B235BB4847DD6FF40B606E6170793C2FB98B314587F9CFD257362DFEAB10B3BD2D97673A1A4BD44C453AAF47FC1F2D3D0F384F74A06F89C089F0DA6CDB7FCEEE8C9821A8E54F25C0416D18C46839A5F8012FBDD3DC74D256279ADC2C0D55AFF6F0622425D1B";
    bytes constant intelRootExponent = hex"010001";

    struct AttestationVerificationData {
        Suave.IASResponse iasResponse;
        string isvEnclaveQuoteBodyBase64;
        bytes isvEnclaveQuoteBodyBytes;
        bytes payload;
    }

    event AttestationVerificationEvent (
        Suave.IASResponse iasResponse,
        string isvEnclaveQuoteBodyBase64,
        bytes isvEnclaveQuoteBodyBytes,
        bytes payload
    );

    function emitAttestationVerification(AttestationVerificationData memory avd) public payable {
        emit AttestationVerificationEvent(
            avd.iasResponse,
            avd.isvEnclaveQuoteBodyBase64,
            avd.isvEnclaveQuoteBodyBytes,
            avd.payload
        );
    }

    function getAttestationVerificationReport() external returns (string memory) {
        Suave.IASResponse memory iasResponse = Suave.getAttestationVerificationReport();
        string memory isvEnclaveQuoteBodyBase64 = Base64.encode(iasResponse.body.isvEnclaveQuoteBody);
        return isvEnclaveQuoteBodyBase64;
    }

    // TODO add arguments for expected mrenclave & mrsigner
    //function example(bytes memory mrenclave, bytes memory mrsigner) external payable returns (bytes memory) {
    function example() external payable returns (bytes memory) {
        require(Suave.isConfidential());
        Suave.IASResponse memory iasResponse = Suave.getAttestationVerificationReport();
        string memory isvEnclaveQuoteBodyBase64 = Base64.encode(iasResponse.body.isvEnclaveQuoteBody);

        bytes memory payload1 = verifyRA(iasResponse);
        bytes memory payload2 = rave(iasResponse);
        assertEq(payload1, payload2);

        bytes memory expPayload = payload();
        assert(keccak256(payload1.substring(0, expPayload.length)) == keccak256(expPayload));

        AttestationVerificationData memory avd;
        avd.iasResponse = iasResponse;
        avd.isvEnclaveQuoteBodyBase64 = isvEnclaveQuoteBodyBase64;
        avd.isvEnclaveQuoteBodyBytes = iasResponse.body.isvEnclaveQuoteBody;
        avd.payload = payload2;

        testIntelCertChainFromSignedX509(iasResponse.headers);

        return abi.encodeWithSelector(this.emitAttestationVerification.selector, avd);
    }


    // test & mocks from Rave
    function verifyRA(Suave.IASResponse memory iasResponse) internal returns (bytes memory) {
        bytes memory report = report(iasResponse.body);
        bytes memory sig = iasResponse.headers.xIASReportSignature;
        bytes memory signingMod = signingMod();
        bytes memory signingExp = signingExp();
        bytes32 mrenclave = mrenclave();
        bytes32 mrsigner = mrsigner();
        bytes memory gotPayload = this.verifyRemoteAttestation(report, sig, signingMod, signingExp, mrenclave, mrsigner);
        return gotPayload;
    }

    function rave(Suave.IASResponse memory iasResponse) public view returns (bytes memory) {
        bytes memory report = report(iasResponse.body);
        bytes memory sig = iasResponse.headers.xIASReportSignature;
        bytes memory signingCert = iasResponse.headers.xIASReportSigningCertificate;

        bytes32 mrenclave = mrenclave();
        bytes32 mrsigner = mrsigner();

        bytes memory payload =
            this.rave(bytes(report), sig, signingCert, intelRootModulus, intelRootExponent, mrenclave, mrsigner);

        return payload;
    }

    function report(Suave.IASResponseBody memory iasResponseBody) internal view returns (bytes memory) {
        return abi.encode(
            iasResponseBody.id,
            iasResponseBody.timestamp,
            iasResponseBody.version,
            iasResponseBody.epidPseudonym,
            iasResponseBody.advisoryURL,
            iasResponseBody.advisoryIDs,
            iasResponseBody.isvEnclaveQuoteStatus,
            // already Base64 decoded by the precompile
            iasResponseBody.isvEnclaveQuoteBody
        );
    }

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

    // adapted from RAVE's tests
    function testIntelCertChainFromSignedX509(Suave.IASResponseHeaders memory iasResponseHeaders) public {
        bytes memory certBytes = iasResponseHeaders.xIASReportSigningCertificate;

        bytes memory expectedLeafModulus =
            hex"A97A2DE0E66EA6147C9EE745AC0162686C7192099AFC4B3F040FAD6DE093511D74E802F510D716038157DCAF84F4104BD3FED7E6B8F99C8817FD1FF5B9B864296C3D81FA8F1B729E02D21D72FFEE4CED725EFE74BEA68FBC4D4244286FCDD4BF64406A439A15BCB4CF67754489C423972B4A80DF5C2E7C5BC2DBAF2D42BB7B244F7C95BF92C75D3B33FC5410678A89589D1083DA3ACC459F2704CD99598C275E7C1878E00757E5BDB4E840226C11C0A17FF79C80B15C1DDB5AF21CC2417061FBD2A2DA819ED3B72B7EFAA3BFEBE2805C9B8AC19AA346512D484CFC81941E15F55881CC127E8F7AA12300CD5AFB5742FA1D20CB467A5BEB1C666CF76A368978B5";
        bytes memory expectedLeafExponent = hex"010001";

        (bytes memory modulus, bytes memory exponent) =
            X509Verifier.verifySignedX509(certBytes, intelRootModulus, intelRootExponent);

        // Correct the lengths since parsing may prepend an empty "0x00"
        uint256 lenGot = modulus.length;
        uint256 lenExpected = expectedLeafModulus.length;
        if (lenGot < lenExpected) {
            modulus = abi.encodePacked(new bytes(lenExpected - lenGot), modulus);
        } else if (lenExpected < lenGot) {
            expectedLeafModulus = abi.encodePacked(new bytes(lenGot - lenExpected), expectedLeafModulus);
        }

        assertEq(keccak256(modulus), keccak256(expectedLeafModulus));
    }
}
