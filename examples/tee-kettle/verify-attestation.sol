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
    bytes constant leafModulus = hex"a97a2de0e66ea6147c9ee745ac0162686c7192099afc4b3f040fad6de093511d74e802f510d716038157dcaf84f4104bd3fed7e6b8f99c8817fd1ff5b9b864296c3d81fa8f1b729e02d21d72ffee4ced725efe74bea68fbc4d4244286fcdd4bf64406a439a15bcb4cf67754489c423972b4a80df5c2e7c5bc2dbaf2d42bb7b244f7c95bf92c75d3b33fc5410678a89589d1083da3acc459f2704cd99598c275e7c1878e00757e5bdb4e840226c11c0a17ff79c80b15c1ddb5af21cc2417061fbd2a2da819ed3b72b7efaa3bfebe2805c9b8ac19aa346512d484cfc81941e15f55881cc127e8f7aa12300cd5afb5742fa1d20cb467a5beb1c666cf76a368978b5";
    bytes constant leafExponent = hex"010001";

    struct AttestationVerificationData {
        bytes32 mrenclave;
        bytes32 mrsigner;
        bytes payload;
    }

    // TODO
    // mrenclave and mrsigner are redundant as they are passed by the client
    // instead, it may be more useful to make the IAS report data available in an
    // event log -- also perhaps, it could be useful to also provide the IAS headers
    // so that one can verify the IAS report offchain as some kind of sanity check (?)
        //Suave.IASResponse iasResponse,
    event AttestationVerificationEvent (
        bytes32 mrenclave,
        bytes32 mrsigner,
        bytes payload
    );

    function emitAttestationVerification(AttestationVerificationData memory avd) public payable {
        emit AttestationVerificationEvent(
            //avd.iasResponse,
            avd.mrenclave,
            avd.mrsigner,
            avd.payload
        );
    }

    function verifyTeeKettle(
        bytes32 mrenclave,
        bytes32 mrsigner,
        bytes memory expectedPayload
    ) external payable returns (bytes memory) {
        // Is this necessary?
        //require(Suave.isConfidential());

        Suave.IASResponse memory iasResponse = Suave.getAttestationVerificationReport();

        // TODO: move this in separate function
        //bytes memory payload1 = verifyRA(iasResponse, mrenclave, mrsigner);

        bytes memory report = _report(iasResponse.body);
        bytes memory sig = iasResponse.headers.xIASReportSignature;
        bytes memory signingCert = iasResponse.headers.xIASReportSigningCertificate;

        // is bytes(report) necessary? it's already bytes _report() returns bytes
        bytes memory payload = this.rave(
            bytes(report),
            sig,
            signingCert,
            intelRootModulus,
            intelRootExponent,
            mrenclave,
            mrsigner
        );

        assert(keccak256(payload.substring(0, expectedPayload.length)) == keccak256(expectedPayload));

        // instantiateevent
        AttestationVerificationData memory avd;
        //avd.iasResponse = iasResponse;
        //avd.isvEnclaveQuoteBodyBase64 = Base64.encode(iasResponse.body.isvEnclaveQuoteBody);
        //avd.isvEnclaveQuoteBodyBytes = iasResponse.body.isvEnclaveQuoteBody;
        avd.mrenclave = mrenclave;
        avd.mrsigner = mrsigner;
        avd.payload = payload;

        // TODO: move this in a separate (test) function
        //testIntelCertChainFromSignedX509(iasResponse.headers);

        return abi.encodeWithSelector(this.emitAttestationVerification.selector, avd);
    }

    function _report(Suave.IASResponseBody memory iasResponseBody) internal view returns (bytes memory) {
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

    function getAttestationVerificationReport() external returns (string memory) {
        Suave.IASResponse memory iasResponse = Suave.getAttestationVerificationReport();
        string memory isvEnclaveQuoteBodyBase64 = Base64.encode(iasResponse.body.isvEnclaveQuoteBody);
        return isvEnclaveQuoteBodyBase64;
    }


    // adapted from RAVE's tests
    function rave(
        Suave.IASResponse memory iasResponse,
        bytes32 mrenclave,
        bytes32 mrsigner
    ) public view returns (bytes memory) {
        bytes memory report = _report(iasResponse.body);
        bytes memory sig = iasResponse.headers.xIASReportSignature;
        bytes memory signingCert = iasResponse.headers.xIASReportSigningCertificate;
        bytes memory payload =
            this.rave(bytes(report), sig, signingCert, intelRootModulus, intelRootExponent, mrenclave, mrsigner);

        return payload;
    }

    function verifyRA(
        Suave.IASResponse memory iasResponse,
        bytes32 mrenclave,
        bytes32 mrsigner
    ) internal returns (bytes memory) {
        bytes memory report = _report(iasResponse.body);
        bytes memory sig = iasResponse.headers.xIASReportSignature;
        bytes memory gotPayload = this.verifyRemoteAttestation(
            report,
            sig,
            leafModulus,
            leafExponent,
            mrenclave,
            mrsigner
        );
        return gotPayload;
    }

    function testIntelCertChainFromSignedX509(Suave.IASResponseHeaders memory iasResponseHeaders) public {
        bytes memory certBytes = iasResponseHeaders.xIASReportSigningCertificate;

        (bytes memory modulus, bytes memory exponent) =
            X509Verifier.verifySignedX509(certBytes, intelRootModulus, intelRootExponent);

        // Correct the lengths since parsing may prepend an empty "0x00"
        uint256 lenGot = modulus.length;
        uint256 lenExpected = leafModulus.length;

        bytes memory expectedLeafModulus = leafModulus;
        if (lenGot < lenExpected) {
            modulus = abi.encodePacked(new bytes(lenExpected - lenGot), modulus);
        } else if (lenExpected < lenGot) {
            expectedLeafModulus = abi.encodePacked(new bytes(lenGot - lenExpected), leafModulus);
        }

        assertEq(keccak256(modulus), keccak256(expectedLeafModulus));
    }
}
