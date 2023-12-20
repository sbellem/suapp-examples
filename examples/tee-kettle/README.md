> [!CAUTION]
> **WORK IN PROGRESS**

> [!CAUTION]
> Since `suave-geth` does not run in SGX yet, this example uses a precompile
> ([`getAttestationVerificationReport`][getAttestationVerificationReport]) that
> currently mocks the action of generating a remote attestation report.

# TEE Kettle Attestation
This example shows how Suapps can use the precompile
[`getAttestationVerificationReport`][getAttestationVerificationReport] to verify that a
kettle is running the expected software (`MRENCLAVE`) on genuine SGX hardware.

## How to use
Use docker compose.

From this directory (`./examples/tee-kettle`):

```shell
docker compose up
```

From the root of the repo:

```shell
docker compose --file examples/tee-kettle/docker-compose.yml up
```

# Current Status and Future Work
RAVE function `rave()` is called with the report (IAS response body)
obtained from the precompile, which returns a hardcoded (mock) IAS response (body and
headers). The call to `rave()` returns a public key, which eventually
will be the kettle address, but for now we are returning a hardcoded mocked value for
the purpose of testing. This public key is contained in `isvEnclaveQuoteBody` which is
part of the IAS response body which is obtained from the call to the precompile
[`getAttestationVerificationReport`][getAttestationVerificationReport].


The code snippet below may help to give context to the above explanation.

```solidity
// examples/tee-kettle/verify-attestation.sol

import { RAVE } from "rave/RAVE.sol";

contract VerifyAttestation is Test, RAVE {

    function verifyRA(Suave.IASResponse memory iasResponse) internal returns (bytes memory) {
        bytes memory report = report(iasResponse.body);
        bytes memory sig = sig();
        bytes memory signingMod = signingMod();
        bytes memory signingExp = signingExp();
        bytes32 mrenclave = mrenclave();
        bytes32 mrsigner = mrsigner();
        bytes memory gotPayload = this.verifyRemoteAttestation(report, sig, signingMod, signingExp, mrenclave, mrsigner);
        return gotPayload;
    }
```

The returned payload is logged to the terminal when running the demo with
`docker compose up`:

```shell
tee-kettle-suapp-tee-kettle-1     | attestation payload hex a4f1e2de42ade42856a6e7b029432278d76ad1c3e86ceccd6f2f46532861c20c0615a3b4f8a3e283d23c09255e51360e00000000000000000000000000000000
```

## Future Work
Generate a quote such that the report data contains the kettle address from
`framework.go` and an optional 64-byte commitment (e.g. SHA 256). Upon successful
verification, add kettle address to a contract state variable that stores kettles
that have been verified, along with their commitment hash.


[getAttestationVerificationReport]: https://github.com/sbellem/suave-geth/blob/da5f949f7e5317c9b71666ec206a5ff8beae9e6c/core/vm/contracts_suave.go#L190
