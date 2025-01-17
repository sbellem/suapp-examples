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
RAVE function `verifyRemoteAttestation()` is called with the report (IAS response body)
obtained from the precompile, which returns a hardcoded (mock) IAS response (body and
headers). The call to `verifyRemoteAttestation()` returns a public key, which eventually
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
The parameters `sig`, `signingMod`, and `signingExp` can be extracted out of the headers
of the IAS response obtained from the precompile. This has yet to be done. Currently,
some hardcoded values from RAVE's tests are used.

The `mrenclave` and `mrsigner` are values which are expected, and could be passed to the
contract entrypoint that triggers the attestation verification. Ultimately, the
`mrenclave` should be obtained from re-building the trusted software that a kettle is
expected to run.

The above code snippet should eventually look like:

```solidity
import { RAVE } from "rave/RAVE.sol";

contract VerifyAttestation is Test, RAVE {

    function verifyRA(
        Suave.IASResponse memory iasResponse,
        bytes32 memory mrenclave,
        bytes32 memory mrsigner
    ) internal returns (bytes memory) {
        bytes memory report = report(iasResponse.body);
        bytes memory sig = sig(iasResponse.headers);
        bytes memory signingMod = signingMod(iasResponse.headers);
        bytes memory signingExp = signingExp(iasResponse.headers);
        bytes memory gotPayload = this.verifyRemoteAttestation(report, sig, signingMod, signingExp, mrenclave, mrsigner);
        return gotPayload;
    }
```


[getAttestationVerificationReport]: https://github.com/sbellem/suave-geth/blob/da5f949f7e5317c9b71666ec206a5ff8beae9e6c/core/vm/contracts_suave.go#L190
