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
RAVE function `verifyRemoteAttestation()` is called with the report data obtained from
the precompiled, which returns a hardcoded (mock) IAS response (body and headers).

The report data is from the IAS response body.

The code snippet below shows the current status:

```solidity
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

The parameters `sig`, `signingMod`, and `signingExp` can be extracted out of the headers
of the IAS response obtained from the precompiled. This has yet to be done. Currently,
some hardcoded values from RAVE's tests are used.

The `mrenclave` and `mrsigner` are values which are expected, and could be passed to the
contract entrypoint that triggers the attestation verification. Ultimately, the
`mrenclave` should be obtained from re-building the trusted software that a kettle is
expected to run.

Hence, the above code snippet should eventually look like:

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
