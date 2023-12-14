**WORK IN PROGRESS**

> [!CAUTION]
> Since `suave-geth` does not run in SGX yet, this example uses a precompile
> ([`getAttestationVerificationReport()`](https://github.com/sbellem/suave-geth/blob/da5f949f7e5317c9b71666ec206a5ff8beae9e6c/core/vm/contracts_suave.go#L190)) that currently mocks the action of generating a remote
> attestation report.

# Example Suapp to verify an SGX IAS remote attestation report
This example shows how Suapps can use the precompile
`getAttestationVerificationReport()` to verify that a kettle is running the expected
software (`MRENCLAVE`) on genuine SGX hardware.

## How to use

Use docker compose from the root of the repo:

```
docker compose --file examples/remote-attestation-verification/docker-compose.yml up
```
