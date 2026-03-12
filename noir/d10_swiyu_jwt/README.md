## Experiment Background

This experiment runs on an SD-JWT object that was obtained from the 
Swiyu E-ID demo issuer. `./data/credential-sdjwt.txt` 

However, in order to do our device binding experiment, we needed to modify
the CNF claim, and add our own public key there.
The result is `./data/sdjwt-payload.json`

Then it got signed using the tools in 
https://github.com/eid-privacy/noir-experiments/tree/main/circuits/tools,
as described in 
https://github.com/eid-privacy/noir-experiments/blob/main/circuits/jwt-swiyu/experiment50/README.md

The output is then used in the `Prover.toml`.
