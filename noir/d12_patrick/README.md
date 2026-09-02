# Patrick Experiment

This experiment is based on [d10_swiyu_jwt](../d10_swiyu_jwt) after
a very interesting discussion with Patrick Amrein from Ubique.
It verifies that the SD-JWT-payload contains the required strings
to mark it as a valid Swiyu JWT:

```json
  "vct": "betaid-sdjwt",
  "_sd_alg": "sha-256",
  "iss": "did:tdw:QmPEZPhDFR4nEYSFK5bMnvECqdpf1tPTPJuWs9QrMjCumw:identifier-reg.trust-infra.swiyu-int.admin.ch:api:v1:did:9a5559f0-b81c-4368-a170-e7b4ae424527",
```

It is implemented as a single string verification.
Comparing it to the runtime of d10_swiyu_jwt shows no visible change in runtime
and only a small increase in circuit size.
