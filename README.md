```
Tests.[test arithmetical operations].TestRelinearizedStraightPolynomial(949871929L)

---context created
r( 949871929^2 + 949871929 + 4 ): should be 902256682452052974
---evaluator created
plaintext noise budget: 34
EvaluatorCurrentPlain: 949871929              ||  ciphertext size: 59.69 KB
plaintext noise budget: 13
---evaluator created
plaintext noise budget: 34
EvaluatorCurrentPlain: 902256682452052974     ||  ciphertext size: 59.69 KB
```

```
Tests.[test evaluator switcher].TestDeepPolynomial(-1692612407L)

-1692612407^2 + 3 * (-1692612407 - 2) + 4: should be 2864936755252496426
plaintext noise budget: 15
EvaluatorCurrentPlain: 2864936760330333649    ||  ciphertext size: 46.48 KB
EvaluatorCurrentPlain: -1692612407            ||  ciphertext size: 31.01 KB
plaintext noise budget: 34
EvaluatorCurrentPlain: -5077837223            ||  ciphertext size: 30.99 KB
plaintext noise budget: 15
EvaluatorCurrentPlain: 2864936755252496426    ||  ciphertext size: 46.49 KB
```

# portableSEAL [![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2FRay-Eldath%2FportableSEAL%2Fbadge%3Ftoken%3Dca034c3d3b6c6457c50a12b5816f717fa554c877%2B&style=flat-square)](https://actions-badge.atrox.dev/Ray-Eldath/portableSEAL/goto?token=ca034c3d3b6c6457c50a12b5816f717fa554c877+)

gRPC binding for [Microsoft SEAL](https://github.com/microsoft/SEAL).

Full unit-tested, see `./Tests` for these tests, one can regard them as examples.

Currently only BFV scheme is supported.