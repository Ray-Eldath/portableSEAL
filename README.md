```
Tests.[test arithmetical operations, relinearize and straight polynomial computation].TestRelinearizedStraightPolynomial(-1654895613L)

---context created
r( -1654895613^2 + -1654895613 + 4 ): should be 2738679488271750160
---evaluator created
[74 ms] plaintext noise budget: 34
EvaluatorCurrentPlain: -1654895613            ||  ciphertext size: 59.66 KB
[85 ms] plaintext noise budget: 12
---evaluator created
[100ms] after r:
plaintext noise budget: 34
EvaluatorCurrentPlain: 2738679488271750160    ||  ciphertext size: 59.67 KB
```

```
Tests.[test evaluator switcher with a deep polynomial].TestDeepPolynomial(1645301092L)

1645301092^2 + 3 * (1645301092 - 2) + 4: should be 2707015688272295738
[7  ms] 0 squared:
plaintext noise budget: 15
EvaluatorCurrentPlain: 2707015683336392464    ||  ciphertext size: 46.46 KB
[10 ms] 1 origin:
EvaluatorCurrentPlain: 1645301092             ||  ciphertext size: 31 KB
[12 ms] 1:
plaintext noise budget: 34
EvaluatorCurrentPlain: 4935903274             ||  ciphertext size: 31 KB
[14 ms] after r:
plaintext noise budget: 15
EvaluatorCurrentPlain: 2707015688272295738    ||  ciphertext size: 46.45 KB
```

# portableSEAL [![GitHub Workflow Status](https://img.shields.io/github/workflow/status/Ray-Eldath/portableSEAL/Server%20-%20.NET%20Core?style=flat-square)](https://github.com/Ray-Eldath/portableSEAL/actions?query=workflow%3A%22Server+-+.NET+Core%22)

gRPC binding for [Microsoft SEAL](https://github.com/microsoft/SEAL).

Full unit-tested, see `./Tests` for these tests, one can regard them as examples.

Currently only BFV scheme is supported.
