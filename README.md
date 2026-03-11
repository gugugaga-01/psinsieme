# multiparty-psi-protocols-experimental

Experimental implementations of multi-party Private Set Intersection (PSI) protocols for research and evaluation.

## Protocols

| Directory | Protocol | Reference |
|-----------|----------|-----------|
| `experiments/ks05_crypto_t-mpsi` | Threshold MPSI | Kissner & Song, CRYPTO 2005 [[doi]](https://doi.org/10.1007/11535218_15) |
| `experiments/beh21_tifs_t-mpsi` | Threshold MPSI | Bay, Erkin, Hoepman, Samardjiska & Vos, IEEE TIFS 2021 [[doi]](https://doi.org/10.1109/TIFS.2021.3118879) |
| `experiments/yyh26_ndss_tt-mpsi` | T-Threshold MPSI | TBD, NDSS 2026 |

## Structure

```
multiparty-psi-protocols-experimental/
├── experiments/          # Academic reference implementations (plaintext TCP)
│   ├── ks05_crypto_t-mpsi/
│   ├── beh21_tifs_t-mpsi/
│   └── yyh26_ndss_tt-mpsi/
└── service/              # gRPC service framework (mTLS, dealer, Python client)
    ├── proto/            # Protobuf definitions
    ├── core/             # Shared transport layer
    ├── ks05_t_mpsi/     # KS05 protocol implementation
    ├── psi_service/      # Client-facing gRPC service (psi_party binary)
    ├── dealer/           # Key dealer service (psi_dealer binary)
    ├── clients/python/   # Python client SDK
    ├── demos/            # End-to-end demo scripts
    ├── certs/            # mTLS certificate generation
    └── tests/            # Integration and unit tests
```

See [service/README.md](service/README.md) for build instructions, usage guide, and API reference.

## Disclaimer

This repository contains experimental implementations for research and evaluation purposes.
