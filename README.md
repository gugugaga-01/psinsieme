# multiparty-psi-protocols-experimental

Experimental implementations of multi-party Private Set Intersection (PSI) protocols for research and evaluation.

## Protocols

| Directory | Protocol | Reference |
|-----------|----------|-----------|
| `experiments/ks05_crypto_ot-mpsi` | Over-Threshold MPSI | Kissner & Song, CRYPTO 2005 [[doi]](https://doi.org/10.1007/11535218_15) |
| `experiments/beh21_tifs_t-mpsi` | Threshold MPSI | Bay, Erkin, Hoepman, Samardjiska & Vos, IEEE TIFS 2021 [[doi]](https://doi.org/10.1109/TIFS.2021.3118879) |
| `experiments/yyh26_ndss_tt-mpsi` | T-Threshold MPSI | TBD, NDSS 2026 |

## Structure

```
multiparty-psi-protocols-experimental/
├── experiments/
│   ├── ks05_crypto_ot-mpsi/
│   ├── beh21_tifs_t-mpsi/
│   └── yyh26_ndss_tt-mpsi/
└── README.md
```

## Disclaimer

This repository contains experimental code for academic research purposes. Implementations may not be optimized for production use.
