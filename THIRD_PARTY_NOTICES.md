# Third-Party Notices

This project includes code from the following external sources.

## Directly Vendored

### MurmurHash3

- **License:** Public Domain
- **Author:** Austin Appleby
- **Source:** https://github.com/aappleby/smhasher
- **Location:** `service/protocols/beh21/third_party/smhasher/`, `experiments/beh21/third_party/smhasher/`

## Git Submodules

The following are included as git submodules and carry their own licenses and transitive dependencies.

### MultipartyPSI

- **Source:** https://github.com/osu-crypto/MultipartyPSI
- **License:** MIT
- **Location:** `experiments/yyh26/upstream/`
- **Notable transitive deps:** cryptoTools, libOTe, SHA-1 (MIT, Project Nayuki)

### libOLE

- **Source:** https://github.com/leodec/ole_wahc
- **Location:** `experiments/yyh26/libOLE/`
- **Notable transitive deps:** BLAKE2 (CC0/OpenSSL/Apache 2.0, Samuel Neves), PALISADE math (BSD 2-Clause, NJIT)
