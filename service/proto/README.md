# Protobuf Definitions

gRPC service and message definitions for the MPSI service.

## Proto Files

| File | Purpose |
|------|---------|
| `common.proto` | Shared message types (elements, status codes) |
| `psi_service.proto` | Client-facing API (`ComputeIntersection` RPC) |
| `ks05_party.proto` | Inter-party KS05 protocol RPCs (polynomial exchange, partial decryption) |
| `dealer.proto` | Key distribution RPCs (Paillier threshold key shares) |

## Code Generation

C++ stubs are generated automatically by CMake during the build — no manual steps needed.

For Python client stubs:

```bash
cd service/clients/python
bash gen_proto.sh
```
