# FPKI
## Yongzhe Xu

## Features

- Issuance and logging of RPC
- Issuance of SPT using RPC
- Verification of RPC using SPT
- Consistency verification of the log

## Dir structure
 .
    ├── cert                    # Certificate for testing. Ex. certificate for PCA
    ├── cmd                     # Executables
    ├── config                  # Configure files for log server and PCA
    ├── cmd                     # Executables
    │   ├── benchmarks          # Load and stress tests
    │   ├── integration         # End-to-end, integration tests (alternatively `e2e`)
    │   └── unit                # Unit tests
    └── ...