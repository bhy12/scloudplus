# Scloud⁺: Lattice-Based KEM with Optimized First-Order Arithmetic Masking

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)](https://www.gnu.org/software/libc/)

This repository contains an optimized C implementation of the **Scloud⁺** post-quantum Key Encapsulation Mechanism (KEM) and Public Key Encryption (PKE) scheme, featuring high-performance **first-order arithmetic masking** countermeasures against side-channel attacks (SCA).

## 🌟 Key Features

- **Full Parameter Support**: Implements 128-bit, 192-bit, and 256-bit NIST security levels.
- **SCA Countermeasures**: First-order arithmetic masking for KeyGen and Decapsulation to protect the long-term ternary secret matrix $S$.
- **Advanced Optimizations**: Reduces masking overhead from ~1.75× to as low as **1.03×** using:
  1. **Unmasked FO Re-encryption**: Exploiting the ephemeral nature of secrets in the Fujisaki-Okamoto transform.
  2. **Fused Two-Share Matrix Multiplication**: Single-pass AES-CTR expansion for shared secrets.
  3. **Unmasked Encapsulation**: Avoiding redundant protection for one-time ephemeral secrets.
- **Architectural Awareness**: Specifically designed to thwart two-phase CPA attacks targeting 32-bit AHB-Lite bus leakage on ARM Cortex-M4.
- **Cross-Platform**: Supports MSYS2/MinGW-64 (Windows) and Linux with AES-NI acceleration.

## 🛠 Project Structure

```text
scloudplus/
├── src/
│   ├── kem.c/h          # KEM API (Standard & Masked)
│   ├── pke.c/h          # PKE Primitive (Standard & Masked)
│   ├── sample.c/h       # Masked sampling and fused matrix operations
│   ├── ds_benchmark.h   # High-precision cycle counting (rdtsc)
│   ├── test.c           # Correctness and performance benchmarks
│   └── Makefile         # Build configurations for 128/192/256 levels
└── README.md
```

## 🚀 Getting Started

### Prerequisites

- **Compiler**: `gcc` with support for `-mavx2` and `-maes` (AES-NI).
- **Environment**: MSYS2 (MinGW64) on Windows or standard GCC on Linux.
- **Libraries**: OpenSSL (`libcrypto`) for SHAKE/SHA3 implementations.

### Building and Running

You can build the project for different security levels. For example, for the 128-bit level:

```bash
# Build Scloud+ 128-bit level
make scloudplus128_aes

# Run correctness tests and benchmarks
./scloudplus128_aes.exe
```

For other levels:
- `make scloudplus192_aes`
- `make scloudplus256_aes`

## 📊 Performance Benchmarks

Performance is measured as the **median cycle count over 1,000 independent runs** on an x86-64 CPU (AES-NI enabled).

| Security Level | Operation | Standard (10³ cyc) | Masked (10³ cyc) | Overhead |
| :--- | :--- | :--- | :--- | :--- |
| **KEM-128** | Encaps + Decaps | 1,228 | 1,297 | **1.06×** |
| **KEM-192** | Encaps + Decaps | 2,605 | 2,692 | **1.03×** |
| **KEM-256** | Encaps + Decaps | 3,954 | 4,252 | **1.08×** |

*Note: Encapsulation overhead is near 0% due to the optimized FO-transform logic.*

## 🛡 Security Analysis

The implementation addresses two primary side-channel leakage sources identified in ARM Cortex-M4 implementations:
1. **Phase 1 (Bus-level HD)**: Consecutive `ldrh` instructions causing Hamming Distance leakage on the data bus. Masking decorrelates the bus transitions from the ternary alphabet.
2. **Phase 2 (Instruction-level HW)**: Write-back Hamming Weight leakage during `strh`. Share refreshing with fresh randomness $\beta$ for every decryption breaks the trace-to-trace alignment.

## 📜 Acknowledgments

The matrix multiplication and sampling logic are inspired by the [FrodoKEM](https://frodokem.org/) implementation. Hash functions use the FIPS202 (SHA-3) implementation.

## ⚖ License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
