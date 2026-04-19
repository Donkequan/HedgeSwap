# HedgeSwap: Universal Hedged Atomic Swaps Against Griefing Attacks

This repository contains implementations of the cryptographic primitives and smart contracts used in the HedgeSwap experiments, as well as the full version of the HedgeSwap paper.

## Repository Structure

- `SIG_AS`: ECDSA-based and Schnorr-based signatures, and adaptor signature implementations, including 2PC.
- `VTD`: Verifiable timed dlog implementation. 
- `Contract`: Contract-based solution and MIMO contract used in the experiments.
- `HedgeSwap`: Full version of the HedgeSwap paper.

## Full version

The full version of the HedgeSwap paper is provided in [HedgeSwap_Full_Version.pdf](./HedgeSwap_Full_Version.pdf).

## Prerequisites

Install crypto dependencies (Ubuntu):

```bash
sudo apt-get install -y build-essential pkg-config libssl-dev libgmp-dev
```

Verifiable timed dlog tests require the
[Pairing-Based Cryptography (PBC)](https://crypto.stanford.edu/pbc/) library.


## Running the tests

### 1. Signature and adaptor signature test

- `make run-ecdsa` — ECDSA-based results.
- `make run-schnorr` — Schnorr-based results.

### 2. Verifiable timed dlog

```bash
make run-vtd
```

