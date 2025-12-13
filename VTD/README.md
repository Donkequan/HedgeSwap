## VTD Build & Test Guide

This project contains the C implementation of Verifiable Timed Dlog (VTD). 

## 1. Prerequisites

Install the toolchain and crypto libraries on Ubuntu:

```bash
sudo apt-get install -y build-essential libgmp-dev libssl-dev
```

The implementation depends on the [Pairing-Based Cryptography (PBC)](https://crypto.stanford.edu/pbc/) library. Please install PBC following the official documentation on the project website.

## 2. Build the dependency libraries

TVTD depends on two auxiliary projects, `range-proof` and `time-puzzles`, which provide the static libraries `liblrp.a` and `liblhp.a`, respectively.
Compile these libraries as follows:

```bash
make -C range-proof
make -C time-puzzles
```
After a successful build, the archives will be available under each project’s `lib/` directory.

## 3. Prepare the VTD build tree

Next, configure the VTD build tree so that the main Makefile can locate the precompiled libraries.
From the root of the repository:

```bash
cd TVTD
mkdir -p build lib
cp ../range-proof/lib/liblrp.a lib/
cp ../time-puzzles/lib/liblhp.a lib/
```

## 4. Run the VTD tests

The TVTD reference implementation now hardcodes the threshold number to `1`, so
there is no longer a `THRESHOLD_NUM` flag to tweak at build time.

```bash
make test EXT_LIBS='-lvtd -llrp -llhp -lgmp -lpbc -lssl -lcrypto'
```

**Sample output**

```
-----------------------------
Running timecode Test (threshold = 1)
-----------------------------
Time taken for Init: [36549] microseconds or [0.037] seconds 
Init test: Passed
Time taken for TCommit: [491556] microseconds or [0.492] seconds 
TCommit test: Passed
Time taken for Verfiy: [274060] microseconds or [0.274] seconds 
Verify test: Passed
Recovered Secret: 1234
Force Open test: Passed
Clean test: Passed
=============================
```
