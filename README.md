# poseidon2-evm-bls12-381

Based on https://github.com/zemse/poseidon2-evm

Implements the Gnark Poseidon2 compress function over BLS12-381,
with t=2, rf=8, rp=56.

## Gas costs

- Unoptimized: 15809
- Optimized: 14265
    - Skips some modular arithmetic ops
