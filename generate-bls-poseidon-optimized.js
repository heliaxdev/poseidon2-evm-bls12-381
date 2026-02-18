const { writeFileSync } = require("fs");
const { ethers } = require("ethers");

// ============================================================================
// CONFIGURATION
// ============================================================================
const PRIME_STR = "0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001";
const PRIME = BigInt(PRIME_STR);
const WIDTH = 2; 
const ROUNDS_F = 8;
const ROUNDS_P = 56;
const D = 5; 

// ============================================================================
// CONSTANT GENERATOR
// ============================================================================
function generateConstants() {
    const seedStr = `Poseidon2-BLS12_381[t=${WIDTH},rF=${ROUNDS_F},rP=${ROUNDS_P},d=${D}]`;
    let currentHash = ethers.keccak256(ethers.toUtf8Bytes(seedStr));
    
    // Gnark warm-up
    currentHash = ethers.keccak256(currentHash);

    const roundKeys = [];
    const totalRounds = ROUNDS_F + ROUNDS_P;
    const rfHalf = ROUNDS_F / 2;

    const nextConst = () => {
        const val = BigInt(currentHash);
        const res = val % PRIME;
        currentHash = ethers.keccak256(currentHash);
        return "0x" + res.toString(16);
    };

    for (let i = 0; i < rfHalf; i++) {
        const row = [];
        for (let j = 0; j < WIDTH; j++) row.push(nextConst());
        roundKeys.push(row);
    }
    for (let i = rfHalf; i < rfHalf + ROUNDS_P; i++) {
        roundKeys.push([nextConst()]);
    }
    for (let i = rfHalf + ROUNDS_P; i < totalRounds; i++) {
        const row = [];
        for (let j = 0; j < WIDTH; j++) row.push(nextConst());
        roundKeys.push(row);
    }
    return roundKeys;
}

// ============================================================================
// OPTIMIZED YUL GENERATOR
// ============================================================================

const round_constants = generateConstants();

function yul_generate_library() {
  return `// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

/// @title Poseidon2 Compress (t=2) for BLS12-381 (Optimized)
library Poseidon2BLS_Optimized {
    
    uint256 constant PRIME = ${PRIME_STR};

    function compress(uint256 left, uint256 right) public pure returns (uint256 result) {
        assembly {
            // 1. Initial Cleanup
            let s0 := mod(left, PRIME)
            let s1 := mod(right, PRIME)
            let original_right := s1

            // ----------------------------------------------------------------
            // ROUNDS
            // ----------------------------------------------------------------

            ${poseidon2_rounds()}
            
            // ----------------------------------------------------------------
            // OUTPUT
            // ----------------------------------------------------------------

            result := addmod(s1, original_right, PRIME)
        }
    }
}
`;
}

function poseidon2_rounds() {
    let code = [];
    
    // Initial Matrix Mix
    // Note: Inputs are Clean, so s0+s1 < 2P (Safe to use add)
    code.push(matMulExternal());

    const rfHalf = ROUNDS_F / 2;

    // First Half Full Rounds
    for (let r = 0; r < rfHalf; r++) {
        code.push(`// Full Round ${r}`);
        code.push(addRoundKeyFull(r)); // Output: Dirty
        code.push(sBoxFull());         // Input: Dirty, Output: Clean
        code.push(matMulExternal());   // Input: Clean
    }

    // Partial Rounds
    for (let r = rfHalf; r < rfHalf + ROUNDS_P; r++) {
        code.push(`// Partial Round ${r}`);
        code.push(addRoundKeyPartial(r)); // Output: s0 Dirty, s1 Clean
        code.push(sBoxSingle("s0"));      // Cleans s0
        code.push(matMulInternal());      // Input: Clean
    }

    // Second Half Full Rounds
    for (let r = rfHalf + ROUNDS_P; r < ROUNDS_F + ROUNDS_P; r++) {
        code.push(`// Full Round ${r}`);
        code.push(addRoundKeyFull(r));
        code.push(sBoxFull());
        code.push(matMulExternal());
    }

    return code.join("\n            ");
}

// --- OPTIMIZED ARITHMETIC ---

// Optimization: Use `add` instead of `addmod`. 
// Safe because s0 (Clean) + k (Clean) < 2*PRIME < 2^256
function addRoundKeyFull(round) {
    const rc = round_constants[round];
    return `
            s0 := add(s0, ${rc[0]})
            s1 := add(s1, ${rc[1]})`;
}

function addRoundKeyPartial(round) {
    const rc = round_constants[round];
    return `
            s0 := add(s0, ${rc[0]})`;
}

// SBox cleans the state (mulmod output is always < PRIME)
function sBoxFull() {
    return `
            ${sBoxSingle("s0")}
            ${sBoxSingle("s1")}`;
}

function sBoxSingle(stateVar) {
    return `
            {
                let sq := mulmod(${stateVar}, ${stateVar}, PRIME)
                let quad := mulmod(sq, sq, PRIME)
                ${stateVar} := mulmod(quad, ${stateVar}, PRIME)
            }`;
}

// Optimization: Use `add` for the sum.
// Safe because inputs are Clean: s0 + s1 < 2*PRIME < 2^256
function matMulExternal() {
    return `
            {
                let sum := add(s0, s1)
                s0 := addmod(s0, sum, PRIME)
                s1 := addmod(s1, sum, PRIME)
            }`;
}

// Optimization: Use `add` for sums and doubling.
// s0, s1 Clean. 
// sum < 2P (Safe)
// s1_double < 2P (Safe)
// addmod handles dirty inputs correctly.
function matMulInternal() {
    return `
            {
                let sum := add(s0, s1)
                s0 := addmod(s0, sum, PRIME)
                
                let s1_double := add(s1, s1)
                s1 := addmod(s1_double, sum, PRIME)
            }`;
}

console.log("Generating Optimized Poseidon2 BLS12-381...");
const output = yul_generate_library();
writeFileSync("Poseidon2BLS_Optimized.sol", output);
console.log("Done.");