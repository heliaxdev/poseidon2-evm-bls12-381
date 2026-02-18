const { writeFileSync } = require("fs");
const { ethers } = require("ethers");

// ============================================================================
// CONFIGURATION: BLS12-381 SCALAR FIELD
// ============================================================================

const PRIME_STR = "0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001";
const PRIME = BigInt(PRIME_STR);

// Gnark Parameters for Compress (t=2)
const WIDTH = 2; 
const ROUNDS_F = 8;
const ROUNDS_P = 56;
const D = 5; 

// ============================================================================
// CONSTANT GENERATOR
// ============================================================================

function generateConstants() {
    // 1. Seed string for t=2
    // Corresponds to: fmt.Sprintf("Poseidon2-BLS12_381[t=%d,rF=%d,rP=%d,d=%d]", ...)
    const seedStr = `Poseidon2-BLS12_381[t=${WIDTH},rF=${ROUNDS_F},rP=${ROUNDS_P},d=${D}]`;
    
    // 2. Initial Hash: H(seed)
    let currentHash = ethers.keccak256(ethers.toUtf8Bytes(seedStr));

    // ========================================================================
    // CRITICAL FIX: Gnark advances the hash chain once BEFORE generating keys.
    // Go Logic:
    //    rnd := hash.Sum(nil)  <-- This is H(seed)
    //    hash.Reset(); hash.Write(rnd);
    //    rnd = hash.Sum(nil)   <-- This is H(H(seed)) (The first constant)
    // ========================================================================
    currentHash = ethers.keccak256(currentHash);

    const roundKeys = [];
    const totalRounds = ROUNDS_F + ROUNDS_P;
    const rfHalf = ROUNDS_F / 2;

    const nextConst = () => {
        // Use current hash as the constant
        const val = BigInt(currentHash);
        const res = val % PRIME;
        
        // Advance chain for the NEXT constant
        currentHash = ethers.keccak256(currentHash);
        
        return "0x" + res.toString(16);
    };

    // 3. Generate Keys
    // First half full rounds
    for (let i = 0; i < rfHalf; i++) {
        const row = [];
        for (let j = 0; j < WIDTH; j++) row.push(nextConst());
        roundKeys.push(row);
    }
    
    // Partial rounds
    for (let i = rfHalf; i < rfHalf + ROUNDS_P; i++) {
        roundKeys.push([nextConst()]);
    }

    // Second half full rounds
    for (let i = rfHalf + ROUNDS_P; i < totalRounds; i++) {
        const row = [];
        for (let j = 0; j < WIDTH; j++) row.push(nextConst());
        roundKeys.push(row);
    }

    return roundKeys;
}

// ============================================================================
// YUL GENERATOR
// ============================================================================

const round_constants = generateConstants();

function yul_generate_library() {
  return `// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

/// @title Poseidon2 Compress (t=2) for BLS12-381
/// @notice Implements the Gnark-Crypto Poseidon2 Compress function
library Poseidon2BLS_Compress {
    
    uint256 constant PRIME = ${PRIME_STR};

    /// @notice Matches the logic of func (h *Permutation) Compress(left, right)
    /// @dev Permutation(left, right) -> (newLeft, newRight); return newRight + right
    function compress(uint256 left, uint256 right) public pure returns (uint256 result) {
        assembly {
            // Ensure inputs are valid field elements
            let s0 := mod(left, PRIME)
            let s1 := mod(right, PRIME)

            // Save original right for the feed-forward step later
            let original_right := s1

            // ----------------------------------------------------------------
            // PERMUTATION START
            // ----------------------------------------------------------------

            ${poseidon2_rounds()}
            
            // ----------------------------------------------------------------
            // PERMUTATION END
            // ----------------------------------------------------------------

            // Compress Output Logic: h.api.Add(vars[1], right)
            result := addmod(s1, original_right, PRIME)
        }
    }
}
`;
}

function poseidon2_rounds() {
    let code = [];
    
    // 1. Initial Matrix Mix (External)
    code.push(`// Initial Matrix Mix`);
    code.push(matMulExternal());

    const rfHalf = ROUNDS_F / 2;

    // 2. First Half Full Rounds
    for (let r = 0; r < rfHalf; r++) {
        code.push(`// Full Round ${r}`);
        code.push(addRoundKeyFull(r));
        code.push(sBoxFull());
        code.push(matMulExternal());
    }

    // 3. Partial Rounds
    for (let r = rfHalf; r < rfHalf + ROUNDS_P; r++) {
        code.push(`// Partial Round ${r}`);
        code.push(addRoundKeyPartial(r));
        code.push(sBoxSingle("s0"));
        code.push(matMulInternal());
    }

    // 4. Second Half Full Rounds
    for (let r = rfHalf + ROUNDS_P; r < ROUNDS_F + ROUNDS_P; r++) {
        code.push(`// Full Round ${r}`);
        code.push(addRoundKeyFull(r));
        code.push(sBoxFull());
        code.push(matMulExternal());
    }

    return code.join("\n            ");
}

// --- Arithmetic Helpers (WIDTH = 2) ---

function addRoundKeyFull(round) {
    const rc = round_constants[round];
    return `
            s0 := addmod(s0, ${rc[0]}, PRIME)
            s1 := addmod(s1, ${rc[1]}, PRIME)`;
}

function addRoundKeyPartial(round) {
    const rc = round_constants[round];
    return `
            s0 := addmod(s0, ${rc[0]}, PRIME)`;
}

function sBoxFull() {
    return `
            ${sBoxSingle("s0")}
            ${sBoxSingle("s1")}`;
}

function sBoxSingle(stateVar) {
    return `
            // ${stateVar} = ${stateVar}^5
            {
                let sq := mulmod(${stateVar}, ${stateVar}, PRIME)
                let quad := mulmod(sq, sq, PRIME)
                ${stateVar} := mulmod(quad, ${stateVar}, PRIME)
            }`;
}

// Matrix for t=2 External: [[2, 1], [1, 2]]
// Logic: tmp = s0+s1; s0 += tmp; s1 += tmp;
function matMulExternal() {
    return `
            {
                // matMulExternal (Gnark T=2)
                let sum := addmod(s0, s1, PRIME)
                s0 := addmod(s0, sum, PRIME)
                s1 := addmod(s1, sum, PRIME)
            }`;
}

// Matrix for t=2 Internal: [[2, 1], [1, 3]]
// Logic: sum = s0+s1; s0 += sum; s1 = 2*s1 + sum
function matMulInternal() {
    return `
            {
                // matMulInternal (Gnark T=2)
                let sum := addmod(s0, s1, PRIME)
                s0 := addmod(s0, sum, PRIME)
                
                let s1_double := addmod(s1, s1, PRIME)
                s1 := addmod(s1_double, sum, PRIME)
            }`;
}

// Execution
console.log("Generating Poseidon2 BLS12-381 Compress (Width=2)...");
const output = yul_generate_library();
writeFileSync("Poseidon2BLS_Compress.sol", output);
console.log("Done! Written to Poseidon2BLS_Compress.sol");