import { poseidon } from "circomlibjs"
import { BigNumberish } from "./types"

/**
 * Generates a nullifier by hashing the identity nullifiers.
 * @param identityNullifier The identity nullifier.
 * @returns The nullifier hash.
 */
export default function generateRoleRegisterNullifierHash(
    identityNullifier: BigNumberish
): bigint {
    return poseidon([BigInt(identityNullifier)])
}
