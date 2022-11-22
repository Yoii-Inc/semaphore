import { groth16 } from "snarkjs"
import { FullVerifyProof } from "./types"

/**
 * Verifies a SnarkJS proof.
 * @param verificationKey The zero-knowledge verification key.
 * @param fullVerifyProof The SnarkJS full proof.
 * @returns True if the proof is valid, false otherwise.
 */
export default function verifyRoleVerifyProof(verificationKey: any, { proof, publicVerifySignals }: FullVerifyProof): Promise<boolean> {
    return groth16.verify(
        verificationKey,
        [
            publicVerifySignals.merkleRoot,
            publicVerifySignals.count,
            publicVerifySignals.nullifierHash,
            publicVerifySignals.candidates,
            publicVerifySignals.externalNullifier,
            publicVerifySignals.signalHash
        ],
        proof
    )
}
