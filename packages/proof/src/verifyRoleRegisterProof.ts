import { groth16 } from "snarkjs"
import { FullRegisterProof } from "./types"

/**
 * Verifies a SnarkJS proof.
 * @param verificationKey The zero-knowledge verification key.
 * @param fullRegisterProof The SnarkJS full proof.
 * @returns True if the proof is valid, false otherwise.
 */
export default function verifyRoleRegisterProof(verificationKey: any, { proof, publicRegisterSignals }: FullRegisterProof): Promise<boolean> {
    return groth16.verify(
        verificationKey,
        [
            publicRegisterSignals.roleCommitment,
            publicRegisterSignals.nullifierHash,
            publicRegisterSignals.candidates
        ],
        proof
    )
}
