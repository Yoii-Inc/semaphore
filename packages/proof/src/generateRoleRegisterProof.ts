import type { Identity } from "@semaphore-protocol/identity"
import { groth16 } from "snarkjs"
import { BigNumberish, FullRegisterProof, SnarkArtifacts } from "./types"

export default async function generateRoleRegisterProof(
    { trapdoor, nullifier, commitment }: Identity,
    role: BigNumberish,
    candidates: BigNumberish[],
    snarkArtifacts?: SnarkArtifacts
): Promise<FullRegisterProof> {

    if (!snarkArtifacts) {
        snarkArtifacts = {
            wasmFilePath: `../../snark-artifacts/register.wasm`,
            zkeyFilePath: `../../snark-artifacts/register.zkey`
        }
    }

    const { proof, publicRegisterSignals } = await groth16.fullProve(
        {
            identityNullifier: nullifier,
            identityTrapdoor: trapdoor,
            role,
            candidates
        },
        snarkArtifacts.wasmFilePath,
        snarkArtifacts.zkeyFilePath
    )

    return {
        proof,
        publicRegisterSignals: {
            roleCommitment: publicRegisterSignals[0],
            nullifierHash: publicRegisterSignals[1],
            candidates: publicRegisterSignals[2]
        }
    }
}
