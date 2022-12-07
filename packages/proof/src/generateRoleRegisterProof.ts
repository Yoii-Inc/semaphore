import type { Identity } from "@semaphore-protocol/identity"
import { groth16 } from "snarkjs"
import { BigNumberish, FullRegisterProof, SnarkArtifacts } from "./types"

export default async function generateRoleRegisterProof(
    { trapdoor, nullifier }: Identity,
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

    const length = candidates.length
    if (candidates.length < 5) {
        const zero = new Array(5-length).fill(0)
        candidates = candidates.concat(zero)
    }

    const { proof, publicSignals } = await groth16.fullProve(
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
            roleCommitment: publicSignals[0],
            nullifierHash: publicSignals[1],
            candidates: publicSignals.slice(2,2+length)
        }
    }
}
