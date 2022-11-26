import { Group } from "@semaphore-protocol/group"
import { Identity } from "@semaphore-protocol/identity"
import { MerkleProof } from "@zk-kit/incremental-merkle-tree"
import { groth16 } from "snarkjs"
import generateSignalHash from "./generateSignalHash"
import { BigNumberish, FullVerifyProof, SnarkArtifacts } from "./types"

export default async function generateRoleVerifyProof(
    { trapdoor, nullifier, commitment }: Identity,
    groupOrMerkleProof: Group | MerkleProof,
    role: BigNumberish,
    candidates: BigNumberish[],
    externalNullifier: BigNumberish,
    signal: string,
    snarkArtifacts?: SnarkArtifacts
): Promise<FullVerifyProof> {
    let merkleProof: MerkleProof

    if ("depth" in groupOrMerkleProof) {
        const index = groupOrMerkleProof.indexOf(commitment)

        if (index === -1) {
            throw new Error("The identity is not part of the roles")
        }

        merkleProof = groupOrMerkleProof.generateProofOfMembership(index)
    } else {
        merkleProof = groupOrMerkleProof
    }

    if (!snarkArtifacts) {
        snarkArtifacts = {
            wasmFilePath: `../../snark-artifacts/verify.wasm`,
            zkeyFilePath: `../../snark-artifacts/verify.zkey`
        }
    }

    const { proof, publicSignals } = await groth16.fullProve(
        {
            identityNullifier: nullifier,
            identityTrapdoor: trapdoor,
            externalNullifier,
            signalHash: generateSignalHash(signal),
            treePathIndices: merkleProof.pathIndices,
            treeSiblings: merkleProof.siblings,
            role: role,
            candidates: candidates
        },
        snarkArtifacts.wasmFilePath,
        snarkArtifacts.zkeyFilePath
    )

    return {
        proof,
        publicVerifySignals: {
            merkleRoot: publicSignals[0],
            count: publicSignals[1],
            nullifierHash: publicSignals[2],
            candidates: publicSignals[5],
            externalNullifier: publicSignals[3],
            signalHash: publicSignals[4]
        }
    }
}
