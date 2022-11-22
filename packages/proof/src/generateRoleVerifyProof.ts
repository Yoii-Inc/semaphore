import { Group } from "@semaphore-protocol/group"
import { Identity } from "@semaphore-protocol/identity"
import { MerkleProof } from "@zk-kit/incremental-merkle-tree"
import { groth16 } from "snarkjs"
import generateSignalHash from "./generateSignalHash"
import { BigNumberish, FullVerifyProof, SnarkArtifacts } from "./types"

export default async function generateRoleVerifyProof(
    { trapdoor, nullifier, commitment }: Identity,
    groupOrMerkleProof: Group | MerkleProof,//ちょっと変えた方が良さそう。
    role: BigNumberish,
    candidates: BigNumberish[],
    externalNullifier: BigNumberish,
    signal: string,
    snarkArtifacts?: SnarkArtifacts
): Promise<FullVerifyProof> {
    let merkleProof: MerkleProof

    //要相談項目。ロール単体で渡されることはあるのか？
    if ("depth" in groupOrMerkleProof) {
        const index = groupOrMerkleProof.indexOf(commitment)

        if (index === -1) {
            throw new Error("The identity is not part of the roles")
        }

        merkleProof = groupOrMerkleProof.generateProofOfMembership(index)
    } else {
        merkleProof = groupOrMerkleProof
    }

    //もしロール単体で渡されることがないのであれば
    //merkleProof = groupOrMerkleProof

    //ファイルパスは変更される可能性あり。
    if (!snarkArtifacts) {
        snarkArtifacts = {
            wasmFilePath: `../../snark-artifacts/verify.wasm`,
            zkeyFilePath: `../../snark-artifacts/verify.zkey`
        }
    }

    const { proof, publicVerifySignals } = await groth16.fullProve(
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
            merkleRoot: publicVerifySignals[0],
            count: publicVerifySignals[1],
            nullifierHash: publicVerifySignals[2],
            candidates: publicVerifySignals[3],
            externalNullifier: publicVerifySignals[4],
            signalHash: publicVerifySignals[5]
        }
    }
}
