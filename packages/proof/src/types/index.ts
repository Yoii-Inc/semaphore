export type BigNumberish = string | bigint

export type SnarkArtifacts = {
    wasmFilePath: string
    zkeyFilePath: string
}

export type Proof = {
    pi_a: BigNumberish[]
    pi_b: BigNumberish[][]
    pi_c: BigNumberish[]
    protocol: string
    curve: string
}

export type FullProof = {
    proof: Proof
    publicSignals: PublicSignals
}

export type FullRegisterProof = {
    proof: Proof
    publicRegisterSignals: PublicRegisterSignals
}

export type FullVerifyProof = {
    proof: Proof
    publicVerifySignals: PublicVerifySignals
}

export type PublicSignals = {
    merkleRoot: BigNumberish
    nullifierHash: BigNumberish
    signalHash: BigNumberish
    externalNullifier: BigNumberish
}

export type PublicRegisterSignals = {
    roleCommitment: BigNumberish
    nullifierHash: BigNumberish
    candidates: BigNumberish
}

export type PublicVerifySignals = {
    merkleRoot: BigNumberish
    count: BigNumberish
    nullifierHash: BigNumberish
    candidates: BigNumberish[]//?
    externalNullifier: BigNumberish
    signalHash: BigNumberish
}

export type SolidityProof = [
    BigNumberish,
    BigNumberish,
    BigNumberish,
    BigNumberish,
    BigNumberish,
    BigNumberish,
    BigNumberish,
    BigNumberish
]
