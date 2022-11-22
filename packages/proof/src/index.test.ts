import { formatBytes32String } from "@ethersproject/strings"
import { Group } from "@semaphore-protocol/group"
import { Identity } from "@semaphore-protocol/identity"
import { getCurveFromName } from "ffjavascript"
import fs from "fs"
import generateNullifierHash from "./generateNullifierHash"
import generateRoleRegisterNullifierHash from "./generateRoleRegisterNullifierHash"
import generateProof from "./generateProof"
import generateRoleRegisterProof from "./generateRoleRegisterProof"
import generateRoleVerifyProof from "./generateRoleVerifyProof"
import generateSignalHash from "./generateSignalHash"
import packToSolidityProof from "./packToSolidityProof"
import { FullProof, FullVerifyProof, FullRegisterProof } from "./types"
import verifyProof from "./verifyProof"
import verifyRoleRegisterProof from "./verifyRoleRegisterProof"
import verifyRoleVerifyProof from "./verifyRoleVerifyProof"

describe("Proof", () => {
    const treeDepth = Number(process.env.TREE_DEPTH) || 20

    const externalNullifier = "1"
    const signal = "0x111"

    const wasmFilePath = `./snark-artifacts/semaphore.wasm`
    const zkeyFilePath = `./snark-artifacts/semaphore.zkey`
    const verificationKeyPath = `./snark-artifacts/semaphore.json`

    const roleRegisterWasmFilePath = `./snark-artifacts/register.wasm`
    const roleRegisterZkeyFilePath = `./snark-artifacts/register.zkey`

    const roleVerifyWasmFilePath = `./snark-artifacts/verify.wasm`
    const roleVerifyZkeyFilePath = `./snark-artifacts/verify.zkey`

    const identity = new Identity()

    let fullProof: FullProof
    let fullRegisterProof: FullRegisterProof
    let fullVerifyProof: FullVerifyProof
    let curve: any

    beforeAll(async () => {
        curve = await getCurveFromName("bn128")
    })

    afterAll(async () => {
        await curve.terminate()
    })

    describe("# generateProof", () => {
        it("Should not generate Semaphore proofs if the identity is not part of the group", async () => {
            const group = new Group(treeDepth)

            group.addMembers([BigInt(1), BigInt(2)])

            const fun = () =>
                generateProof(identity, group, externalNullifier, signal, {
                    wasmFilePath,
                    zkeyFilePath
                })

            await expect(fun).rejects.toThrow("The identity is not part of the group")
        })

        it("Should not generate a Semaphore proof with default snark artifacts with Node.js", async () => {
            const group = new Group(treeDepth)

            group.addMembers([BigInt(1), BigInt(2), identity.commitment])

            const fun = () => generateProof(identity, group, externalNullifier, signal)

            await expect(fun).rejects.toThrow("ENOENT: no such file or directory")
        })

        it("Should generate a Semaphore proof passing a group as parameter", async () => {
            const group = new Group(treeDepth)

            group.addMembers([BigInt(1), BigInt(2), identity.commitment])

            fullProof = await generateProof(identity, group, externalNullifier, signal, {
                wasmFilePath,
                zkeyFilePath
            })

            expect(typeof fullProof).toBe("object")
            expect(fullProof.publicSignals.externalNullifier).toBe(externalNullifier)
            expect(fullProof.publicSignals.merkleRoot).toBe(group.root.toString())
        }, 20000)

        it("Should generate a Semaphore proof passing a Merkle proof as parametr", async () => {
            const group = new Group(treeDepth)

            group.addMembers([BigInt(1), BigInt(2), identity.commitment])

            fullProof = await generateProof(identity, group.generateProofOfMembership(2), externalNullifier, signal, {
                wasmFilePath,
                zkeyFilePath
            })

            expect(typeof fullProof).toBe("object")
            expect(fullProof.publicSignals.externalNullifier).toBe(externalNullifier)
            expect(fullProof.publicSignals.merkleRoot).toBe(group.root.toString())
        }, 20000)
    })

    describe("# generateSignalHash", () => {
        it("Should generate a valid signal hash", async () => {
            const signalHash = generateSignalHash(signal)

            expect(signalHash.toString()).toBe(fullProof.publicSignals.signalHash)
        })

        it("Should generate a valid signal hash by passing a valid hex string", async () => {
            const signalHash = generateSignalHash(formatBytes32String(signal))

            expect(signalHash.toString()).toBe(fullProof.publicSignals.signalHash)
        })
    })

    describe("# generateNullifierHash", () => {
        it("Should generate a valid nullifier hash", async () => {
            const nullifierHash = generateNullifierHash(externalNullifier, identity.getNullifier())

            expect(nullifierHash.toString()).toBe(fullProof.publicSignals.nullifierHash)
        })
    })

    describe("# packToSolidityProof", () => {
        it("Should return a Solidity proof", async () => {
            const solidityProof = packToSolidityProof(fullProof.proof)

            expect(solidityProof).toHaveLength(8)
        })
    })

    describe("# verifyProof", () => {
        it("Should generate and verify a Semaphore proof", async () => {
            const verificationKey = JSON.parse(fs.readFileSync(verificationKeyPath, "utf-8"))

            const response = await verifyProof(verificationKey, fullProof)

            expect(response).toBe(true)
        })
    })

    describe("# generateRoleRegisterProof", () => {
        it("Should generate a Register proof", async () => {
            const role = BigInt(1)

            const candidates = [BigInt(1),BigInt(2)]

            fullRegisterProof = await generateRoleRegisterProof(identity, role, candidates, {
                wasmFilePath: roleRegisterWasmFilePath,
                zkeyFilePath: roleRegisterZkeyFilePath
            })

            expect(typeof fullRegisterProof).toBe("object")
            expect(fullRegisterProof.publicRegisterSignals.candidates).toBe(candidates)
        }, 20000)
    })

    describe("# generateRoleRegisterNullifierHash", () => {
        it("Should generate a valid nullifier hash", async () => {
            const nullifierHash = generateRoleRegisterNullifierHash(identity.getNullifier())

            expect(nullifierHash.toString()).toBe(fullRegisterProof.publicRegisterSignals.nullifierHash)
        })
    })

    describe("# verifyRoleRegisterProof", () => {
        it("Should generate and verify a Reigster proof", async () => {
            const verificationKey = JSON.parse(fs.readFileSync(verificationKeyPath, "utf-8"))

            const response = await verifyRoleRegisterProof(verificationKey, fullRegisterProof)

            expect(response).toBe(true)
        })
    })

    describe("# generateRoleVerifyProof", () => {
        it("Should not generate Semaphore proofs if the identity is not part of the group", async () => {
            const group = new Group(treeDepth)

            group.addMembers([BigInt(1), BigInt(2)])

            const fun = () =>
                generateRoleVerifyProof(identity, group, BigInt(3), [BigInt(2)],  externalNullifier, signal, {
                    wasmFilePath: roleVerifyWasmFilePath,
                    zkeyFilePath: roleVerifyZkeyFilePath
                })

            await expect(fun).rejects.toThrow("The identity is not part of the role")
        })

        it("Should not generate a Semaphore proof with default snark artifacts with Node.js", async () => {
            const group = new Group(treeDepth)

            group.addMembers([BigInt(1), BigInt(2), identity.commitment])

            const role = BigInt(1)
            const candidates = [BigInt(1), BigInt(2)]

            const fun = () => generateRoleVerifyProof(identity, group, role, candidates, externalNullifier, signal)

            await expect(fun).rejects.toThrow("ENOENT: no such file or directory")
        })

        it("Should generate a Semaphore proof passing a group as parameter", async () => {
            const group = new Group(treeDepth)

            group.addMembers([BigInt(1), BigInt(2), identity.commitment])

            const role = BigInt(1)
            const candidates = [BigInt(1), BigInt(2)]

            fullVerifyProof = await generateRoleVerifyProof(identity, group, role, candidates, externalNullifier, signal, {
                wasmFilePath: roleVerifyWasmFilePath,
                zkeyFilePath: roleVerifyZkeyFilePath
            })

            expect(typeof fullVerifyProof).toBe("object")
            expect(fullVerifyProof.publicVerifySignals.externalNullifier).toBe(externalNullifier)
            expect(fullVerifyProof.publicVerifySignals.merkleRoot).toBe(group.root.toString())
        }, 20000)

        it("Should generate a Semaphore proof passing a Merkle proof as parametr", async () => {
            const group = new Group(treeDepth)

            group.addMembers([BigInt(1), BigInt(2), identity.commitment])

            const role = BigInt(1)
            const candidates = [BigInt(1), BigInt(2)]

            fullVerifyProof = await generateRoleVerifyProof(identity, group.generateProofOfMembership(2), role, candidates, externalNullifier, signal, {
                wasmFilePath: roleVerifyWasmFilePath,
                zkeyFilePath: roleVerifyZkeyFilePath
            })

            expect(typeof fullVerifyProof).toBe("object")
            expect(fullVerifyProof.publicVerifySignals.externalNullifier).toBe(externalNullifier)
            expect(fullVerifyProof.publicVerifySignals.merkleRoot).toBe(group.root.toString())
        }, 20000)
    })

    describe("# verifyRoleVerifyProof", () => {
        it("Should generate and verify a RoleVerify proof", async () => {
            const verificationKey = JSON.parse(fs.readFileSync(verificationKeyPath, "utf-8"))

            const response = await verifyRoleVerifyProof(verificationKey, fullVerifyProof)

            expect(response).toBe(true)
        })
    })

})
