import { formatBytes32String } from "@ethersproject/strings"
import { Group } from "@semaphore-protocol/group"
import { Identity } from "@semaphore-protocol/identity"
import { getCurveFromName } from "ffjavascript"
import fs from "fs"
import generateNullifierHash from "./generateNullifierHash"
import generateRoleRegisterNullifierHash from "./generateRoleRegisterNullifierHash"
import generateRoleRegisterProof from "./generateRoleRegisterProof"
import generateRoleVerifyProof from "./generateRoleVerifyProof"
import generateSignalHash from "./generateSignalHash"
import packToSolidityProof from "./packToSolidityProof"
import { FullVerifyProof, FullRegisterProof } from "./types"
import verifyRoleRegisterProof from "./verifyRoleRegisterProof"
import verifyRoleVerifyProof from "./verifyRoleVerifyProof"

describe("Proof", () => {
    const treeDepth = Number(process.env.TREE_DEPTH) || 20

    const externalNullifier = "1"
    const signal = "0x111"

    const roleRegisterWasmFilePath = `./snark-artifacts/register.wasm`
    const roleRegisterZkeyFilePath = `./snark-artifacts/register.zkey`
    const roleRegisterVerificationKeyPath = `./snark-artifacts/register.json`

    const roleVerifyWasmFilePath = `./snark-artifacts/verify.wasm`
    const roleVerifyZkeyFilePath = `./snark-artifacts/verify.zkey`
    const roleVerifyVerificationKeyPath = `./snark-artifacts/verify.json`

    const identity = new Identity()

    let fullRegisterProof: FullRegisterProof
    let fullVerifyProof: FullVerifyProof
    let curve: any

    beforeAll(async () => {
        curve = await getCurveFromName("bn128")
    })

    afterAll(async () => {
        await curve.terminate()
    })

    describe("# generateRoleRegisterProof", () => {
        it("Should not generate a RoleRegister proof with default snark artifacts with Node.js", async () => {
            const role = BigInt(1)

            const candidates = [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)]

            const fun = () => generateRoleRegisterProof(identity, role, candidates)

            await expect(fun).rejects.toThrow("ENOENT: no such file or directory")
        })

        it("Should generate a Register proof", async () => {
            const role = BigInt(1)

            const candidates = [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)]

            fullRegisterProof = await generateRoleRegisterProof(identity, role, candidates, {
                wasmFilePath: roleRegisterWasmFilePath,
                zkeyFilePath: roleRegisterZkeyFilePath
            })

            identity.addRole(role)
            identity.updateRoleCommitment()

            expect(typeof fullRegisterProof).toBe("object")
            expect(fullRegisterProof.publicRegisterSignals.roleCommitment).toBe(identity.roleCommitment.toString())
            expect(fullRegisterProof.publicRegisterSignals.candidates).toStrictEqual(candidates.map(e => String(e)))
        }, 20000)

        it("Should generate a Register proof with inadequate array", async () => {
            const role = BigInt(1)

            const candidates = [BigInt(1),BigInt(2),BigInt(3)]

            fullRegisterProof = await generateRoleRegisterProof(identity, role, candidates, {
                wasmFilePath: roleRegisterWasmFilePath,
                zkeyFilePath: roleRegisterZkeyFilePath
            })

            identity.addRole(role)
            identity.updateRoleCommitment()

            expect(typeof fullRegisterProof).toBe("object")
            expect(fullRegisterProof.publicRegisterSignals.roleCommitment).toBe(identity.roleCommitment.toString())
            expect(fullRegisterProof.publicRegisterSignals.candidates).toStrictEqual(candidates.map(e => String(e)))
        }, 20000)
    })

    describe("# generateRoleRegisterNullifierHash", () => {
        it("Should generate a valid nullifier hash", async () => {
            const nullifierHash = generateRoleRegisterNullifierHash(identity.getNullifier())

            expect(nullifierHash.toString()).toBe(fullRegisterProof.publicRegisterSignals.nullifierHash)
        })
    })

    describe("# packToSolidityRoleRegisterProof", () => {
        it("Should return a Solidity proof", async () => {
            const solidityProof = packToSolidityProof(fullRegisterProof.proof)

            expect(solidityProof).toHaveLength(8)
        })
    })

    describe("# verifyRoleRegisterProof", () => {
        it("Should generate and verify a Reigster proof", async () => {
            const verificationKey = JSON.parse(fs.readFileSync(roleRegisterVerificationKeyPath, "utf-8"))

            const response = await verifyRoleRegisterProof(verificationKey, fullRegisterProof)

            expect(response).toBe(true)
        })
    })

    describe("# generateRoleVerifyProof", () => {
        it("Should not generate RoleVerify proofs if the identity is not part of the group", async () => {
            const group = new Group(treeDepth)

            group.addMembers([BigInt(1), BigInt(2)])

            const fun = () =>
                generateRoleVerifyProof(identity, group, [BigInt(2)],  externalNullifier, signal, {
                    wasmFilePath: roleVerifyWasmFilePath,
                    zkeyFilePath: roleVerifyZkeyFilePath
                })

            await expect(fun).rejects.toThrow("The identity is not part of the group")
        })

        it("Should not generate a RoleVerify proof with default snark artifacts with Node.js", async () => {
            const group = new Group(treeDepth)

            group.addMembers([BigInt(1), BigInt(2), identity.roleCommitment])

            const candidates = [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)]

            const fun = () => generateRoleVerifyProof(identity, group, candidates, externalNullifier, signal)

            await expect(fun).rejects.toThrow("ENOENT: no such file or directory")
        })

        it("Should generate a RoleVerify proof passing a group as parameter with role not in candidates", async () => {
            const group = new Group(treeDepth)

            identity.addRole(BigInt(1))
            identity.updateRoleCommitment()

            group.addMembers([BigInt(1), BigInt(2), identity.roleCommitment])

            const candidates = [BigInt(2),BigInt(3),BigInt(4),BigInt(5),BigInt(6)]

            fullVerifyProof = await generateRoleVerifyProof(identity, group, candidates, externalNullifier, signal, {
                wasmFilePath: roleVerifyWasmFilePath,
                zkeyFilePath: roleVerifyZkeyFilePath
            })

            expect(typeof fullVerifyProof).toBe("object")
            expect(fullVerifyProof.publicVerifySignals.externalNullifier).toBe(externalNullifier)
            expect(fullVerifyProof.publicVerifySignals.merkleRoot).toBe(group.root.toString())
            expect(fullVerifyProof.publicVerifySignals.candidates).toStrictEqual(candidates.map(e => String(e)))
            expect(fullVerifyProof.publicVerifySignals.count).toBe("0")
        }, 20000)

        it("Should generate a RoleVerify proof passing a Merkle proof as parameter  with role not in candidates", async () => {
            const group = new Group(treeDepth)

            identity.addRole(BigInt(1))
            identity.updateRoleCommitment()

            group.addMembers([BigInt(1), BigInt(2), identity.roleCommitment])

            const candidates = [BigInt(2),BigInt(3),BigInt(4),BigInt(5),BigInt(6)]

            fullVerifyProof = await generateRoleVerifyProof(identity, group.generateProofOfMembership(2), candidates, externalNullifier, signal, {
                wasmFilePath: roleVerifyWasmFilePath,
                zkeyFilePath: roleVerifyZkeyFilePath
            })

            expect(typeof fullVerifyProof).toBe("object")
            expect(fullVerifyProof.publicVerifySignals.externalNullifier).toBe(externalNullifier)
            expect(fullVerifyProof.publicVerifySignals.merkleRoot).toBe(group.root.toString())
            expect(fullVerifyProof.publicVerifySignals.candidates).toStrictEqual(candidates.map(e => String(e)))
            expect(fullVerifyProof.publicVerifySignals.count).toBe("0")
        }, 20000)

        it("Should generate a RoleVerify proof passing a group as parameter with role in candidates", async () => {
            const group = new Group(treeDepth)

            identity.addRole(BigInt(1))
            identity.updateRoleCommitment()

            group.addMembers([BigInt(1), BigInt(2), identity.roleCommitment])

            const candidates = [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)]

            fullVerifyProof = await generateRoleVerifyProof(identity, group, candidates, externalNullifier, signal, {
                wasmFilePath: roleVerifyWasmFilePath,
                zkeyFilePath: roleVerifyZkeyFilePath
            })

            expect(typeof fullVerifyProof).toBe("object")
            expect(fullVerifyProof.publicVerifySignals.externalNullifier).toBe(externalNullifier)
            expect(fullVerifyProof.publicVerifySignals.merkleRoot).toBe(group.root.toString())
            expect(fullVerifyProof.publicVerifySignals.candidates).toStrictEqual(candidates.map(e => String(e)))
            expect(fullVerifyProof.publicVerifySignals.count).toBe("1")
        }, 20000)

        it("Should generate a RoleVerify proof passing a Merkle proof as parameter with role in candidates", async () => {
            const group = new Group(treeDepth)

            identity.addRole(BigInt(1))
            identity.updateRoleCommitment()

            group.addMembers([BigInt(1), BigInt(2), identity.roleCommitment])

            const candidates = [BigInt(1),BigInt(2),BigInt(3),BigInt(4),BigInt(5)]

            fullVerifyProof = await generateRoleVerifyProof(identity, group.generateProofOfMembership(2), candidates, externalNullifier, signal, {
                wasmFilePath: roleVerifyWasmFilePath,
                zkeyFilePath: roleVerifyZkeyFilePath
            })

            expect(typeof fullVerifyProof).toBe("object")
            expect(fullVerifyProof.publicVerifySignals.externalNullifier).toBe(externalNullifier)
            expect(fullVerifyProof.publicVerifySignals.merkleRoot).toBe(group.root.toString())
            expect(fullVerifyProof.publicVerifySignals.candidates).toStrictEqual(candidates.map(e => String(e)))
            expect(fullVerifyProof.publicVerifySignals.count).toBe("1")
        }, 20000)

        it("Should generate a RoleVerify proof with inadequate candidates", async () => {
            const group = new Group(treeDepth)

            identity.addRole(BigInt(1))
            identity.updateRoleCommitment()

            group.addMembers([BigInt(1), BigInt(2), identity.roleCommitment])

            const candidates = [BigInt(1),BigInt(2),BigInt(3)]

            fullVerifyProof = await generateRoleVerifyProof(identity, group, candidates, externalNullifier, signal, {
                wasmFilePath: roleVerifyWasmFilePath,
                zkeyFilePath: roleVerifyZkeyFilePath
            })

            expect(typeof fullVerifyProof).toBe("object")
            expect(fullVerifyProof.publicVerifySignals.externalNullifier).toBe(externalNullifier)
            expect(fullVerifyProof.publicVerifySignals.merkleRoot).toBe(group.root.toString())
            expect(fullVerifyProof.publicVerifySignals.candidates).toStrictEqual(candidates.map(e => String(e)))
            expect(fullVerifyProof.publicVerifySignals.count).toBe("1")
        }, 20000)
    })

    describe("# generateSignalHash", () => {
        it("Should generate a valid signal hash", async () => {
            const signalHash = generateSignalHash(signal)

            expect(signalHash.toString()).toBe(fullVerifyProof.publicVerifySignals.signalHash)
        })

        it("Should generate a valid signal hash by passing a valid hex string", async () => {
            const signalHash = generateSignalHash(formatBytes32String(signal))

            expect(signalHash.toString()).toBe(fullVerifyProof.publicVerifySignals.signalHash)
        })
    })

    describe("# generateNullifierHash", () => {
        it("Should generate a valid nullifier hash", async () => {
            const nullifierHash = generateNullifierHash(externalNullifier, identity.getNullifier())

            expect(nullifierHash.toString()).toBe(fullVerifyProof.publicVerifySignals.nullifierHash)
        })
    })

    describe("# packToSolidityRoleVerifyProof", () => {
        it("Should return a Solidity proof", async () => {
            const solidityProof = packToSolidityProof(fullVerifyProof.proof)

            expect(solidityProof).toHaveLength(8)
        })
    })

    describe("# verifyRoleVerifyProof", () => {
        it("Should generate and verify a RoleVerify proof", async () => {
            const verificationKey = JSON.parse(fs.readFileSync(roleVerifyVerificationKeyPath, "utf-8"))

            const response = await verifyRoleVerifyProof(verificationKey, fullVerifyProof)

            expect(response).toBe(true)
        })
    })

})
