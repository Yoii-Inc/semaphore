import { BigNumber } from "@ethersproject/bignumber"
import { poseidon } from "circomlibjs"
import checkParameter from "./checkParameter"
import { generateCommitment, generateRoleCommitment, genRandomNumber, isJsonArray, sha256 } from "./utils"

export default class Identity {
    private _trapdoor: bigint
    private _nullifier: bigint
    private _role: bigint
    private _commitment: bigint
    private _roleCommitment: bigint

    /**
     * Initializes the class attributes based on the strategy passed as parameter.
     * @param identityOrMessage Additional data needed to create identity for given strategy.
     */
    constructor(identityOrMessage?: string) {
        this._role = BigInt(-1)

        if (identityOrMessage === undefined) {
            this._trapdoor = genRandomNumber()
            this._nullifier = genRandomNumber()
            this._commitment = generateCommitment(this._nullifier, this._trapdoor)
            this._roleCommitment = generateRoleCommitment(this._nullifier, this._trapdoor, this._role)

            return
        }

        checkParameter(identityOrMessage, "identityOrMessage", "string")

        if (!isJsonArray(identityOrMessage)) {
            const messageHash = sha256(identityOrMessage).slice(2)

            this._trapdoor = BigNumber.from(sha256(`${messageHash}identity_trapdoor`)).toBigInt()
            this._nullifier = BigNumber.from(sha256(`${messageHash}identity_nullifier`)).toBigInt()
            this._commitment = generateCommitment(this._nullifier, this._trapdoor)
            this._roleCommitment = generateRoleCommitment(this._nullifier, this._trapdoor, this._role)

            return
        }

        const [trapdoor, nullifier] = JSON.parse(identityOrMessage)

        this._trapdoor = BigNumber.from(`0x${trapdoor}`).toBigInt()
        this._nullifier = BigNumber.from(`0x${nullifier}`).toBigInt()
        this._commitment = generateCommitment(this._nullifier, this._trapdoor)
        this._roleCommitment = generateRoleCommitment(this._nullifier, this._trapdoor, this._role)
    }

    /**
     * Returns the identity trapdoor.
     * @returns The identity trapdoor.
     */
    public get trapdoor(): bigint {
        return this._trapdoor
    }

    /**
     * Returns the identity trapdoor.
     * @returns The identity trapdoor.
     */
    public getTrapdoor(): bigint {
        return this._trapdoor
    }

    /**
     * Returns the identity nullifier.
     * @returns The identity nullifier.
     */
    public get nullifier(): bigint {
        return this._nullifier
    }

    /**
     * Returns the identity nullifier.
     * @returns The identity nullifier.
     */
    public getNullifier(): bigint {
        return this._nullifier
    }

    /**
     * Returns the role.
     * @returns The role.
     */
     public get role(): bigint {
        return this._role
    }

    /**
     * Returns the role.
     * @returns The role.
     */
    public getRole(): bigint {
        return this._role
    }

    /**
     * Add the role.
     */
     public addRole(role: bigint): void {
        this._role = role
    }

    /**
     * Returns the identity commitment.
     * @returns The identity commitment.
     */
    public get commitment(): bigint {
        return this._commitment
    }

    /**
     * Returns the identity commitment.
     * @returns The identity commitment.
     */
    public getCommitment(): bigint {
        return this._commitment
    }

    /**
     * Returns the identity commitment.
     * @returns The identity commitment.
     */
     public get roleCommitment(): bigint {
        return this._roleCommitment
    }

    /**
     * Returns the identity commitment.
     * @returns The identity commitment.
     */
    public getRoleCommitment(): bigint {
        return this._roleCommitment
    }

    /**
     * @deprecated since version 2.6.0
     * Generates the identity commitment from trapdoor and nullifier.
     * @returns identity commitment
     */
    public generateCommitment(): bigint {
        return poseidon([poseidon([this._nullifier, this._trapdoor])])
    }

    /**
     * @deprecated since version 2.6.0
     * Generates the identity commitment from trapdoor and nullifier and role.
     * @returns identity commitment
     */
     public generateRoleCommitment(): bigint {
        return poseidon([poseidon([this._nullifier, this._trapdoor]), this._role])
    }

    /**
     * @deprecated since version 2.6.0
     * Updates the identity commitment from trapdoor and nullifier and role.
     */
    public updateRoleCommitment(): void {
        this._roleCommitment = poseidon([poseidon([this._nullifier, this._trapdoor]), this._role])
    }

    /**
     * Returns a JSON string with trapdoor and nullifier. It can be used
     * to export the identity and reuse it later.
     * @returns The string representation of the identity.
     */
    public toString(): string {
        return JSON.stringify([this._trapdoor.toString(16), this._nullifier.toString(16)])
    }

    /**
     * Returns a JSON string with trapdoor and nullifier and role. It can be used
     * to export the identity and reuse it later.
     * @returns The string representation of the identity.
     */
     public toStringRole(): string {
        return JSON.stringify([this._trapdoor.toString(16), this._nullifier.toString(16), this._role.toString(16)])
    }
}
