pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";
include "./tree.circom";
include "./partial.circom";

template CalculateSecretIdentity() {
    signal input identityTrapdoor;

    signal output out;

    component poseidon = Poseidon(1);

    poseidon.inputs[0] <== identityTrapdoor;

    out <== poseidon.out;
}


template CalculateRoleCommitment() {
    signal input role;
    signal input secretIdentity;

    signal output out;

    component poseidon = Poseidon(2);

    poseidon.inputs[0] <== role;
    poseidon.inputs[1] <==  secretIdentity;

    out <== poseidon.out;
}


// nLevels must be < 32.
template Zkrole(nLevels, N) {
    signal input identityTrapdoor;
    signal input role;
    signal input treePathIndices[nLevels];
    signal input treeSiblings[nLevels];

    signal input isInclusion;
    signal input candidates[N];

    signal input signalHash;

    signal output root;

    component calculateSecretIdentity = CalculateSecretIdentity();
    calculateSecretIdentity.identityTrapdoor <== identityTrapdoor;

    signal secretIdentity;
    secretIdentity <== calculateSecretIdentity.out;

    component calculateRoleCommitment = CalculateRoleCommitment();
    calculateRoleCommitment.role <== role;
    calculateRoleCommitment.secretIdentity <== secretIdentity;


    component inclusionProof = MerkleTreeInclusionProof(nLevels);
    inclusionProof.leaf <== calculateRoleCommitment.out;

    for (var i = 0; i < nLevels; i++) {
        inclusionProof.siblings[i] <== treeSiblings[i];
        inclusionProof.pathIndices[i] <== treePathIndices[i];
    }

    root <== inclusionProof.root;

    // Dummy square to prevent tampering signalHash.
    signal signalHashSquared;
    signalHashSquared <== signalHash * signalHash;

    // isInclusion should be bool value
    isInclusion*(1-isInclusion) === 0;

    // Inclusion or exclusion proof of role.
    component oneOf = OneOf(N);
    component notIn = NotIn(N);
    oneOf.role <== role;
    notIn.role <== role;
    for (var i=0;i<N;i++) {
        oneOf.candidates[i] <== candidates[i];
        notIn.candidates[i] <== candidates[i];
    }
    signal target;
    target <-- isInclusion!=0 ? oneOf.out : notIn.out;
    target === 1;
}

component main {public [isInclusion, candidates]} = Zkrole(20, 10);