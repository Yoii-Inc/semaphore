//SPDX-License-Identifier: MIT
pragma solidity 0.8.4;

/// @title Role interface.
/// @dev Interface of Role contract.
interface IRoleVerify {
    /// @notice Emitted when a proof is verified correctly and a new nullifier hash is added.
    /// @param nullifierHash: Hash of external and identity nullifiers.
    event NullifierHashAdded(uint256 nullifierHash);
}
