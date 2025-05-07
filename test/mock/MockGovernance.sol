// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title MockGovernance
/// @notice Simple governance contract for testing voting
contract MockGovernance {
    // Map of voter address => proposal ID => (voted, support)
    mapping(address => mapping(uint256 => VoteInfo)) private votes;

    struct VoteInfo {
        bool voted;
        bool support;
    }

    function castVote(uint256 proposalId, bool support) external {
        votes[msg.sender][proposalId] = VoteInfo({voted: true, support: support});
    }

    function getVote(address voter, uint256 proposalId) external view returns (bool voted, bool support) {
        VoteInfo memory voteInfo = votes[voter][proposalId];
        return (voteInfo.voted, voteInfo.support);
    }
}
