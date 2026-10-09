// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice Local research registry. Never deploy this public-test-wallet setup to a public chain.
contract AccessGrantRegistry {
    bytes32 public constant REGISTRY_VERSION = keccak256("AdaptiveIAM.AccessGrantRegistry.v1");
    address public immutable writer;
    uint256 public auditCount;
    bytes32 public auditHead;
    mapping(uint256 => bytes32) public auditHashes;

    struct Grant {
        bytes32 subjectHash;
        bytes32 resourceHash;
        uint64 expiresAt;
        bool revoked;
        bool exists;
    }
    mapping(bytes32 => Grant) public grants;
    event AuditAnchored(uint256 indexed sequence, bytes32 eventHash, bytes32 previousHash);
    event GrantRecorded(bytes32 indexed grantId, bytes32 indexed subjectHash, bytes32 indexed resourceHash, uint64 expiresAt);
    event GrantRevoked(bytes32 indexed grantId);

    modifier onlyWriter() {
        require(msg.sender == writer, "trusted writer only");
        _;
    }

    constructor() {
        require(block.chainid == 31337, "local research chain only");
        writer = msg.sender;
    }

    function anchorAudit(bytes32 eventHash, bytes32 expectedPreviousHash) external onlyWriter {
        require(eventHash != bytes32(0), "empty event hash");
        require(expectedPreviousHash == auditHead, "audit head mismatch");
        auditCount += 1;
        auditHashes[auditCount] = eventHash;
        auditHead = eventHash;
        emit AuditAnchored(auditCount, eventHash, expectedPreviousHash);
    }

    function recordGrant(bytes32 grantId, bytes32 subjectHash, bytes32 resourceHash, uint64 expiresAt) external onlyWriter {
        require(grantId != bytes32(0) && subjectHash != bytes32(0) && resourceHash != bytes32(0), "empty identity hash");
        require(!grants[grantId].exists, "grant already recorded");
        require(expiresAt > block.timestamp, "grant already expired");
        require(expiresAt <= block.timestamp + 72 hours, "grant duration exceeds policy");
        grants[grantId] = Grant(subjectHash, resourceHash, expiresAt, false, true);
        emit GrantRecorded(grantId, subjectHash, resourceHash, expiresAt);
    }

    function revokeGrant(bytes32 grantId) external onlyWriter {
        require(grants[grantId].exists, "unknown grant");
        grants[grantId].revoked = true;
        emit GrantRevoked(grantId);
    }

    function hasAccess(bytes32 grantId, bytes32 subjectHash, bytes32 resourceHash) external view returns (bool) {
        Grant storage grant = grants[grantId];
        return grant.exists && !grant.revoked && grant.expiresAt > block.timestamp
            && grant.subjectHash == subjectHash && grant.resourceHash == resourceHash;
    }
}
