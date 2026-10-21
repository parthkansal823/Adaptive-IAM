// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice Local research registry. Never deploy this public-test-wallet setup to a public chain.
contract AccessGrantRegistry {
    bytes32 public constant REGISTRY_VERSION = keccak256("AdaptiveIAM.AccessGrantRegistry.v1");
    address public immutable writer;
    uint256 public auditCount;
    bytes32 public auditHead;
    mapping(uint256 => bytes32) public auditHashes;
    bytes32 public constant AUDIT_BATCH_VERSION = keccak256("AdaptiveIAM.AuditBatch.v1");
    uint256 public auditBatchCount;
    bytes32 public auditBatchHead;
    uint64 public auditBatchEnd;

    struct AuditBatch {
        uint64 startSequence;
        uint64 endSequence;
        bytes32 root;
        bytes32 auditEndHash;
        bytes32 previousRoot;
    }
    mapping(uint256 => AuditBatch) public auditBatches;

    struct Grant {
        bytes32 subjectHash;
        bytes32 resourceHash;
        uint64 expiresAt;
        bool revoked;
        bool exists;
    }
    mapping(bytes32 => Grant) public grants;
    event AuditAnchored(uint256 indexed sequence, bytes32 eventHash, bytes32 previousHash);
    event AuditBatchAnchored(uint256 indexed batchId, uint64 startSequence, uint64 endSequence, bytes32 root, bytes32 auditEndHash, bytes32 previousRoot);
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

    /// @notice Supplemental proof index over an already anchored audit prefix.
    /// @dev A trusted writer commits the root. This never creates grant authority.
    function anchorAuditBatch(uint64 startSequence, uint64 endSequence, bytes32 root, bytes32 auditEndHash, bytes32 previousRoot) external onlyWriter {
        require(startSequence == auditBatchEnd + 1 && endSequence >= startSequence, "batch range mismatch");
        require(endSequence - startSequence + 1 <= 256, "batch too large");
        require(root != bytes32(0), "empty batch root");
        require(previousRoot == auditBatchHead, "batch head mismatch");
        require(endSequence <= auditCount && auditHashes[endSequence] == auditEndHash, "batch audit checkpoint mismatch");
        auditBatchCount += 1;
        auditBatches[auditBatchCount] = AuditBatch(startSequence, endSequence, root, auditEndHash, previousRoot);
        auditBatchHead = root;
        auditBatchEnd = endSequence;
        emit AuditBatchAnchored(auditBatchCount, startSequence, endSequence, root, auditEndHash, previousRoot);
    }

    /// @notice Verify the custom sequence/hash leaf using RFC 9162 tree shape.
    function verifyAuditBatchInclusion(uint256 batchId, uint64 sequence, bytes32 eventHash, bytes32[] calldata path) external view returns (bool) {
        AuditBatch memory batch = auditBatches[batchId];
        if (batch.root == bytes32(0) || eventHash == bytes32(0) || sequence < batch.startSequence || sequence > batch.endSequence || path.length > 8) return false;
        uint256 index = sequence - batch.startSequence;
        uint256 last = batch.endSequence - batch.startSequence;
        bytes32 node = sha256(abi.encodePacked(bytes1(0x00), sequence, eventHash));
        for (uint256 i = 0; i < path.length; i++) {
            if (last == 0) return false;
            if ((index & 1) == 1 || index == last) {
                node = sha256(abi.encodePacked(bytes1(0x01), path[i], node));
                while ((index & 1) == 0 && index != 0) {
                    index >>= 1;
                    last >>= 1;
                }
            } else {
                node = sha256(abi.encodePacked(bytes1(0x01), node, path[i]));
            }
            index >>= 1;
            last >>= 1;
        }
        return last == 0 && node == batch.root;
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
