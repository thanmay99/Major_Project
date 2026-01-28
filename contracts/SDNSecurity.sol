// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SDNSecurity {
    // --------------------------
    // 1. STRUCT DEFINITIONS
    // --------------------------

    struct SecurityEvent {
        string eventType;
        string eventData;
        uint256 timestamp;
        address reporter;
    }

    struct FlowRecord {
        string srcIp;
        string dstIp;
        string path;
        uint256 createdAt;
        uint256 packetCount;
        string securityLevel;
        bool isActive;
    }

    struct CongestionEvent {
        string path;
        uint256 utilization;
        uint256 timestamp;
        string action;
    }

    // ✅ NEW STRUCT for packet-level security
    struct PacketRecord {
        string packetHash;
        string src;
        string dst;
        uint256 timestamp;
    }

    // --------------------------
    // 2. STATE VARIABLES
    // --------------------------

    address private owner;
    SecurityEvent[] public securityEvents;
    CongestionEvent[] public congestionEvents;
    mapping(string => FlowRecord) public flows;

    // ✅ New packet proof storage
    mapping(string => PacketRecord) public packetProofs;
    string[] public packetHashes;

    // --------------------------
    // 3. EVENTS
    // --------------------------

    event SecurityEventLogged(string indexed eventType, string eventData, uint256 timestamp);
    event FlowCreated(string indexed flowId, string srcIp, string dstIp, uint256 timestamp);
    event CongestionEventLogged(string indexed path, uint256 utilization, string action);
    event PacketProofStored(string indexed hashValue, string src, string dst, uint256 timestamp);
    event PacketVerified(string indexed hashValue, bool valid);

    // --------------------------
    // 4. ACCESS CONTROL
    // --------------------------

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // --------------------------
    // 5. CONTROL PLANE SECURITY (existing features)
    // --------------------------

    function logSecurityEvent(string memory eventType, string memory eventData) public onlyOwner {
        securityEvents.push(SecurityEvent({
            eventType: eventType,
            eventData: eventData,
            timestamp: block.timestamp,
            reporter: msg.sender
        }));
        emit SecurityEventLogged(eventType, eventData, block.timestamp);
    }

    function logCongestionEvent(string memory path, uint256 utilization, string memory action) public onlyOwner {
        congestionEvents.push(CongestionEvent({
            path: path,
            utilization: utilization,
            timestamp: block.timestamp,
            action: action
        }));
        emit CongestionEventLogged(path, utilization, action);
    }

    function createFlowRecord(
        string memory flowId,
        string memory srcIp,
        string memory dstIp,
        string memory path,
        string memory securityLevel
    ) public onlyOwner {
        flows[flowId] = FlowRecord({
            srcIp: srcIp,
            dstIp: dstIp,
            path: path,
            createdAt: block.timestamp,
            packetCount: 0,
            securityLevel: securityLevel,
            isActive: true
        });
        emit FlowCreated(flowId, srcIp, dstIp, block.timestamp);
    }

    function updatePacketCount(string memory flowId, uint256 newCount) public onlyOwner {
        require(flows[flowId].isActive, "Flow not active");
        flows[flowId].packetCount = newCount;
    }

    // --------------------------
    // 6. DATA PLANE SECURITY (new feature)
    // --------------------------

    // Store packet integrity proof
    function storePacketProof(string memory src, string memory dst, string memory hashValue) public onlyOwner {
        require(bytes(packetProofs[hashValue].packetHash).length == 0, "Packet already stored");

        packetProofs[hashValue] = PacketRecord({
            packetHash: hashValue,
            src: src,
            dst: dst,
            timestamp: block.timestamp
        });

        packetHashes.push(hashValue);
        emit PacketProofStored(hashValue, src, dst, block.timestamp);
    }

    // Verify packet integrity
    function verifyPacketProof(string memory hashValue) public view returns (bool) {
        return bytes(packetProofs[hashValue].packetHash).length != 0;
    }

    // --------------------------
    // 7. VIEW FUNCTIONS
    // --------------------------

    function getSecurityEventsCount() public view returns (uint256) {
        return securityEvents.length;
    }

    function getCongestionEventsCount() public view returns (uint256) {
        return congestionEvents.length;
    }

    function getFlowInfo(string memory flowId) public view returns (
        string memory srcIp,
        string memory dstIp,
        uint256 packetCount,
        string memory securityLevel,
        bool isActive
    ) {
        FlowRecord memory flow = flows[flowId];
        return (flow.srcIp, flow.dstIp, flow.packetCount, flow.securityLevel, flow.isActive);
    }

    function getPacketProofCount() public view returns (uint256) {
        return packetHashes.length;
    }

    function getLastSecurityEvent() public view returns (string memory, string memory, uint256) {
        require(securityEvents.length > 0, "No events");
        SecurityEvent memory lastEvent = securityEvents[securityEvents.length - 1];
        return (lastEvent.eventType, lastEvent.eventData, lastEvent.timestamp);
    }
}
