// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract ForensicChain {
    enum Role { None, Court, Officer, Forensic, Lawyer }
    enum EvidenceType { Image, Video, Document, Other }

    struct Evidence {
        string evidenceId;
        string cidEncrypted;
        string hash;
        EvidenceType evidenceType;
        address submittedBy;
        bool confirmed;
        uint256 submittedAt;
        address[] chainOfCustody;
    }

    struct FIR {
        string firId;               
        address filedBy;     
        string description;     
        uint256 timestamp;          
        bool promotedToCase;        
        string associatedCaseId;    

        string firId;
        address filedBy;
        string description;
        uint256 timestamp;
        bool promotedToCase;
        string associatedCaseId;
    }

    struct Case {
        string caseId;
        string title;
        string description;
        address createdBy;
        bool seal;
        bool open;
        string[] tags;
        uint256 evidenceCount;
    }

    address public owner;
    bool public isSystemLocked;

    mapping(address => Role) public globalRoles;
    mapping(string => FIR) public firs;
    mapping(string => Case) public cases;
    mapping(string => mapping(address => Role)) public caseRoles;
    mapping(string => mapping(address => bool)) public evidenceConfirmed;
    mapping(bytes32 => bool) public usedCIDHash;
    mapping(string => address[]) public caseAuditTrail;
    mapping(string => mapping(uint => mapping(address => bool))) public evidenceAccessed;
    mapping(string => mapping(uint256 => Evidence)) public caseEvidenceMapping;

    modifier onlyRole(Role role) {
        require(globalRoles[msg.sender] == role, "Unauthorized role");
        _;
    }

    modifier onlyCourt() {
        require(globalRoles[msg.sender] == Role.Court, "Only Court");
        _;
    }

    modifier onlyCaseAssigned(string memory caseId) {
        require(caseRoles[caseId][msg.sender] != Role.None, "Not assigned to case");
        _;
    }

    modifier caseOpen(string memory caseId) {
        require(cases[caseId].open && !cases[caseId].seal, "Case not open");
        _;
    }

    modifier notLocked() {
        require(!isSystemLocked, "System in emergency lock");
        _;
    }

    constructor() {
        owner = msg.sender;
        globalRoles[msg.sender] = Role.Court;
    }

    function toggleSystemLock() external onlyCourt {
        isSystemLocked = !isSystemLocked;
    }

    function setGlobalRole(address user, Role role) external onlyCourt {
        require(role != Role.None, "Invalid role");
        globalRoles[user] = role;
    }

    function fileFIR(string memory firId, string memory description) external notLocked onlyRole(Role.Officer) {
        require(firs[firId].filedBy == address(0), "FIR exists");
        firs[firId] = FIR({
            firId: firId,
            filedBy: msg.sender,
            description: description,
            timestamp: block.timestamp,
            promotedToCase: false,
            associatedCaseId: ""
        });
    }

    function submitFIREvidence(
        string memory firId,
        string memory evidenceId,
        string memory cidEncrypted,
        string memory hash,
        EvidenceType evidenceType
    ) external notLocked {
        require(globalRoles[msg.sender] == Role.Officer || globalRoles[msg.sender] == Role.Forensic, "Unauthorized");
        require(firs[firId].filedBy != address(0), "FIR not found");
        require(!firs[firId].promotedToCase, "FIR promoted");
        bytes32 unique = keccak256(abi.encodePacked(cidEncrypted, hash));
        require(!usedCIDHash[unique], "Duplicate evidence");

        string memory caseId = firs[firId].associatedCaseId;
        require(bytes(caseId).length != 0, "Case not associated");

        Evidence memory e = Evidence({
            evidenceId: evidenceId,
            cidEncrypted: cidEncrypted,
            hash: hash,
            evidenceType: evidenceType,
            submittedBy: msg.sender,
            confirmed: false,
            submittedAt: block.timestamp,
            chainOfCustody: new address[](0)
        });

        _addNewEvidence(caseId, e);
        usedCIDHash[unique] = true;
    }

    function _addNewEvidence(string memory caseId, Evidence memory e) internal {
        Case storage c = cases[caseId];
        caseEvidenceMapping[caseId][c.evidenceCount] = e;
        c.evidenceCount++;
    }

    function createCaseFromFIR(
        string memory caseId,
        string memory firId,
        string memory title,
        string memory description,
        string[] memory tags
    ) external notLocked onlyCourt {
        require(cases[caseId].createdBy == address(0), "Case exists");
        require(firs[firId].filedBy != address(0), "FIR not found");
        require(!firs[firId].promotedToCase, "Already promoted");

        Case storage c = cases[caseId];
        c.caseId = caseId;
        c.title = title;
        c.description = description;
        c.createdBy = msg.sender;
        c.seal = false;
        c.open = true;
        c.tags = tags;
        c.evidenceCount = 0;

        firs[firId].promotedToCase = true;
        firs[firId].associatedCaseId = caseId;
        caseRoles[caseId][msg.sender] = Role.Court;
    }

    function assignCaseRole(string memory caseId, address user, Role role) external notLocked onlyCourt {
        require(role != Role.None, "Invalid role");
        caseRoles[caseId][user] = role;
        caseAuditTrail[caseId].push(user);
    }

    function submitCaseEvidence(
        string memory caseId,
        string memory evidenceId,
        string memory cidEncrypted,
        string memory hash,
        EvidenceType evidenceType
    ) external notLocked onlyCaseAssigned(caseId) caseOpen(caseId) {
        require(
            globalRoles[msg.sender] == Role.Officer ||
            globalRoles[msg.sender] == Role.Forensic,
            "Unauthorized role to submit evidence"
        );

        bytes32 unique = keccak256(abi.encodePacked(cidEncrypted, hash));
        require(!usedCIDHash[unique], "Duplicate evidence");

        Evidence memory e = Evidence({
            evidenceId: evidenceId,
            cidEncrypted: cidEncrypted,
            hash: hash,
            evidenceType: evidenceType,
            submittedBy: msg.sender,
            confirmed: false,
            submittedAt: block.timestamp,
            chainOfCustody: new address[](0)
        });

        _addNewEvidence(caseId, e);
        usedCIDHash[unique] = true;
    }

    function confirmCaseEvidence(string memory caseId, uint index) external notLocked onlyCaseAssigned(caseId) {
        Evidence storage e = caseEvidenceMapping[caseId][index];
        require(!e.confirmed, "Already confirmed");
        require(e.submittedBy != msg.sender, "Self-confirmation denied");
        e.confirmed = true;
        e.chainOfCustody.push(msg.sender);
    }

    function sealCase(string memory caseId) external onlyCourt {
        cases[caseId].seal = true;
    }

    function reopenCase(string memory caseId) external onlyCourt {
        require(cases[caseId].seal, "Not seal");
        cases[caseId].seal = false;
        cases[caseId].open = true;
    }

    function closeCase(string memory caseId) external onlyCourt {
        cases[caseId].open = false;
        for (uint i = 0; i < caseAuditTrail[caseId].length; i++) {
            caseRoles[caseId][caseAuditTrail[caseId][i]] = Role.None;
        }
    }

    function getMyRoleInCase(string memory caseId) external view returns (Role) {
        return caseRoles[caseId][msg.sender];
    }

    function getGlobalRole(address user) external view returns (Role) {
        return globalRoles[user];
    }

    function getCase(string memory caseId) external view returns (Case memory) {
        return cases[caseId];
    }

    function getFIR(string memory firId) external view returns (FIR memory) {
        return firs[firId];
    }

    function accessEvidenceLog(string memory caseId, uint index) external onlyCaseAssigned(caseId) {
        require(index < cases[caseId].evidenceCount, "Invalid index");
        evidenceAccessed[caseId][index][msg.sender] = true;
        caseEvidenceMapping[caseId][index].chainOfCustody.push(msg.sender);
    }
    function getEvidence(string memory caseId, uint index) public view returns (Evidence memory) {
    return caseEvidenceMapping[caseId][index];
}
}
