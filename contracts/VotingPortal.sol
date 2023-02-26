// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

//@title EVM - Electornic Voting MAchine
//@author Aradhya Mittal
contract voterPortal is ERC721, Ownable{

    using ECDSA for bytes32;

    uint startTime;
    uint endTime;
    uint candidateLength;
    string[] public candidateList;// List of candidates taking part in elections
    mapping (uint => bool) public voted; // TOkenId => 0/1
    mapping (string => uint) public votes; // CandidateId => vote count

    event CandidateReset(string Id);
    event CandidateRegistered(string Id);

    constructor(string memory name, string memory symbol, address _a) ERC721(name, symbol){
        transferOwnership(_a);
    }

    modifier isStarted{
        require(block.timestamp < endTime, "Election Ended");
        require( block.timestamp > startTime, "Election not Started");
        _;
    }

    function setTime(uint durationInHours) external onlyOwner{
        uint durationInSeconds = durationInHours * 3600;
        startTime = block.timestamp;
        endTime = startTime + durationInSeconds;
    }

    function getTokenId(string memory voterId) external pure returns(uint tId){
        tId = uint(keccak256(abi.encodePacked(voterId)));
    }


    function mint(address a, uint tokenId) external onlyOwner{
        _mint(a, tokenId);
    }

    function burn(uint tokenId) external onlyOwner{
        _burn(tokenId);
    }

    function _checkCandidate(string memory s) internal view returns (bool can){
        for(uint i;i<candidateLength && !can;i++){
            if(keccak256(abi.encodePacked(candidateList[i])) == keccak256(abi.encodePacked(s))){
                can = true;                
            }
        }
    }

    function candidateRegister(string memory Id) external onlyOwner{
        require(!_checkCandidate(Id), "Already Registered");
        // require(!candidates[Id], "Already Registered");
        // candidates[Id] = true;
        candidateList.push(Id);
        ++candidateLength;
        emit CandidateRegistered(Id);
    }

    function candidateReset(string memory Id) external onlyOwner{
        // require(_checkCandidate(Id), "Not Registered");
        uint l = candidateLength;
        for(uint8 i;i<l;++i){
            if(keccak256(abi.encodePacked(candidateList[i])) == keccak256(abi.encodePacked(Id))){
                candidateList[i] = candidateList[l-1];
                delete candidateList[l-1];
                --candidateLength;
                break ;
            }
        }
        emit CandidateReset(Id);
    }

    function vote(uint tokenId, string memory candidateId, bytes memory sig) external onlyOwner isStarted{
        require(!voted[tokenId], "Already voted");
        require(_checkCandidate(candidateId), "Invalid Candidate");

        bytes32 messageHash = getMessageHash(tokenId, candidateId);
        bytes32 ethSignedHash = _getEthSignedHash(messageHash);

        address voter = _recover(ethSignedHash, sig);
        require(voter != address(0), "Invalid Signature");
        require(voter == ownerOf(tokenId), "Unauthorised Voting");
        voted[tokenId] = true;
        votes[candidateId]++;
    }

    function getMessageHash(uint tokenId, string memory candidateId) public pure returns(bytes32 hash){
        hash = keccak256(abi.encodePacked(tokenId, candidateId));
    }

    function _getEthSignedHash(bytes32 hash) internal pure returns (bytes32 signedHash){
        signedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    function _recover(bytes32 ethsignedHash, bytes memory signature) internal pure returns(address voter){
        (bytes32 r, bytes32 s, uint8 v) = _split(signature);
        voter = ecrecover(ethsignedHash, v, r, s);
    }

    function _split(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v){
        require(sig.length == 65, "Invalid Sign");
        assembly{
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }


}