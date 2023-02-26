// SPDX-License-Identifier: MIT
pragma solidity 0.8.17;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/*
* @title EVM - Electronic Voting Machine
* @author Aradhya Mittal
* @dev This contract implements an electronic voting machine on the Ethereum network, where users can 
* cast votes for candidates by sending transactions to the contract.
 */
contract voterPortal is ERC721, Ownable{

    uint public startTime; // The timestamp when the voting period starts
    uint public endTime; // The timestamp when the voting period ends
    uint public candidateLength; // The total number of candidates registered
    string[] public candidateList; // List of candidates taking part in elections
    mapping (uint => bool) public voted; // A mapping of token ID to boolean to keep track of whether a token has been used to vote
    mapping (string => uint) public votes; // A mapping of candidate ID to vote count

    event CandidateReset(string Id);
    event CandidateRegistered(string Id);

    /*
    * @dev Initializes the contract with the given name, symbol and the owner address.
    * @param name The name of the ERC721 token.
    * @param symbol The symbol of the ERC721 token.
    * @param _a The address of the contract owner.
    */
    constructor(string memory name, string memory symbol, address _a) ERC721(name, symbol){
        transferOwnership(_a);
    }

    /*
    * @dev Modifier to check if the voting period has started.
    */
    modifier isStarted{
        require(block.timestamp < endTime, "Election Ended");
        require( block.timestamp > startTime, "Election not Started");
        _;
    }

    /*
    * @dev Sets the duration of the voting period.
    * @param durationInHours The duration of the voting period in hours.
    */
    function setTime(uint durationInHours) external onlyOwner{
        uint durationInSeconds = durationInHours * 3600;
        startTime = block.timestamp;
        endTime = startTime + durationInSeconds;
    }

    /*
    * @dev Converts the given voter ID string to a unique token ID by computing its keccak256 hash.
    * @param voterId The string voter ID.
    * @return tId The unique token ID.
    */
    function getTokenId(string memory voterId) external pure returns(uint tId){
        tId = uint(keccak256(abi.encodePacked(voterId)));
    }

    /*
    * @dev Mints new voting tokens to the given address.
    * @param voter The address of the user to whom new voting tokens will be minted.
    * @param tokenId The unique token ID to be minted.
    */
    function mint(address voter, uint tokenId) external onlyOwner{
        _mint(voter, tokenId);
    }

    /*
    * @dev Burns the given voting token.
    * @param tokenId The unique token ID to be burned.
    */
    function burn(uint tokenId) external onlyOwner{
        _burn(tokenId);
    }

    /*
    * @dev Checks if the candidate with the given ID is registered or not.
    * @param candidateId The ID of the candidate to check.
    * @return can A boolean value indicating whether the candidate is registered or not.
    */
    function _checkCandidate(string memory candidateId) internal view returns (bool can){
        for(uint i;i<candidateLength && !can;i++){
            if(keccak256(abi.encodePacked(candidateList[i])) == keccak256(abi.encodePacked(candidateId))){
                can = true;                
            }
        }
    }

    /*
    * @notice Registers a candidate by adding their ID to the array
    * @param Id The ID of the candidate to register
    */
    function candidateRegister(string memory Id) external onlyOwner{
        require(!_checkCandidate(Id), "Already Registered");
        candidateList.push(Id);
        ++candidateLength;
        emit CandidateRegistered(Id);
    }

    /*
    * @notice Removes candidates from the array
    * @param Id The ID of the candidate to be removed
    */
    function candidateReset(string memory Id) external onlyOwner{
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

    /*
    * @notice Adds a vote to the specified candidate using the provided token ID and signature
    * @param tokenId The token ID of the voter
    * @param candidateId The ID of the candidate to vote for
    * @param sig The signature of the message to verify the voter's identity
    */
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

    /*
    * @notice Hashes and returns the hash of the token ID and candidate ID
    * @param tokenId The token ID of the voter
    * @param candidateId The ID of the candidate to vote for
    * @return The hash of the token ID and candidate ID
    */
    function getMessageHash(uint tokenId, string memory candidateId) public pure returns(bytes32 hash){
        hash = keccak256(abi.encodePacked(tokenId, candidateId));
    }

    /*
    * @dev Returns the Eth Signed message of the given hash
    * @param hash The hash to sign
    * @return The Eth Signed message of the hash
    */
    function _getEthSignedHash(bytes32 hash) internal pure returns (bytes32 signedHash){
        signedHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    /*
    * @notice Recovers the signer of the given Eth Signed message using the provided signature
    * @param ethsignedHash The Eth Signed message to use for recovery
    * @param signature The signature to recover the signer from
    * @return The address of the recovered signer
    */
        function _recover(bytes32 ethsignedHash, bytes memory signature) internal pure returns(address voter){
        (bytes32 r, bytes32 s, uint8 v) = _split(signature);
        voter = ecrecover(ethsignedHash, v, r, s);
    }

    /*
    * @dev Helper function for splitting the signature into r, s, and v components
    * @param sig The signature to split
    * @return The r, s, and v components of the signature
    */
    function _split(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v){
        require(sig.length == 65, "Invalid Sign");
        assembly{
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }


}