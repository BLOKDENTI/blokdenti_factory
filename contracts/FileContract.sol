// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import "./factories/AllFilesMetadata.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract FileContract is Ownable {
    mapping(string => uint256) private publicKeyToEncryptionKeyId;
    mapping(address => uint256) public recieverAddressToRecieverId;
    string private FileName;
    string private IPFSAddress;
    string public OwnerPublicKey;
    string public SecretKey;
    uint256 public EncryptionKeyId;
    uint256 id;
    bool public PublicType;
    bool public setEncryptionKey;
    address ownerFile;
    address[] public RecieversFile;

    function addReciever(address _reciever_address) external onlyOwner {
        RecieversFile.push(_reciever_address);
        recieverAddressToRecieverId[_reciever_address] =
            RecieversFile.length -
            1;
    }

    function verifyReciever(address msg_sender) public view returns (bool) {
        address recieverAddress = RecieversFile[
            recieverAddressToRecieverId[msg_sender]
        ];
        return recieverAddress == msg_sender;
    }

    function addFileMetadata(
        string memory _FileName,
        string memory _IPFSAddress,
        string memory _PublicKey,
        address _owner
    ) external {
        FileName = _FileName;
        IPFSAddress = _IPFSAddress;
        OwnerPublicKey = _PublicKey;
        ownerFile = _owner;
    }

    function compareString(string memory a, string memory b)
        internal
        pure
        returns (bool)
    {
        return (keccak256(abi.encodePacked((a))) ==
            keccak256(abi.encodePacked((b))));
    }

    function verifyType() external view returns (bool) {
        return PublicType;
    }

    function mapping_to_encryptionkeyid(string memory _publickey)
        external
        view
        returns (uint256)
    {
        uint256 encryptionKeyId = publicKeyToEncryptionKeyId[_publickey];
        return encryptionKeyId;
    }

    function addEncryptionKeyId(uint256 _EncryptionKeyId) external onlyOwner {
        require(setEncryptionKey == false);
        EncryptionKeyId = _EncryptionKeyId;
        SecretKey = "";
        PublicType = false;
        setEncryptionKey = true;
        publicKeyToEncryptionKeyId[OwnerPublicKey] = _EncryptionKeyId;
    }

    function addSecretKey(string memory _SecretKey) external {
        bool _false = compareString(SecretKey, _SecretKey);
        require(_false == false);
        PublicType = true;
        SecretKey = _SecretKey;
        EncryptionKeyId = 0;
        setEncryptionKey = false;
    }

    function RetrievesIPFSAddress() external view returns (string memory) {
        return (IPFSAddress);
    }

    function RetrievesSecretKey() external view returns (string memory) {
        return (SecretKey);
    }

    function RetrievesFileName() external view returns (string memory) {
        return (FileName);
    }

    function RetrievesFileId() external view returns (uint256) {
        return (id);
    }

    function RetrievesOwner() external view returns (address) {
        return (ownerFile);
    }

    function verifyEncryptionKey() external view returns (bool) {
        return (setEncryptionKey);
    }
}
