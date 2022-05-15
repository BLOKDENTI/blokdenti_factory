// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import "../../contracts/FileContract.sol";
import "../../contracts/factories/AllUsersMetadata.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract AllFilesMetadata is Ownable {
    mapping(string => address) public PublicKeyToOwnerFile;
    mapping(FileContract => bool) public FileContractToFileType;
    mapping(uint256 => FileContract) public IdToFileContract;
    mapping(FileContract => string) public FileContractToPublicKey;

    address public addressAllUserMetadata;
    bool StoreUserFactory;
    uint256 public ids;

    function setAddressAllUserMetadata(address _addressAllUserMetadata)
        external
        onlyOwner
    {
        require(StoreUserFactory == false);
        addressAllUserMetadata = _addressAllUserMetadata;
        StoreUserFactory = true;
    }

    function retrunIdGlobal() public view returns (uint256) {
        return ids;
    }

    function retrieveMsgSender(string memory _publickey)
        internal
        view
        returns (address)
    {
        AllUsersMetadata UserFactory = AllUsersMetadata(addressAllUserMetadata);
        address msg_sender;
        msg_sender = UserFactory.retrieveMsgSender(_publickey);
        (_publickey);
        return msg_sender;
    }

    function AddUserFile(
        string memory _FileName,
        string memory _IPFSAddress,
        string memory _OwnerPublicKey
    ) public returns (uint256) {
        FileContract fileContract = new FileContract();
        fileContract.addFileMetadata(
            _FileName,
            _IPFSAddress,
            _OwnerPublicKey,
            msg.sender
        );
        AllUsersMetadata UserFactory = AllUsersMetadata(addressAllUserMetadata);
        require(
            UserFactory.retrieveMsgSender(_OwnerPublicKey) == msg.sender,
            "You are not the owner of the public key"
        );
        PublicKeyToOwnerFile[_OwnerPublicKey] = msg.sender;
        FileContractToPublicKey[fileContract] = _OwnerPublicKey;
        uint256 FileId = ids;
        IdToFileContract[FileId] = fileContract;
        ids++;
        string memory filename = fileContract.RetrievesFileName();
        UserFactory.AddFileDeployedAddress(FileId, _FileName, _OwnerPublicKey);
        return FileId;
    }

    function deleteRecieverFile(
        string memory _publickey,
        uint256 _id,
        string memory _filename,
        address _reciever_address
    ) public {
        AllUsersMetadata UserFactory = AllUsersMetadata(addressAllUserMetadata);
        require(
            verifyId(_publickey, _id) == true &&
                UserFactory.validFile(_filename, _id, msg.sender) == true
        );
        UserFactory.deleteFileStruct(
            _publickey,
            _id,
            _reciever_address,
            msg.sender
        );
    }

    function retrievesEncryptionKeyId(
        string memory _publickey,
        uint256 _id,
        string memory _filename
    ) public returns (uint256) {
        AllUsersMetadata UserFactory = AllUsersMetadata(addressAllUserMetadata);
        require(
            UserFactory.validFile(_filename, _id, msg.sender) == true &&
                verifyId(_publickey, _id) == true
        );
        FileContract fileContract = IdToFileContract[_id];
        address OwnerFile = fileContract.RetrievesOwner();
        if (msg.sender == OwnerFile) {
            uint256 encryptionKeyId;
            encryptionKeyId = fileContract.mapping_to_encryptionkeyid(
                _publickey
            );
            return encryptionKeyId;
        } else {
            bool recieverAccess = fileContract.verifyReciever(msg.sender);
            require(recieverAccess == true);
            uint256 encryptionKeyId;
            encryptionKeyId = fileContract.mapping_to_encryptionkeyid(
                _publickey
            );
            return encryptionKeyId;
        }
    }

    function RetrieveSecretKey(
        string memory _publickey,
        uint256 _id,
        string memory _filename
    ) public view returns (string memory) {
        FileContract filecontract = IdToFileContract[_id];
        require(
            verifyId(_publickey, _id) == true &&
                FileContractToFileType[filecontract] == true
        );
        string memory SecretKey;
        SecretKey = filecontract.RetrievesSecretKey();
        return SecretKey;
    }

    function verifyId(string memory _publickey, uint256 _id)
        public
        view
        returns (bool)
    {
        FileContract filecontract = FileContract(IdToFileContract[_id]);
        string memory publickey = FileContractToPublicKey[filecontract];
        bool result = compareStrings(publickey, _publickey);
        return result;
    }

    function verifyTypeFile(string memory _publickey, uint256 _id)
        public
        view
        returns (bool)
    {
        require(verifyId(_publickey, _id) == true);
        FileContract fileContract = IdToFileContract[_id];
        bool FileType;
        FileType = fileContract.verifyType();
        return FileType;
    }

    function compareStrings(string memory a, string memory b)
        public
        pure
        returns (bool)
    {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    function RetrieveIPFSAddress(
        string memory _publickey,
        uint256 _id,
        string memory _filename
    ) public returns (string memory) {
        AllUsersMetadata UserFactory = AllUsersMetadata(addressAllUserMetadata);
        require(
            verifyId(_publickey, _id) == true &&
                UserFactory.validFile(_filename, _id, msg.sender) == true
        );
        FileContract filecontract = IdToFileContract[_id];
        string memory ipfsAddress;
        ipfsAddress = filecontract.RetrievesIPFSAddress();
        return ipfsAddress;
    }

    function setShareMode(
        string memory _publicKey,
        uint256 _id,
        string memory _filename,
        string memory _reciver_publickey,
        uint256 _EncryptionKeyId
    ) public returns (address) {
        bool verify_id = verifyId(_publicKey, _id);
        require(
            verify_id == true && msg.sender == PublicKeyToOwnerFile[_publicKey]
        );
        address reciever_address;
        reciever_address = retrieveMsgSender(_reciver_publickey);
        AllUsersMetadata UserFactory = AllUsersMetadata(addressAllUserMetadata);
        UserFactory.AddFileDeployedAddress(_id, _filename, _publicKey);
        FileContract fileContract = IdToFileContract[_id];
        fileContract.addReciever(reciever_address);
        string memory filename = fileContract.RetrievesFileName();
        UserFactory.AddFileDeployedAddress(_id, filename, _reciver_publickey);
        if (fileContract.verifyEncryptionKey() == false) {
            fileContract.addEncryptionKeyId(_EncryptionKeyId);
            FileContractToFileType[fileContract] = false;
            return reciever_address;
        } else return reciever_address;
    }

    function returnFileContract(string memory _publickey, uint256 _id)
        public
        returns (FileContract)
    {
        bool verify_id = verifyId(_publickey, _id);
        require(
            verify_id == true && msg.sender == PublicKeyToOwnerFile[_publickey]
        );
        FileContract filecontract = IdToFileContract[_id];
        return filecontract;
    }

    function setPublicMode(
        string memory _publicKey,
        uint256 _id,
        string memory _SecretKey
    ) public {
        bool verify_id = verifyId(_publicKey, _id);
        require(
            verify_id == true && PublicKeyToOwnerFile[_publicKey] == msg.sender
        );
        FileContract fileContract = IdToFileContract[_id];
        fileContract.addSecretKey(_SecretKey);
        FileContractToFileType[fileContract] = true;
    }

    function ThisAddress() public view returns (address) {
        return address(this);
    }
}
