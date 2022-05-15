// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.12;

import "../contracts/FileContract.sol";

contract UserContract {
    mapping(string => uint256) public fileNameToId;
    mapping(uint256 => uint256) idFileToLength;
    mapping(uint256 => filesWithMe) idFileToStruct;
    address private OwnerAddress;
    string public UserPublicKey;
    uint256 public EncryptedRegistrationId;
    bool existance = false;
    filesWithMe[] public FilesMe;

    struct filesWithMe {
        uint256 id;
        string filename;
        string publickey;
        bool _isDeleted;
    }

    function addUserMetadata(
        string memory _UserPublicKey,
        uint256 _encryptedRegistrationId
    ) public {
        UserPublicKey = _UserPublicKey;
        EncryptedRegistrationId = _encryptedRegistrationId;
        existance = true;
    }

    function verifyContract() public view returns (bool) {
        return existance;
    }

    function addFileContract(
        uint256 _id,
        string memory _filename,
        string memory _publickey
    ) external {
        require(compareString(_publickey, UserPublicKey) == true);
        fileNameToId[_filename] = _id;
        FilesMe.push(
            filesWithMe({
                id: _id,
                filename: _filename,
                publickey: UserPublicKey,
                _isDeleted: false
            })
        );
        idFileToLength[_id] = FilesMe.length - 1;
        idFileToStruct[_id] = filesWithMe(_id, _filename, UserPublicKey, false);
    }

    function deletestruct(uint256 _id) external {
        delete FilesMe[idFileToLength[_id]];
        filesWithMe storage fileDelete = idFileToStruct[_id];
        fileDelete._isDeleted = true;
    }

    function RegistrationKeyToValidate() public view returns (uint256) {
        return EncryptedRegistrationId;
    }

    function compareString(string memory a, string memory b)
        internal
        pure
        returns (bool)
    {
        return (keccak256(abi.encodePacked((a))) ==
            keccak256(abi.encodePacked((b))));
    }

    function verifyIdFile(string memory _filename, uint256 _id)
        external
        view
        returns (bool)
    {
        bool isFileDeleted = idFileToStruct[_id]._isDeleted;
        require(isFileDeleted == false);
        uint256 id = fileNameToId[_filename];
        if (id == _id) {
            return true;
        } else return true;
    }
}
