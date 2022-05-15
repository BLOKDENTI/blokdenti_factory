// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.12;

import "../UserContract.sol";
import "../factories/AllFilesMetadata.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract AllUsersMetadata is Ownable {
    mapping(string => UserContract) public PublicKeyToUserSmartContract;
    mapping(string => address) public PublicKeyToMsgSender;
    mapping(address => UserContract) public MsgSenderToUserContract;
    mapping(address => bool) public MsgSenderToExistance;
    mapping(string => bool) public PublicKeyToExistance;

    function addUserContract(
        string memory _UserPublicKey,
        uint256 _encryptedRegistrationId
    ) public returns (UserContract) {
        require(
            MsgSenderToExistance[msg.sender] == false &&
                PublicKeyToExistance[_UserPublicKey] == false
        );
        UserContract userContract = new UserContract();
        userContract.addUserMetadata(_UserPublicKey, _encryptedRegistrationId);
        PublicKeyToUserSmartContract[_UserPublicKey] = userContract;
        PublicKeyToMsgSender[_UserPublicKey] = msg.sender;
        MsgSenderToUserContract[msg.sender] = userContract;
        MsgSenderToExistance[msg.sender] = true;
        PublicKeyToExistance[_UserPublicKey] = true;
        return userContract;
    }

    function retrievesRegistrationKey(string memory _publickey)
        public
        view
        returns (uint256)
    {
        require(msg.sender == PublicKeyToMsgSender[_publickey]);
        UserContract usercontract = UserContract(
            PublicKeyToUserSmartContract[_publickey]
        );
        uint256 _encryptedRegistrationId = usercontract
            .RegistrationKeyToValidate();
        return _encryptedRegistrationId;
    }

    function ThisAddress() public view returns (address) {
        return address(this);
    }

    function retrieveMsgSender(string memory _publickey)
        external
        view
        returns (address)
    {
        address msg_sender;
        msg_sender = PublicKeyToMsgSender[_publickey];
        return msg_sender;
    }

    function AddFileDeployedAddress(
        uint256 _id,
        string memory _filename,
        string memory _publickey
    ) external {
        require(PublicKeyToExistance[_publickey] == true);
        UserContract userContract = PublicKeyToUserSmartContract[_publickey];
        userContract.addFileContract(_id, _filename, _publickey);
    }

    function validFile(
        string memory _filename,
        uint256 _id,
        address _address
    ) external view returns (bool) {
        UserContract userContract = MsgSenderToUserContract[_address];
        bool verified = userContract.verifyIdFile(_filename, _id);
        return verified;
    }

    function deleteFileStruct(
        string memory _publickey,
        uint256 _id,
        address _reciever_address,
        address _owner_address
    ) external {
        require(_owner_address == PublicKeyToMsgSender[_publickey]);
        UserContract userContract = MsgSenderToUserContract[_reciever_address];
        userContract.deletestruct(_id);
    }
}
