from brownie import network, exceptions
from scripts.deploy import deploy_user_factory_and_files_factory
from scripts.helpful_scripts import (
    LOCAL_BLOCKCHAIN_ENVIRONMENTS,
    get_account,
)
import pytest
import rsa
import string
import random

def arrange_statements():
    account = get_account()
    account2 = get_account(index=1)
    UserFactory, FileFactory = deploy_user_factory_and_files_factory()
    def random_string(length=24):
        character_set = string.ascii_letters
        return "".join(random.choice(character_set) for i in range(length))
    # Account 1
    publickey, privatekey = rsa.newkeys(1024)
    PublicKey = publickey.save_pkcs1().decode("utf-8")
    PrivateKey = privatekey.save_pkcs1().decode("utf-8")
    registration_key = "viva_mexico".encode("utf-8")
    filename = "myfile.txt"
    ipfs_address = "ipfs://Qmd9MCGtdVz2miNumBHDbvj8bigSgTwnr4SbyH6DNnpWdt?filename=0-PUG.json"
    EncryptedRegistrationKey = rsa.encrypt(registration_key, publickey)
    SecretKey = random_string(24)
    EncryptionKey = rsa.encrypt(SecretKey.encode(), publickey)
    # Account 2
    publickey2, privatekey2 = rsa.newkeys(1024)
    PublicKey2 = publickey2.save_pkcs1().decode("utf-8")
    PrivateKey2 = privatekey2.save_pkcs1().decode("utf-8")
    registration_key2 = "más energia".encode("utf-8")
    filename2 = "supersecret.txt"
    ipfs_address2 = "ipfs://Qma7qkBFfiBrouK4GFPjARCtevxu24mr9NDDLYJw5tj2do?filename=0-Beethoven.json"
    EncryptedRegistrationKey2 = rsa.encrypt(registration_key2, publickey2)
    SecretKey2 = random_string(24)
    EncryptionKey2 = rsa.encrypt(SecretKey2.encode(), publickey2)
    if network.show_active() not in LOCAL_BLOCKCHAIN_ENVIRONMENTS:
        pytest.skip("Only for local testing!")
    return UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2

def test_publickey_mapping():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    tx2 = FileFactory.AddUserFile(filename, ipfs_address, PublicKey, {"from": account})
    tx2.wait(1)
    OwnerAddress = FileFactory.PublicKeyToOwnerFile(PublicKey, {"from": account})
    # Assert 
    assert OwnerAddress == account

def test_file_id():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    tx2 = FileFactory.AddUserFile(filename, ipfs_address, PublicKey, {"from": account})
    tx2.wait(1)
    fileid = tx2.return_value
    verifed = FileFactory.verifyId(PublicKey, fileid, {"from": account})
    FileContract = FileFactory.IdToFileContract(fileid, {"from": account})
    # Assert 
    assert verifed == True


def test_share_mode():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    encryptedregistration.append(EncryptedRegistrationKey2)
    length2 = len(encryptedregistration) - 1
    tx2 = UserFactory.addUserContract(PublicKey2, length2, {"from": account2})
    tx2.wait(1)
    tx3 = FileFactory.AddUserFile(filename, ipfs_address, PublicKey, {"from": account})
    tx3.wait(1)
    fileid = tx3.return_value
    tx4 = FileFactory.AddUserFile(filename2, ipfs_address2, PublicKey2, {"from": account2})
    tx4.wait(1)
    fileid2 = tx4.return_value
    encryptionkeys = []
    encryptionkeys.append(EncryptionKey)
    length3 = len(encryptionkeys) - 1
    tx5 = FileFactory.setShareMode(PublicKey, fileid, filename, PublicKey2, length3, {"from": account})
    tx5.wait(1)
    encryptionkeys.append(EncryptionKey2)
    length4 = len(encryptionkeys) - 1
    tx6 = FileFactory.setShareMode(PublicKey2, fileid2, filename2, PublicKey, length4, {"from": account2})
    tx6.wait(1)
    FileContract = FileFactory.IdToFileContract(fileid, {"from": account})
    FileContract2 = FileFactory.IdToFileContract(fileid2, {"from": account2})
    FileType = FileFactory.FileContractToFileType(FileContract, {"from": account})
    FileType2 = FileFactory.FileContractToFileType(FileContract2, {"from": account2})
    # Assert
    assert FileType == False
    assert FileType2 == False

def test_file_contract_to_publickey():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    print(PublicKey)
    print(PublicKey2)
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    tx2 = FileFactory.AddUserFile(filename, ipfs_address, PublicKey, {"from": account})
    tx2.wait(1)
    fileid = tx2.return_value
    FileContract = FileFactory.IdToFileContract(fileid, {"from": account})
    publickey = FileFactory.FileContractToPublicKey(FileContract, {"from": account})
    # Assert
    assert PublicKey == publickey

def test_verify_ipfs_address():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    tx2 = FileFactory.AddUserFile(filename, ipfs_address, PublicKey, {"from": account})
    tx2.wait(1)
    fileid = tx2.return_value
    tx3 = FileFactory.RetrieveIPFSAddress(PublicKey, fileid, filename, {"from": account})
    tx3.wait(1)
    ipfsaddress = tx3.return_value
    # Assert
    assert ipfs_address == ipfsaddress


def test_try_to_set_twice_allusermetadata():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    with pytest.raises(exceptions.VirtualMachineError):
        error = FileFactory.setAddressAllUserMetadata(UserFactory, {"from": account})

def test_try_to_user_other_publickey():
    # Arrange 
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    encryptedregistration.append(EncryptedRegistrationKey2)
    length2 = len(encryptedregistration) - 1
    tx2 = UserFactory.addUserContract(PublicKey2, length2, {"from": account2})
    tx2.wait(1)
    with pytest.raises(exceptions.VirtualMachineError):
        error = FileFactory.AddUserFile(filename, ipfs_address, PublicKey, {"from": account2})

def test_extract_file_from_other_user():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Assert
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    encryptedregistration.append(EncryptedRegistrationKey2)
    length2 = len(encryptedregistration) - 1
    tx2 = UserFactory.addUserContract(PublicKey2, length2, {"from": account2})
    tx2.wait(1)
    tx3 = FileFactory.AddUserFile(filename, ipfs_address, PublicKey, {"from": account})
    tx3.wait(1)
    fileid = tx3.return_value
    # Assert
    with pytest.raises(exceptions.VirtualMachineError):
        error = FileFactory.RetrieveIPFSAddress(PublicKey, fileid, filename, {"from": account2})
        erro2 = FileFactory.returnFileContract(PublicKey, fileid, {"from": account2})

def test_set_new_mode_and_verify_it():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    encryptedregistration.append(EncryptedRegistrationKey2)
    length2 = len(encryptedregistration) - 1
    tx2 = UserFactory.addUserContract(PublicKey2, length2, {"from": account2})
    tx2.wait(1)
    tx3 = FileFactory.AddUserFile(filename, ipfs_address, PublicKey, {"from": account})
    tx3.wait(1)
    fileid = tx3.return_value
    tx4 = FileFactory.AddUserFile(filename2, ipfs_address2, PublicKey2, {"from": account2})
    tx4.wait(1)
    fileid2 = tx4.return_value
    encryptionkeys = []
    encryptionkeys.append(EncryptionKey)
    length3 = len(encryptionkeys) - 1
    tx5 = FileFactory.setShareMode(PublicKey, fileid, filename, PublicKey2, length3, {"from": account})
    tx5.wait(1)
    encryptionkeys.append(EncryptionKey2)
    length4 = len(encryptionkeys) - 1
    tx6 = FileFactory.setShareMode(PublicKey2, fileid2, filename2, PublicKey, length4, {"from": account2})
    tx6.wait(1)
    FileContract = FileFactory.IdToFileContract(fileid, {"from": account})
    FileContract2 = FileFactory.IdToFileContract(fileid2, {"from": account2})
    tx7 = FileFactory.setPublicMode(PublicKey, fileid, SecretKey, {"from": account})
    tx7.wait(1)
    tx8 = FileFactory.setPublicMode(PublicKey2, fileid2, SecretKey2, {"from": account2})
    tx8.wait(1)
    FileType = FileFactory.FileContractToFileType(FileContract, {"from": account})
    FileType2 = FileFactory.FileContractToFileType(FileContract2, {"from": account2})
    # Assert 
    assert FileType == True
    assert FileType2 == True

def test_try_to_set_up_new_mode_from_other_user():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    encryptedregistration.append(EncryptedRegistrationKey2)
    length2 = len(encryptedregistration) - 1
    tx2 = UserFactory.addUserContract(PublicKey2, length2, {"from": account2})
    tx2.wait(1)
    tx3 = FileFactory.AddUserFile(filename, ipfs_address, PublicKey, {"from": account})
    tx3.wait(1)
    fileid = tx3.return_value
    with pytest.raises(exceptions.VirtualMachineError):
        tx3 = FileFactory.setPublicMode(PublicKey, fileid, SecretKey, {"from": account2})

def test_verify_file_type():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    encryptedregistration.append(EncryptedRegistrationKey2)
    length2 = len(encryptedregistration) - 1
    tx2 = UserFactory.addUserContract(PublicKey2, length2, {"from": account2})
    tx2.wait(1)
    tx3 = FileFactory.AddUserFile(filename, ipfs_address, PublicKey, {"from": account})
    tx3.wait(1)
    fileid = tx3.return_value
    tx4 = FileFactory.AddUserFile(filename2, ipfs_address2, PublicKey2, {"from": account2})
    tx4.wait(1)
    fileid2 = tx4.return_value
    encryptionkeys = []
    encryptionkeys.append(EncryptionKey)
    length3 = len(encryptionkeys) - 1
    tx5 = FileFactory.setShareMode(PublicKey, fileid, filename, PublicKey2, length3, {"from": account})
    tx5.wait(1)
    tx6 = FileFactory.setPublicMode(PublicKey2, fileid2, SecretKey, {"from": account2})
    tx6.wait(1)
    FileType = FileFactory.verifyTypeFile(PublicKey, fileid, {"from": account})
    FileType2 = FileFactory.verifyTypeFile(PublicKey2, fileid2, {"from": account2})
    # Assert
    assert FileType == False
    assert FileType2 == True    

def test_retrieves_secret_key():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    encryptedregistration.append(EncryptedRegistrationKey2)
    length2 = len(encryptedregistration) - 1
    tx2 = UserFactory.addUserContract(PublicKey2, length2, {"from": account2})
    tx2.wait(1)
    tx4 = FileFactory.AddUserFile(filename2, ipfs_address2, PublicKey2, {"from": account2})
    tx4.wait(1)
    fileid2 = tx4.return_value
    tx6 = FileFactory.setPublicMode(PublicKey2, fileid2, SecretKey2, {"from": account2})
    tx6.wait(1)
    FileContract2 = FileFactory.IdToFileContract(fileid2, {"from": account2})
    secretkey = FileFactory.RetrieveSecretKey(PublicKey2, fileid2, filename2, {"from": account2})
    # Assert
    assert secretkey == SecretKey2

def test_publickey_to_encryptionkey_from_owner():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    encryptedregistration.append(EncryptedRegistrationKey2)
    length2 = len(encryptedregistration) - 1
    tx2 = UserFactory.addUserContract(PublicKey2, length2, {"from": account2})
    tx2.wait(1)
    publickey = tx.return_value
    tx3 = FileFactory.AddUserFile(filename, ipfs_address, PublicKey, {"from": account})
    tx3.wait(1)
    fileid = tx3.return_value
    tx4 = FileFactory.AddUserFile(filename2, ipfs_address2, PublicKey2, {"from": account2})
    tx4.wait(1)
    fileid2 = tx4.return_value
    encryptionkeys = []
    encryptionkeys.append(EncryptionKey)
    length3 = len(encryptionkeys) - 1
    tx5 = FileFactory.setShareMode(PublicKey, fileid, filename, PublicKey2, length3, {"from": account})
    tx5.wait(1)
    encryptionkeys.append(EncryptionKey2)
    length4 = len(encryptionkeys) - 1
    tx6 = FileFactory.setShareMode(PublicKey2, fileid2, filename2, PublicKey, length4, {"from": account2})
    tx6.wait(1)
    tx7 = FileFactory.retrievesEncryptionKeyId(PublicKey, fileid, filename, {"from": account})
    encryptionkey = tx7.return_value
    print(encryptionkey)
    tx8 = FileFactory.retrievesEncryptionKeyId(PublicKey2, fileid2, filename2, {"from": account2})
    encryptionkey2 = tx8.return_value
    print(encryptionkey2)
    extractedencryptionkey = encryptionkeys[encryptionkey]
    extractedencryptionkey2 = encryptionkeys[encryptionkey2]
    # Assert
    assert extractedencryptionkey == EncryptionKey
    assert extractedencryptionkey2 == EncryptionKey2

def test_retrieves_encryptionkey_from_reciever():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    encryptedregistration.append(EncryptedRegistrationKey2)
    length2 = len(encryptedregistration) - 1
    tx2 = UserFactory.addUserContract(PublicKey2, length2, {"from": account2})
    tx2.wait(1)
    publickey = tx.return_value
    tx3 = FileFactory.AddUserFile(filename, ipfs_address, PublicKey, {"from": account})
    tx3.wait(1)
    fileid = tx3.return_value
    tx4 = FileFactory.AddUserFile(filename2, ipfs_address2, PublicKey2, {"from": account2})
    tx4.wait(1)
    fileid2 = tx4.return_value
    encryptionkeys = []
    encryptionkeys.append(EncryptionKey)
    length3 = len(encryptionkeys) - 1
    tx5 = FileFactory.setShareMode(PublicKey, fileid, filename, PublicKey2, length3, {"from": account})
    tx5.wait(1)
    encryptionkeys.append(EncryptionKey2)
    length4 = len(encryptionkeys) - 1
    tx6 = FileFactory.setShareMode(PublicKey2, fileid2, filename2, PublicKey, length4, {"from": account2})
    tx6.wait(1)
    tx7 = FileFactory.retrievesEncryptionKeyId(PublicKey, fileid, filename, {"from": account2})
    encryptionkey = tx7.return_value
    print(encryptionkey)
    tx8 = FileFactory.retrievesEncryptionKeyId(PublicKey2, fileid2, filename2, {"from": account})
    encryptionkey2 = tx8.return_value
    print(encryptionkey2)
    extractedencryptionkey = encryptionkeys[encryptionkey]
    extractedencryptionkey2 = encryptionkeys[encryptionkey2]
    # Assert
    assert extractedencryptionkey == EncryptionKey
    assert extractedencryptionkey2 == EncryptionKey2

def test_retrieves_encryptionkey_from_foreign_account():
    # Arrange
    account3 = get_account(index=2)
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    encryptedregistration.append(EncryptedRegistrationKey2)
    length2 = len(encryptedregistration) - 1
    tx2 = UserFactory.addUserContract(PublicKey2, length2, {"from": account2})
    tx2.wait(1)
    publickey = tx.return_value
    tx3 = FileFactory.AddUserFile(filename, ipfs_address, PublicKey, {"from": account})
    tx3.wait(1)
    fileid = tx3.return_value
    tx4 = FileFactory.AddUserFile(filename2, ipfs_address2, PublicKey2, {"from": account2})
    tx4.wait(1)
    fileid2 = tx4.return_value
    encryptionkeys = []
    encryptionkeys.append(EncryptionKey)
    length3 = len(encryptionkeys) - 1
    tx5 = FileFactory.setShareMode(PublicKey, fileid, filename, PublicKey2, length3, {"from": account})
    tx5.wait(1)
    encryptionkeys.append(EncryptionKey2)
    length4 = len(encryptionkeys) - 1
    tx6 = FileFactory.setShareMode(PublicKey2, fileid2, filename2, PublicKey, length4, {"from": account2})
    tx6.wait(1)
    with pytest.raises(exceptions.VirtualMachineError):
        tx7 = FileFactory.retrievesEncryptionKeyId(PublicKey, fileid, filename, {"from": account3})
        tx8 = FileFactory.retrievesEncryptionKeyId(PublicKey2, fileid2, filename2, {"from": account3})

def test_delete_file_struct():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    encryptedregistration.append(EncryptedRegistrationKey2)
    length2 = len(encryptedregistration) - 1
    tx2 = UserFactory.addUserContract(PublicKey2, length2, {"from": account2})
    tx2.wait(1)
    publickey = tx.return_value
    tx3 = FileFactory.AddUserFile(filename, ipfs_address, PublicKey, {"from": account})
    tx3.wait(1)
    fileid = tx3.return_value
    encryptionkeys = []
    encryptionkeys.append(EncryptionKey)
    length3 = len(encryptionkeys) - 1
    tx4 = FileFactory.setShareMode(PublicKey, fileid, filename, PublicKey2, length3, {"from": account})
    tx4.wait(1)
    tx5 = FileFactory.deleteRecieverFile(PublicKey, fileid, filename, account2, {"from": account})
    tx5.wait(1)
    # try to retrieves encryption key id once delete of the file struct
    with pytest.raises(exceptions.VirtualMachineError):
        tx6 = FileFactory.retrievesEncryptionKeyId(PublicKey, fileid, filename, {"from": account2})
        tx6.wait(1)

def test_delete_file_from_another_account():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    encryptedregistration.append(EncryptedRegistrationKey2)
    length2 = len(encryptedregistration) - 1
    tx2 = UserFactory.addUserContract(PublicKey2, length2, {"from": account2})
    tx2.wait(1)
    publickey = tx.return_value
    tx3 = FileFactory.AddUserFile(filename, ipfs_address, PublicKey, {"from": account})
    tx3.wait(1)
    fileid = tx3.return_value
    encryptionkeys = []
    encryptionkeys.append(EncryptionKey)
    length3 = len(encryptionkeys) - 1
    tx4 = FileFactory.setShareMode(PublicKey, fileid, filename, PublicKey2, length3, {"from": account})
    tx4.wait(1)
    with pytest.raises(exceptions.VirtualMachineError):
        tx5 = FileFactory.deleteRecieverFile(PublicKey, fileid, filename, account2, {"from": account2})
        tx5.wait(1)

def test_retrieves_secret_key_from_another_account():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    encryptedregistration.append(EncryptedRegistrationKey2)
    length2 = len(encryptedregistration) - 1
    tx2 = UserFactory.addUserContract(PublicKey2, length2, {"from": account2})
    tx2.wait(1)
    tx4 = FileFactory.AddUserFile(filename2, ipfs_address2, PublicKey2, {"from": account2})
    tx4.wait(1)
    fileid2 = tx4.return_value
    tx6 = FileFactory.setPublicMode(PublicKey2, fileid2, SecretKey2, {"from": account2})
    tx6.wait(1)
    secretkey = FileFactory.RetrieveSecretKey(PublicKey2, fileid2, filename2, {"from": account})
    # Assert
    assert secretkey == SecretKey2

def test_return_id_global():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    encryptedregistration.append(EncryptedRegistrationKey2)
    length2 = len(encryptedregistration) - 1
    tx2 = UserFactory.addUserContract(PublicKey2, length2, {"from": account2})
    tx2.wait(1)
    tx3 = FileFactory.AddUserFile(filename, ipfs_address, PublicKey, {"from": account})
    tx3.wait(1)
    fileid = tx3.return_value
    tx4 = FileFactory.AddUserFile(filename2, ipfs_address2, PublicKey2, {"from": account2})
    tx4.wait(1)
    globalindex = FileFactory.retrunIdGlobal()
    assert globalindex == 2

def test_verify_id():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    encryptedregistration.append(EncryptedRegistrationKey2)
    length2 = len(encryptedregistration) - 1
    tx2 = UserFactory.addUserContract(PublicKey2, length2, {"from": account2})
    tx2.wait(1)
    tx3 = FileFactory.AddUserFile(filename, ipfs_address, PublicKey, {"from": account})
    tx3.wait(1)
    fileid = tx3.return_value
    tx4 = FileFactory.AddUserFile(filename2, ipfs_address2, PublicKey2, {"from": account2})
    tx4.wait(1)
    fileid2 = tx4.return_value
    verified = FileFactory.verifyId(PublicKey, fileid, {"from": account})
    verified2 = FileFactory.verifyId(PublicKey2, fileid2, {"from": account2})
    assert verified == True
    assert verified2 == True

def test_return_file_contract():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    encryptedregistration.append(EncryptedRegistrationKey2)
    length2 = len(encryptedregistration) - 1
    tx2 = UserFactory.addUserContract(PublicKey2, length2, {"from": account2})
    tx2.wait(1)
    tx3 = FileFactory.AddUserFile(filename, ipfs_address, PublicKey, {"from": account})
    tx3.wait(1)
    fileid = tx3.return_value
    tx4 = FileFactory.AddUserFile(filename2, ipfs_address2, PublicKey2, {"from": account2})
    tx4.wait(1)
    fileid2 = tx4.return_value
    tx5 = FileFactory.returnFileContract(PublicKey, fileid, {"from": account})
    tx5.wait(1)
    Filecontract = tx5.return_value
    tx6 = FileFactory.returnFileContract(PublicKey2, fileid2, {"from": account2})
    tx6.wait(1)
    Filecontract2 = tx6.return_value
    publickey = FileFactory.FileContractToPublicKey(Filecontract, {"from": account})
    publickey2 = FileFactory.FileContractToPublicKey(Filecontract2, {"from": account2})
    assert PublicKey == publickey
    assert PublicKey2 == publickey2

def test_return_file_contract_from_another_contract():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    encryptedregistration.append(EncryptedRegistrationKey2)
    length2 = len(encryptedregistration) - 1
    tx2 = UserFactory.addUserContract(PublicKey2, length2, {"from": account2})
    tx2.wait(1)
    tx3 = FileFactory.AddUserFile(filename, ipfs_address, PublicKey, {"from": account})
    tx3.wait(1)
    fileid = tx3.return_value
    tx4 = FileFactory.AddUserFile(filename2, ipfs_address2, PublicKey2, {"from": account2})
    tx4.wait(1)
    fileid2 = tx4.return_value
    with pytest.raises(exceptions.VirtualMachineError):
        tx5 = FileFactory.returnFileContract(PublicKey, fileid, {"from": account2})
        tx5.wait(1)
        Filecontract = tx5.return_value
        tx6 = FileFactory.returnFileContract(PublicKey2, fileid2, {"from": account})
        tx6.wait(1)

def test_retrieves_a_fake_ipfs_address():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    with pytest.raises(exceptions.VirtualMachineError):
        tx3 = FileFactory.RetrieveIPFSAddress(PublicKey, 0, filename, {"from": account})
        tx3.wait(1)