from brownie import network, exceptions, config, AllFilesMetadata, AllUsersMetadata
from scripts.deploy import deploy_user_factory_and_files_factory
from scripts.helpful_scripts import (
    LOCAL_BLOCKCHAIN_ENVIRONMENTS,
    get_account
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


def test_validate_the_user_address():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    userContract = UserFactory.addUserContract(PublicKey, length, {"from": account})
    UserAddress = UserFactory.PublicKeyToMsgSender(PublicKey, {"from": account})
    print(UserAddress)
    # Assert
    assert account == UserAddress

def test_validate_publickey_existance():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    userContract = UserFactory.addUserContract(PublicKey, length, {"from": account})
    existance = UserFactory.PublicKeyToExistance(PublicKey)
    # Assert
    assert existance == True

def test_validate_owner_existance():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    userContract = UserFactory.addUserContract(PublicKey, length, {"from": account})
    existance = UserFactory.MsgSenderToExistance(account)
    # Assert 
    assert existance == True

def test_user_contract_validation():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    userContract = UserFactory.addUserContract(PublicKey, length, {"from": account})
    OwnerAddress = UserFactory.PublicKeyToUserSmartContract(PublicKey, {"from": account})
    owneraddress = UserFactory.MsgSenderToUserContract(account, {"from": account})
    # Assert
    assert OwnerAddress == owneraddress

def test_add_user_contract():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    userContract = tx.return_value
    Usercontract = UserFactory.PublicKeyToUserSmartContract(PublicKey, {"from": account})
    # Assert 
    assert userContract == Usercontract

def test_add_user_contract_twice():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    with pytest.raises(exceptions.VirtualMachineError):
        tx2 = UserFactory.addUserContract(PublicKey, length, {"from": account})
        tx2.wait(1)

def test_add_user_contract_from_other_account():
    # Arrange and Act
    account = get_account()
    account2 = get_account(index=1)
    UserFactory = AllUsersMetadata.deploy({"from": account})
    FileFactory = AllFilesMetadata.deploy(
        {"from": account},
        publish_source=config["networks"][network.show_active()]["verify"],
    )
    # Assert
    with pytest.raises(exceptions.VirtualMachineError):
        tx = FileFactory.setAddressAllUserMetadata(UserFactory, {"from": account2})
        tx.wait(1)

def test_add_foreign_user_contract():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    with pytest.raises(exceptions.VirtualMachineError):
        tx2 = UserFactory.addUserContract(PublicKey2, length, {"from": account})
        tx2.wait(1)

def test_retrieves_registration_key():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    tx2 = UserFactory.retrievesRegistrationKey(PublicKey, {"from": account})
    registrationencrypted = tx2.return_value
    print(type(registrationencrypted))
    print(registrationencrypted)
    encryptedfound = encryptedregistration[registrationencrypted]
    print(encryptedfound)
    # Assert
    assert encryptedfound == EncryptedRegistrationKey

def test_retrieves_foreign_registration_key():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    # Assert
    with pytest.raises(exceptions.VirtualMachineError):
        tx3 = UserFactory.retrievesRegistrationKey(PublicKey, {"from": account2})

def test_retrieves_msgsender():
    # Arrange
    UserFactory, FileFactory, PublicKey, EncryptedRegistrationKey, account, account2, filename, ipfs_address, PublicKey2, EncryptedRegistrationKey2, filename2, ipfs_address2, EncryptionKey, EncryptionKey2, SecretKey, SecretKey2 = arrange_statements()
    # Act
    encryptedregistration = []
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
    msgsender = UserFactory.retrieveMsgSender(PublicKey)
    # Assert
    assert msgsender == account


def test_retrieves_registration_key():
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
    registrationid = UserFactory.retrievesRegistrationKey(PublicKey, {"from": account})
    registrationid2 = UserFactory.retrievesRegistrationKey(PublicKey2, {"from": account2})
    extractedregistrationkey = encryptedregistration[registrationid]
    extractedregistrationkey2 = encryptedregistration[registrationid2]
    assert extractedregistrationkey == EncryptedRegistrationKey
    assert extractedregistrationkey2 == EncryptedRegistrationKey2

def test_retrieves_registration_key_from_another_account():
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
        registrationid = UserFactory.retrievesRegistrationKey(PublicKey, {"from": account2})
        registrationid2 = UserFactory.retrievesRegistrationKey(PublicKey2, {"from": account})