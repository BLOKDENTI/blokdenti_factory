from brownie import network, exceptions
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
    account3 = get_account(index=2)
    account4 = get_account(index=4)
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
    # Account 3
    publickey3, privatekey3 = rsa.newkeys(1024)
    PublicKey3 = publickey3.save_pkcs1().decode("utf-8")
    PrivateKey3 = privatekey3.save_pkcs1().decode("utf-8")
    registration_key3 = "me caes bien".encode("utf-8")
    filename3 = "iwanttobehirebygoogle.txt"
    ipfs_address3 = "ipfs://Qmd2YrWTLKfzmX4DWuSPNNLkN1jznkhhEVG6zSSVXqLoaA?filename=google_contract_encrypted.txt"
    EncryptedRegistrationKey3 = rsa.encrypt(registration_key3, publickey3)
    SecretKey3 = random_string(24)
    EncryptionKey3 = rsa.encrypt(SecretKey3.encode(), publickey3)
    # Account 4
    publickey4, privatekey4 = rsa.newkeys(1024)
    PublicKey4 = publickey4.save_pkcs1().decode("utf-8")
    PrivateKey4 = privatekey4.save_pkcs1().decode("utf-8")
    registration_key4 = "mexican food is the best".encode("utf-8")
    filename4 = "iwanttobehirebygoogle.txt"
    ipfs_address4 = "ipfs://Qmd2YrWTLKfzmX4DWuSPNNLkN1jznkhhEVG6zSSVXqLoaA?filename=google_contract_encrypted.txt"
    EncryptedRegistrationKey4 = rsa.encrypt(registration_key4, publickey4)
    SecretKey4 = random_string(24)
    EncryptionKey4 = rsa.encrypt(SecretKey4.encode(), publickey4)
    if network.show_active() not in LOCAL_BLOCKCHAIN_ENVIRONMENTS:
        pytest.skip("Only for local testing!")
    return UserFactory, FileFactory, PublicKey, PublicKey3, PublicKey2 , PublicKey4, PrivateKey3, PrivateKey4, EncryptedRegistrationKey, EncryptedRegistrationKey3, EncryptedRegistrationKey4 , account, account2, account3, account4, filename, filename2, filename3, filename4, ipfs_address, ipfs_address2, ipfs_address3, ipfs_address4, EncryptedRegistrationKey2, EncryptedRegistrationKey3, EncryptedRegistrationKey4, EncryptionKey, EncryptionKey2, EncryptionKey3 , EncryptionKey4, SecretKey, SecretKey2, SecretKey3, SecretKey4

def test_allfilesmetadata_and_allusermetadata():
    # Arrange
        # First we execute the two factories, and inializate the variables
    UserFactory, FileFactory, PublicKey, PublicKey3, PublicKey2 , PublicKey4, PrivateKey3, PrivateKey4, EncryptedRegistrationKey, EncryptedRegistrationKey3, EncryptedRegistrationKey4 , account, account2, account3, account4, filename, filename2, filename3, filename4, ipfs_address, ipfs_address2, ipfs_address3, ipfs_address4, EncryptedRegistrationKey2, EncryptedRegistrationKey3, EncryptedRegistrationKey4, EncryptionKey, EncryptionKey2, EncryptionKey3 , EncryptionKey4, SecretKey, SecretKey2, SecretKey3, SecretKey4 = arrange_statements()
    # Act
        # Second we use UserFactory to add four users that we will use
    encryptedregistration = []
         # User 1
    encryptedregistration.append(EncryptedRegistrationKey)
    length = len(encryptedregistration) - 1
    tx = UserFactory.addUserContract(PublicKey, length, {"from": account})
    tx.wait(1)
        # User 2
    encryptedregistration.append(EncryptedRegistrationKey2)
    length2 = len(encryptedregistration) - 1
    tx2 = UserFactory.addUserContract(PublicKey2, length2, {"from": account2})
    tx2.wait(1)
        # User 3
    encryptedregistration.append(EncryptedRegistrationKey3)
    length3 = len(encryptedregistration) - 1
    tx3 = UserFactory.addUserContract(PublicKey3, length3, {"from": account3})
    tx3.wait(1)
        # User 4
    encryptedregistration.append(EncryptedRegistrationKey4)
    length4 = len(encryptedregistration) - 1
    tx4 = UserFactory.addUserContract(PublicKey4, length4, {"from": account4})
    tx4.wait(1)
        # After of that the user will want to add a new file, using FileFactory add a new files with their differents variables
        # in order to add a new file the user needs to be validated already so the FileFactory call UserFactory to get "msg.sender" that allows the user to add a new file 
        # User 1 file
    tx5 = FileFactory.AddUserFile(filename, ipfs_address, PublicKey, {"from": account})
    tx5.wait(1)
    fileid = tx5.return_value
        # User 2 file
    tx6 = FileFactory.AddUserFile(filename2, ipfs_address2, PublicKey2, {"from": account2})
    tx6.wait(1)
    fileid2 = tx6.return_value
        # if the user 1 want to share him file metadata, he use the setShareMode function and provides the user public key with whom the file needs to share with (in this case the user 2)
    encryptionkeys = []
        # User 1 set share mode in him file (he share the file with user 2 and user 3)
    encryptionkeys.append(EncryptionKey)
    length5 = len(encryptionkeys) - 1
    tx7 = FileFactory.setShareMode(PublicKey, fileid, filename, PublicKey2, length5, {"from": account})
    tx7.wait(1)
    tx8 = FileFactory.setShareMode(PublicKey, fileid, filename, PublicKey3, length5, {"from": account})
    tx8.wait(1)
        # now if the user 2 want to share him file to all people but the people can't know who is the owner, then the user use "setPublicMode" that allows to every single user registered in the app to access the file
    tx9 = FileFactory.setPublicMode(PublicKey2, fileid2, SecretKey2, {"from": account2})
    tx9.wait(1)
        # then if the user 2 and 3 want to access the file of the user 1 then he first retrieves ipfs address that is the file uploaded in the cloud, and even if the user owner want to open him file in the application need the same process
        # User 2 extract
    tx10 = FileFactory.RetrieveIPFSAddress(PublicKey, fileid, filename, {"from": account2})
    tx10.wait(1)
    ipfs_address_extracted = tx10.return_value 
        # Now imagine that the owner of the file regrets sharing user 3 and removes it from the share list
    tx18 = FileFactory.deleteRecieverFile(PublicKey, fileid, filename, account3, {"from": account})
        # Onwer of the file extract
    tx12 = FileFactory.RetrieveIPFSAddress(PublicKey, fileid, filename, {"from": account})
    tx12.wait(1)
    ipfs_address_extracted3 = tx12.return_value
        # therefore in order to decrypt the file they need to have encryptionkey too
        # User 2 extract
    tx13 = FileFactory.retrievesEncryptionKeyId(PublicKey, fileid, filename, {"from": account2})
    encryptionkey = tx13.return_value
    extractedencryptionkey = encryptionkeys[encryptionkey]
        # File owner extract
    tx15 = FileFactory.retrievesEncryptionKeyId(PublicKey, fileid, filename, {"from": account})
    encryptionkey3 = tx15.return_value
    extractedencryptionkey3 = encryptionkeys[encryptionkey3]
    # But now the user 4 can access to the file of the user 2 becuase it is public type, and to get access it, everyone needs the secret key which is extracted from Blockchain
    secretkey = FileFactory.RetrieveSecretKey(PublicKey2, fileid2, filename2, {"from": account4})
    # Assert
        # Now suppose the user 4 want to extract ipfs and encryptionkey but he isn't allowed to do that, it is going to return an error
    with pytest.raises(exceptions.VirtualMachineError):
        tx16 = FileFactory.RetrieveIPFSAddress(PublicKey, fileid, filename, {"from": account4})
        tx16.wait(1)
        tx17 = FileFactory.retrievesEncryptionKeyId(PublicKey2, fileid2, filename2, {"from": account})
        # After that the user 3 want to access the file, but he is no longer allowed to do that
    with pytest.raises(exceptions.VirtualMachineError):
        tx14 = FileFactory.retrievesEncryptionKeyId(PublicKey2, fileid2, filename2, {"from": account3})
        encryptionkey2 = tx14.return_value
        tx11 = FileFactory.RetrieveIPFSAddress(PublicKey, fileid, filename, {"from": account3})
        tx11.wait(1)
    assert ipfs_address_extracted == ipfs_address
    assert ipfs_address_extracted3 == ipfs_address
    assert extractedencryptionkey == EncryptionKey
    assert extractedencryptionkey3 == EncryptionKey
    assert SecretKey2 == secretkey
    