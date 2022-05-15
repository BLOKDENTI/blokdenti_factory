from brownie import AllFilesMetadata, config, AllUsersMetadata, network
from scripts.helpful_scripts import (
    get_account,
    get_public_key,
    get_secret_key,
)

def deploy_user_factory_and_files_factory():
    account = get_account()
    UserFactory = AllUsersMetadata.deploy({"from": account})
    FileFactory = AllFilesMetadata.deploy(
        {"from": account},
        publish_source=config["networks"][network.show_active()]["verify"],
    )
    tx = FileFactory.setAddressAllUserMetadata(UserFactory, {"from": account})
    tx.wait(1)
    return UserFactory, FileFactory


def main():
    deploy_user_factory_and_files_factory()