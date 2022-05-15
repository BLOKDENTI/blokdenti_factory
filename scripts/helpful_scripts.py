from pickletools import uint1
from brownie import network, accounts, config, Contract

NON_FORKED_LOCAL_BLOCKCHAIN_ENVIRONMENTS = ["hardhat", "development", "ganache"]
LOCAL_BLOCKCHAIN_ENVIRONMENTS = [
    "development",
    "ganache-local",
    "mainnet-fork",
    "binance-fork",
    "matic-fork",
]

# contract_to_mock = {
#     "all_files_metadata": MockV3Aggregator,
# }

contract_to_address = {
    "all_files_metadata": "0x895Ee61C3D6E6A7227e2A0ec6cE2470074034121",
    "all_users_metadata": "0x895Ee61C3D6E6A7227e2A0ec6cE2470074034121",
}

publickeys = {
    # These are false public keys
    "public_key1": "c8e1028cad7b105814d4a2e0e292f5f7904aad7b6cbc46a5",
    "public_key2": "75d46a3859410f7cce054c24068637e85a45dfab48b4dc47",
}

secrets_key = {
    # These are false secret keys please don't use them
    "secret_key1": "KdkiwrdgDAD",
    "secret_key2": "KaIjsk1dks9",
}


def get_public_key(index=uint1):
    # dictonary
    if index == 1:
        return publickeys["public_key1"]
    if index == 2:
        return publickeys["public_key2"]


def get_contract_address(index=uint1):
    # dictonary
    if index == 1:
        return contract_to_address["all_files_metadata"]
    if index == 2:
        return contract_to_address["all_users_metadata"]


def get_secret_key(index=uint1):
    # dictonary
    if index == 1:
        return secrets_key["secret_key1"]
    if index == 2:
        return secrets_key["secret_key2"]


def get_account(index=None, id=None):
    if index:
        return accounts[index]
    if network.show_active() in LOCAL_BLOCKCHAIN_ENVIRONMENTS:
        return accounts[0]
    if id:
        return accounts.load(id)
    return accounts.add(config["wallets"]["from_key"])


# def get_contract(contract_name):
#     """If you want to use this function, go to the brownie config and add a new entry for
#     the contract that you want to be able to 'get'. Then add an entry in the in the variable 'contract_to_mock'.
#     You'll see examples like the 'link_token'.
#         This script will then either:
#             - Get a address from the config
#             - Or deploy a mock to use for a network that doesn't have it
#         Args:
#             contract_name (string): This is the name that is refered to in the
#             brownie config and 'contract_to_mock' variable.
#         Returns:
#             brownie.network.contract.ProjectContract: The most recently deployed
#             Contract of the type specificed by the dictonary. This could be either
#             a mock or the 'real' contract on a live network.
#     """
#     contract_type = contract_to_mock[contract_name]
#     if network.show_active() in LOCAL_BLOCKCHAIN_ENVIRONMENTS:
#         if len(contract_type) <= 0:
#             deploy_mocks()
#         contract = contract_type[-1]
#     else:
#         contract_address = config["networks"][network.show_active()][contract_name]
#         # address
#         # ABI
#         contract = Contract.from_abi(
#             contract_type._name, contract_address, contract_type.abi
#         )
#     return contract


def get_verify_status():
    verify = (
        config["networks"][network.show_active()]["verify"]
        if config["networks"][network.show_active()].get("verify")
        else False
    )
    return verify


def deploy_mocks():
    """
    Use this script if you want to deploy mocks to a testnet
    """
    print(f"The active network is {network.show_active()}")
    print("Deploying Mocks...")
    account = get_account()