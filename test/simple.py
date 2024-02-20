from web3 import Web3, EthereumTesterProvider
from solcx import compile_source
import json


w3 = Web3(EthereumTesterProvider())
res = w3.is_connected()
print(res)

w3 = Web3(Web3.EthereumTesterProvider())
w3.eth.default_account = w3.eth.accounts[0]

# Load the compiled contract ABI and bytecode from the output directory
with open('build/GlobalPublicParams.abi', 'r') as abi_file:
    contract_abi = json.load(abi_file)

with open('build/GlobalPublicParams.bin', 'r') as bin_file:
    contract_bytecode = bin_file.read()

# Deploy the contract
MyContract = w3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)
tx_hash = MyContract.constructor().transact()
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

# Get the deployed contract address
contract_address = tx_receipt['contractAddress']

print("Contract deployed at:", contract_address)

