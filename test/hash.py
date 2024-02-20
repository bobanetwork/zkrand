from web3 import Web3, EthereumTesterProvider
import subprocess
#import os
import json


w3 = Web3(EthereumTesterProvider())
res = w3.is_connected()
print(res)

w3 = Web3(Web3.EthereumTesterProvider())
w3.eth.default_account = w3.eth.accounts[0]

# Set the working directory to the directory containing the Python script
#script_directory = os.path.dirname(os.path.realpath(__file__))
#os.chdir(script_directory)

# Solidity source file path
source_file = f'../TestHash.sol'
# Output directory
output_directory = '../build/'
# solc command
solc_command = [
    'solc',
    source_file,
    '--abi',
    '--bin',
    '--optimize',
    '--overwrite',
    '-o',
    output_directory
]
# Run the solc command using subprocess
subprocess.run(solc_command)


# Load the compiled contract ABI and bytecode from the output directory
with open(f'{output_directory}/TestHash.abi', 'r') as abi_file:
    contract_abi = json.load(abi_file)

with open(f'{output_directory}/TestHash.bin', 'r') as bin_file:
    contract_bytecode = bin_file.read()

# Deploy the contract
MyContract = w3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)
tx_hash = MyContract.constructor().transact()
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

# Get the deployed contract address
contract_address = tx_receipt['contractAddress']
print("Contract deployed at: ", contract_address)
print("transaction receipt: ", tx_receipt)

hash_contract = w3.eth.contract(
    address=contract_address,
    abi=contract_abi
)

return_value = hash_contract.functions.keccak().call()
print("\nkeccak test = ", return_value)
for byte in return_value[1]:
    print(byte, end=", ")


# test contract call
domain = b"evm compatible version"
message = b"hello world"
return_value = hash_contract.functions.hashToField(domain, message).call()
print("\n\nhash to field = ", return_value)

return_value = hash_contract.functions.hashToG1(domain, message).call()
print("\n\nhash to G1 = ", return_value)

# real transaction
tx_hash = hash_contract.functions.hashToG1(domain, message).transact()
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print("tx receipt ", tx_receipt)