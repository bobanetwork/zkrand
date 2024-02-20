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
source_file = f'../PseudoRand.sol'
# Output directory
output_directory = '../build/'
# solc command
solc_command = [
    'solc',
    '--via-ir',
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
with open(f'{output_directory}/PseudoRand.abi', 'r') as abi_file:
    contract_abi = json.load(abi_file)

with open(f'{output_directory}/PseudoRand.bin', 'r') as bin_file:
    contract_bytecode = bin_file.read()

# Deploy the contract
MyContract = w3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)
tx_hash = MyContract.constructor().transact()
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

# Get the deployed contract address
contract_address = tx_receipt['contractAddress']
print("Contract deployed at: ", contract_address)
print("transaction receipt: ", tx_receipt)

pseudo_contract = w3.eth.contract(
    address=contract_address,
    abi=contract_abi
)

def bytes_to_ints(list):
    integers = [int.from_bytes(bytes, byteorder='little') for bytes in list]
    return integers


# read instance
directory = '../data'

with open(f'{directory}/eval.json', 'r') as file:
    json_data = file.read()

data_from_rust = json.loads(json_data)
sigma_bytes = data_from_rust['value']
assert len(sigma_bytes) == 2, "should have 2 elements for G1"
sigma_value = bytes_to_ints(sigma_bytes)
sigma = {
    'X': sigma_value[0],
    'Y': sigma_value[1],
}

proof_bytes = data_from_rust['proof']
assert len(proof_bytes) == 2, "should have 2 elements for G1"
proof_value = bytes_to_ints(proof_bytes)
proof = {
    'z': proof_value[0],
    'c': proof_value[1],
}

vk_bytes = data_from_rust['vk']
assert len(vk_bytes) == 2, "should have 2 elements for G1"
vk_value = bytes_to_ints(vk_bytes)
vk = {
    'X': vk_value[0],
    'Y': vk_value[1],
}

hash_bytes = data_from_rust['hash']
assert len(hash_bytes) == 2, "should have 2 elements for G1"
hash_value = bytes_to_ints(hash_bytes)
hash = {
    'X': hash_value[0],
    'Y': hash_value[1],
}

# test contract call
message = b"first random"
return_value = pseudo_contract.functions.verifyPartialEval(message, sigma, proof, vk).call()
print("\nverify partial evaluation = ", return_value)

# real transaction
tx_hash = pseudo_contract.functions.verifyPartialEval(message, sigma, proof, vk).transact()
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print("tx receipt ", tx_receipt)

return_value = pseudo_contract.functions.verifyPartialEvalFast(hash, sigma, proof, vk).call()
print("\nverify partial evaluation fast = ", return_value)

# real transaction
tx_hash = pseudo_contract.functions.verifyPartialEvalFast(hash, sigma, proof, vk).transact()
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print("tx receipt ", tx_receipt)


with open(f'{directory}/pseudo.json', 'r') as file:
    json_data = file.read()

data_from_rust = json.loads(json_data)
assert len(data_from_rust) == 2, "should have 2 elements for pseudo random value"
value = [int.from_bytes(bytes_list, byteorder='little') for bytes_list in data_from_rust]
pseudo = {
    'X': value[0],
    'Y': value[1]
}

with open(f'{directory}/g2a.json', 'r') as file:
    json_data = file.read()

data_from_rust = json.loads(json_data)
assert len(data_from_rust) == 4, "should have 4 elements for gpk"
value = [int.from_bytes(bytes_list, byteorder='little') for bytes_list in data_from_rust]
gpk = {
    'X': value[0:2],
    'Y': value[2:]
}

# test contract call
return_value = pseudo_contract.functions.verifyPseudoRand(message, pseudo, gpk).call()
print("\nverify pseudo random value = ", return_value)

# real transaction
tx_hash = pseudo_contract.functions.verifyPseudoRand(message, pseudo, gpk).transact()
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print("tx receipt ", tx_receipt)

return_value = pseudo_contract.functions.verifyPseudoRandFast(hash, pseudo, gpk).call()
print("\nverify pseudo random value fast = ", return_value)

# real transaction
tx_hash = pseudo_contract.functions.verifyPseudoRandFast(hash, pseudo, gpk).transact()
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print("tx receipt ", tx_receipt)
