from web3 import Web3, EthereumTesterProvider
import subprocess
import json


w3 = Web3(EthereumTesterProvider())
res = w3.is_connected()
print(res)

w3 = Web3(Web3.EthereumTesterProvider())
w3.eth.default_account = w3.eth.accounts[0]

threshold = 3
number_of_members = 5
directory = '../data'

# Solidity source file path
source_file = f'../GlobalPublicParams.sol'
# Output directory
output_directory = '../build/'
# solc command
solc_command = [
    'solc',
    '--via-ir',
    source_file,
    '--bin',
    '--abi',
    '--optimize',
    '--overwrite',
    '-o',
    output_directory
]
# Run the solc command using subprocess
subprocess.run(solc_command)

# Load the compiled contract ABI and bytecode from the output directory
with open(f'{output_directory}/GlobalPublicParams.abi', 'r') as abi_file:
    contract_abi = json.load(abi_file)

with open(f'{output_directory}/GlobalPublicParams.bin', 'r') as bin_file:
    contract_bytecode = bin_file.read()

# Deploy the contract
MyContract = w3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)
tx_hash = MyContract.constructor().transact()
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

# Get the deployed contract address
contract_address = tx_receipt['contractAddress']
print("Contract deployed at: ", contract_address)
print("transaction receipt: ", tx_receipt)


# read all instances
with open(f'{directory}/all_instances.json', 'r') as file:
    json_data = file.read()

data_from_rust = json.loads(json_data)
instances = [[int.from_bytes(item, byteorder='little') for item in sublist] for sublist in data_from_rust]
truncated_len = 4 * number_of_members + 4
truncated_instances = [instance[:truncated_len] for instance in instances]

# read g2a
with open(f'{directory}/g2a.json', 'r') as file:
    json_data = file.read()

data_from_rust = json.loads(json_data)
assert len(data_from_rust) == 4, "should have 4 elements for g2a"
value = [int.from_bytes(bytes_list, byteorder='little') for bytes_list in data_from_rust]
gpk = {
    'X': value[0:2],
    'Y': value[2:]
}
#print("g2a = ", g2a)
# contract call to create gpk and vk_1, ... vk_n
gpp_contract = w3.eth.contract(
    address=contract_address,
    abi=contract_abi
)
# test contract call
return_value = gpp_contract.functions.createGpp(number_of_members, gpk, truncated_instances).call()
print("gpk = ", return_value[0])
#vks = return_value[1]
#for vk in vks:
#    print(f"({hex(vk[0]), hex(vk[1])})", vk)

# real transaction
tx_hash = gpp_contract.functions.createGpp(number_of_members, gpk, truncated_instances).transact()
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print("tx receipt ", tx_receipt)
