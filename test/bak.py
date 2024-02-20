from web3 import Web3, EthereumTesterProvider
from solcx import compile_source, set_solc_version, install_solc
import json

#install_solc('0.8.4')
#set_solc_version("0.8.4")

w3 = Web3(EthereumTesterProvider())
res = w3.is_connected()
print(res)

w3 = Web3(Web3.EthereumTesterProvider())
w3.eth.default_account = w3.eth.accounts[0]

#directory = './contracts_generated/verifier-one-3-5'
#directory = './contracts_generated/verifier-one-5-9'
#directory = 'CreateGpp'


with open(f'Pairing.sol', 'r') as file:
    pairing = file.read()

compiled_sol = compile_source(pairing,
    output_values=['abi', 'bin'],
    optimize=True
)
contract_id_pairing, contract_interface = compiled_sol.popitem()
pairing_abi = contract_interface['abi']
pairing_bin = contract_interface['bin']

# Deploy Pairing.sol
pairing_contract = w3.eth.contract(abi=pairing_abi, bytecode=pairing_bin)
tx_hash_pairing = pairing_contract.constructor().transact()
tx_receipt_pairing = w3.eth.wait_for_transaction_receipt(tx_hash_pairing)
pairing_address = tx_receipt_pairing['contractAddress']
print("pairing address =", pairing_address)

with open(f'GlobalPublicParams.sol', 'r') as file:
    # Read the entire contents of the file into a string
    createGpp = file.read()
#    print(verifier)


compiled_sol = compile_source(createGpp,
    output_values=['abi', 'bin'],
    optimize=True,
)
contract_id_gpp, contract_interface = compiled_sol.popitem()
print("gpp contract id = ", contract_id_gpp)
gpp_bin = contract_interface['bin']
gpp_abi = contract_interface['abi']

#linked_bin = bytecode.replace(f'__Pairing______________________________', pairing_address[2:])
create_gpp_contract = w3.eth.contract(abi=gpp_abi, bytecode=gpp_bin)
tx_hash = create_gpp_contract.constructor(pairing_address).transact()
#print("tx hash =", tx_hash)
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print("tx receipt ", tx_receipt)
print("contract address =", tx_receipt.contractAddress)


'''
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
'''
