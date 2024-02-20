from web3 import Web3, EthereumTesterProvider
from solcx import compile_source
import json

w3 = Web3(EthereumTesterProvider())
res = w3.is_connected()
print(res)

directory = '../data'
threshold = 3
number_of_members = 5

contract_name = f'../Halo2Verifier-{threshold}-{number_of_members}-g2.sol'
with open(contract_name, 'r') as file:
    # Read the entire contents of the file into a string
    verifier = file.read()
#    print(verifier)


compiled_sol = compile_source(verifier,
    output_values=['abi', 'bin'],
    optimize=True
)

contract_id, contract_interface = compiled_sol.popitem()
print("contract id = ", contract_id)

bytecode = contract_interface['bin']
abi = contract_interface['abi']
w3 = Web3(Web3.EthereumTesterProvider())
w3.eth.default_account = w3.eth.accounts[0]

verifier_contract = w3.eth.contract(abi=abi, bytecode=bytecode)
tx_hash = verifier_contract.constructor().transact()
#print("tx hash =", tx_hash)
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print("tx receipt ", tx_receipt)

verifier = w3.eth.contract(
    address=tx_receipt.contractAddress,
    abi=abi
)
print("contract address =", tx_receipt.contractAddress)

# read proof
with open(f'{directory}/proof.dat', 'rb') as file:
    proof = file.read()

# read instance
with open(f'{directory}/instance.json', 'r') as file:
    json_data = file.read()

data_from_rust = json.loads(json_data)
instance = [int.from_bytes(bytes_list, byteorder='little') for bytes_list in data_from_rust]

print(f"size of proof {len(proof)}, num instance {len(instance)}")
# call() for testing
print("testing verify proof call")
return_value = verifier.functions.verifyProof(proof, instance).call()
print(f"Returned value: {return_value}")

# real transaction
tx_hash = verifier.functions.verifyProof(proof, instance).transact()
tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
print("tx receipt ", tx_receipt)

