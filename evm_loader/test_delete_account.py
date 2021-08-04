from solana.publickey import PublicKey
from solana.transaction import AccountMeta, TransactionInstruction, Transaction
import unittest
from eth_utils import abi
from spl.token.instructions import get_associated_token_address

from eth_tx_utils import make_keccak_instruction_data, make_instruction_data_from_tx
from solana_utils import *

CONTRACTS_DIR = os.environ.get("CONTRACTS_DIR", "evm_loader/")
ETH_TOKEN_MINT_ID: PublicKey = PublicKey(os.environ.get("ETH_TOKEN_MINT"))
evm_loader_id = os.environ.get("EVM_LOADER")

class EvmLoaderTestsNewAccount(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        print("\ntest_delete_account.py setUpClass")

        wallet = WalletAccount(wallet_path())
        cls.loader = EvmLoader(wallet, evm_loader_id)
        cls.acc = wallet.get_acc()

        # Create ethereum account for user account
        cls.caller_ether = eth_keys.PrivateKey(cls.acc.secret_key()).public_key.to_canonical_address()
        (cls.caller, cls.caller_nonce) = cls.loader.ether2program(cls.caller_ether)

        if getBalance(cls.caller) == 0:
            print("Create caller account...")
            _ = cls.loader.createEtherAccount(cls.caller_ether)
            print("Done\n")

        print('Account:', cls.acc.public_key(), bytes(cls.acc.public_key()).hex())
        print("Caller:", cls.caller_ether.hex(), cls.caller_nonce, "->", cls.caller,
              "({})".format(bytes(PublicKey(cls.caller)).hex()))
    
    def deploy_contract(self):
        print("deploy contract: ")
        program_and_code = self.loader.deployChecked(
                CONTRACTS_DIR+'SelfDestructContract.binary',
                self.caller,
                self.caller_ether
            )
        owner_contract = program_and_code[0]
        contract_code = program_and_code[2]
        print("contract id: ", owner_contract, solana2ether(owner_contract).hex())
        print("code id: ", contract_code)
        return (owner_contract, contract_code)

    def make_transactions(self, owner_contract, contract_code, nonce, position):
        if nonce is None:
            nonce = getTransactionCount(client, self.caller)

        tx = {
            'to': solana2ether(owner_contract),
            'value': 0,
            'gas': 9999999,
            'gasPrice': 1,
            'nonce': nonce,
            'data': abi.function_signature_to_4byte_selector('callSelfDestruct()'),
            'chainId': 111
        }
        (_from_addr, sign, msg) = make_instruction_data_from_tx(tx, self.acc.secret_key())
        trx_data = self.caller_ether + sign + msg
        keccak_instruction = make_keccak_instruction_data(position, len(msg))
        
        keccak_tx = self.sol_instr_keccak(keccak_instruction)
        call_tx = self.sol_instr_call(trx_data, owner_contract, contract_code)
        return (keccak_tx, call_tx)

    def sol_instr_keccak(self, keccak_instruction):
        return  TransactionInstruction(program_id="KeccakSecp256k11111111111111111111111111111", data=keccak_instruction, keys=[
                    AccountMeta(pubkey=self.caller, is_signer=False, is_writable=False),
                ])
    
    def sol_instr_call(self, trx_data, owner_contract, contract_code):
        return TransactionInstruction(program_id=self.loader.loader_id, data=bytearray.fromhex("05") + trx_data, keys=[
                    AccountMeta(pubkey=owner_contract, is_signer=False, is_writable=True),
                    AccountMeta(pubkey=get_associated_token_address(PublicKey(owner_contract), ETH_TOKEN_MINT_ID), is_signer=False, is_writable=True),
                    AccountMeta(pubkey=contract_code, is_signer=False, is_writable=True),
                    AccountMeta(pubkey=self.caller, is_signer=False, is_writable=True),
                    AccountMeta(pubkey=get_associated_token_address(PublicKey(self.caller), ETH_TOKEN_MINT_ID), is_signer=False, is_writable=True),
                    AccountMeta(pubkey=PublicKey("Sysvar1nstructions1111111111111111111111111"), is_signer=False, is_writable=False),
                    AccountMeta(pubkey=self.loader.loader_id, is_signer=False, is_writable=False),
                    AccountMeta(pubkey=PublicKey("SysvarC1ock11111111111111111111111111111111"), is_signer=False, is_writable=False),
                ])


    def test_fail_on_tx_after_delete(self):
        # Check that contact accounts marked invalid on deletion and couldn't be used in same block
        (owner_contract, contract_code) = self.deploy_contract()

        init_nonce = getTransactionCount(client, self.caller)
        (keccak_tx_1, call_tx_1) = self.make_transactions(owner_contract, contract_code, init_nonce, 1)
        init_nonce += 1
        (keccak_tx_2, call_tx_2) = self.make_transactions(owner_contract, contract_code, init_nonce, 3)

        trx = Transaction().add( keccak_tx_1 ).add( call_tx_1 ).add( keccak_tx_2 ).add( call_tx_2 )

        err = "invalid account data for instruction"
        with self.assertRaisesRegex(Exception,err):
            result = send_transaction(client, trx, self.acc)
            print(result)


    def test_success_deletion(self):
        (owner_contract, contract_code) = self.deploy_contract()

        caller_balance_pre = getBalance(self.caller)
        contract_balance_pre = getBalance(owner_contract)
        code_balance_pre = getBalance(contract_code)

        (keccak_tx_1, call_tx_1) = self.make_transactions(owner_contract, contract_code, None, 1)
        trx = Transaction().add( keccak_tx_1 ).add( call_tx_1 )

        send_transaction(client, trx, self.acc)

        caller_balance_post = getBalance(self.caller)
        contract_balance_post = getBalance(owner_contract)
        code_balance_post = getBalance(contract_code)

        # Check that lamports moved from code accounts to caller
        self.assertEqual(caller_balance_post, contract_balance_pre + caller_balance_pre + code_balance_pre)
        self.assertEqual(contract_balance_post, 0)
        self.assertEqual(code_balance_post, 0)

        err = "Can't get information about"
        with self.assertRaisesRegex(Exception,err):
            nonce = getTransactionCount(client, owner_contract)
            print(nonce)



if __name__ == '__main__':
    unittest.main()