import random
import string

import pytest
from eth_utils import to_text

from .solana_utils import write_transaction_to_holder_account, get_neon_balance, solana_client, \
    execute_transaction_steps_from_account_no_chain_id, neon_cli
from .utils.constants import TAG_FINALIZED_STATE
from .utils.contract import make_deployment_transaction, make_contract_call_trx
from .utils.ethereum import create_contract_address
from .utils.layouts import FINALIZED_STORAGE_ACCOUNT_INFO_LAYOUT
from .utils.transaction_checks import check_holder_account_tag, check_transaction_logs_have_text


class TestTransactionStepFromAccountNoChainId:

    def test_deploy_eof_contract(self, operator_keypair, holder_acc, treasury_pool, evm_loader, sender_with_tokens):
        eof = True
        contract_filename = "hello_world.binary"
        contract = create_contract_address(sender_with_tokens, evm_loader)

        signed_tx = make_deployment_transaction(
            sender_with_tokens, contract_filename, chain_id=None)
        write_transaction_to_holder_account(
            signed_tx, holder_acc, operator_keypair)

        contract_path = (
            pytest.EOF_CONTRACTS_PATH if eof else pytest.EOF_CONTRACTS_PATH) / contract_filename
        with open(contract_path, 'rb') as f:
            contract_code = f.read()

        steps_count = neon_cli().get_steps_count(
            evm_loader, sender_with_tokens, "deploy", contract_code.hex())
        resp = execute_transaction_steps_from_account_no_chain_id(operator_keypair, evm_loader, treasury_pool,
                                                                  holder_acc,
                                                                  [contract.solana_address,
                                                                   sender_with_tokens.solana_account_address],
                                                                  steps_count)
        check_holder_account_tag(
            holder_acc, FINALIZED_STORAGE_ACCOUNT_INFO_LAYOUT, TAG_FINALIZED_STATE)
        check_transaction_logs_have_text(
            resp.value.transaction.transaction.signatures[0], "exit_status=0x12")

    def test_call_eof_contract_function_with_neon_transfer(self, operator_keypair, treasury_pool,
                                                           sender_with_tokens, string_setter_eof_contract, holder_acc,
                                                           evm_loader):
        exit_status = "exit_status=0x12"
        transfer_amount = random.randint(1, 1000)

        sender_balance_before = get_neon_balance(
            solana_client, sender_with_tokens.solana_account_address)
        contract_balance_before = get_neon_balance(
            solana_client, string_setter_eof_contract.solana_address)

        text = ''.join(random.choice(string.ascii_letters) for _ in range(10))

        signed_tx = make_contract_call_trx(sender_with_tokens, string_setter_eof_contract, "set(string)", [text],
                                           value=transfer_amount, chain_id=None)
        write_transaction_to_holder_account(
            signed_tx, holder_acc, operator_keypair)

        resp = execute_transaction_steps_from_account_no_chain_id(operator_keypair, evm_loader, treasury_pool,
                                                                  holder_acc,
                                                                  [string_setter_eof_contract.solana_address,
                                                                   sender_with_tokens.solana_account_address]
                                                                  )

        check_holder_account_tag(
            holder_acc, FINALIZED_STORAGE_ACCOUNT_INFO_LAYOUT, TAG_FINALIZED_STATE)
        check_transaction_logs_have_text(
            resp.value.transaction.transaction.signatures[0], exit_status)

        sender_balance_after = get_neon_balance(
            solana_client, sender_with_tokens.solana_account_address)
        contract_balance_after = get_neon_balance(
            solana_client, string_setter_eof_contract.solana_address)
        assert sender_balance_before - transfer_amount == sender_balance_after
        assert contract_balance_before + transfer_amount == contract_balance_after

        assert text in to_text(
            neon_cli().call_contract_get_function(evm_loader, sender_with_tokens, string_setter_eof_contract,
                                                  "get()"))
