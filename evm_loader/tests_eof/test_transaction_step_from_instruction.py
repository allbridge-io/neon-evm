import random
import string
import time

import pytest
import solana
from eth_utils import to_text

from .solana_utils import get_neon_balance, solana_client, execute_transaction_steps_from_instruction, neon_cli, \
    send_transaction_step_from_instruction
from .utils.assert_messages import InstructionAsserts
from .utils.constants import TAG_FINALIZED_STATE
from .utils.contract import make_deployment_transaction, make_contract_call_trx
from .utils.ethereum import create_contract_address
from .utils.layouts import FINALIZED_STORAGE_ACCOUNT_INFO_LAYOUT
from .utils.transaction_checks import check_transaction_logs_have_text, check_holder_account_tag


class TestTransactionStepFromInstruction:

    @pytest.mark.parametrize("chain_id", [None, 111])
    def test_deploy_eof_contract(self, operator_keypair, holder_acc, treasury_pool, evm_loader, sender_with_tokens,
                                 chain_id):
        self.deploy_contract(operator_keypair, holder_acc, treasury_pool, evm_loader, sender_with_tokens,
                             chain_id, True)

    def deploy_contract(self, operator_keypair, holder_acc, treasury_pool, evm_loader, sender_with_tokens,
                        chain_id, eof):
        contract_filename = "small.binary"

        signed_tx = make_deployment_transaction(
            sender_with_tokens, contract_filename, chain_id=chain_id, eof=eof)
        contract = create_contract_address(sender_with_tokens, evm_loader)

        contract_path = (
            pytest.EOF_CONTRACTS_PATH if eof else pytest.CONTRACTS_PATH) / contract_filename
        with open(contract_path, 'rb') as f:
            contract_code = f.read()

        steps_count = neon_cli().get_steps_count(
            evm_loader, sender_with_tokens, "deploy", contract_code.hex())
        resp = execute_transaction_steps_from_instruction(operator_keypair, evm_loader, treasury_pool, holder_acc,
                                                          signed_tx, [contract.solana_address,
                                                                      sender_with_tokens.solana_account_address],
                                                          steps_count)

        check_holder_account_tag(
            holder_acc, FINALIZED_STORAGE_ACCOUNT_INFO_LAYOUT, TAG_FINALIZED_STATE)
        check_transaction_logs_have_text(resp.value, "exit_status=0x12")

    def test_call_eof_contract_function_without_neon_transfer(self, operator_keypair, treasury_pool, sender_with_tokens,
                                                              evm_loader, holder_acc, string_setter_eof_contract):
        self.call_contract_function_without_neon_transfer(operator_keypair, treasury_pool, sender_with_tokens,
                                                          evm_loader, holder_acc, string_setter_eof_contract, "exit_status=0x12")

    def call_contract_function_without_neon_transfer(self, operator_keypair, treasury_pool, sender_with_tokens,
                                                     evm_loader, holder_acc, string_setter_contract, exit_status):
        text = ''.join(random.choice(string.ascii_letters) for _ in range(10))
        signed_tx = make_contract_call_trx(
            sender_with_tokens, string_setter_contract, "set(string)", [text])

        resp = execute_transaction_steps_from_instruction(operator_keypair, evm_loader, treasury_pool, holder_acc,
                                                          signed_tx, [string_setter_contract.solana_address,
                                                                      sender_with_tokens.solana_account_address]
                                                          )

        check_holder_account_tag(
            holder_acc, FINALIZED_STORAGE_ACCOUNT_INFO_LAYOUT, TAG_FINALIZED_STATE)
        check_transaction_logs_have_text(resp.value, exit_status)

        assert text in to_text(
            neon_cli().call_contract_get_function(evm_loader, sender_with_tokens, string_setter_contract,
                                                  "get()"))

    def test_call_eof_contract_function_with_neon_transfer(self, operator_keypair, treasury_pool, sender_with_tokens,
                                                           evm_loader, holder_acc, string_setter_eof_contract):
        self.call_contract_function_with_neon_transfer(operator_keypair, treasury_pool, sender_with_tokens,
                                                       evm_loader, holder_acc, string_setter_eof_contract, "exit_status=0x12")

    def call_contract_function_with_neon_transfer(self, operator_keypair, treasury_pool, sender_with_tokens,
                                                  evm_loader, holder_acc, string_setter_contract, exit_status):
        transfer_amount = random.randint(1, 1000)

        sender_balance_before = get_neon_balance(
            solana_client, sender_with_tokens.solana_account_address)
        contract_balance_before = get_neon_balance(
            solana_client, string_setter_contract.solana_address)

        text = ''.join(random.choice(string.ascii_letters) for i in range(10))
        signed_tx = make_contract_call_trx(sender_with_tokens, string_setter_contract, "set(string)", [text],
                                           value=transfer_amount)

        resp = execute_transaction_steps_from_instruction(operator_keypair, evm_loader, treasury_pool, holder_acc,
                                                          signed_tx, [string_setter_contract.solana_address,
                                                                      sender_with_tokens.solana_account_address]
                                                          )

        check_holder_account_tag(
            holder_acc, FINALIZED_STORAGE_ACCOUNT_INFO_LAYOUT, TAG_FINALIZED_STATE)
        check_transaction_logs_have_text(resp.value, exit_status)

        sender_balance_after = get_neon_balance(
            solana_client, sender_with_tokens.solana_account_address)
        contract_balance_after = get_neon_balance(
            solana_client, string_setter_contract.solana_address)
        assert sender_balance_before - transfer_amount == sender_balance_after
        assert contract_balance_before + transfer_amount == contract_balance_after

        assert text in to_text(
            neon_cli().call_contract_get_function(evm_loader, sender_with_tokens, string_setter_contract,
                                                  "get()"))


class TestStepFromInstructionChangingOperatorsDuringTrxRun:

    def test_eof_next_operator_can_continue_trx_after_some_time(self, rw_lock_eof_contract, user_account, evm_loader,
                                                                operator_keypair, second_operator_keypair, treasury_pool,
                                                                new_holder_acc):
        self.next_operator_can_continue_trx_after_some_time(rw_lock_eof_contract, user_account, evm_loader,
                                                            operator_keypair, second_operator_keypair, treasury_pool,
                                                            new_holder_acc, "exit_status=0x12")

    def next_operator_can_continue_trx_after_some_time(self, rw_lock_contract, user_account, evm_loader,
                                                       operator_keypair, second_operator_keypair, treasury_pool,
                                                       new_holder_acc, exit_status):
        signed_tx = make_contract_call_trx(
            user_account, rw_lock_contract, 'update_storage_str(string)', ['text'])

        send_transaction_step_from_instruction(operator_keypair, evm_loader, treasury_pool, new_holder_acc,
                                               signed_tx,
                                               [user_account.solana_account_address,
                                                rw_lock_contract.solana_address], 1, operator_keypair)
        # next operator can't continue trx during OPERATOR_PRIORITY_SLOTS*0.4
        with pytest.raises(solana.rpc.core.RPCException,
                           match=rf"{InstructionAsserts.INVALID_OPERATOR_KEY}|{InstructionAsserts.INVALID_HOLDER_OWNER}"):
            send_transaction_step_from_instruction(second_operator_keypair, evm_loader, treasury_pool, new_holder_acc,
                                                   signed_tx,
                                                   [user_account.solana_account_address,
                                                    rw_lock_contract.solana_address], 500, second_operator_keypair)

        time.sleep(15)
        send_transaction_step_from_instruction(second_operator_keypair, evm_loader, treasury_pool, new_holder_acc,
                                               signed_tx,
                                               [user_account.solana_account_address,
                                                rw_lock_contract.solana_address], 500, second_operator_keypair)
        resp = send_transaction_step_from_instruction(second_operator_keypair, evm_loader, treasury_pool,
                                                      new_holder_acc, signed_tx,
                                                      [user_account.solana_account_address,
                                                       rw_lock_contract.solana_address], 1, second_operator_keypair)
        check_transaction_logs_have_text(resp.value, exit_status)
