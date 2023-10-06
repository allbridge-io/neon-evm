import random
import string
import time
import pytest
import solana

from eth_utils import abi, to_text

from solana.rpc.commitment import Confirmed
from solana.rpc.types import TxOpts
from solana.rpc.api import Client

from .solana_utils import solana_client, get_neon_balance, execute_trx_from_instruction, neon_cli, execute_transaction_steps_from_account, \
    execute_transaction_steps_from_instruction, send_transaction_step_from_instruction, execute_transaction_steps_from_account_no_chain_id, \
    write_transaction_to_holder_account, send_transaction_step_from_account, get_solana_balance, get_transaction_count, send_transaction

from .utils.contract import make_contract_call_trx, make_deployment_transaction, deploy_contract
from .utils.transaction_checks import check_transaction_logs_have_text, check_holder_account_tag
from .utils.ethereum import create_contract_address, make_eth_transaction
from .utils.storage import create_holder
from .utils.assert_messages import InstructionAsserts
from .utils.constants import TAG_FINALIZED_STATE, SOLANA_URL
from .utils.layouts import FINALIZED_STORAGE_ACCOUNT_INFO_LAYOUT
from .utils.instructions import TransactionWithComputeBudget, make_ExecuteTrxFromAccountDataIterativeOrContinue, make_PartialCallOrContinueFromRawEthereumTX

def test_emulate_eof_contract_deploy(user_account, evm_loader):
    contract_path = pytest.EOF_CONTRACTS_PATH / "hello_world.binary"

    with open(contract_path, 'rb') as f:
        contract_code = f.read()

    result = neon_cli().emulate(
        evm_loader.loader_id,
        user_account.eth_address.hex(),
        'deploy',
        contract_code.hex()
    )
    assert result[
        'exit_status'] == 'succeed', f"The 'exit_status' field is not succeed. Result: {result}"
    assert result[
        'steps_executed'] > 0, f"Steps executed amount is not 0. Result: {result}"
    assert result['used_gas'] > 0, f"Used gas is less than 0. Result: {result}"

def test_emulate_call_eof_contract_function(user_account, evm_loader, operator_keypair, treasury_pool):
    contract = deploy_contract(operator_keypair, user_account,
                                "hello_world.binary", evm_loader, treasury_pool)

    assert contract.eth_address
    assert get_solana_balance(contract.solana_address) > 0
    data = abi.function_signature_to_4byte_selector('call_hello_world()')
    result = neon_cli().emulate(
        evm_loader.loader_id,
        user_account.eth_address.hex(),
        contract.eth_address.hex(),
        data.hex()
    )

    assert result[
        'exit_status'] == 'succeed', f"The 'exit_status' field is not succeed. Result: {result}"
    assert result['steps_executed'] > 0, f"Steps executed amount is 0. Result: {result}"
    assert result['used_gas'] > 0, f"Used gas is less than 0. Result: {result}"
    assert "Hello World" in to_text(result["result"])

def test_cancel_trx_eof(evm_loader, user_account, rw_lock_eof_contract, operator_keypair, treasury_pool):
    func_name = abi.function_signature_to_4byte_selector(
        'unchange_storage(uint8,uint8)')
    data = (func_name + bytes.fromhex("%064x" %
            0x01) + bytes.fromhex("%064x" % 0x01))

    eth_transaction = make_eth_transaction(
        rw_lock_eof_contract.eth_address,
        data,
        user_account.solana_account,
        user_account.solana_account_address,
    )
    storage_account = create_holder(operator_keypair)
    instruction = eth_transaction.rawTransaction
    trx = TransactionWithComputeBudget(operator_keypair)
    trx.add(
        make_PartialCallOrContinueFromRawEthereumTX(
            instruction,
            operator_keypair, evm_loader, storage_account, treasury_pool.account, treasury_pool.buffer, 1,
            [
                rw_lock_eof_contract.solana_address,
                user_account.solana_account_address,
            ]
        )
    )
    solana_client = Client(SOLANA_URL)

    receipt = send_transaction(solana_client, trx, operator_keypair)
    assert receipt.value.transaction.meta.err is None
    user_nonce = get_transaction_count(
        solana_client, user_account.solana_account_address)

    result = neon_cli().call(
        f"cancel-trx --evm_loader={evm_loader.loader_id} {storage_account}")
    assert result["transaction"] is not None
    assert user_nonce < get_transaction_count(
        solana_client, user_account.solana_account_address)


class TestExecuteTrxFromInstruction:

    def test_call_eof_contract_function_without_neon_transfer(self, operator_keypair, treasury_pool, sender_with_tokens,
                                                              evm_loader, string_setter_eof_contract):
        exit_status = "exit_status=0x12"
        text = ''.join(random.choice(string.ascii_letters) for _ in range(10))
        signed_tx = make_contract_call_trx(
            sender_with_tokens, string_setter_eof_contract, "set(string)", [text])

        resp = execute_trx_from_instruction(operator_keypair, evm_loader, treasury_pool.account, treasury_pool.buffer,
                                            signed_tx,
                                            [sender_with_tokens.solana_account_address,
                                             string_setter_eof_contract.solana_address],
                                            operator_keypair)

        check_transaction_logs_have_text(resp.value, exit_status)
        assert text in to_text(
            neon_cli().call_contract_get_function(evm_loader, sender_with_tokens, string_setter_eof_contract,
                                                  "get()"))


class TestTransactionStepFromAccount:

    def test_deploy_eof_contract(self, operator_keypair, holder_acc, treasury_pool, evm_loader, sender_with_tokens):
        contract_filename = "small.binary"
        contract = create_contract_address(sender_with_tokens, evm_loader)

        signed_tx = make_deployment_transaction(
            sender_with_tokens, contract_filename)
        write_transaction_to_holder_account(
            signed_tx, holder_acc, operator_keypair)

        resp_from_acc = execute_transaction_steps_from_account(operator_keypair, evm_loader, treasury_pool, holder_acc,
                                                               [contract.solana_address,
                                                                sender_with_tokens.solana_account_address]).value
        signed_tx = make_deployment_transaction(
            sender_with_tokens, contract_filename)
        holder_acc = create_holder(operator_keypair)
        contract = create_contract_address(sender_with_tokens, evm_loader)

        signature = execute_transaction_steps_from_instruction(operator_keypair, evm_loader, treasury_pool, holder_acc,
                                                               signed_tx, [contract.solana_address,
                                                                           sender_with_tokens.solana_account_address])
        resp_from_inst = solana_client.get_transaction(signature.value).value
        assert resp_from_acc.transaction.meta.fee == resp_from_inst.transaction.meta.fee
        assert len(resp_from_acc.transaction.meta.inner_instructions) == len(
            resp_from_inst.transaction.meta.inner_instructions)
        assert len(resp_from_acc.transaction.transaction.message.account_keys) == len(
            resp_from_acc.transaction.transaction.message.account_keys)


class TestTransactionStepFromInstruction:

    @pytest.mark.parametrize("chain_id", [None, 111])
    def test_deploy_eof_contract(self, operator_keypair, holder_acc, treasury_pool, evm_loader, sender_with_tokens,
                                 chain_id):
        contract_filename = "small.binary"

        signed_tx = make_deployment_transaction(
            sender_with_tokens, contract_filename, chain_id=chain_id)
        contract = create_contract_address(sender_with_tokens, evm_loader)

        contract_path = pytest.EOF_CONTRACTS_PATH / contract_filename
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
        exit_status = "exit_status=0x12"
        text = ''.join(random.choice(string.ascii_letters) for _ in range(10))
        signed_tx = make_contract_call_trx(
            sender_with_tokens, string_setter_eof_contract, "set(string)", [text])

        resp = execute_transaction_steps_from_instruction(operator_keypair, evm_loader, treasury_pool, holder_acc,
                                                          signed_tx, [string_setter_eof_contract.solana_address,
                                                                      sender_with_tokens.solana_account_address]
                                                          )

        check_holder_account_tag(
            holder_acc, FINALIZED_STORAGE_ACCOUNT_INFO_LAYOUT, TAG_FINALIZED_STATE)
        check_transaction_logs_have_text(resp.value, exit_status)

        assert text in to_text(
            neon_cli().call_contract_get_function(evm_loader, sender_with_tokens, string_setter_eof_contract,
                                                  "get()"))

    def test_call_eof_contract_function_with_neon_transfer(self, operator_keypair, treasury_pool, sender_with_tokens,
                                                           evm_loader, holder_acc, string_setter_eof_contract):
        exit_status = "exit_status=0x12"
        transfer_amount = random.randint(1, 1000)

        sender_balance_before = get_neon_balance(
            solana_client, sender_with_tokens.solana_account_address)
        contract_balance_before = get_neon_balance(
            solana_client, string_setter_eof_contract.solana_address)

        text = ''.join(random.choice(string.ascii_letters) for i in range(10))
        signed_tx = make_contract_call_trx(sender_with_tokens, string_setter_eof_contract, "set(string)", [text],
                                           value=transfer_amount)

        resp = execute_transaction_steps_from_instruction(operator_keypair, evm_loader, treasury_pool, holder_acc,
                                                          signed_tx, [string_setter_eof_contract.solana_address,
                                                                      sender_with_tokens.solana_account_address]
                                                          )

        check_holder_account_tag(
            holder_acc, FINALIZED_STORAGE_ACCOUNT_INFO_LAYOUT, TAG_FINALIZED_STATE)
        check_transaction_logs_have_text(resp.value, exit_status)

        sender_balance_after = get_neon_balance(
            solana_client, sender_with_tokens.solana_account_address)
        contract_balance_after = get_neon_balance(
            solana_client, string_setter_eof_contract.solana_address)
        assert sender_balance_before - transfer_amount == sender_balance_after
        assert contract_balance_before + transfer_amount == contract_balance_after

        assert text in to_text(
            neon_cli().call_contract_get_function(evm_loader, sender_with_tokens, string_setter_eof_contract,
                                                  "get()"))


class TestStepFromInstructionChangingOperatorsDuringTrxRun:

    def test_eof_next_operator_can_continue_trx_after_some_time(self, rw_lock_eof_contract, user_account, evm_loader,
                                                                operator_keypair, second_operator_keypair, treasury_pool,
                                                                new_holder_acc):
        exit_status = "exit_status=0x12"
        signed_tx = make_contract_call_trx(
            user_account, rw_lock_eof_contract, 'update_storage_str(string)', ['text'])

        send_transaction_step_from_instruction(operator_keypair, evm_loader, treasury_pool, new_holder_acc,
                                               signed_tx,
                                               [user_account.solana_account_address,
                                                rw_lock_eof_contract.solana_address], 1, operator_keypair)
        # next operator can't continue trx during OPERATOR_PRIORITY_SLOTS*0.4
        with pytest.raises(solana.rpc.core.RPCException,
                           match=rf"{InstructionAsserts.INVALID_OPERATOR_KEY}|{InstructionAsserts.INVALID_HOLDER_OWNER}"):
            send_transaction_step_from_instruction(second_operator_keypair, evm_loader, treasury_pool, new_holder_acc,
                                                   signed_tx,
                                                   [user_account.solana_account_address,
                                                    rw_lock_eof_contract.solana_address], 500, second_operator_keypair)

        time.sleep(15)
        send_transaction_step_from_instruction(second_operator_keypair, evm_loader, treasury_pool, new_holder_acc,
                                               signed_tx,
                                               [user_account.solana_account_address,
                                                rw_lock_eof_contract.solana_address], 500, second_operator_keypair)
        resp = send_transaction_step_from_instruction(second_operator_keypair, evm_loader, treasury_pool,
                                                      new_holder_acc, signed_tx,
                                                      [user_account.solana_account_address,
                                                       rw_lock_eof_contract.solana_address], 1, second_operator_keypair)
        check_transaction_logs_have_text(resp.value, exit_status)


class TestTransactionStepFromAccountNoChainId:

    def test_deploy_eof_contract(self, operator_keypair, holder_acc, treasury_pool, evm_loader, sender_with_tokens):
        contract_filename = "hello_world.binary"
        contract = create_contract_address(sender_with_tokens, evm_loader)

        signed_tx = make_deployment_transaction(
            sender_with_tokens, contract_filename, chain_id=None)
        write_transaction_to_holder_account(
            signed_tx, holder_acc, operator_keypair)

        contract_path = pytest.EOF_CONTRACTS_PATH / contract_filename
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


class TestTransactionStepFromAccount:

    def test_deploy_eof_contract(self, operator_keypair, holder_acc, treasury_pool, evm_loader, sender_with_tokens):
        contract_filename = "hello_world.binary"
        contract = create_contract_address(sender_with_tokens, evm_loader)

        signed_tx = make_deployment_transaction(
            sender_with_tokens, contract_filename)
        write_transaction_to_holder_account(
            signed_tx, holder_acc, operator_keypair)

        contract_path = pytest.EOF_CONTRACTS_PATH/ contract_filename
        with open(contract_path, 'rb') as f:
            contract_code = f.read()

        steps_count = neon_cli().get_steps_count(
            evm_loader, sender_with_tokens, "deploy", contract_code.hex())
        resp = execute_transaction_steps_from_account(operator_keypair, evm_loader, treasury_pool, holder_acc,
                                                      [contract.solana_address,
                                                       sender_with_tokens.solana_account_address],
                                                      steps_count)
        check_holder_account_tag(
            holder_acc, FINALIZED_STORAGE_ACCOUNT_INFO_LAYOUT, TAG_FINALIZED_STATE)
        check_transaction_logs_have_text(
            resp.value.transaction.transaction.signatures[0], "exit_status=0x12")

    def test_call_eof_contract_function_without_neon_transfer(self, operator_keypair, holder_acc, treasury_pool,
                                                              sender_with_tokens, evm_loader, string_setter_eof_contract):
        exit_status = "exit_status=0x12"
        text = ''.join(random.choice(string.ascii_letters) for _ in range(10))
        signed_tx = make_contract_call_trx(
            sender_with_tokens, string_setter_eof_contract, "set(string)", [text])
        write_transaction_to_holder_account(
            signed_tx, holder_acc, operator_keypair)

        resp = execute_transaction_steps_from_account(operator_keypair, evm_loader, treasury_pool, holder_acc,
                                                      [string_setter_eof_contract.solana_address,
                                                       sender_with_tokens.solana_account_address])

        check_holder_account_tag(
            holder_acc, FINALIZED_STORAGE_ACCOUNT_INFO_LAYOUT, TAG_FINALIZED_STATE)
        check_transaction_logs_have_text(
            resp.value.transaction.transaction.signatures[0], exit_status)

        assert text in to_text(
            neon_cli().call_contract_get_function(evm_loader, sender_with_tokens, string_setter_eof_contract,
                                                  "get()"))

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
                                           value=transfer_amount)
        write_transaction_to_holder_account(
            signed_tx, holder_acc, operator_keypair)

        resp = execute_transaction_steps_from_account(operator_keypair, evm_loader, treasury_pool, holder_acc,
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


class TestStepFromAccountChangingOperatorsDuringTrxRun:

    def test_next_operator_can_continue_trx_after_some_time(self, rw_lock_eof_contract, user_account, evm_loader,
                                                            operator_keypair, second_operator_keypair, treasury_pool,
                                                            new_holder_acc):
        exit_status = "exit_status=0x12"
        signed_tx = make_contract_call_trx(
            user_account, rw_lock_eof_contract, 'update_storage_str(string)', ['text'])
        write_transaction_to_holder_account(
            signed_tx, new_holder_acc, operator_keypair)

        trx = TransactionWithComputeBudget(operator_keypair)
        trx.add(
            make_ExecuteTrxFromAccountDataIterativeOrContinue(
                operator_keypair, evm_loader, new_holder_acc, treasury_pool.account, treasury_pool.buffer, 1,
                [user_account.solana_account_address,
                 rw_lock_eof_contract.solana_address]
            )
        )
        solana_client.send_transaction(trx, operator_keypair,
                                       opts=TxOpts(skip_confirmation=True, preflight_commitment=Confirmed))

        # next operator can't continue trx during OPERATOR_PRIORITY_SLOTS*0.4
        with pytest.raises(solana.rpc.core.RPCException,
                           match=rf"{InstructionAsserts.INVALID_OPERATOR_KEY}|{InstructionAsserts.INVALID_HOLDER_OWNER}"):
            send_transaction_step_from_account(second_operator_keypair, evm_loader, treasury_pool, new_holder_acc,
                                               [user_account.solana_account_address,
                                                rw_lock_eof_contract.solana_address], 500, second_operator_keypair)

        time.sleep(15)
        send_transaction_step_from_account(second_operator_keypair, evm_loader, treasury_pool, new_holder_acc,
                                           [user_account.solana_account_address,
                                            rw_lock_eof_contract.solana_address], 500, second_operator_keypair)
        resp = send_transaction_step_from_account(second_operator_keypair, evm_loader, treasury_pool, new_holder_acc,
                                                  [user_account.solana_account_address,
                                                   rw_lock_eof_contract.solana_address], 1, second_operator_keypair)
        check_transaction_logs_have_text(
            resp.value.transaction.transaction.signatures[0], exit_status)
