import os
import random

import pytest
from solana.rpc.api import Client
from solana.publickey import PublicKey
from solana.rpc.commitment import Confirmed

from .solana_utils import neon_cli, create_treasury_pool_address, get_neon_balance, get_transaction_count
from .solana_utils import solana_client, wait_confirm_transaction, get_solana_balance, send_transaction
from .utils.constants import SOLANA_URL
from .utils.contract import deploy_contract
from .utils.ethereum import make_eth_transaction
from eth_utils import abi, to_text

from .utils.instructions import TransactionWithComputeBudget, make_PartialCallOrContinueFromRawEthereumTX
from .utils.storage import create_holder


def gen_hash_of_block(size: int) -> str:
    """Generates a block hash of the given size"""
    try:
        block_hash = hex(int.from_bytes(os.urandom(size), "big"))
        if bytes.fromhex(block_hash[2:]) or len(block_hash[2:]) != size * 2:
            return block_hash
    except ValueError:
        return gen_hash_of_block(size)


def test_emulate_transfer(user_account, evm_loader, session_user):
    result = neon_cli().emulate(
        evm_loader.loader_id,
        user_account.eth_address.hex(),
        session_user.eth_address.hex(),
        data=None
    )
    assert result[
        'exit_status'] == 'succeed', f"The 'exit_status' field is not succeed. Result: {result}"
    assert result[
        'steps_executed'] == 1, f"Steps executed amount is not 1. Result: {result}"
    assert result['used_gas'] > 0, f"Used gas is less than 0. Result: {result}"


def test_emulate_contract_deploy(user_account, evm_loader):
    contract_path = pytest.CONTRACTS_PATH / "hello_world.binary"
    emulate_contract_deploy(user_account, evm_loader, contract_path)


def emulate_contract_deploy(user_account, evm_loader, contract_path):
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


def test_emulate_call_contract_function(user_account, evm_loader, operator_keypair, treasury_pool):
    contract = deploy_contract(operator_keypair, user_account,
                               "hello_world.binary", evm_loader, treasury_pool)
    emulate_call_contract_function(
        user_account, evm_loader, operator_keypair, treasury_pool, contract)


def emulate_call_contract_function(user_account, evm_loader, operator_keypair, treasury_pool, contract):
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


def test_neon_elf_params(evm_loader):
    result = neon_cli().call(
        f"--evm_loader={evm_loader.loader_id} neon-elf-params")
    some_fields = ['NEON_CHAIN_ID', 'NEON_TOKEN_MINT', 'NEON_REVISION']
    for field in some_fields:
        assert field in result, f"The field {field} is not in result {result}"
        assert result[field] != "", f"The value for fiels {field} is empty"


def test_collect_treasury(evm_loader):
    command_args = f"collect-treasury --evm_loader {evm_loader.loader_id}"
    index = random.randint(0, 127)
    treasury_pool_address = create_treasury_pool_address(index)
    result = neon_cli().call(command_args)
    main_pool_address = PublicKey(result["pool_address"])
    balance_before = get_solana_balance(main_pool_address)

    amount = random.randint(1, 1000)
    trx = solana_client.request_airdrop(treasury_pool_address, amount)
    wait_confirm_transaction(solana_client, trx.value)
    result = neon_cli().call(command_args)

    balance_after = get_solana_balance(PublicKey(main_pool_address))
    assert balance_after >= balance_before + amount


def test_init_environment(evm_loader):
    result = neon_cli().call(
        f"init-environment --evm_loader {evm_loader.loader_id}")
    assert len(result["transactions"]) == 0


def test_get_ether_account_data(evm_loader, user_account):
    result = neon_cli().call(
        f"get-ether-account-data --evm_loader {evm_loader.loader_id} {user_account.eth_address.hex()}")

    assert f"0x{user_account.eth_address.hex()}" == result["address"]
    assert str(user_account.solana_account_address) == result["solana_address"]

    assert solana_client.get_account_info(
        user_account.solana_account.public_key).value is not None


def test_create_ether_account(evm_loader):
    acc = gen_hash_of_block(20)
    result = neon_cli().call(
        f"create-ether-account --evm_loader {evm_loader.loader_id} {acc}")

    acc_info = solana_client.get_account_info(
        PublicKey(result['solana_address']), commitment=Confirmed)
    assert acc_info.value is not None


def test_deposit(evm_loader, user_account):
    amount = random.randint(1, 100000)
    result = neon_cli().call(
        f"deposit --evm_loader {evm_loader.loader_id} {amount} {user_account.eth_address.hex()}")
    balance_after = get_neon_balance(
        solana_client, user_account.solana_account_address)
    assert result["transaction"] is not None
    assert balance_after == amount * 1000000000


def test_get_storage_at(evm_loader, operator_keypair, user_account, treasury_pool):
    contract = deploy_contract(
        operator_keypair, user_account, "hello_world.binary", evm_loader, treasury_pool)
    expected_storage = '0000000000000000000000000000000000000000000000000000000000000005'
    result = neon_cli().call(
        f"get-storage-at --evm_loader {evm_loader.loader_id} {contract.eth_address.hex()} 0x0")
    assert result == expected_storage
