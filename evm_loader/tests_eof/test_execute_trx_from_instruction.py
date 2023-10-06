import random
import string

import pytest
import solana
import eth_abi
from eth_utils import abi, to_text

from .solana_utils import execute_trx_from_instruction, solana_client, get_neon_balance, neon_cli
from .utils.contract import make_contract_call_trx
from .utils.ethereum import make_eth_transaction
from .utils.transaction_checks import check_transaction_logs_have_text


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
