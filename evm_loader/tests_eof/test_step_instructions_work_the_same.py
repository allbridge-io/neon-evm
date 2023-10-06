from .solana_utils import solana_client, execute_transaction_steps_from_account, write_transaction_to_holder_account, \
    execute_transaction_steps_from_instruction
from .utils.contract import make_deployment_transaction
from .utils.ethereum import create_contract_address
from .utils.storage import create_holder


class TestTransactionStepFromAccount:

    def test_deploy_eof_contract(self, operator_keypair, holder_acc, treasury_pool, evm_loader, sender_with_tokens):
        eof = True
        contract_filename = "small.binary"
        contract = create_contract_address(sender_with_tokens, evm_loader)

        signed_tx = make_deployment_transaction(
            sender_with_tokens, contract_filename, eof=eof)
        write_transaction_to_holder_account(
            signed_tx, holder_acc, operator_keypair)

        resp_from_acc = execute_transaction_steps_from_account(operator_keypair, evm_loader, treasury_pool, holder_acc,
                                                               [contract.solana_address,
                                                                sender_with_tokens.solana_account_address]).value
        signed_tx = make_deployment_transaction(
            sender_with_tokens, contract_filename, eof=eof)
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
