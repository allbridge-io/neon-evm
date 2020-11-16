//! Program entrypoint

#![cfg(feature = "program")]
#![cfg(not(feature = "no-entrypoint"))]

//use crate::{error::TokenError, processor::Processor};
use arrayref::{array_ref, array_refs, array_mut_ref, mut_array_refs};
use std::convert::TryInto;
use solana_sdk::{
    account_info::{next_account_info, AccountInfo},
    entrypoint, entrypoint::ProgramResult,
    program_error::{ProgramError, PrintProgramError}, pubkey::Pubkey,
    program_utils::{limited_deserialize},
    loader_instruction::LoaderInstruction,
    info,
};

use evm::backend::{MemoryVicinity, MemoryAccount, MemoryBackend, Apply};
use evm::executor::StackExecutor;
use primitive_types::{H160, H256, U256};
use std::collections::BTreeMap;

fn unpack_loader_instruction(data: &[u8]) -> LoaderInstruction {
    LoaderInstruction::Finalize
}

//fn pubkey_to_address(key: &Pubkey) -> H160 {
//    H256::from_slice(key.as_ref()).into()
//}


enum AccountData {
    Empty,
    Account {
        nonce: u64,
    },
    Contract {
        nonce: u64,
        code_size: u64,
        /// Actual items count in hash map
        hash_count: u64,
        /// Maximum items count in hash map
        max_hash_count: u64,
    },
}

impl AccountData {
    fn unpack(src: &[u8]) -> Result<Self, ProgramError> {
        use ProgramError::InvalidAccountData;
        let (&tag, rest) = src.split_first().ok_or(InvalidAccountData)?;
        Ok(match tag {
            0 => Self::Empty,
            1 => {
                let (nonce, rest) = rest.split_at(8);
                let nonce = nonce.try_into().ok().map(u64::from_le_bytes).ok_or(InvalidAccountData)?;
                Self::Account {nonce,}
            },
            2 => {
                let src = array_ref![rest, 0, 32];
                let (nonce, code_size, hash_count, max_hash_count) = array_refs![src, 8, 8, 8, 8];
                Self::Contract {
                        nonce: u64::from_le_bytes(*nonce),
                        code_size: u64::from_le_bytes(*code_size),
                        hash_count: u64::from_le_bytes(*hash_count),
                        max_hash_count: u64::from_le_bytes(*max_hash_count),
                }
            },
            _ => return Err(InvalidAccountData),
        })
    }

    fn pack(&self, dst: &mut [u8]) {
        match self {
            AccountData::Empty => dst[0] = 0,
            &AccountData::Account {nonce} => {
                let nonce_dst = array_mut_ref![dst, 1, 8];
                *nonce_dst = nonce.to_le_bytes();
            },
            &AccountData::Contract {nonce, code_size, hash_count, max_hash_count} => {
                let dst = array_mut_ref![dst, 0, 32];
                let (nonce_dst, code_size_dst, hash_count_dst, max_hash_count_dst) = 
                        mut_array_refs![dst, 8, 8, 8, 8];
                *nonce_dst = nonce.to_le_bytes();
                *code_size_dst = code_size.to_le_bytes();
                *hash_count_dst = hash_count.to_le_bytes();
                *max_hash_count_dst = max_hash_count.to_le_bytes();
            }
        }
    }
}


entrypoint!(process_instruction);
fn process_instruction<'a>(
    program_id: &Pubkey,
    accounts: &'a [AccountInfo<'a>],
    instruction_data: &[u8],
) -> ProgramResult {


    let instruction: LoaderInstruction = limited_deserialize(instruction_data)
            .map_err(|_| ProgramError::InvalidInstructionData)?;

    let account_info_iter = &mut accounts.iter();
    let program_info = next_account_info(account_info_iter)?;

    let mut data = program_info.data.borrow_mut();

    if data[0] == 0 {
        match instruction {
            LoaderInstruction::Write {offset, bytes} => {
//                info!("LoaderInstruction");
//                info!(&offset.to_string());
//                info!(&hex::encode(&bytes));
//                info!(&bs58::encode(program_info.key).into_string());
                return do_write(program_info, &mut data, offset, &bytes);
            },
            LoaderInstruction::Finalize => {
                info!("FinalizeInstruction");
                return do_finalize(program_info, &mut data);
            },
        }
    } else {
        return do_execute();
    }
    Ok(())
}

fn do_write(program_info: &AccountInfo, data: &mut [u8], offset: u32, bytes: &Vec<u8>) -> ProgramResult {
    let offset = offset as usize;
    if data.len() < offset+1 + bytes.len() {
        info!("Account data too small");
        return Err(ProgramError::AccountDataTooSmall);
    }
    data[offset+1..offset+1 + bytes.len()].copy_from_slice(&bytes);
    Ok(())
}

fn do_finalize(program_info: &AccountInfo, data: &mut [u8]) -> ProgramResult {
    let vicinity = MemoryVicinity {
        gas_price: U256::zero(),
        origin: H160::default(),
        chain_id: U256::zero(),
        block_hashes: Vec::new(),
        block_number: U256::zero(),
        block_coinbase: H160::default(),
        block_timestamp: U256::zero(),
        block_difficulty: U256::zero(),
        block_gas_limit: U256::zero(),
    };
    let mut state = BTreeMap::new();

    let backend = MemoryBackend::new(&vicinity, state);
    let config = evm::Config::istanbul();
    let mut executor = StackExecutor::new(&backend, usize::max_value(), &config);

    //trace!("Execute transact_create");

    //let data = Vec::new();
    //let _ = executor.transact_call(H160::default(), H160::default(), U256::zero(), Vec::new(), usize::max_value(),);
    let exit_reason = executor.transact_create(H160::zero(), U256::zero(), data[1..].to_vec(), usize::max_value());
    if exit_reason.is_succeed() {
        info!("Succeed execution");
    } else {
        info!("Not succeed execution");
    }

    Ok(())
}

fn do_execute() -> ProgramResult {
    Ok(())
}

//  let mut keyed_accounts_iter = keyed_accounts.iter();
//  let keyed_account = next_keyed_account(&mut keyed_accounts_iter)?;

//    let vicinity = MemoryVicinity {
//        gas_price: U256::zero(),
//        origin: H160::default(),
//        chain_id: U256::zero(),
//        block_hashes: Vec::new(),
//        block_number: U256::zero(),
//        block_coinbase: H160::default(),
//        block_timestamp: U256::zero(),
//        block_difficulty: U256::zero(),
//        block_gas_limit: U256::zero(),
//    };
//    let mut state = BTreeMap::new();
//
//    trace!("Read accounts data");
//
//    let backend = MemoryBackend::new(&vicinity, state);
//    let config = evm::Config::istanbul();
//    let mut executor = StackExecutor::new(&backend, usize::max_value(), &config);
//
//    trace!("Execute transact_create");

//    let data = Vec::new();
//    let exit_reason = executor.transact_create(H160::zero(), U256::zero(), data, usize::max_value());
//
//    let (_applies, _logs) = executor.deconstruct();
//    let gas = U256::zero();
//    Ok(())
//}




// Pull in syscall stubs when building for non-BPF targets
//#[cfg(not(target_arch = "bpf"))]
//solana_sdk::program_stubs!();

#[cfg(test)]
mod tests {
    use super::*;
    use solana_sdk::{program_error::ProgramError, pubkey::Pubkey};

    #[test]
    fn test_write() {
        let program_id = Pubkey::new(&[0; 32]);

        let string = b"letters and such";
        assert_eq!(Ok(()), process_instruction(&program_id, &[], string));

        let emoji = "🐆".as_bytes();
        let bytes = [0xF0, 0x9F, 0x90, 0x86];
        assert_eq!(emoji, bytes);
        assert_eq!(Ok(()), process_instruction(&program_id, &[], &emoji));

        let mut bad_utf8 = bytes;
        bad_utf8[3] = 0xFF; // Invalid UTF-8 byte
        assert_eq!(
            Err(ProgramError::InvalidInstructionData),
            process_instruction(&program_id, &[], &bad_utf8)
        );
    }
}

