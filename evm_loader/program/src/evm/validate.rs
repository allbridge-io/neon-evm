#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap
)]

use super::eof::Container;
use crate::error::{Error, Result};
use crate::evm::analysis::Bitvec;
use crate::evm::eof::FunctionMetadata;
use crate::evm::opcode_table::OpCode;
use crate::evm::opcode_table::OpCode::{
    CALLCODE, CALLF, JUMP, JUMPI, PC, PUSH0, PUSH1, PUSH32, RETF, RJUMP, RJUMPI, RJUMPV,
    SELFDESTRUCT,
};
use crate::evm::Buffer;
use std::collections::HashMap;

impl Container {
    /// [Specification](https://eips.ethereum.org/EIPS/eip-4750#:~:text=The%20return%20stack%20is%20limited%20to%20a%20maximum%201024%20items.)
    pub const STACK_LIMIT: usize = 1024;

    pub const DEPRECATED_OPCODES: [u8; 5] = [
        CALLCODE as u8,
        SELFDESTRUCT as u8,
        JUMP as u8,
        JUMPI as u8,
        PC as u8,
    ];

    pub fn validate_container(&self) -> Result<()> {
        for (section, code) in self.code.iter().enumerate() {
            Self::validate_code(code, section, &self.types)?;
        }

        Ok(())
    }

    pub fn validate_code(
        code: &Buffer,
        section: usize,
        metadata: &Vec<FunctionMetadata>,
    ) -> Result<()> {
        let mut i: usize = 0;
        // Tracks the number of actual instructions in the code (e.g.
        // non-immediate values). This is used at the end to determine
        // if each instruction is reachable.
        let mut instruction_count: usize = 0;
        let mut analysis: Option<Bitvec> = None;
        let mut opcode: u8 = 0;

        // This loop visits every single instruction and verifies:
        // * if the instruction is valid for the given jump table.
        // * if the instruction has an immediate value, it is not truncated.
        // * if performing a relative jump, all jump destinations are valid.
        // * if changing code sections, the new code section index is valid and
        //   will not cause a stack overflow.
        while i < code.len() {
            instruction_count += 1;
            opcode = code.get_or_default(i);

            if !OpCode::has_opcode(opcode) && Self::DEPRECATED_OPCODES.contains(&opcode) {
                return Err(Error::ValidationUndefinedInstruction(opcode, i));
            }

            if opcode > PUSH0 && opcode <= PUSH32 {
                let size = opcode - PUSH0 as u8;
                if code.len() <= i + size as usize {
                    return Err(Error::ValidationTruncatedImmediate(opcode, i));
                }
                i += size as usize;
            }

            if opcode == RJUMP || opcode == RJUMPI {
                if code.len() <= i + 2 {
                    return Err(Error::ValidationTruncatedImmediate(opcode, i));
                }
                analysis = Some(Self::check_dest(code, analysis, i + 1, i + 3, code.len())?);
                i += 2;
            }

            if opcode == RJUMPV {
                if code.len() <= i + 1 {
                    return Err(Error::ValidationTruncatedImmediate(opcode, i));
                }
                instruction_count = code.get_or_default(i + 1) as usize;
                if instruction_count == 0 {
                    return Err(Error::ValidationInvalidBranchCount(i));
                }
                if code.len() <= i + instruction_count {
                    return Err(Error::ValidationTruncatedImmediate(opcode, i));
                }
                for j in 0..instruction_count {
                    analysis = Some(Self::check_dest(
                        code,
                        analysis,
                        i + 2 + j * 2,
                        i + 2 * instruction_count + 2,
                        code.len(),
                    )?);
                }
                i += 1 + 2 * instruction_count;
            }

            if opcode == CALLF {
                if i + 2 >= code.len() {
                    return Err(Error::ValidationTruncatedImmediate(opcode, i));
                }
                let arg = code.get_u16_or_default(i + 1);

                if arg as usize >= metadata.len() {
                    return Err(Error::ValidationInvalidSectionArgument(
                        arg,
                        metadata.len(),
                        i,
                    ));
                }
                i += 2;
            }

            i += 1;
        }

        // Code sections may not "fall through" and require proper termination.
        // Therefore, the last instruction must be considered terminal.
        if !OpCode::is_terminal_opcode(opcode) {
            return Err(Error::ValidationInvalidCodeTermination(opcode, i));
        }

        let path = Self::validate_control_flow(code, section, metadata)?;
        if path != instruction_count {
            return Err(Error::ValidationUnreachableCode);
        }
        Ok(())
    }

    /// checkDest parses a relative offset at code[0:2] and checks if it is a valid jump destination.
    fn check_dest(
        code: &Buffer,
        analysis_option: Option<Bitvec>,
        imm: usize,
        from: usize,
        length: usize,
    ) -> Result<Bitvec> {
        if code.len() < imm + 2 {
            return Err(Error::UnexpectedEndOfFile);
        }
        let analysis = match analysis_option {
            Some(a) => a,
            None => Bitvec::eof_code_bitmap(code),
        };
        let offset = code.get_i16_or_default(imm);
        let dest = (from as isize + offset as isize) as usize;
        if dest >= length || !analysis.is_code_segment(dest) {
            return Err(Error::ValidationInvalidJumpDest(offset, dest, imm));
        }

        Ok(analysis)
    }

    /// validateControlFlow iterates through all possible branches the provided code
    /// value and determines if it is valid per EOF v1.
    #[allow(clippy::too_many_lines)]
    fn validate_control_flow(
        code: &Buffer,
        section: usize,
        metadata: &[FunctionMetadata],
    ) -> Result<usize> {
        struct Item {
            pub pos: usize,
            pub height: usize,
        }
        let mut heights: HashMap<usize, usize> = HashMap::new();

        let current_section = metadata
            .get(section)
            .ok_or(Error::FunctionMetadataNotFound(section))?;

        let mut worklist: Vec<Item> = vec![Item {
            pos: 0,
            height: current_section.input as usize,
        }];

        let mut max_stack_height = current_section.input as usize;
        while !worklist.is_empty() {
            let worklist_item = worklist.pop().unwrap();
            let mut pos = worklist_item.pos;
            let mut height = worklist_item.height;

            while pos < code.len() {
                let op = code.get_or_default(pos);
                let want_option = heights.get(&pos);

                // Check if pos has already be visited; if so, the stack heights should be the same.
                if let Some(want) = want_option {
                    if *want != height {
                        return Err(Error::ValidationConflictingStack(height, *want));
                    }
                    // Already visited this path and stack height
                    // matches.
                    break;
                }

                heights.insert(pos, height);

                let op_code: OpCode = op.try_into()?;
                let opcode_info = OpCode::opcode_info(op_code);

                // Validate height for current op and update as needed.
                if opcode_info.min_stack > height {
                    return Err(Error::StackUnderflow);
                }
                if opcode_info.max_stack < height {
                    return Err(Error::StackOverflow);
                }

                height = height + Self::STACK_LIMIT - opcode_info.max_stack;

                match op_code {
                    CALLF => {
                        let arg = code.get_u16_or_default(pos + 1) as usize;

                        let metadata = metadata
                            .get(arg)
                            .ok_or(Error::FunctionMetadataNotFound(arg))?;

                        let input = metadata.input as usize;
                        let output = metadata.output as usize;

                        if input > height {
                            return Err(Error::StackUnderflow);
                        }
                        if output + height > Self::STACK_LIMIT {
                            return Err(Error::StackOverflow);
                        }

                        height -= input;
                        height += output;
                        pos += 3;
                    }
                    RETF => {
                        if current_section.output as usize != height {
                            return Err(Error::ValidationInvalidOutputs(
                                current_section.output,
                                height,
                                pos,
                            ));
                        }
                        break;
                    }
                    RJUMP => {
                        let arg = code.get_i16_or_default(pos + 1);
                        pos = (pos as isize + 3 + arg as isize) as usize;
                    }
                    RJUMPI => {
                        let arg = code.get_i16_or_default(pos + 1);
                        worklist.push(Item {
                            pos: (pos as isize + 3 + arg as isize) as usize,
                            height,
                        });
                        pos += 3;
                    }
                    RJUMPV => {
                        let count = code.get_or_default(pos + 1) as usize;

                        for i in 0..count {
                            let arg = code.get_i16_or_default(pos + 2 + 2 * i as usize);
                            worklist.push(Item {
                                pos: (pos as isize + 2 + 2 * count as isize + arg as isize)
                                    as usize,
                                height,
                            });
                        }

                        pos += 2 + 2 * count as usize;
                    }
                    _ if op >= PUSH1 && op <= PUSH32 => {
                        pos += 1 + (op - PUSH0.u8()) as usize;
                    }
                    _ if opcode_info.terminal => {
                        break;
                    }
                    _ => {
                        // Simple op, no operand.
                        pos += 1;
                    }
                }

                max_stack_height = max_stack_height.max(height);
            }
        }

        if max_stack_height != current_section.max_stack_height as usize {
            return Err(Error::ValidationInvalidMaxStackHeight(
                section,
                max_stack_height,
                current_section.max_stack_height,
            ));
        }
        Ok(heights.len())
    }
}

#[allow(clippy::enum_glob_use)]
#[cfg(test)]
mod tests {
    use super::OpCode::*;
    use super::*;
    use crate::evm::Buffer;

    #[test]
    fn validation_test() {
        let codes = vec![
            (
                Buffer::from_slice(&[CALLER as u8, POP as u8, STOP as u8]),
                vec![FunctionMetadata {
                    input: 0,
                    output: 0,
                    max_stack_height: 1,
                }],
            ),
            (
                Buffer::from_slice(&[CALLF as u8, 0x00, 0x00, STOP as u8]),
                vec![FunctionMetadata {
                    input: 0,
                    output: 0,
                    max_stack_height: 0,
                }],
            ),
            (
                Buffer::from_slice(&[ADDRESS as u8, CALLF as u8, 0x00, 0x00, STOP as u8]),
                vec![FunctionMetadata {
                    input: 0,
                    output: 0,
                    max_stack_height: 1,
                }],
            ),
            (
                Buffer::from_slice(&[
                    RJUMP as u8,
                    0x00,
                    0x03,
                    JUMPDEST as u8,
                    JUMPDEST as u8,
                    RETURN as u8,
                    PUSH1 as u8,
                    20,
                    PUSH1 as u8,
                    39,
                    PUSH1 as u8,
                    0x00,
                    CODECOPY as u8,
                    PUSH1 as u8,
                    20,
                    PUSH1 as u8,
                    0x00,
                    RJUMP as u8,
                    0xff,
                    0xef,
                ]),
                vec![FunctionMetadata {
                    input: 0,
                    output: 0,
                    max_stack_height: 3,
                }],
            ),
            (
                Buffer::from_slice(&[
                    PUSH1 as u8,
                    1,
                    RJUMPI as u8,
                    0x00,
                    0x03,
                    JUMPDEST as u8,
                    JUMPDEST as u8,
                    STOP as u8,
                    PUSH1 as u8,
                    20,
                    PUSH1 as u8,
                    39,
                    PUSH1 as u8,
                    0x00,
                    CODECOPY as u8,
                    PUSH1 as u8,
                    20,
                    PUSH1 as u8,
                    0x00,
                    RETURN as u8,
                ]),
                vec![FunctionMetadata {
                    input: 0,
                    output: 0,
                    max_stack_height: 3,
                }],
            ),
            (
                Buffer::from_slice(&[
                    PUSH1 as u8,
                    1,
                    RJUMPV as u8,
                    0x02,
                    0x00,
                    0x03,
                    0xff,
                    0xf8,
                    JUMPDEST as u8,
                    JUMPDEST as u8,
                    STOP as u8,
                    PUSH1 as u8,
                    20,
                    PUSH1 as u8,
                    39,
                    PUSH1 as u8,
                    0x00,
                    CODECOPY as u8,
                    PUSH1 as u8,
                    20,
                    PUSH1 as u8,
                    0x00,
                    RETURN as u8,
                ]),
                vec![FunctionMetadata {
                    input: 0,
                    output: 0,
                    max_stack_height: 3,
                }],
            ),
            (
                Buffer::from_slice(&[RETF as u8]),
                vec![FunctionMetadata {
                    input: 3,
                    output: 3,
                    max_stack_height: 3,
                }],
            ),
            (
                Buffer::from_slice(&[CALLF as u8, 0x00, 0x01, POP as u8, STOP as u8]),
                vec![
                    FunctionMetadata {
                        input: 0,
                        output: 0,
                        max_stack_height: 1,
                    },
                    FunctionMetadata {
                        input: 0,
                        output: 1,
                        max_stack_height: 0,
                    },
                ],
            ),
            (
                Buffer::from_slice(&[
                    ORIGIN as u8,
                    ORIGIN as u8,
                    CALLF as u8,
                    0x00,
                    0x01,
                    POP as u8,
                    RETF as u8,
                ]),
                vec![
                    FunctionMetadata {
                        input: 0,
                        output: 0,
                        max_stack_height: 2,
                    },
                    FunctionMetadata {
                        input: 2,
                        output: 1,
                        max_stack_height: 2,
                    },
                ],
            ),
        ];

        for (code, meta) in codes {
            Container::validate_code(&code, 0, &meta).unwrap();
        }
    }

    #[test]
    #[should_panic(expected = "FunctionMetadataNotFound(0)")]
    fn validation_test_with_function_metadata_not_found() {
        let code = Buffer::from_slice(&[RETF as u8]);
        let metas = vec![];

        Container::validate_code(&code, 0, &metas).unwrap();
    }

    #[test]
    #[should_panic(expected = "ValidationInvalidCodeTermination(80, 2)")]
    fn validation_test_with_invalid_code_termination() {
        let code = Buffer::from_slice(&[CALLER.u8(), POP.u8()]);
        let meta = FunctionMetadata {
            input: 0,
            output: 0,
            max_stack_height: 1,
        };
        Container::validate_code(&code, 0, &vec![meta]).unwrap();
    }

    #[test]
    #[should_panic(expected = "ValidationUnreachableCode")]
    fn validation_test_with_unreachable_code_1() {
        let code = Buffer::from_slice(&[RJUMP as u8, 0x00, 0x01, CALLER as u8, STOP as u8]);
        let meta = FunctionMetadata {
            input: 0,
            output: 0,
            max_stack_height: 0,
        };
        Container::validate_code(&code, 0, &vec![meta]).unwrap();
    }

    #[test]
    #[should_panic(expected = "ValidationUnreachableCode")]
    fn validation_test_with_unreachable_code_2() {
        let code = Buffer::from_slice(&[STOP as u8, STOP as u8, INVALID as u8]);
        let meta = FunctionMetadata {
            input: 0,
            output: 0,
            max_stack_height: 0,
        };
        Container::validate_code(&code, 0, &vec![meta]).unwrap();
    }

    #[test]
    #[should_panic(expected = "StackUnderflow")]
    fn validation_test_stack_underflow() {
        let code = Buffer::from_slice(&[PUSH1 as u8, 0x42, ADD as u8, STOP as u8]);
        let meta = FunctionMetadata {
            input: 0,
            output: 0,
            max_stack_height: 1,
        };

        Container::validate_code(&code, 0, &vec![meta]).unwrap();
    }

    #[test]
    #[should_panic(expected = "ValidationInvalidMaxStackHeight(0, 1, 2)")]
    fn validation_test_with_invalid_max_stack_height() {
        let code = Buffer::from_slice(&[PUSH1 as u8, 0x42, POP as u8, STOP as u8]);
        let meta = FunctionMetadata {
            input: 0,
            output: 0,
            max_stack_height: 2,
        };
        Container::validate_code(&code, 0, &vec![meta]).unwrap();
    }

    #[test]
    #[should_panic(expected = "ValidationInvalidJumpDest(1, 5, 2)")]
    fn validation_test_with_invalid_jump_dest_1() {
        let code = Buffer::from_slice(&[
            PUSH0 as u8,
            RJUMPI as u8,
            0x00,
            0x01,
            PUSH1 as u8,
            0x42, // jumps to here
            POP as u8,
            STOP as u8,
        ]);
        let meta = FunctionMetadata {
            input: 0,
            output: 0,
            max_stack_height: 1,
        };
        Container::validate_code(&code, 0, &vec![meta]).unwrap();
    }

    #[test]
    #[should_panic(expected = "ValidationInvalidJumpDest(1, 8, 3)")]
    fn validation_test_with_invalid_jump_dest_2() {
        let code = Buffer::from_slice(&[
            PUSH0 as u8,
            RJUMPV as u8,
            0x02,
            0x00,
            0x01,
            0x00,
            0x02,
            PUSH1 as u8,
            0x42,      // jumps to here
            POP as u8, // and here
            STOP as u8,
        ]);
        let meta = FunctionMetadata {
            input: 0,
            output: 0,
            max_stack_height: 1,
        };
        Container::validate_code(&code, 0, &vec![meta]).unwrap();
    }

    #[test]
    #[should_panic(expected = "ValidationInvalidBranchCount(1)")]
    fn validation_test_with_invalid_branch_count() {
        let code = Buffer::from_slice(&[PUSH0 as u8, RJUMPV as u8, 0x00, STOP as u8]);
        let meta = FunctionMetadata {
            input: 0,
            output: 0,
            max_stack_height: 1,
        };
        Container::validate_code(&code, 0, &vec![meta]).unwrap();
    }

    #[test]
    #[should_panic(expected = "ValidationInvalidOutputs(1, 0, 0)")]
    fn validation_test_with_invalid_outputs() {
        let code = Buffer::from_slice(&[RETF as u8]);
        let meta = FunctionMetadata {
            input: 0,
            output: 1,
            max_stack_height: 0,
        };
        Container::validate_code(&code, 0, &vec![meta]).unwrap();
    }
}
