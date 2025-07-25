// SPDX-FileCopyrightText: 2024-2025 TriliTech <contact@trili.tech>
// SPDX-FileCopyrightText: 2025 Nomadic Labs <contact@nomadic-labs.com>
//
// SPDX-License-Identifier: MIT

//! JIT-compiled blocks of instructions

use super::ICallPlaced;
use crate::machine_state::MachineCoreState;
use crate::machine_state::StepManyResult;
use crate::machine_state::block_cache::block::Block;
use crate::machine_state::block_cache::block::BlockLayout;
use crate::machine_state::block_cache::block::dispatch::DispatchCompiler;
use crate::machine_state::block_cache::block::dispatch::DispatchTarget;
use crate::machine_state::block_cache::block::interpreted;
use crate::machine_state::instruction::Instruction;
use crate::machine_state::memory::Address;
use crate::machine_state::memory::MemoryConfig;
use crate::state::NewState;
use crate::state_backend::AllocatedOf;
use crate::state_backend::EnrichedCell;
use crate::state_backend::FnManager;
use crate::state_backend::Ref;
use crate::state_backend::owned_backend::Owned;
use crate::traps::EnvironException;

/// Blocks that are compiled to native code for execution, when possible.
///
/// Not all instructions are currently supported, when a block contains
/// unsupported instructions, a fallback to [`super::Interpreted`] mode occurs.
///
/// Blocks are compiled upon calling [`Block::run_block`], in a *stop the world* fashion.
pub struct Jitted<D: DispatchCompiler<MC>, MC: MemoryConfig> {
    fallback: interpreted::Interpreted<MC, Owned>,
    dispatch: DispatchTarget<D, MC>,
}

impl<D: DispatchCompiler<MC>, MC: MemoryConfig> Jitted<D, MC> {
    /// The default initial dispatcher for inline jit.
    ///
    /// This will run the block in interpreted mode by default, but will attempt to JIT-compile
    /// the block.
    ///
    /// # SAFETY
    ///
    /// The `block_builder` must be the same every time this function is called.
    ///
    /// This ensures that the builder in question is guaranteed to be alive, for at least as long
    /// as this block may be run via [`Block::run_block`].
    pub(super) unsafe extern "C" fn run_block_interpreted(
        &mut self,
        core: &mut MachineCoreState<MC, Owned>,
        instr_pc: Address,
        result: &mut Result<(), EnvironException>,
        block_builder: &mut D,
    ) -> usize {
        if !block_builder.should_compile(&mut self.dispatch) {
            return unsafe { self.run_block_not_compiled(core, instr_pc, result, block_builder) };
        }

        // trigger JIT compilation
        let instr = self
            .fallback
            .instr
            .iter()
            .take(self.num_instr())
            .map(|i| i.read_stored())
            .collect::<Vec<_>>();

        let fun = block_builder.compile(&mut self.dispatch, instr);

        // Safety: the block builder passed to this function is always the same for the
        // lifetime of the block
        unsafe { (fun)(self, core, instr_pc, result, block_builder) }
    }

    /// Run a block where JIT-compilation has been attempted, but failed for any reason.
    ///
    /// # SAFETY
    ///
    /// The `block_builder` must be the same every time this function is called.
    ///
    /// This ensures that the builder in question is guaranteed to be alive, for at least as long
    /// as this block may be run via [`Block::run_block`].
    pub(super) unsafe extern "C" fn run_block_not_compiled(
        &mut self,
        core: &mut MachineCoreState<MC, Owned>,
        instr_pc: Address,
        result: &mut Result<(), EnvironException>,
        _block_builder: &mut D,
    ) -> usize {
        let block_result = unsafe {
            // Safety: this function is always safe to call
            self.fallback
                .run_block(core, instr_pc, &mut interpreted::InterpretedBlockBuilder)
        };

        *result = match block_result.error {
            Some(exc) => Err(exc),
            None => Ok(()),
        };

        block_result.steps
    }
}

impl<D: DispatchCompiler<MC>, MC: MemoryConfig> NewState<Owned> for Jitted<D, MC> {
    fn new() -> Self {
        Self {
            fallback: interpreted::Interpreted::new(),
            dispatch: DispatchTarget::default(),
        }
    }
}

impl<D: DispatchCompiler<MC>, MC: MemoryConfig> Block<MC, Owned> for Jitted<D, MC> {
    type BlockBuilder = D;

    fn start_block(&mut self) {
        self.dispatch.reset();
        self.fallback.start_block()
    }

    fn invalidate(&mut self) {
        self.dispatch.reset();
        self.fallback.invalidate()
    }

    fn reset(&mut self) {
        self.dispatch.reset();
        self.fallback.reset()
    }

    fn push_instr(&mut self, instr: Instruction) {
        self.dispatch.reset();
        self.fallback.push_instr(instr)
    }

    fn instr(&self) -> &[EnrichedCell<ICallPlaced<MC, Owned>, Owned>] {
        self.fallback.instr()
    }

    fn bind(allocated: AllocatedOf<BlockLayout, Owned>) -> Self {
        Self {
            fallback: interpreted::Interpreted::bind(allocated),
            dispatch: DispatchTarget::default(),
        }
    }

    fn struct_ref<'a, F: FnManager<Ref<'a, Owned>>>(
        &'a self,
    ) -> AllocatedOf<BlockLayout, F::Output> {
        self.fallback.struct_ref::<F>()
    }

    /// Run a block, using the currently selected dispatch mechanism
    ///
    /// # SAFETY
    ///
    /// The `block_builder` must be the same every time this function is called.
    ///
    /// This ensures that the builder in question is guaranteed to be alive, for at least as long
    /// as this block may be run via [`Block::run_block`].
    unsafe fn run_block(
        &mut self,
        core: &mut MachineCoreState<MC, Owned>,
        instr_pc: Address,
        block_builder: &mut Self::BlockBuilder,
    ) -> StepManyResult<EnvironException> {
        let mut result = Ok(());

        let fun = self.dispatch.get();

        // SAFETY: The block builder is always the same instance, guaranteeing that any JIT-compiled
        // function is still alive.
        let steps = unsafe { (fun)(self, core, instr_pc, &mut result, block_builder) };

        StepManyResult {
            steps,
            error: result.err(),
        }
    }

    fn num_instr(&self) -> usize {
        self.fallback.num_instr()
    }
}

impl<D: DispatchCompiler<MC>, MC: MemoryConfig> Clone for Jitted<D, MC> {
    fn clone(&self) -> Self {
        Self {
            fallback: self.fallback.clone(),
            dispatch: DispatchTarget::default(),
        }
    }
}
