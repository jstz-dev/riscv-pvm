// SPDX-FileCopyrightText: 2024 TriliTech <contact@trili.tech>
// SPDX-FileCopyrightText: 2024-2025 Nomadic Labs <contact@nomadic-labs.com>
//
// SPDX-License-Identifier: MIT

mod reveals;

use std::ops::Bound;
use std::path::Path;

use reveals::RevealRequestResponseMap;
use serde::Serialize;
use serde::de::DeserializeOwned;
use tezos_smart_rollup_utils::inbox::Inbox;

use super::Stepper;
use super::StepperStatus;
use crate::kernel_loader;
use crate::machine_state::MachineCoreState;
use crate::machine_state::MachineError;
use crate::machine_state::block_cache::BlockCacheConfig;
use crate::machine_state::block_cache::DefaultCacheConfig;
use crate::machine_state::block_cache::block::Block;
use crate::machine_state::block_cache::block::Interpreted;
use crate::machine_state::block_cache::block::InterpretedBlockBuilder;
use crate::machine_state::memory::M1G;
use crate::machine_state::memory::MemoryConfig;
use crate::program::Program;
use crate::pvm::Pvm;
use crate::pvm::PvmLayout;
use crate::pvm::PvmStatus;
use crate::pvm::hooks::NoHooks;
use crate::pvm::hooks::PvmHooks;
use crate::range_utils::bound_saturating_sub;
use crate::state_backend::AllocatedOf;
use crate::state_backend::FnManagerIdent;
use crate::state_backend::ManagerBase;
use crate::state_backend::ManagerReadWrite;
use crate::state_backend::OwnedProofPart;
use crate::state_backend::ProofLayout;
use crate::state_backend::ProofPart;
use crate::state_backend::ProofTree;
use crate::state_backend::Ref;
use crate::state_backend::hash::Hash;
use crate::state_backend::owned_backend::Owned;
use crate::state_backend::proof_backend::ProofGen;
use crate::state_backend::proof_backend::proof::Proof;
use crate::state_backend::proof_backend::proof::deserialise_owned;
use crate::state_backend::proof_backend::proof::deserialise_stream::{self};
use crate::state_backend::proof_backend::proof::serialise_merkle_tree;
use crate::state_backend::verify_backend::ProofVerificationFailure;
use crate::state_backend::verify_backend::Verifier;
use crate::state_backend::verify_backend::handle_stepper_panics;
use crate::storage::binary;

/// Error during PVM stepping
#[derive(Debug, derive_more::From, thiserror::Error, derive_more::Display)]
pub enum PvmStepperError {
    /// Errors related to the machine state
    MachineError(MachineError),

    /// Errors arising from loading the kernel
    KernelError(kernel_loader::Error),
}

/// Wrapper over a PVM that lets you step through it
pub struct PvmStepper<
    H,
    MC: MemoryConfig = M1G,
    BCC: BlockCacheConfig = DefaultCacheConfig,
    M: ManagerBase = Owned,
    B: Block<MC, M> = Interpreted<MC, M>,
> {
    pvm: Pvm<MC, BCC, B, M>,
    hooks: H,
    inbox: Inbox,
    rollup_address: [u8; 20],
    origination_level: u32,
    reveal_request_response_map: RevealRequestResponseMap,
}

/// Variant of the [`PvmStepper`] used for verifying proofs
type PvmVerifier<MC, BCC> = PvmStepper<NoHooks, MC, BCC, Verifier, Interpreted<MC, Verifier>>;

impl<H, MC: MemoryConfig, B: Block<MC, Owned>, BCC: BlockCacheConfig>
    PvmStepper<H, MC, BCC, Owned, B>
{
    /// Create a new PVM stepper.
    pub fn new(
        program: &[u8],
        inbox: Inbox,
        hooks: H,
        rollup_address: [u8; 20],
        origination_level: u32,
        preimages_dir: Option<Box<Path>>,
        block_builder: B::BlockBuilder,
    ) -> Result<Self, PvmStepperError> {
        let mut pvm = Pvm::empty(block_builder);

        let program = Program::<MC>::from_elf(program)?;

        pvm.setup_linux_process(&program)?;

        let reveal_request_response_map =
            RevealRequestResponseMap::new(rollup_address, origination_level, preimages_dir);

        Ok(Self {
            pvm,
            hooks,
            inbox,
            rollup_address,
            origination_level,
            reveal_request_response_map,
        })
    }

    /// Obtain the root hash for the PVM state.
    pub fn hash(&self) -> Hash {
        self.pvm.hash().unwrap()
    }
}

impl<H, MC: MemoryConfig, BCC: BlockCacheConfig> PvmStepper<H, MC, BCC, Owned> {
    /// Produce the Merkle proof for evaluating one step on the given PVM state.
    /// The given stepper takes one step.
    pub fn produce_proof(&mut self) -> Option<Proof>
    where
        AllocatedOf<BCC::Layout, Verifier>: 'static,
    {
        // Step using the proof mode stepper in order to obtain the proof
        let mut proof_stepper = self.start_proof_mode();

        proof_stepper.try_step().then_some(())?;

        let proof = proof_stepper.pvm.produce_proof().ok()?;
        Some(proof)
    }
}

impl<H: PvmHooks, MC: MemoryConfig, BCC: BlockCacheConfig, B: Block<MC, M>, M: ManagerReadWrite>
    PvmStepper<H, MC, BCC, M, B>
{
    /// Non-continuing variant of [`Stepper::step_max`]
    fn step_max_once(&mut self, steps: Bound<usize>) -> StepperStatus {
        // SAFETY: We're in a stepper context where divergence (e.g. early exit) is allowed.
        unsafe {
            if let Some(exit_code) = self.pvm.has_exited() {
                return StepperStatus::Exited {
                    steps: 0,
                    success: exit_code == 0,
                    status: format!("Exited with code {}", exit_code),
                };
            }
        }

        match self.pvm.status() {
            PvmStatus::Evaluating => {
                let steps = self.pvm.eval_max(&mut self.hooks, steps);
                StepperStatus::Running { steps }
            }

            PvmStatus::WaitingForInput => match self.inbox.next() {
                Some((level, counter, payload)) => {
                    let success =
                        self.pvm
                            .provide_inbox_message(level, counter, payload.as_slice());

                    if success {
                        StepperStatus::Running { steps: 1 }
                    } else {
                        StepperStatus::Errored {
                            steps: 0,
                            cause: "PVM was waiting for input".to_owned(),
                            message: "Providing input did not succeed".to_owned(),
                        }
                    }
                }

                None => StepperStatus::Exited {
                    steps: 0,
                    success: true,
                    status: "Inbox has been drained".to_owned(),
                },
            },

            PvmStatus::WaitingForReveal => {
                let reveal_request = self.pvm.reveal_request();

                let Some(reveal_response) = self
                    .reveal_request_response_map
                    .get_response(reveal_request.as_slice())
                else {
                    // TODO: RV-573: Handle incorrectly encoded request/ Unavailable data differently in the sandbox.
                    // When the PVM sends an incorrectly encoded reveal request, the stepper should return an error.
                    // When the PVM sends a request for unavailable data, the stepper should exit.
                    self.pvm.provide_reveal_error_response();

                    return StepperStatus::Running { steps: 1 };
                };

                let success = self.pvm.provide_reveal_response(&reveal_response);
                if success {
                    StepperStatus::Running { steps: 1 }
                } else {
                    StepperStatus::Errored {
                        steps: 0,
                        cause: "PVM was waiting for reveal response".to_owned(),
                        message: "Providing reveal response did not succeed".to_owned(),
                    }
                }
            }
        }
    }

    /// Try to take one step and return true if the PVM is not in an errored state.
    fn try_step(&mut self) -> bool {
        match self.step_max_once(Bound::Included(1)) {
            // We don't include errors in this case because errors count as 0 steps. That means if
            // we receive a [`StepperStatus::Errored`] with `steps: 1` then it tried to run 2 steps
            // but failed at the second.
            StepperStatus::Running { steps: 1 } | StepperStatus::Exited { steps: 1, .. } => true,
            _ => false,
        }
    }

    /// Given a manager morphism `f : &M -> N`, return the layout's allocated structure containing
    /// the constituents of `N` that were produced from the constituents of `&M`.
    pub fn struct_ref(&self) -> AllocatedOf<PvmLayout<MC, BCC>, Ref<'_, M>> {
        self.pvm.struct_ref::<FnManagerIdent>()
    }

    /// Re-bind the PVM type by serialising and deserialising its state in order to eliminate
    /// ephemeral state that doesn't make it into the serialised output.
    ///
    /// We additionally pass a new instance of the [`BlockBuilder`], to be used in the deserialised
    /// pvm.
    ///
    /// [`BlockBuilder`]: Block::BlockBuilder
    pub fn rebind_via_serde(&mut self, block_builder: B::BlockBuilder)
    where
        for<'a> AllocatedOf<PvmLayout<MC, BCC>, Ref<'a, M>>: Serialize,
        AllocatedOf<PvmLayout<MC, BCC>, M>: DeserializeOwned,
    {
        let space = {
            let refs = self.pvm.struct_ref::<FnManagerIdent>();
            let data = binary::serialise(&refs).unwrap();
            binary::deserialise(&data).unwrap()
        };

        self.pvm = Pvm::bind(space, block_builder);
    }
}

impl<H, MC: MemoryConfig, BCC: BlockCacheConfig, M: ManagerReadWrite> PvmStepper<H, MC, BCC, M> {
    /// Create a new stepper in which the existing PVM is managed by
    /// the proof-generating backend.
    pub fn start_proof_mode(&self) -> PvmStepper<NoHooks, MC, BCC, ProofGen<Ref<'_, M>>> {
        PvmStepper {
            pvm: self.pvm.start_proof(),
            rollup_address: self.rollup_address,
            origination_level: self.origination_level,

            // The inbox needs to be cloned because we should not mutate it through the new stepper
            // instance.
            inbox: self.inbox.clone(),

            // We don't want to re-use the same hooks to avoid polluting logs with refutation game
            // output. Instead we use hooks that don't do anything.
            hooks: NoHooks,

            reveal_request_response_map: self.reveal_request_response_map.clone(),
        }
    }

    /// Similar to [`PvmStepper::verify_proof`] but constructs the allocated space by using the raw deserialisation.
    ///
    /// Useful for testing the stream deserialisation.
    pub fn verify_proof_using_raw_bytes(&self, proof: Proof) -> Result<(), ProofVerificationFailure>
    where
        AllocatedOf<<BCC as BlockCacheConfig>::Layout, Verifier>: 'static,
    {
        let tree_serialisation: Box<[u8]> = serialise_merkle_tree(proof.tree()).collect();
        let (space, merkle_tree) =
            deserialise_stream::deserialise::<PvmLayout<MC, BCC>>(&tree_serialisation)
                .map_err(|_| ProofVerificationFailure::UnexpectedProofShape)?;

        let deserialised_proof_tree = match merkle_tree {
            OwnedProofPart::Present(ref merkle_tree) => ProofTree::Present(merkle_tree),
            OwnedProofPart::Absent => ProofTree::Absent,
        };
        debug_assert_eq!(
            ProofTree::Present(proof.tree()),
            deserialised_proof_tree,
            "The Merkle proof tree obtained through deserialisation should match the original proof tree"
        );

        let stepper = self.as_verify_stepper(space)?;

        stepper.verify_proof_internal(ProofPart::Present(proof.tree()), proof.final_state_hash())
    }

    /// Verify a Merkle proof. The [`PvmStepper`] is used for inbox information.
    pub fn verify_proof(&self, proof: Proof) -> Result<(), ProofVerificationFailure>
    where
        AllocatedOf<BCC::Layout, Verifier>: 'static,
    {
        let proof_tree = ProofTree::Present(proof.tree());
        let (space, deserialised_proof_tree) =
            deserialise_owned::deserialise::<PvmLayout<MC, BCC>>(proof_tree)
                .map_err(|_| ProofVerificationFailure::UnexpectedProofShape)?;

        let deserialised_proof_tree = match deserialised_proof_tree {
            OwnedProofPart::Present(ref merkle_tree) => ProofTree::Present(merkle_tree),
            OwnedProofPart::Absent => ProofTree::Absent,
        };
        debug_assert_eq!(
            proof_tree, deserialised_proof_tree,
            "The Merkle proof tree obtained through deserialisation should match the original proof tree"
        );

        let stepper = self.as_verify_stepper(space)?;
        stepper.verify_proof_internal(proof_tree, proof.final_state_hash())
    }

    fn as_verify_stepper(
        &self,
        space: AllocatedOf<PvmLayout<MC, BCC>, Verifier>,
    ) -> Result<PvmVerifier<MC, BCC>, ProofVerificationFailure> {
        let pvm = Pvm::<MC, BCC, Interpreted<MC, Verifier>, Verifier>::bind(
            space,
            InterpretedBlockBuilder,
        );
        Ok(PvmStepper {
            pvm,
            rollup_address: self.rollup_address,
            origination_level: self.origination_level,

            // The inbox needs to be cloned because we should not mutate it through the new stepper
            // instance.
            inbox: self.inbox.clone(),

            // We don't want to re-use the same hooks to avoid polluting logs with refutation game
            // output. Instead we use hooks that don't do anything.
            hooks: NoHooks,

            reveal_request_response_map: self.reveal_request_response_map.clone(),
        })
    }
}

impl<H: PvmHooks, MC: MemoryConfig, BCC: BlockCacheConfig, M: ManagerReadWrite>
    PvmStepper<H, MC, BCC, M>
{
    /// Perform one evaluation step.
    pub fn eval_one(&mut self) {
        self.pvm.eval_one(&mut self.hooks)
    }
}

impl<H: PvmHooks, MC: MemoryConfig, BCC: BlockCacheConfig, B: Block<MC, Verifier>>
    PvmStepper<H, MC, BCC, Verifier, B>
{
    /// Try to take one step. Stepping with the [`Verifier`] backend may panic
    /// when attempting to access absent data. Return [`NotFound`] panics, which
    /// are expected in the case of verifying an invalid proof, as
    /// [`ProofVerificationFailure::AbsentDataAccess`] and all other panics
    /// as [`ProofVerificationFailure::StepperPanic`].
    ///
    /// [`NotFound`]: crate::state_backend::verify_backend::NotFound
    fn try_step_partial(self) -> Result<Self, ProofVerificationFailure> {
        // Wrapping the stepper in a Mutex, which implements poisoning, in order to pass it
        // across the unwind boundary.
        let mutex = std::sync::Mutex::new(self);
        handle_stepper_panics(move || {
            {
                let mut stepper = mutex.lock().unwrap();
                if !stepper.try_step() {
                    return Err(ProofVerificationFailure::StepperError);
                };
            }
            // Since all panics were handled and returned as errors, at this point
            // the mutex cannot be poisoned.
            Ok(mutex.into_inner().unwrap())
        })?
    }

    fn verify_proof_internal(
        self,
        proof_tree: ProofTree,
        expected_final_hash: Hash,
    ) -> Result<(), ProofVerificationFailure>
    where
        AllocatedOf<<BCC as BlockCacheConfig>::Layout, Verifier>: 'static,
    {
        let stepper = self.try_step_partial()?;

        let refs = stepper.pvm.struct_ref::<FnManagerIdent>();
        let final_hash = PvmLayout::<MC, BCC>::partial_state_hash(refs, proof_tree)?;
        if final_hash != expected_final_hash {
            return Err(ProofVerificationFailure::FinalHashMismatch {
                expected: expected_final_hash,
                computed: final_hash,
            });
        }

        Ok(())
    }
}

impl<H: PvmHooks, MC: MemoryConfig, B: Block<MC, Owned>, BCC: BlockCacheConfig> Stepper
    for PvmStepper<H, MC, BCC, Owned, B>
{
    type MemoryConfig = MC;

    type BlockCacheConfig = BCC;

    type Manager = Owned;

    fn machine_state(&self) -> &MachineCoreState<Self::MemoryConfig, Self::Manager> {
        &self.pvm.machine_state.core
    }

    type StepResult = StepperStatus;

    fn step_max(&mut self, mut step_bounds: Bound<usize>) -> Self::StepResult {
        let mut total_steps = 0usize;

        loop {
            match self.step_max_once(step_bounds) {
                StepperStatus::Running { steps } => {
                    total_steps = total_steps.saturating_add(steps);
                    step_bounds = bound_saturating_sub(step_bounds, steps);

                    if steps < 1 {
                        // Break if no progress has been made.
                        break StepperStatus::Running { steps: total_steps };
                    }
                }

                StepperStatus::Exited {
                    steps,
                    success,
                    status,
                } => {
                    break StepperStatus::Exited {
                        steps: total_steps.saturating_add(steps),
                        success,
                        status,
                    };
                }

                StepperStatus::Errored {
                    steps,
                    cause,
                    message,
                } => {
                    break StepperStatus::Errored {
                        steps: total_steps.saturating_add(steps),
                        cause,
                        message,
                    };
                }
            }
        }
    }
}
