// SPDX-FileCopyrightText: 2024-2025 TriliTech <contact@trili.tech>
//
// SPDX-License-Identifier: MIT

//! The instruction context forms the building blocks used for executing RISC-V instructions.
//!
//! By providing these building blocks for various execution formats, the same implementation can
//! be used for both interpretation and compilation of instructions.

pub(super) mod arithmetic;
pub(super) mod comparable;
pub(crate) mod value;

use arithmetic::Arithmetic;
use comparable::Comparable;
use rustc_apfloat::Float;
use rustc_apfloat::Status;
use rustc_apfloat::StatusAnd;
use rustc_apfloat::ieee::Double;

pub use self::value::StoreLoadInt;
use crate::instruction_context::value::PhiValue;
use crate::interpreter::atomics::ReservationSetOption;
use crate::interpreter::atomics::reset_reservation_set;
use crate::interpreter::float::RoundingMode;
use crate::machine_state::MachineCoreState;
use crate::machine_state::ProgramCounterUpdate;
use crate::machine_state::csregisters::CSRRepr;
use crate::machine_state::csregisters::CSRegister;
use crate::machine_state::instruction::Args;
use crate::machine_state::memory::Address;
use crate::machine_state::memory::BadMemoryAccess;
use crate::machine_state::memory::Memory;
use crate::machine_state::memory::MemoryConfig;
use crate::machine_state::registers::FRegister;
use crate::machine_state::registers::FValue;
use crate::machine_state::registers::NonZeroXRegister;
use crate::machine_state::registers::XRegister;
use crate::machine_state::registers::XValue;
use crate::machine_state::registers::XValue32;
use crate::parser::XRegisterParsed;
use crate::parser::instruction::InstrWidth;
use crate::parser::split_x0;
use crate::state_backend::ManagerReadWrite;
use crate::traps::Exception;

/// Type of function that may be used to lower [`Instructions`] to IR.
///
/// [`Instructions`]: crate::machine_state::instruction::Instruction
pub type IcbLoweringFn<I> = unsafe fn(&Args, &mut I) -> IcbFnResult<I>;

/// Result of lowering an instruction.
pub type IcbFnResult<I> = <I as ICB>::IResult<ProgramCounterUpdate<<I as ICB>::XValue>>;

/// Instruction Context Builder contains operations required to
/// execute RISC-V instructions.
#[expect(clippy::upper_case_acronyms, reason = "ICB looks cooler than Icb")]
pub(crate) trait ICB {
    /// A 64-bit value stored in [`XRegisters`].
    ///
    /// [`XRegisters`]: crate::machine_state::registers::XRegisters
    type XValue: Arithmetic<Self> + Comparable<Self, Result = Self::Bool>;

    /// A 64-bit floating-point value stored in [`FRegisters`].
    ///
    /// [`FRegisters`]: crate::machine_state::registers::FRegisters
    type FValue;

    /// Perform a read to a [`NonZeroXRegister`], with the given value.
    /// This is a specialized version of `xregister_read` that is only used for
    /// registers that are guaranteed not to be x0.
    fn xregister_read_nz(&mut self, reg: NonZeroXRegister) -> Self::XValue;

    /// Perform a write to a [`NonZeroXRegister`], with the given value.
    /// This is a specialized version of `xregister_write` that is only used for
    /// registers that are guaranteed not to be x0.
    fn xregister_write_nz(&mut self, reg: NonZeroXRegister, value: Self::XValue);

    /// Construct an [`ICB::XValue`] from an `imm: i64`.
    fn xvalue_of_imm(&mut self, imm: i64) -> Self::XValue;

    /// Construct an [`ICB::XValue32`] from an `imm: i32`.
    fn xvalue32_of_imm(&mut self, imm: i32) -> Self::XValue32;

    #[expect(unused, reason = "Will Be Used Soon™")]
    fn fregister_read(&mut self, reg: FRegister) -> Self::FValue;

    /// Perform a write to a [`FRegister`], with the given value.
    fn fregister_write(&mut self, reg: FRegister, value: Self::FValue);

    /// Perform a read of the program counter.
    fn pc_read(&mut self) -> Self::XValue;

    /// Type for boolean operations.
    type Bool;

    /// Perform a logical `and` operation of two [`ICB::Bool`] values.
    fn bool_and(&mut self, lhs: Self::Bool, rhs: Self::Bool) -> Self::Bool;

    /// A 32-bit value to be used only in word-width operations.
    type XValue32: Arithmetic<Self> + Comparable<Self, Result = Self::Bool>;

    /// Convert an [`XValue`] to a [`XValue32`].
    fn narrow(&mut self, value: Self::XValue) -> Self::XValue32;

    /// Sign-extend an [`XValue32`] to an [`XValue`].
    fn extend_signed(&mut self, value: Self::XValue32) -> Self::XValue;

    /// Zero-extend an [`XValue32`] to an [`XValue`].
    #[expect(dead_code, reason = "Will Be Used Soon™")]
    fn extend_unsigned(&mut self, value: Self::XValue32) -> Self::XValue;

    /// Multiply two [`XValue`] values and return the high 64 bits of the result, with
    /// the appropriate sign-extension passed in as 2 boolean arguments.
    fn mul_high(
        &mut self,
        lhs: Self::XValue,
        rhs: Self::XValue,
        mul_high_type: MulHighType,
    ) -> Self::XValue;

    /// Convert a boolean value to an xvalue.
    ///
    /// Coerces to the following:
    /// - `true -> 1`
    /// - `false -> 0`
    fn xvalue_from_bool(&mut self, value: Self::Bool) -> Self::XValue;

    /// Branching instruction.
    ///
    /// If `condition` is true, the branch will be taken. The PC update
    /// will be to the address returned by `take_branch`.
    ///
    /// If false, the PC update is to the next instruction.
    fn branch(
        &mut self,
        condition: Self::Bool,
        offset: i64,
        instr_width: InstrWidth,
    ) -> ProgramCounterUpdate<Self::XValue>;

    /// Take a branch based on the given condition and return to a common line of execution.
    ///
    /// This is used for situations where we have a common execution path following branching.
    /// The `cond` is the condition to branch on, and the `true_branch` and `false_branch` are the
    /// functions to execute for the left and right branches, respectively.
    ///
    /// Semantically, this function returns the caller into the context of the common
    /// execution path with the resulting value of the branch that was taken.
    fn branch_merge<Phi: PhiValue, OnTrue, OnFalse>(
        &mut self,
        cond: Self::Bool,
        true_branch: OnTrue,
        false_branch: OnFalse,
    ) -> Phi::IcbValue<Self>
    where
        OnTrue: FnOnce(&mut Self) -> Phi::IcbValue<Self>,
        OnFalse: FnOnce(&mut Self) -> Phi::IcbValue<Self>;

    /// Representation for the manipulation of fallible operations.
    type IResult<Value>;

    /// Wrap a value as a fallible value.
    fn ok<Value>(&mut self, val: Value) -> Self::IResult<Value>;

    /// Raise an [`Exception::IllegalInstruction`] error.
    fn err_illegal_instruction<In>(&mut self) -> Self::IResult<In>;

    /// Raise an [`Exception::StoreAMOAccessFault`] error if `address` is not
    /// aligned to the given [`LoadStoreWidth`].
    fn atomic_access_fault_guard<V: StoreLoadInt>(
        &mut self,
        address: Self::XValue,
        reservation_set_option: ReservationSetOption,
    ) -> Self::IResult<()>;

    /// Map the fallible-value into a fallible-value of a different type.
    fn map<Value, Next, F>(res: Self::IResult<Value>, f: F) -> Self::IResult<Next>
    where
        F: FnOnce(Value) -> Next;

    /// Run a fallible operation over the fallible-value as input.
    fn and_then<Value, Next, F>(res: Self::IResult<Value>, f: F) -> Self::IResult<Next>
    where
        F: FnOnce(Value) -> Self::IResult<Next>;

    /// Exception to perform an ECall at the current mode
    fn ecall(&mut self) -> Self::IResult<ProgramCounterUpdate<Self::XValue>>;

    /// Write value to main memory, at the given address.
    ///
    /// The value is truncated to the width given by [`LoadStoreWidth`].
    fn main_memory_store<V: StoreLoadInt>(
        &mut self,
        phys_address: Self::XValue,
        value: Self::XValue,
    ) -> Self::IResult<()>;

    /// Read value from main memory, at the given address.
    ///
    /// The value is truncated to the width given by [`LoadStoreWidth`].
    fn main_memory_load<V: StoreLoadInt>(
        &mut self,
        phys_address: Self::XValue,
    ) -> Self::IResult<Self::XValue>;

    /// Write the start address of the reservation set.
    ///
    /// The address must be aligned to the size of the reservation set.
    fn reservation_set_write(&mut self, address: Self::XValue);

    /// Read the reservation set start address.
    fn reservation_set_read(&mut self) -> Self::XValue;

    /// Take an `XValue` and convert it to a 64-bit float with the dynamic rounding mode in the `frm` field of the
    /// `fcsr` register, returning the result as an `FValue`.
    fn f64_from_x64_unsigned_dynamic(&mut self, xval: Self::XValue) -> Self::IResult<Self::FValue>;

    /// Take an `XValue` and a static rounding mode, and convert it to a 64-bit float
    /// with the given rounding mode, returning the resulting `FValue`.
    fn f64_from_x64_unsigned_static(
        &mut self,
        xval: Self::XValue,
        rm: RoundingMode,
    ) -> Self::FValue;

    // ----------------
    // Provided Methods
    // ----------------

    /// Read a value from an [`XRegister`].
    ///
    /// If the register is `x0`, the value read is always zero.
    fn xregister_read(&mut self, reg: XRegister) -> Self::XValue {
        match split_x0(reg) {
            XRegisterParsed::X0 => self.xvalue_of_imm(0),
            XRegisterParsed::NonZero(reg) => self.xregister_read_nz(reg),
        }
    }

    /// Write a value to an [`XRegister`].
    ///
    /// If the register is `x0`, this is a no-op.
    fn xregister_write(&mut self, reg: XRegister, value: Self::XValue) {
        if let XRegisterParsed::NonZero(reg) = split_x0(reg) {
            self.xregister_write_nz(reg, value)
        }
    }
}

impl<MC: MemoryConfig, M: ManagerReadWrite> ICB for MachineCoreState<MC, M> {
    type XValue = XValue;

    type FValue = FValue;

    #[inline(always)]
    fn xregister_read_nz(&mut self, reg: NonZeroXRegister) -> Self::XValue {
        self.hart.xregisters.read_nz(reg)
    }

    #[inline(always)]
    fn xregister_read(&mut self, reg: XRegister) -> Self::XValue {
        self.hart.xregisters.read(reg)
    }

    #[inline(always)]
    fn xregister_write_nz(&mut self, reg: NonZeroXRegister, value: Self::XValue) {
        self.hart.xregisters.write_nz(reg, value)
    }

    #[inline(always)]
    fn xregister_write(&mut self, reg: XRegister, value: Self::XValue) {
        self.hart.xregisters.write(reg, value)
    }

    #[inline(always)]
    fn xvalue_of_imm(&mut self, imm: i64) -> Self::XValue {
        imm as u64
    }

    fn xvalue32_of_imm(&mut self, imm: i32) -> Self::XValue32 {
        imm as u32
    }

    #[inline(always)]
    fn fregister_read(&mut self, reg: FRegister) -> Self::FValue {
        self.hart.fregisters.read(reg)
    }

    #[inline(always)]
    fn fregister_write(&mut self, reg: FRegister, value: Self::FValue) {
        self.hart.fregisters.write(reg, value)
    }

    #[inline(always)]
    fn pc_read(&mut self) -> Self::XValue {
        self.hart.pc.read()
    }

    type Bool = bool;

    #[inline(always)]
    fn bool_and(&mut self, lhs: Self::Bool, rhs: Self::Bool) -> Self::Bool {
        lhs && rhs
    }

    type XValue32 = XValue32;

    #[inline(always)]
    fn narrow(&mut self, value: Self::XValue) -> Self::XValue32 {
        value as u32
    }

    #[inline(always)]
    fn extend_signed(&mut self, value: Self::XValue32) -> Self::XValue {
        value as i32 as u64
    }

    #[inline(always)]
    fn extend_unsigned(&mut self, value: Self::XValue32) -> Self::XValue {
        value as u64
    }

    #[inline(always)]
    fn mul_high(
        &mut self,
        lhs: Self::XValue,
        rhs: Self::XValue,
        mul_high_type: MulHighType,
    ) -> Self::XValue {
        let (lhs, rhs) = match mul_high_type {
            MulHighType::Signed => (lhs as i64 as i128 as u128, rhs as i64 as i128 as u128),
            MulHighType::Unsigned => (lhs as u128, rhs as u128),
            MulHighType::SignedUnsigned => (lhs as i64 as i128 as u128, rhs as u128),
        };
        let result = lhs.wrapping_mul(rhs);

        (result >> 64) as u64
    }

    #[inline(always)]
    fn xvalue_from_bool(&mut self, value: Self::Bool) -> Self::XValue {
        value as XValue
    }

    #[inline(always)]
    fn branch(
        &mut self,
        predicate: Self::Bool,
        offset: i64,
        instr_width: InstrWidth,
    ) -> ProgramCounterUpdate<Self::XValue> {
        if predicate {
            let pc = self.pc_read();
            let address = pc.wrapping_add(offset as u64);
            ProgramCounterUpdate::Set(address)
        } else {
            ProgramCounterUpdate::Next(instr_width)
        }
    }

    #[inline(always)]
    fn branch_merge<Phi: PhiValue, OnTrue, OnFalse>(
        &mut self,
        cond: Self::Bool,
        true_branch: OnTrue,
        false_branch: OnFalse,
    ) -> Phi::IcbValue<Self>
    where
        OnTrue: FnOnce(&mut Self) -> Phi::IcbValue<Self>,
        OnFalse: FnOnce(&mut Self) -> Phi::IcbValue<Self>,
    {
        if cond {
            true_branch(self)
        } else {
            false_branch(self)
        }
    }

    #[inline(always)]
    fn atomic_access_fault_guard<V: StoreLoadInt>(
        &mut self,
        address: Address,
        reservation_set_option: ReservationSetOption,
    ) -> Self::IResult<()> {
        let width = self.xvalue_of_imm(V::WIDTH as i64);
        let remainder = address.modulus_unsigned(width, self);
        let zero = self.xvalue_of_imm(0);

        if remainder.compare(zero, Predicate::NotEqual, self) {
            if let ReservationSetOption::Reset = reservation_set_option {
                reset_reservation_set(self);
            }
            Err(Exception::StoreAMOAccessFault(address))
        } else {
            Ok(())
        }
    }

    type IResult<In> = Result<In, Exception>;

    #[inline(always)]
    fn ok<In>(&mut self, val: In) -> Self::IResult<In> {
        Ok(val)
    }

    #[inline(always)]
    fn err_illegal_instruction<In>(&mut self) -> Self::IResult<In> {
        Err(Exception::IllegalInstruction)
    }

    #[inline(always)]
    fn map<In, Out, F>(res: Self::IResult<In>, f: F) -> Self::IResult<Out>
    where
        F: FnOnce(In) -> Out,
    {
        res.map(f)
    }

    #[inline(always)]
    fn and_then<In, Out, F>(res: Self::IResult<In>, f: F) -> Self::IResult<Out>
    where
        F: FnOnce(In) -> Self::IResult<Out>,
    {
        res.and_then(f)
    }

    fn ecall(&mut self) -> Self::IResult<ProgramCounterUpdate<Self::XValue>> {
        Err(Exception::EnvCall)
    }

    #[inline(always)]
    fn main_memory_store<V: StoreLoadInt>(
        &mut self,
        address: Self::XValue,
        value: Self::XValue,
    ) -> Self::IResult<()> {
        self.main_memory
            .write(address, V::from_xvalue(value))
            .map_err(|_: BadMemoryAccess| Exception::StoreAMOAccessFault(address))
    }

    #[inline(always)]
    fn main_memory_load<V: StoreLoadInt>(
        &mut self,
        address: Self::XValue,
    ) -> Self::IResult<Self::XValue> {
        self.main_memory
            .read(address)
            .map(V::to_xvalue)
            .map_err(|_: BadMemoryAccess| Exception::LoadAccessFault(address))
    }

    #[inline(always)]
    fn reservation_set_write(&mut self, address: Self::XValue) {
        self.hart.reservation_set.start_addr.write(address);
    }

    #[inline(always)]
    fn reservation_set_read(&mut self) -> Self::XValue {
        self.hart.reservation_set.start_addr.read()
    }

    fn f64_from_x64_unsigned_static(
        &mut self,
        xval: Self::XValue,
        rm: RoundingMode,
    ) -> Self::FValue {
        let extended = xval as u128;

        let StatusAnd { status, value } = Double::from_u128_r(extended, rm.into());

        if status != Status::OK {
            self.hart.csregisters.set_exception_flag_status(status);
        }

        value.into()
    }

    fn f64_from_x64_unsigned_dynamic(&mut self, xval: Self::XValue) -> Self::IResult<Self::FValue> {
        let extended = xval as u128;
        let rm: RoundingMode = self
            .hart
            .csregisters
            .read::<CSRRepr>(CSRegister::frm)
            .try_into()?;

        let StatusAnd { status, value } = Double::from_u128_r(extended, rm.into());

        if status != Status::OK {
            self.hart.csregisters.set_exception_flag_status(status);
        }

        Ok(value.into())
    }
}

/// Operators for producing a boolean from two values.
pub enum Predicate {
    Equal,
    NotEqual,
    LessThanSigned,
    LessThanUnsigned,
    LessThanOrEqualSigned,
    GreaterThanSigned,
    GreaterThanOrEqualSigned,
    GreaterThanOrEqualUnsigned,
}

/// The type of shift operation to perform.
pub enum Shift {
    /// Logical left shift. Zeroes are shifted into the least significant bits.
    Left,
    /// Logical right shift. Zeroes are shifted into the most significant bits.
    RightUnsigned,
    /// Arithmetic right shift. Sign-bits (ones) are shifted into the most significant bits.
    RightSigned,
}

/// The type of X64 mul_high operation to perform.
pub enum MulHighType {
    Signed,
    Unsigned,
    SignedUnsigned,
}

/// Supported value widths for loading from/storing to main memory for XRegisters.
///
/// **NB** This type may be passed over C-FFI. See [state_access] for more
/// information.
///
/// For now, the approach taken chooses to pass enums as integers, and parse
/// them back into the Enum variant on the rust side - to avoid potential UB
/// should an incorrect discriminant be parsed. We therefore choose explicit
/// constants for each - so that we know very precisely what values are expected.
///
/// [state_access]: crate::jit::state_access
#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum LoadStoreWidth {
    Byte = Self::BYTE_WIDTH,
    Half = Self::HALF_WIDTH,
    Word = Self::WORD_WIDTH,
    Double = Self::DOUBLE_WIDTH,
}

impl LoadStoreWidth {
    const BYTE_WIDTH: u8 = std::mem::size_of::<u8>() as u8;
    const HALF_WIDTH: u8 = std::mem::size_of::<u16>() as u8;
    const WORD_WIDTH: u8 = std::mem::size_of::<u32>() as u8;
    const DOUBLE_WIDTH: u8 = std::mem::size_of::<u64>() as u8;
}
