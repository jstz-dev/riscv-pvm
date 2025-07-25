// SPDX-FileCopyrightText: 2025 TriliTech <contact@trili.tech>
//
// SPDX-License-Identifier: MIT

//! Helper functionality for generating ABI interface code.

use cranelift::codegen::ir::AbiParam;
use cranelift::codegen::ir::Signature;
use cranelift::codegen::ir::Type;
use cranelift::codegen::ir::types::I8;
use cranelift::codegen::ir::types::I16;
use cranelift::codegen::ir::types::I32;
use cranelift::codegen::ir::types::I64;
use cranelift::prelude::isa::CallConv;
use cranelift::prelude::types::F64;
use cranelift_jit::JITModule;
use cranelift_module::FuncId;
use cranelift_module::Linkage;
use cranelift_module::Module;
use cranelift_module::ModuleResult;

use crate::machine_state::registers::FRegister;
use crate::machine_state::registers::NonZeroXRegister;

/// This struct is used to produce and declare function signatures for external function calls.
///
/// It is generic over the number of parameters `T` and the return type of the function call.
pub(super) struct AbiCall<const T: usize> {
    params: [CraneliftRepr; T],
    ret: Option<CraneliftRepr>,
}

impl<const T: usize> AbiCall<T> {
    /// Declare a function with the given name in the JIT module so it can be called from a JIT function.
    pub(super) fn declare_function(
        &self,
        module: &mut JITModule,
        name: &str,
        ptr_type: Type,
        call_conv: CallConv,
    ) -> ModuleResult<FuncId> {
        let params = self
            .params
            .iter()
            .map(|param| match param {
                CraneliftRepr::Ptr => AbiParam::new(ptr_type),
                CraneliftRepr::Value(ty) => AbiParam::new(*ty),
            })
            .collect();

        let returns = match &self.ret {
            Some(param) => vec![match param {
                CraneliftRepr::Ptr => AbiParam::new(ptr_type),
                CraneliftRepr::Value(ty) => AbiParam::new(*ty),
            }],
            None => vec![],
        };

        let sig = Signature {
            params,
            returns,
            call_conv,
        };
        module.declare_function(name, Linkage::Import, &sig)
    }
}

/// This macro is used to implement the functions that produce the [`AbiCall`] struct
/// for external function calls with different numbers of arguments.
macro_rules! impl_abicall {
    ($($arg:ident),*) => {
        pub(super) fn args<$($arg: ToCraneliftRepr),*, Ret: Returnable>(_fun: extern "C" fn($($arg),*) -> Ret)
        -> Self
        {
            let params = [$($arg::CRANELIFT_TYPE,)*];
            let ret = Ret::convert();
            AbiCall { params, ret }
        }
    };
}

impl AbiCall<1> {
    impl_abicall!(A1);
}
impl AbiCall<2> {
    impl_abicall!(A1, A2);
}
impl AbiCall<3> {
    impl_abicall!(A1, A2, A3);
}

impl AbiCall<4> {
    impl_abicall!(A1, A2, A3, A4);
}

/// Holds the IR representation of a function parameter's type, which is needed for
/// registering the function's [`Signature`] in the [`JITModule`].
pub(super) enum CraneliftRepr {
    /// Pointer for reference type parameters. This will be mapped to the default
    /// cranelift IR pointer type for the target architecture.
    Ptr,
    /// Value-type parameters that will be represented directly by a cranelift IR type.
    Value(Type),
}

/// This Type can be transformed into a cranelift IR Type.
pub(super) trait ToCraneliftRepr {
    /// Associated constant to determine the Cranelift type at compile time.
    const CRANELIFT_TYPE: CraneliftRepr;
}

impl ToCraneliftRepr for u64 {
    const CRANELIFT_TYPE: CraneliftRepr = CraneliftRepr::Value(I64);
}

impl ToCraneliftRepr for i64 {
    const CRANELIFT_TYPE: CraneliftRepr = CraneliftRepr::Value(I64);
}

impl ToCraneliftRepr for bool {
    const CRANELIFT_TYPE: CraneliftRepr = CraneliftRepr::Value(I8);
}

impl ToCraneliftRepr for NonZeroXRegister {
    const CRANELIFT_TYPE: CraneliftRepr = CraneliftRepr::Value(I8);
}

impl ToCraneliftRepr for u8 {
    const CRANELIFT_TYPE: CraneliftRepr = CraneliftRepr::Value(I8);
}

impl ToCraneliftRepr for i8 {
    const CRANELIFT_TYPE: CraneliftRepr = CraneliftRepr::Value(I8);
}

impl ToCraneliftRepr for i16 {
    const CRANELIFT_TYPE: CraneliftRepr = CraneliftRepr::Value(I16);
}

impl ToCraneliftRepr for u16 {
    const CRANELIFT_TYPE: CraneliftRepr = CraneliftRepr::Value(I16);
}

impl ToCraneliftRepr for i32 {
    const CRANELIFT_TYPE: CraneliftRepr = CraneliftRepr::Value(I32);
}

impl ToCraneliftRepr for u32 {
    const CRANELIFT_TYPE: CraneliftRepr = CraneliftRepr::Value(I32);
}

impl<T> ToCraneliftRepr for &T {
    const CRANELIFT_TYPE: CraneliftRepr = CraneliftRepr::Ptr;
}

impl<T> ToCraneliftRepr for &mut T {
    const CRANELIFT_TYPE: CraneliftRepr = CraneliftRepr::Ptr;
}

impl ToCraneliftRepr for FRegister {
    const CRANELIFT_TYPE: CraneliftRepr = CraneliftRepr::Value(I8);
}

impl ToCraneliftRepr for f64 {
    const CRANELIFT_TYPE: CraneliftRepr = CraneliftRepr::Value(F64);
}

/// A valid return type for an external function call.
pub(super) trait Returnable {
    /// Convert the return type of a function to a cranelift IR type.
    /// If the type is `()`, return `None` to indicate that there is no return value.
    fn convert() -> Option<CraneliftRepr>;
}

impl Returnable for () {
    fn convert() -> Option<CraneliftRepr> {
        None
    }
}

impl<T: ToCraneliftRepr> Returnable for T {
    fn convert() -> Option<CraneliftRepr> {
        Some(T::CRANELIFT_TYPE)
    }
}
