// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity ^0.8.18;

// Exported for convenience.
//forge-lint: disable-next-line(unused-import)
import {IParserV2} from "./IParserV2.sol";
import {IInterpreterStoreV3} from "./IInterpreterStoreV3.sol";
import {IInterpreterV4} from "./IInterpreterV4.sol";
import {

    // Exported for convenience.
    //forge-lint: disable-start(unused-import)
    SignedContextV1,
    SIGNED_CONTEXT_SIGNER_OFFSET,
    SIGNED_CONTEXT_CONTEXT_OFFSET,
    SIGNED_CONTEXT_SIGNATURE_OFFSET
} from "./deprecated/v2/IInterpreterCallerV3.sol";

//forge-lint: disable-end

/// @param interpreter Will evaluate the expression. Callers MUST NOT use an
/// `EvaluableV4` with a zero or untrusted interpreter address.
/// @param store Will store state changes due to evaluation of the expression.
/// MAY be `address(0)` only if the expression never writes state.
/// @param bytecode Will be evaluated by the interpreter.
struct EvaluableV4 {
    IInterpreterV4 interpreter;
    IInterpreterStoreV3 store;
    bytes bytecode;
}

/// @dev EIP-712 type of the data a `SignedContextV2` signature is over: the signer
/// and the context words. The `signature` field is not a member.
string constant SIGNED_CONTEXT_V2_TYPE = "SignedContextV2(address signer,bytes32[] context)";

/// @dev `keccak256` of `SIGNED_CONTEXT_V2_TYPE`, written as a literal so the hash
/// is computed at compile time.
bytes32 constant SIGNED_CONTEXT_V2_TYPEHASH = keccak256("SignedContextV2(address signer,bytes32[] context)");

/// Typed embodiment of some context data with associated signer and signature,
/// signed as EIP-712 typed data. The signature MUST be over the digest
/// `keccak256(abi.encodePacked(hex"1901", domainSeparator, hashStruct))` where
/// `hashStruct` is `LibContext.hashStruct`, i.e.
/// `keccak256(abi.encodePacked(SIGNED_CONTEXT_V2_TYPEHASH, signer, keccak256(abi.encodePacked(context))))`,
/// and `domainSeparator` is the EIP-712 domain separator of the calling
/// contract, passed by it to `LibContext.buildV2`. The calling contract chooses
/// its domain (which fields it has and their values) and MAY publish it per
/// ERC-5267; the same signed data under a different domain separator does not
/// verify.
///
/// The domain separates this calling contract's signed contexts from other
/// domains. It is not replay protection: the calling contract (likely with the
/// help of `LibContext`) is responsible for ensuring the authenticity of the
/// signature, but not authorizing _who_ can sign. IN ADDITION to authorisation
/// of the signer to known-good entities the expression is also responsible for:
///
/// - Enforcing the context is the expected data (e.g. a word identifying what
///   the signed context is for)
/// - Tracking and enforcing nonces if signed contexts are only usable one time
/// - Tracking and enforcing uniqueness of signed data if relevant
/// - Checking and enforcing expiry times if present and relevant in the context
/// - Many other potential constraints that expressions may want to enforce
///
/// EIP-1271 smart contract signatures are supported in addition to EOA
/// signatures via. the Open Zeppelin `SignatureChecker` library, which is
/// wrapped by `LibContext.buildV2`. As smart contract signatures are checked
/// onchain they CAN BE REVOKED AT ANY MOMENT as the smart contract can simply
/// return `false` when it previously returned `true`.
///
/// A `SignedContextV1` signature (EIP-191 `personal_sign` over the context
/// hash) is not a valid `SignedContextV2` signature, and vice versa.
///
/// @param signer The account that produced the signature. Part of the signed
/// data, so a signature verifies for exactly one signer, for smart contract
/// signers too.
/// @param context The signed data in a format that can be merged into a
/// 2-dimensional context matrix as-is.
/// @param signature The EIP-712 signature over `signer` and `context` under
/// the calling contract's domain. Not part of the signed data.
struct SignedContextV2 {
    address signer;
    bytes32[] context;
    bytes signature;
}

/// @title IInterpreterCallerV4
/// @notice A contract that calls an `IInterpreterV4` via. `eval4`. There are
/// near zero requirements on a caller other than:
///
/// - Provide the context, which can be built in a standard way by `LibContext`
/// - Handle the stack array returned from `eval4`
/// - OPTIONALLY emit the `Context` event
/// - OPTIONALLY set state on the associated `IInterpreterStoreV3`.
interface IInterpreterCallerV4 {
    /// Calling contracts SHOULD emit `Context` before calling `eval4` if they
    /// are able. Notably `eval4` MAY be called within a static call which means
    /// that events cannot be emitted, in which case this does not apply. It MAY
    /// NOT be useful to emit this multiple times for several eval calls if they
    /// all share a common context, in which case a single emit is sufficient.
    /// @param sender `msg.sender` building the context.
    /// @param context The context that was built.
    event ContextV2(address sender, bytes32[][] context);
}
