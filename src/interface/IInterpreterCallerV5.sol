// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity ^0.8.18;

// Exported for convenience.
//forge-lint: disable-start(unused-import)
import {IParserV2} from "./IParserV2.sol";
import {IInterpreterStoreV3} from "./IInterpreterStoreV3.sol";
import {IInterpreterV4} from "./IInterpreterV4.sol";
import {EvaluableV4} from "./deprecated/v3/IInterpreterCallerV4.sol";
//forge-lint: disable-end

/// @dev EIP-712 type of a `SignedContextV2`. `signature` is not a member.
string constant SIGNED_CONTEXT_V2_TYPE = "SignedContextV2(address signer,bytes32[] context)";

/// @dev Literal so the hash is computed at compile time.
bytes32 constant SIGNED_CONTEXT_V2_TYPEHASH = keccak256("SignedContextV2(address signer,bytes32[] context)");

/// Context data signed by `signer` as EIP-712 typed data under the calling
/// contract's domain separator. `signer` is signed over, so a signature
/// verifies for exactly one account, ERC-1271 accounts included. ERC-1271
/// signatures are checked onchain and can be revoked at any time.
///
/// The domain is not replay protection. The expression is responsible for
/// authorising signers and for binding the words to their use (purpose,
/// nonces, uniqueness, expiry).
/// @param signer The account that produced the signature.
/// @param context Words merged as-is as one column of the context matrix.
/// @param signature EIP-712 signature over `signer` and `context`.
struct SignedContextV2 {
    address signer;
    bytes32[] context;
    bytes signature;
}

/// @title IInterpreterCallerV5
/// @notice A contract that calls an `IInterpreterV4` via. `eval4`, with signed
/// context as `SignedContextV2`. There are near zero requirements on a caller
/// other than:
///
/// - Provide the context, which can be built in a standard way by
///   `LibContext.buildV2`
/// - Handle the stack array returned from `eval4`
/// - OPTIONALLY emit the `ContextV2` event
/// - OPTIONALLY set state on the associated `IInterpreterStoreV3`.
interface IInterpreterCallerV5 {
    /// Calling contracts SHOULD emit `ContextV2` before calling `eval4` if
    /// they are able.
    /// @param sender `msg.sender` building the context.
    /// @param context The context that was built.
    event ContextV2(address sender, bytes32[][] context);
}
