// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity ^0.8.25;

import {SignatureChecker} from "@openzeppelin-contracts-5.7.0/utils/cryptography/SignatureChecker.sol";
import {MessageHashUtils} from "@openzeppelin-contracts-5.7.0/utils/cryptography/MessageHashUtils.sol";

import {SignedContextV2, SIGNED_CONTEXT_V2_TYPEHASH} from "../../interface/IInterpreterCallerV5.sol";

/// Thrown when the ith signature from a list of signed contexts is invalid.
/// @param i The index of the invalid signature in the list of signed contexts.
error InvalidSignature(uint256 i);

/// @dev Column of the base context in a context built by `LibContext.buildV2`.
uint256 constant CONTEXT_BASE_COLUMN = 0;
/// @dev Rows of the base context: `msg.sender`, calling contract, domain
/// separator.
uint256 constant CONTEXT_BASE_V2_ROWS = 3;
/// @dev Row of `msg.sender` in the base context.
uint256 constant CONTEXT_BASE_ROW_SENDER = 0;
/// @dev Row of the calling contract in the base context.
uint256 constant CONTEXT_BASE_ROW_CALLING_CONTRACT = 1;
/// @dev Row of the EIP-712 domain separator the signed contexts were verified
/// under, so an expression can pin it.
uint256 constant CONTEXT_BASE_ROW_DOMAIN_SEPARATOR = 2;

/// @title LibContext
/// @notice Standard construction and authentication of the context matrix
/// for an `IInterpreterCallerV5`.
library LibContext {
    /// `[msg.sender, address(this), domainSeparator]` as a context column.
    /// The interpreter cannot inspect its caller, so these are provided as
    /// context.
    /// @param domainSeparator The EIP-712 domain separator of the calling
    /// contract.
    /// @return The base context column.
    function baseV2(bytes32 domainSeparator) internal view returns (bytes32[] memory) {
        bytes32[] memory baseArray;
        assembly ("memory-safe") {
            baseArray := mload(0x40)
            mstore(baseArray, 3)
            mstore(add(baseArray, 0x20), caller())
            mstore(add(baseArray, 0x40), address())
            mstore(add(baseArray, 0x60), domainSeparator)
            mstore(0x40, add(baseArray, 0x80))
        }
        return baseArray;
    }

    /// EIP-712 `hashStruct` of a `SignedContextV2`. Uses memory past the free
    /// memory pointer without allocating.
    /// @param signedContext The signed context to hash.
    /// @return The EIP-712 struct hash of `signedContext`.
    function hashStruct(SignedContextV2 memory signedContext) internal pure returns (bytes32) {
        bytes32 typeHash = SIGNED_CONTEXT_V2_TYPEHASH;
        address signer = signedContext.signer;
        bytes32[] memory context = signedContext.context;
        bytes32 hashed;
        assembly ("memory-safe") {
            let contextHash := keccak256(add(context, 0x20), mul(mload(context), 0x20))
            let ptr := mload(0x40)
            mstore(ptr, typeHash)
            mstore(add(ptr, 0x20), signer)
            mstore(add(ptr, 0x40), contextHash)
            hashed := keccak256(ptr, 0x60)
        }
        return hashed;
    }

    /// Builds the context matrix: `baseV2(domainSeparator)`, then
    /// `baseContext`, then, only if there are signed contexts, a column of
    /// their signers followed by one column per signed context.
    ///
    /// Each signed context is verified through `SignatureChecker` (EOA and
    /// ERC-1271) against
    /// `MessageHashUtils.toTypedDataHash(domainSeparator, hashStruct(signedContext))`.
    /// @param baseContext Calling contract columns. MUST have a consistent
    /// number of columns so the expression can locate the signed columns.
    /// @param signedContexts Contexts signed by third parties, provided by
    /// `msg.sender`.
    /// @param domainSeparator The EIP-712 domain separator of the calling
    /// contract.
    /// @return The context matrix. REVERTS with `InvalidSignature(i)` at the
    /// first signed context `i` that does not verify.
    function buildV2(bytes32[][] memory baseContext, SignedContextV2[] memory signedContexts, bytes32 domainSeparator)
        internal
        view
        returns (bytes32[][] memory)
    {
        unchecked {
            bytes32[] memory signers = new bytes32[](signedContexts.length);

            uint256 contextLength = 1 + baseContext.length + (signedContexts.length > 0 ? signedContexts.length + 1 : 0);

            bytes32[][] memory context = new bytes32[][](contextLength);
            uint256 offset = 0;
            context[offset] = LibContext.baseV2(domainSeparator);

            for (uint256 i = 0; i < baseContext.length; i++) {
                offset++;
                context[offset] = baseContext[i];
            }

            if (signedContexts.length > 0) {
                offset++;
                context[offset] = signers;

                for (uint256 i = 0; i < signedContexts.length; i++) {
                    if (!SignatureChecker.isValidSignatureNow(
                            signedContexts[i].signer,
                            MessageHashUtils.toTypedDataHash(domainSeparator, hashStruct(signedContexts[i])),
                            signedContexts[i].signature
                        )) {
                        revert InvalidSignature(i);
                    }

                    signers[i] = bytes32(uint256(uint160(signedContexts[i].signer)));
                    offset++;
                    context[offset] = signedContexts[i].context;
                }
            }

            return context;
        }
    }
}
