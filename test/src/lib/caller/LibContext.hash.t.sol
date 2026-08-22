// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {Test} from "forge-std-1.16.2/src/Test.sol";
import {SignedContextV1, LibContext} from "src/lib/caller/LibContext.sol";
import {LibContextSlow} from "./LibContextSlow.sol";

contract LibContextHashTest is Test {
    function testFuzzHash0() public pure {
        SignedContextV1[] memory signedContexts = new SignedContextV1[](3);
        signedContexts[0] = SignedContextV1(address(0), new bytes32[](5), new bytes(65));
        signedContexts[1] = SignedContextV1(address(0), new bytes32[](5), new bytes(65));
        signedContexts[2] = SignedContextV1(address(0), new bytes32[](5), new bytes(65));

        LibContext.hash(signedContexts);
    }

    function testHash(uint256 foo) public pure {
        assembly ("memory-safe") {
            mstore(0x00, foo)
            pop(keccak256(0x00, 0x20))
        }
    }

    function testHashGas0() public pure {
        assembly ("memory-safe") {
            mstore(0, 0)
            pop(keccak256(0, 0x20))
        }
    }

    /// Concrete test: hash of SignedContextV1 with empty context and signature
    /// matches reference implementation.
    function testSignedContextHashEmpty() public pure {
        SignedContextV1 memory ctx = SignedContextV1(address(0), new bytes32[](0), "");
        assertEq(LibContext.hash(ctx), LibContextSlow.hashSlow(ctx));
    }

    /// forge-config: default.fuzz.runs = 100
    function testSignedContextHashReferenceImplementation(SignedContextV1 memory signedContext) public pure {
        assertEq(LibContext.hash(signedContext), LibContextSlow.hashSlow(signedContext));
    }

    function testSignedContextArrayHashReferenceImplementation0() public pure {
        SignedContextV1[] memory signedContexts = new SignedContextV1[](1);
        signedContexts[0] = SignedContextV1(address(0), new bytes32[](0), "");
        assertEq(LibContext.hash(signedContexts), LibContextSlow.hashSlow(signedContexts));
    }

    function testSignedContextHashGas0() public pure {
        SignedContextV1 memory context = SignedContextV1(address(0), new bytes32[](5), new bytes(65));
        LibContext.hash(context);
        // 1199 gas
        // bytes memory bytes = abi.encode(context);
        // keccak256(bytes);
    }

    function testSignedContextHashEncodeGas0() public pure {
        SignedContextV1 memory context = SignedContextV1(address(0), new bytes32[](5), new bytes(65));
        // 1199 gas
        bytes memory data = abi.encode(context);
        keccak256(data);
    }

    /// forge-config: default.fuzz.runs = 100
    function testSignedContextArrayHashReferenceImplementation(SignedContextV1[] memory signedContexts) public pure {
        assertEq(LibContext.hash(signedContexts), LibContextSlow.hashSlow(signedContexts));
    }
}
