// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {LibHashNoAlloc, HASH_NIL} from "rain-lib-hash-0.1.0/src/LibHashNoAlloc.sol";
import {LibCast} from "rain-lib-typecast-0.1.4/src/LibCast.sol";
import {LibUint256Array} from "rain-solmem-0.1.26/src/lib/LibUint256Array.sol";

import {SignedContextV1} from "src/interface/IInterpreterCallerV4.sol";

library LibContextSlow {
    using LibUint256Array for uint256;
    using LibCast for uint256[];

    function hashSlow(SignedContextV1 memory signedContext) internal pure returns (bytes32) {
        bytes32 a = LibHashNoAlloc.hashWords(uint256(uint160(signedContext.signer)).arrayFrom().asBytes32Array());
        bytes32 b = LibHashNoAlloc.hashWords(signedContext.context);
        bytes32 c = LibHashNoAlloc.combineHashes(a, b);
        bytes32 d = LibHashNoAlloc.hashBytes(signedContext.signature);
        bytes32 e = LibHashNoAlloc.combineHashes(c, d);
        return e;
    }

    function hashSlow(SignedContextV1[] memory signedContexts) internal pure returns (bytes32) {
        bytes32 hashed = HASH_NIL;

        for (uint256 i = 0; i < signedContexts.length; i++) {
            hashed = LibHashNoAlloc.combineHashes(hashed, hashSlow(signedContexts[i]));
        }

        return hashed;
    }

    function buildStructureSlow(bytes32[][] memory baseContext, SignedContextV1[] memory signedContexts)
        internal
        view
        returns (bytes32[][] memory)
    {
        uint256 signedLen = signedContexts.length > 0 ? signedContexts.length + 1 : 0;
        bytes32[][] memory context = new bytes32[][](1 + baseContext.length + signedLen);
        context[0] = new bytes32[](2);
        context[0][0] = bytes32(uint256(uint160(address(msg.sender))));
        context[0][1] = bytes32(uint256(uint160(address(this))));

        uint256 offset = 1;
        uint256 i = 0;
        for (; i < baseContext.length; i++) {
            context[i + offset] = baseContext[i];
        }
        offset = offset + i;

        if (signedContexts.length > 0) {
            bytes32[] memory signers = new bytes32[](signedContexts.length);
            for (i = 0; i < signedContexts.length; i++) {
                signers[i] = bytes32(uint256(uint160(signedContexts[i].signer)));
            }
            context[offset] = signers;
            offset = offset + 1;

            i = 0;
            for (; i < signedContexts.length; i++) {
                context[i + offset] = signedContexts[i].context;
            }
        }

        return context;
    }
}
