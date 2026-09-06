// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {Test} from "forge-std-1.16.2/src/Test.sol";
import {LibContext, MessageHashUtils, SignedContextV1, InvalidSignature} from "src/lib/caller/LibContext.sol";
import {SignedContextV2} from "src/interface/IInterpreterCallerV4.sol";
import {LibSignedContextV2TypedData, EIP712Domain} from "test/lib/caller/LibSignedContextV2TypedData.sol";
import {LibContextSlow} from "./LibContextSlow.sol";

contract LibContextBuildV2Test is Test {
    /// Private key of the signer used throughout.
    uint256 constant SIGNER_PK = 0x5163;
    /// Private key of a second signer.
    uint256 constant OTHER_PK = 0xB0B;
    /// Largest fuzzed context, in words, so the JSON the digests come from
    /// stays small.
    uint256 constant MAX_WORDS = 16;

    function buildV2External(
        bytes32[][] memory baseContext,
        SignedContextV2[] memory signedContexts,
        bytes32 domainSeparator
    ) external view returns (bytes32[][] memory) {
        return LibContext.buildV2(baseContext, signedContexts, domainSeparator);
    }

    function buildExternal(bytes32[][] memory baseContext, SignedContextV1[] memory signedContexts)
        external
        view
        returns (bytes32[][] memory)
    {
        return LibContext.build(baseContext, signedContexts);
    }

    /// The domain the signed contexts are verified under.
    function domain() internal pure returns (EIP712Domain memory) {
        return EIP712Domain("LibContextBuildV2Test", "1", 1, 0x1234567890123456789012345678901234567890);
    }

    function signingDomainSeparator() internal pure returns (bytes32) {
        return LibSignedContextV2TypedData.domainSeparator(domain());
    }

    /// `words` truncated to at most `MAX_WORDS`.
    function bounded(bytes32[] memory words) internal pure returns (bytes32[] memory) {
        if (words.length > MAX_WORDS) {
            assembly ("memory-safe") {
                mstore(words, MAX_WORDS)
            }
        }
        return words;
    }

    /// One signed context from `pk` presenting `context` under a signature
    /// over `signedWords` in `signingDomain`.
    function signedContextsFor(
        uint256 pk,
        EIP712Domain memory signingDomain,
        bytes32[] memory context,
        bytes32[] memory signedWords
    ) internal pure returns (SignedContextV2[] memory) {
        SignedContextV2[] memory signedContexts = new SignedContextV2[](1);
        signedContexts[0] = SignedContextV2({
            signer: vm.addr(pk),
            context: context,
            signature: LibSignedContextV2TypedData.sign(pk, signingDomain, signedWords)
        });
        return signedContexts;
    }

    /// One signed context from `pk` presenting and signing `context` in the
    /// test domain.
    function signedContextsFor(uint256 pk, bytes32[] memory context) internal pure returns (SignedContextV2[] memory) {
        return signedContextsFor(pk, domain(), context, context);
    }

    function words1(bytes32 x) internal pure returns (bytes32[] memory words) {
        words = new bytes32[](1);
        words[0] = x;
    }

    function words2(bytes32 x, bytes32 y) internal pure returns (bytes32[] memory words) {
        words = new bytes32[](2);
        words[0] = x;
        words[1] = y;
    }

    function assertEqContext(bytes32[][] memory expected, bytes32[][] memory actual) internal pure {
        assertEq(expected.length, actual.length, "column count");
        for (uint256 i = 0; i < expected.length; i++) {
            assertEq(expected[i], actual[i]);
        }
    }

    /// A signature over the EIP-712 digest of the presented words in the
    /// domain `buildV2` is given builds the context, laid out as the
    /// reference, with the signer in the signers column and the words as the
    /// signed column.
    /// forge-config: default.fuzz.runs = 100
    function testBuildV2ValidSignatureBuilds(bytes32[][] memory base, bytes32[] memory words) external view {
        words = bounded(words);
        SignedContextV2[] memory signedContexts = signedContextsFor(SIGNER_PK, words);

        bytes32[][] memory actual = LibContext.buildV2(base, signedContexts, signingDomainSeparator());
        assertEqContext(LibContextSlow.buildStructureSlow(base, signedContexts), actual);

        assertEq(actual.length, 1 + base.length + 2);
        assertEq(actual[1 + base.length], words1(bytes32(uint256(uint160(vm.addr(SIGNER_PK))))));
        assertEq(actual[2 + base.length], words);
    }

    /// Several signed contexts, each from its own signer, are all verified
    /// under the one domain separator and laid out in order.
    function testBuildV2SeveralSignedContextsBuild(bytes32 x, bytes32 y, bytes32 z) external view {
        SignedContextV2[] memory signedContexts = new SignedContextV2[](2);
        signedContexts[0] = signedContextsFor(SIGNER_PK, words2(x, y))[0];
        signedContexts[1] = signedContextsFor(OTHER_PK, words1(z))[0];

        bytes32[][] memory actual = LibContext.buildV2(new bytes32[][](0), signedContexts, signingDomainSeparator());
        assertEqContext(LibContextSlow.buildStructureSlow(new bytes32[][](0), signedContexts), actual);

        assertEq(actual.length, 4);
        assertEq(
            actual[1],
            words2(bytes32(uint256(uint160(vm.addr(SIGNER_PK)))), bytes32(uint256(uint160(vm.addr(OTHER_PK)))))
        );
        assertEq(actual[2], words2(x, y));
        assertEq(actual[3], words1(z));
    }

    /// With no signed contexts the domain separator plays no part and the
    /// result is the base context plus the caller's columns, as `build`
    /// returns it.
    /// forge-config: default.fuzz.runs = 100
    function testBuildV2ZeroSignedContexts(bytes32[][] memory base, bytes32 anyDomainSeparator) external view {
        SignedContextV2[] memory signedContexts = new SignedContextV2[](0);

        bytes32[][] memory actual = LibContext.buildV2(base, signedContexts, anyDomainSeparator);
        assertEqContext(LibContextSlow.buildStructureSlow(base, signedContexts), actual);
        assertEqContext(LibContext.build(base, new SignedContextV1[](0)), actual);
        assertEq(actual.length, 1 + base.length);
    }

    /// First signature valid, second invalid: the revert names index 1.
    function testBuildV2InvalidSignatureSecondIndexReverts(bytes32 x) external {
        SignedContextV2[] memory signedContexts = new SignedContextV2[](2);
        signedContexts[0] = signedContextsFor(SIGNER_PK, words1(x))[0];
        signedContexts[1] = SignedContextV2({signer: address(0xdead), context: words1(x), signature: new bytes(65)});

        vm.expectRevert(abi.encodeWithSelector(InvalidSignature.selector, uint256(1)));
        this.buildV2External(new bytes32[][](0), signedContexts, signingDomainSeparator());
    }

    /// A signature over `[x]` does not authenticate `[y]`.
    function testBuildV2WrongWordReverts(bytes32 x, bytes32 y) external {
        vm.assume(x != y);
        SignedContextV2[] memory signedContexts = signedContextsFor(SIGNER_PK, domain(), words1(y), words1(x));

        vm.expectRevert(abi.encodeWithSelector(InvalidSignature.selector, uint256(0)));
        this.buildV2External(new bytes32[][](0), signedContexts, signingDomainSeparator());
    }

    /// A signature over `[x]` does not authenticate `[x, y]`.
    function testBuildV2AppendedWordReverts(bytes32 x, bytes32 y) external {
        SignedContextV2[] memory signedContexts = signedContextsFor(SIGNER_PK, domain(), words2(x, y), words1(x));

        vm.expectRevert(abi.encodeWithSelector(InvalidSignature.selector, uint256(0)));
        this.buildV2External(new bytes32[][](0), signedContexts, signingDomainSeparator());
    }

    /// A signature over `[x]` does not authenticate `[x, 0]`.
    function testBuildV2AppendedZeroReverts(bytes32 x) external {
        SignedContextV2[] memory signedContexts = signedContextsFor(SIGNER_PK, domain(), words2(x, 0), words1(x));

        vm.expectRevert(abi.encodeWithSelector(InvalidSignature.selector, uint256(0)));
        this.buildV2External(new bytes32[][](0), signedContexts, signingDomainSeparator());
    }

    /// A signature over `[x, y]` does not authenticate its prefix `[x]`.
    function testBuildV2TruncatedReverts(bytes32 x, bytes32 y) external {
        SignedContextV2[] memory signedContexts = signedContextsFor(SIGNER_PK, domain(), words1(x), words2(x, y));

        vm.expectRevert(abi.encodeWithSelector(InvalidSignature.selector, uint256(0)));
        this.buildV2External(new bytes32[][](0), signedContexts, signingDomainSeparator());
    }

    /// A signature over `[x]` does not authenticate `[]`.
    function testBuildV2EmptiedReverts(bytes32 x) external {
        SignedContextV2[] memory signedContexts = signedContextsFor(SIGNER_PK, domain(), new bytes32[](0), words1(x));

        vm.expectRevert(abi.encodeWithSelector(InvalidSignature.selector, uint256(0)));
        this.buildV2External(new bytes32[][](0), signedContexts, signingDomainSeparator());
    }

    /// A signature by one signer over `words` presented as another signer's
    /// does not verify: the signer is in the signed data and is the account
    /// the signature is checked for.
    function testBuildV2WrongSignerReverts(bytes32[] memory words, uint256 otherPk) external {
        words = bounded(words);
        otherPk = bound(otherPk, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        vm.assume(otherPk != SIGNER_PK);

        SignedContextV2[] memory signedContexts = signedContextsFor(SIGNER_PK, words);
        signedContexts[0].signer = vm.addr(otherPk);

        vm.expectRevert(abi.encodeWithSelector(InvalidSignature.selector, uint256(0)));
        this.buildV2External(new bytes32[][](0), signedContexts, signingDomainSeparator());
    }

    /// An empty signature does not verify.
    function testBuildV2EmptySignatureReverts(bytes32[] memory words) external {
        SignedContextV2[] memory signedContexts = new SignedContextV2[](1);
        signedContexts[0] = SignedContextV2({signer: vm.addr(SIGNER_PK), context: words, signature: ""});

        vm.expectRevert(abi.encodeWithSelector(InvalidSignature.selector, uint256(0)));
        this.buildV2External(new bytes32[][](0), signedContexts, signingDomainSeparator());
    }

    /// The same words signed in one domain do not verify under any other
    /// domain separator.
    function testBuildV2DifferentDomainSeparatorReverts(bytes32[] memory words, bytes32 otherDomainSeparator) external {
        words = bounded(words);
        vm.assume(otherDomainSeparator != signingDomainSeparator());
        SignedContextV2[] memory signedContexts = signedContextsFor(SIGNER_PK, words);

        vm.expectRevert(abi.encodeWithSelector(InvalidSignature.selector, uint256(0)));
        this.buildV2External(new bytes32[][](0), signedContexts, otherDomainSeparator);
    }

    /// The same words signed for one verifying contract do not verify under
    /// the domain of another, and likewise across chain ids.
    function testBuildV2DifferentDomainFieldsRevert(
        bytes32[] memory words,
        uint64 otherChainId,
        address otherVerifyingContract
    ) external {
        words = bounded(words);
        EIP712Domain memory signingDomain = domain();
        vm.assume(otherChainId != signingDomain.chainId);
        vm.assume(otherVerifyingContract != signingDomain.verifyingContract);
        SignedContextV2[] memory signedContexts = signedContextsFor(SIGNER_PK, words);

        EIP712Domain memory otherContract = domain();
        otherContract.verifyingContract = otherVerifyingContract;
        vm.expectRevert(abi.encodeWithSelector(InvalidSignature.selector, uint256(0)));
        this.buildV2External(
            new bytes32[][](0), signedContexts, LibSignedContextV2TypedData.domainSeparator(otherContract)
        );

        EIP712Domain memory otherChain = domain();
        otherChain.chainId = otherChainId;
        vm.expectRevert(abi.encodeWithSelector(InvalidSignature.selector, uint256(0)));
        this.buildV2External(
            new bytes32[][](0), signedContexts, LibSignedContextV2TypedData.domainSeparator(otherChain)
        );
    }

    /// A `SignedContextV1` signature, `personal_sign` over the keccak of the
    /// packed words, does not verify as a `SignedContextV2` signature over the
    /// same words.
    function testBuildV2PersonalSignSignatureReverts(bytes32[] memory words) external {
        bytes32 personalSignDigest = MessageHashUtils.toEthSignedMessageHash(keccak256(abi.encodePacked(words)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, personalSignDigest);

        SignedContextV1[] memory v1 = new SignedContextV1[](1);
        v1[0] = SignedContextV1({signer: vm.addr(SIGNER_PK), context: words, signature: abi.encodePacked(r, s, v)});
        assertEq(LibContext.build(new bytes32[][](0), v1).length, 3, "verifies as V1");

        SignedContextV2[] memory signedContexts = new SignedContextV2[](1);
        signedContexts[0] = SignedContextV2({signer: v1[0].signer, context: words, signature: v1[0].signature});

        vm.expectRevert(abi.encodeWithSelector(InvalidSignature.selector, uint256(0)));
        this.buildV2External(new bytes32[][](0), signedContexts, signingDomainSeparator());
    }

    /// A `SignedContextV2` signature does not verify as a `SignedContextV1`
    /// signature over the same words.
    function testBuildV2SignatureDoesNotVerifyAsV1(bytes32[] memory words) external {
        words = bounded(words);
        SignedContextV2[] memory signedContexts = signedContextsFor(SIGNER_PK, words);
        assertEq(
            LibContext.buildV2(new bytes32[][](0), signedContexts, signingDomainSeparator()).length, 3, "verifies as V2"
        );

        SignedContextV1[] memory v1 = new SignedContextV1[](1);
        v1[0] =
            SignedContextV1({signer: signedContexts[0].signer, context: words, signature: signedContexts[0].signature});

        vm.expectRevert(abi.encodeWithSelector(InvalidSignature.selector, uint256(0)));
        this.buildExternal(new bytes32[][](0), v1);
    }
}
