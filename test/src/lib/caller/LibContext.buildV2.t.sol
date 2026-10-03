// SPDX-License-Identifier: LicenseRef-DCL-1.0
// SPDX-FileCopyrightText: Copyright (c) 2020 Rain Open Source Software Ltd
pragma solidity =0.8.25;

import {Test} from "forge-std-1.16.2/src/Test.sol";
import {IERC1271} from "@openzeppelin-contracts-5.6.1/interfaces/IERC1271.sol";
import {
    LibContext,
    MessageHashUtils,
    SignedContextV1,
    InvalidSignature,
    CONTEXT_BASE_COLUMN,
    CONTEXT_BASE_ROWS,
    CONTEXT_BASE_V2_ROWS,
    CONTEXT_BASE_ROW_SENDER,
    CONTEXT_BASE_ROW_CALLING_CONTRACT,
    CONTEXT_BASE_ROW_DOMAIN_SEPARATOR
} from "src/lib/caller/LibContext.sol";
import {SignedContextV2} from "src/interface/IInterpreterCallerV4.sol";
import {LibSignedContextV2TypedData, EIP712Domain} from "test/lib/caller/LibSignedContextV2TypedData.sol";
import {ERC1271WalletMock} from "test/lib/caller/ERC1271WalletMock.sol";
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
        assertEqContext(LibContextSlow.buildStructureSlow(base, signedContexts, signingDomainSeparator()), actual);

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
        assertEqContext(
            LibContextSlow.buildStructureSlow(new bytes32[][](0), signedContexts, signingDomainSeparator()), actual
        );

        assertEq(actual.length, 4);
        assertEq(
            actual[1],
            words2(bytes32(uint256(uint160(vm.addr(SIGNER_PK)))), bytes32(uint256(uint160(vm.addr(OTHER_PK)))))
        );
        assertEq(actual[2], words2(x, y));
        assertEq(actual[3], words1(z));
    }

    /// With no signed contexts nothing is verified and the result is the base
    /// context plus the caller's columns, as `build` returns it, except that
    /// the base column still carries the domain separator as its third row.
    /// forge-config: default.fuzz.runs = 100
    function testBuildV2ZeroSignedContexts(bytes32[][] memory base, bytes32 anyDomainSeparator) external view {
        SignedContextV2[] memory signedContexts = new SignedContextV2[](0);

        bytes32[][] memory actual = LibContext.buildV2(base, signedContexts, anyDomainSeparator);
        assertEqContext(LibContextSlow.buildStructureSlow(base, signedContexts, anyDomainSeparator), actual);
        assertEq(actual.length, 1 + base.length);

        bytes32[][] memory v1 = LibContext.build(base, new SignedContextV1[](0));
        assertEq(v1.length, actual.length);
        assertEq(v1[0].length, CONTEXT_BASE_ROWS);
        assertEq(actual[0].length, CONTEXT_BASE_V2_ROWS);
        assertEq(actual[0][CONTEXT_BASE_ROW_SENDER], v1[0][CONTEXT_BASE_ROW_SENDER]);
        assertEq(actual[0][CONTEXT_BASE_ROW_CALLING_CONTRACT], v1[0][CONTEXT_BASE_ROW_CALLING_CONTRACT]);
        assertEq(actual[0][CONTEXT_BASE_ROW_DOMAIN_SEPARATOR], anyDomainSeparator);
        for (uint256 i = 1; i < v1.length; i++) {
            assertEq(v1[i], actual[i]);
        }
    }

    /// `baseV2` is `base` with the domain separator appended as the third
    /// row, and the constants name its shape.
    function testBaseV2(bytes32 domainSeparator) external view {
        bytes32[] memory base = LibContext.base();
        bytes32[] memory baseV2 = LibContext.baseV2(domainSeparator);

        assertEq(CONTEXT_BASE_COLUMN, 0);
        assertEq(CONTEXT_BASE_V2_ROWS, CONTEXT_BASE_ROWS + 1);
        assertEq(CONTEXT_BASE_ROW_DOMAIN_SEPARATOR, CONTEXT_BASE_ROWS);

        assertEq(base.length, CONTEXT_BASE_ROWS);
        assertEq(baseV2.length, CONTEXT_BASE_V2_ROWS);
        assertEq(baseV2[CONTEXT_BASE_ROW_SENDER], base[CONTEXT_BASE_ROW_SENDER]);
        assertEq(baseV2[CONTEXT_BASE_ROW_SENDER], bytes32(uint256(uint160(msg.sender))));
        assertEq(baseV2[CONTEXT_BASE_ROW_CALLING_CONTRACT], base[CONTEXT_BASE_ROW_CALLING_CONTRACT]);
        assertEq(baseV2[CONTEXT_BASE_ROW_CALLING_CONTRACT], bytes32(uint256(uint160(address(this)))));
        assertEq(baseV2[CONTEXT_BASE_ROW_DOMAIN_SEPARATOR], domainSeparator);
    }

    /// `baseV2` allocates exactly its three words: the free memory pointer
    /// advances by the array's length word plus three rows, and the array
    /// starts where the pointer was.
    function testBaseV2Allocates(bytes32 domainSeparator) external view {
        uint256 freeMemoryPointerBefore;
        assembly ("memory-safe") {
            freeMemoryPointerBefore := mload(0x40)
        }
        bytes32[] memory baseV2 = LibContext.baseV2(domainSeparator);
        uint256 freeMemoryPointerAfter;
        uint256 baseV2Pointer;
        assembly ("memory-safe") {
            freeMemoryPointerAfter := mload(0x40)
            baseV2Pointer := baseV2
        }
        assertEq(baseV2Pointer, freeMemoryPointerBefore);
        assertEq(freeMemoryPointerAfter, freeMemoryPointerBefore + 0x20 * (1 + CONTEXT_BASE_V2_ROWS));
    }

    /// The domain separator row of a built context is the domain separator
    /// the signed contexts were verified under, at a fixed coordinate however
    /// many caller columns and signed contexts there are. An expression that
    /// pins `context<0 2>()` to its deployment's domain separator therefore
    /// pins the domain every signer in the matrix signed under.
    /// forge-config: default.fuzz.runs = 100
    function testBuildV2ExposesVerifiedDomainSeparator(bytes32[][] memory base, bytes32 x, bytes32 y, bytes32 z)
        external
        view
    {
        SignedContextV2[] memory signedContexts = new SignedContextV2[](2);
        signedContexts[0] = signedContextsFor(SIGNER_PK, words2(x, y))[0];
        signedContexts[1] = signedContextsFor(OTHER_PK, words1(z))[0];

        bytes32[][] memory actual = LibContext.buildV2(base, signedContexts, signingDomainSeparator());
        assertEq(actual.length, 1 + base.length + 3);
        assertEq(actual[CONTEXT_BASE_COLUMN].length, CONTEXT_BASE_V2_ROWS);
        assertEq(actual[CONTEXT_BASE_COLUMN][CONTEXT_BASE_ROW_DOMAIN_SEPARATOR], signingDomainSeparator());
        // The caller's columns are not shifted by the extra base row.
        for (uint256 i = 0; i < base.length; i++) {
            assertEq(actual[1 + i], base[i]);
        }
    }

    /// The domain separator row is exactly the separator `buildV2` was given,
    /// not derived from anything else. With the signed contexts signed under
    /// that same separator this is the only value the row can hold, because
    /// any other separator does not verify
    /// (`testBuildV2DifferentDomainSeparatorReverts`).
    function testBuildV2DomainSeparatorRowIsTheVerifyingSeparator(
        bytes32[] memory words,
        uint64 chainId,
        address verifyingContract
    ) external view {
        words = bounded(words);
        EIP712Domain memory signingDomain = EIP712Domain("LibContextBuildV2Test", "1", chainId, verifyingContract);
        bytes32 domainSeparator = LibSignedContextV2TypedData.domainSeparator(signingDomain);
        SignedContextV2[] memory signedContexts = signedContextsFor(SIGNER_PK, signingDomain, words, words);

        bytes32[][] memory actual = LibContext.buildV2(new bytes32[][](0), signedContexts, domainSeparator);
        assertEq(actual[CONTEXT_BASE_COLUMN][CONTEXT_BASE_ROW_DOMAIN_SEPARATOR], domainSeparator);
        assertEq(actual[2], words);
    }

    /// An ERC-1271 contract account whose owner key signed the digest naming
    /// the account as `signer` verifies, and the signers column shows the
    /// account, not the owner key.
    function testBuildV2ERC1271SignerBuilds(bytes32[] memory words) external {
        words = bounded(words);
        ERC1271WalletMock wallet = new ERC1271WalletMock(vm.addr(SIGNER_PK));

        SignedContextV2[] memory signedContexts = new SignedContextV2[](1);
        signedContexts[0] = SignedContextV2({
            signer: address(wallet),
            context: words,
            signature: LibSignedContextV2TypedData.signFor(SIGNER_PK, domain(), address(wallet), words)
        });

        bytes32[][] memory actual = this.buildV2External(new bytes32[][](0), signedContexts, signingDomainSeparator());
        assertEq(actual.length, 3);
        assertEq(actual[1], words1(bytes32(uint256(uint160(address(wallet))))));
        assertEq(actual[2], words);
    }

    /// An ERC-1271 signature is checked onchain, so the account can revoke
    /// it: the same signed context that built before the account revoked does
    /// not verify after.
    function testBuildV2ERC1271RevokedReverts(bytes32[] memory words) external {
        words = bounded(words);
        ERC1271WalletMock wallet = new ERC1271WalletMock(vm.addr(SIGNER_PK));

        SignedContextV2[] memory signedContexts = new SignedContextV2[](1);
        signedContexts[0] = SignedContextV2({
            signer: address(wallet),
            context: words,
            signature: LibSignedContextV2TypedData.signFor(SIGNER_PK, domain(), address(wallet), words)
        });
        assertEq(this.buildV2External(new bytes32[][](0), signedContexts, signingDomainSeparator()).length, 3);

        wallet.revoke();
        vm.expectRevert(abi.encodeWithSelector(InvalidSignature.selector, uint256(0)));
        this.buildV2External(new bytes32[][](0), signedContexts, signingDomainSeparator());
    }

    /// Two ERC-1271 accounts with the same owner key accept the same
    /// `(digest, signature)` pairs, so a signature account A's owner produced
    /// for A would also satisfy account B if the digest did not name the
    /// account. `signer` is in the signed data, so the digest for A presented
    /// as B's does not verify: the signers column cannot show B vouching for
    /// words only A's owner signed for A.
    function testBuildV2ERC1271SharedOwnerDoesNotCrossAccounts(bytes32[] memory words) external {
        words = bounded(words);
        ERC1271WalletMock walletA = new ERC1271WalletMock(vm.addr(SIGNER_PK));
        ERC1271WalletMock walletB = new ERC1271WalletMock(vm.addr(SIGNER_PK));
        bytes memory signatureForA = LibSignedContextV2TypedData.signFor(SIGNER_PK, domain(), address(walletA), words);

        // B would accept A's digest and signature if asked directly: the two
        // accounts share a validator.
        bytes32 digestForA = LibSignedContextV2TypedData.digest(domain(), address(walletA), words);
        assertEq(walletB.isValidSignature(digestForA, signatureForA), IERC1271.isValidSignature.selector);

        SignedContextV2[] memory signedContexts = new SignedContextV2[](1);
        signedContexts[0] = SignedContextV2({signer: address(walletA), context: words, signature: signatureForA});
        assertEq(this.buildV2External(new bytes32[][](0), signedContexts, signingDomainSeparator()).length, 3);

        signedContexts[0].signer = address(walletB);
        vm.expectRevert(abi.encodeWithSelector(InvalidSignature.selector, uint256(0)));
        this.buildV2External(new bytes32[][](0), signedContexts, signingDomainSeparator());
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
