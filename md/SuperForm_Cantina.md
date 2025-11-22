# Introduction

A time-boxed security review of the **Superform-Core** protocol was done by **0xodus**, with a focus on the security aspects of the application's smart contracts implementation.

# Disclaimer

A smart contract security review can never verify the complete absence of vulnerabilities. This is a time, resource and expertise bound effort where I try to find as many vulnerabilities as possible. I can not guarantee 100% security after the review or even if the review will find any problems with your smart contracts. Subsequent security reviews, bug bounty programs and on-chain monitoring are strongly recommended.

# Severity classification

| Severity               | Impact: High | Impact: Medium | Impact: Low |
| ---------------------- | ------------ | -------------- | ----------- |
| **Likelihood: High**   | Critical     | High           | Medium      |
| **Likelihood: Medium** | High         | Medium         | Low         |
| **Likelihood: Low**    | Medium       | Low            | Low         |

**Impact** - the technical, economic and reputation damage of a successful attack

**Likelihood** - the chance that a particular vulnerability gets discovered and exploited

**Severity** - the overall criticality of the risk

# Findings Summary

| ID     | Title                                                                            | Severity | Status    |
| ------ | -------------------------------------------------------------------------------- | -------- | --------- |
| [M-01] | Infinite Validity Signatures Incorrectly Rejected Due to Zero Timestamp Handling | Medium   | Confirmed |
| [L-01] | Morpho RepayAndWithdrawHook Fails When No Outstanding Debt Exists                | Low      | Confirmed |

# Detailed Findings

# [M-01] | Infinite Validity Signatures Incorrectly Rejected Due to Zero Timestamp Handling

## Summary

The signature validation logic in `SuperDestinationValidator` and `SuperValidatorBase` incorrectly treats `validUntil = 0` as an expired signature instead of recognizing it as infinite validity, causing legitimate signatures intended to be valid forever to be rejected.

## Finding Description

The issue exists in the `_isSignatureValid` function implementations across the validator contracts, specifically in `SuperDestinationValidator.sol` and the base implementation in `SuperValidatorBase.sol`. The issue stems from the conditional check `validUntil >= block.timestamp` which fails when `validUntil` is set to 0.

According to the the documentation in `ERC7579ValidatorBase.sol` specifically in `_packValidationData` function that is called by `SuperMerkleValidator::validateUserOp` .

> @param validUntil - Last timestamp this UserOperation is valid (or zero for infinite).

Also according to the ERC-4337 standard, a `validUntil` value of `0` should indicate infinite validity.

> validUntil is 6-byte timestamp value, or zero for “infinite”. The UserOperation is valid only up to this time.

However, the current implementation treats `0` as a timestamp, causing the comparison `0 >= block.timestamp` to always evaluate to false since `block.timestamp` is always greater than `0` in any realistic blockchain scenario.

This breaks the security guarantee that signatures with infinite validity should remain valid indefinitely. The issue occurs automatically whenever a user or system attempts to create a signature with infinite validity by setting `validUntil = 0`, which is the standard way to indicate this according to ERC-4337.

The vulnerability affects multiple validator contracts:

`SuperDestinationValidator.sol` - Direct implementation in `_isSignatureValid` `SuperMerkleValidator.sol` - Inherits the vulnerable validation logic from the base contract

## Impact Explanation

This vulnerability has a Medium impact because:

    - Functionality Denial: Users cannot create signatures with infinite validity, limiting the flexibility of the signature system
    - User Experience Degradation: Applications expecting infinite validity signatures will fail unexpectedly
    - Integration Issues: Third-party integrations relying on infinite validity signatures will break
    - Protocol Deviation: The implementation deviates from ERC-4337 standard behavior, potentially causing interoperability issues

While this doesn't directly lead to fund loss or unauthorized access, it breaks core functionality and user expectations, making it a significant operational issue.

## Likelihood Explanation

This vulnerability has a High likelihood because:

    - Standard Usage Pattern: Setting validUntil = 0 for infinite validity is a standard pattern in ERC-4337 implementations
    - Automatic Occurrence: The issue triggers automatically whenever infinite validity is attempted - no special conditions or attack vectors needed
    - Multiple Affected Contracts: The vulnerability exists in multiple validator contracts due to inheritance
    - User Expectation: Users familiar with ERC-4337 will naturally expect to be able to use infinite validity signatures

## Proof of Concept

Place the following function in `test/unit/validators/SuperDestinationValidator.t.sol`

```solidity
    function test_infinitySigNotValidUntilInfinity() public {
        vm.warp(block.timestamp + 2 hours);
        uint48 validUntil = 0;

        bytes32[] memory leaves = new bytes32[](1);

        leaves[0] = _createDestinationValidatorLeaf(
            approveDestinationData.callData,
            approveDestinationData.chainId,
            approveDestinationData.sender,
            approveDestinationData.executor,
            approveDestinationData.dstTokens,
            approveDestinationData.intentAmounts,
            validUntil
        );

        (bytes32[][] memory proof, bytes32 root) = _createValidatorMerkleTree(leaves);

        bytes memory signature = _getSignature(root);

        bytes memory sigDataRaw = abi.encode(validUntil, root, "", proof[0], signature);

        bytes memory destinationDataRaw = abi.encode(
            approveDestinationData.callData,
            approveDestinationData.chainId,
            approveDestinationData.sender,
            approveDestinationData.executor,
            approveDestinationData.dstTokens,
            approveDestinationData.intentAmounts
        );

        vm.startPrank(signerAddr);
        validator.onInstall(abi.encode(signerAddr));
        vm.stopPrank();
        bytes4 validationResult =
            validator.isValidDestinationSignature(signerAddr, abi.encode(sigDataRaw, destinationDataRaw));

        assertEq(validationResult, bytes4(""), "Sig should be invalid");
    }

```

# [L-01] | Morpho RepayAndWithdrawHook Fails When No Outstanding Debt Exists

## Summary

The `RepayAndWithdrawHook` in Morpho loan hooks contains an issue that prevents users from withdrawing their collateral after fully repaying their debt. When users attempt to repay and withdraw in a single transaction after having previously repaid their loan, the hook fails due to Morpho's input validation that requires exactly one of assets or shares to be non-zero, causing the withdraw functionality to become permanently inaccessible.

## Finding Description

The vulnerability exists in the `RepayAndWithdrawHook` implementation where the hook first calls Morpho's repay function before attempting to withdraw collateral. The issue manifests in the following sequence:

1. User supplies an asset as collateral and borrows a loan token using `borrowHook`
2. User repays the loan token using `RepayHook` (debt becomes zero)
3. User attempts to withdraw collateral using `RepayAndWithdrawHook`
4. The hook calls Morpho's repay function first, which contains the validation: https://github.com/morpho-org/morpho-blue/blob/d89ca53ff6cbbacf8717a8ce819ee58f49bcc592/src/Morpho.sol#L278

```solidity
require(UtilsLib.exactlyOneZero(assets, shares), ErrorsLib.INCONSISTENT_INPUT);
```

5. Since the loan was previously repaid, both `assets` and `shares` parameters are zero
6. The `exactlyOneZero` validation fails because it requires exactly one parameter to be zero and one to be non-zero
7. The transaction reverts before reaching the withdraw functionality

This breaks the security guarantee that users should always be able to withdraw their collateral when they have no outstanding debt. The vulnerability occurs due to poor hook design that attempts to perform a repay operation even when no debt exists, coupled with Morpho's strict input validation.

## Impact Explanation

The impact is assessed as **Medium** because:

- **Protocol Functionality Breakdown**: The core functionality of withdrawing collateral after debt repayment is completely broken
- **User Experience Degradation**: Users lose confidence in the protocol's reliability to withdraw their funds

The severity is elevated because this affects a fundamental operation (collateral withdrawal) that users expect to work reliably.

## Likelihood Explanation

The likelihood is assessed as **Medium** because:

- **Common User Flow**: The sequence of repaying debt and then withdrawing collateral is a natural and expected user behavior
- **No Special Conditions Required**: The bug triggers under normal usage patterns without requiring specific market conditions or complex setups
- **Hook Design Flaw**: The issue is inherent in the hook's logic design, making it inevitable rather than edge-case dependent
- **User Interface Integration**: If UIs integrate this hook for convenience, many users would encounter this issue
- **No Workaround Visibility**: Users may not realize they need to use separate transactions or different hooks

## Proof of Concept

Create a file and paste the following contract:

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

// external
import { BaseTest } from "../BaseTest.t.sol";

import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import { IERC4626 } from "@openzeppelin/contracts/interfaces/IERC4626.sol";

import { MinimalBaseNexusIntegrationTest } from "./MinimalBaseNexusIntegrationTest.t.sol";
import { INexus } from "../../src/vendor/nexus/INexus.sol";
import { MockRegistry } from "../mocks/MockRegistry.sol";
import { ISuperExecutor } from "../../src/core/interfaces/ISuperExecutor.sol";
import { SuperMerkleValidator } from "src/core/validators/SuperMerkleValidator.sol";

// Hooks
import { BaseLoanHook } from "src/core/hooks/loan/BaseLoanHook.sol";
import { MorphoRepayAndWithdrawHook } from "src/core/hooks/loan/morpho/MorphoRepayAndWithdrawHook.sol";
import { MorphoRepayHook } from "src/core/hooks/loan/morpho/MorphoRepayHook.sol";
import { MorphoBorrowHook } from "src/core/hooks/loan/morpho/MorphoBorrowHook.sol";
import { Id, IMorpho, MarketParams, Market } from "src/vendor/morpho/IMorpho.sol";

import { console } from "forge-std/console.sol";

contract MophoTesting is MinimalBaseNexusIntegrationTest, BaseTest {
    IMorpho public morpho;
    uint256 public CHAIN_8453_TIMESTAMP;
    MockRegistry public nexusRegistry;
    address[] public attesters;
    uint8 public threshold;
    address account1;
    // SuperMerkleValidator superMerkleValidator;

    bytes public mockSignature;
    uint256 baseFork;

    function setUp() public override(MinimalBaseNexusIntegrationTest, BaseTest) {
        string memory BASE_RPC_URL = vm.envString("BASE_RPC_URL");
        vm.createSelectFork(BASE_RPC_URL);
        CHAIN_8453_TIMESTAMP = block.timestamp;
        super.setUp();
        morpho = IMorpho(address(0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb));
        blockNumber = ETH_BLOCK;
        nexusRegistry = new MockRegistry();
        attesters = new address[](1);
        attesters[0] = address(MANAGER);
        threshold = 1;
        superMerkleValidator = new SuperMerkleValidator();
        (signer, signerPrvKey) = makeAddrAndKey("signer");

        account1 = accountInstances[uint64(block.chainid)].account;

        mockSignature = abi.encodePacked(hex"41414141");
        // account1 = _makeAccount(uint64(block.chainid), "testAccount").account;
    }

    function test_RepayAndWithdrawHook_Fails_If_RepaymentHasBeenDoneFully() public {
        // So for this test am looking at a scanario which a user Supplies an asset and Borrows a loantoken, using the
        // BorrowHook and then repays the loanToken using the RepayHook however when they try to withdraw the collateral
        // using the RepayAndWithdrawHook it fails, since they have no outstanding debt and reverts and therefore cant
        // access the withdraw part of the hook
        address collateralTokenR = 0xcbB7C0000aB88B473b1f5aFd9ef808440eed33Bf;
        address loanTokenR = 0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913;

        // address nexusAccount = _createWithNexus(address(nexusRegistry), attesters, threshold, 1e18);
        // _assertAccountCreation(nexusAccount);
        console.log("Balance of LoanToken before: ", IERC20(loanTokenR).balanceOf(account1));
        deal(0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913, account1, 100e18);

        address oracleR;
        address irmR;
        uint256 amountR = 10e6;
        uint256 ltvRatioR = 400_000_000_000_000_000;
        bool usePrevHookAmountR = false;
        uint256 lltvR;
        bool placeHolderR;

        Id marketIdR = Id.wrap(0x9103c3b4e834476c9a62ea009ba2c884ee42e94e6e314a26f04d312434191836);
        MarketParams memory marketParamsR = morpho.idToMarketParams(marketIdR);

        MorphoBorrowHook borrowHookR = new MorphoBorrowHook(address(morpho));

        address[] memory hookAddresses = new address[](1);
        hookAddresses[0] = address(borrowHookR);

        bytes[] memory hooksData = new bytes[](1);
        hooksData[0] = _createMorphoBorrowHookData(
            marketParamsR.loanToken,
            marketParamsR.collateralToken,
            marketParamsR.oracle,
            marketParamsR.irm,
            amountR,
            ltvRatioR,
            usePrevHookAmountR,
            marketParamsR.lltv
        );
        ISuperExecutor.ExecutorEntry memory entry =
            ISuperExecutor.ExecutorEntry({ hooksAddresses: hookAddresses, hooksData: hooksData });

        _executeThroughEntrypoint(account1, entry);
        console.log("Balance of LoanToken after: ", IERC20(loanTokenR).balanceOf(account1));

        // Now we have borrowed the loanToken, lets repay it using the RepayHook
        MorphoRepayHook repayHookR = new MorphoRepayHook(address(morpho));

        address[] memory hookRepayAddress = new address[](1);
        hookRepayAddress[1] = address(borrowHookR);

        bytes[] memory hooksDataRepay = new bytes[](1);
        hooksDataRepay[1] = _createMorphoRepayHookData(
            marketParamsR.loanToken,
            marketParamsR.collateralToken,
            marketParamsR.oracle,
            marketParamsR.irm,
            amountR,
            marketParamsR.lltv,
            usePrevHookAmountR,
            true
        );
        ISuperExecutor.ExecutorEntry memory entry1 =
            ISuperExecutor.ExecutorEntry({ hooksAddresses: hookRepayAddress, hooksData: hooksDataRepay });

        _executeThroughEntrypoint(account1, entry1);
        console.log("Balance of LoanToken after Repay: ", IERC20(loanTokenR).balanceOf(account1));

        // Now lets test the RepayAndWithdrawHook since its the only withdrawal option available, which should fail
        // since we
        // have no outstanding debt, then we have no way to withdraw our collateral via the hooks
        MorphoRepayAndWithdrawHook repayAndWithdrawHookR = new MorphoRepayAndWithdrawHook(address(morpho));

        address[] memory hookRepayAndWithdrawAddress = new address[](1);
        hookRepayAndWithdrawAddress[0] = address(repayAndWithdrawHookR);

        bytes[] memory hooksDataRepayAndWithdraw = new bytes[](1);
        hooksDataRepayAndWithdraw[0] = _createMorphoRepayAndWithdrawHookData(
            marketParamsR.loanToken,
            marketParamsR.collateralToken,
            marketParamsR.oracle,
            marketParamsR.irm,
            amountR,
            marketParamsR.lltv,
            usePrevHookAmountR,
            true
        );

        ISuperExecutor.ExecutorEntry memory entryWithdrawal = ISuperExecutor.ExecutorEntry({
            hooksAddresses: hookRepayAndWithdrawAddress,
            hooksData: hooksDataRepayAndWithdraw
        });

        vm.expectRevert();
        _executeThroughEntrypoint(account1, entryWithdrawal);
    }
}
```

## Recommendation

The issue can be fixed by implementing conditional logic in the `RepayAndWithdrawHook` to skip the repay operation when there's no debt to repay or remove the combined hook and force users to use individual operations:

**src/core/hooks/loan/morpho/MorphoRepayAndWithdrawHook.sol**

```solidity
if (vars.isFullRepayment) {
    uint128 borrowBalance = deriveShareBalance(id, account);
    uint256 shareBalance = uint256(borrowBalance);
    uint256 amountToApprove = deriveLoanAmount(id, account) + deriveInterest(marketParams) + fee;
    collateralForWithdraw = deriveCollateralForFullRepayment(id, account);

    executions[1] = Execution({
        target: vars.loanToken,
        value: 0,
        callData: abi.encodeCall(IERC20.approve, (morpho, amountToApprove))
    });
    executions[2] = Execution({
        target: morpho,
        value: 0,
        callData: abi.encodeCall(IMorphoBase.repay, (marketParams, 0, shareBalance, account, "")) // 0 assets as
            // we are repaying in full
    });
    executions[4] = Execution({
        target: morpho,
        value: 0,
        callData: abi.encodeCall(
            IMorphoBase.withdrawCollateral, (marketParams, collateralForWithdraw, account, account)
        )
    });
}
```
