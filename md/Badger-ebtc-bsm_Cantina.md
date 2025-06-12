# Introduction

A time-boxed security review of the **Badger-ebtc-bsm_Cantina** protocol was done by **0xodus**, with a focus on the security aspects of the application's smart contracts implementation.

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

| ID     | Title                                                                                                                | Severity | Status    |
| ------ | -------------------------------------------------------------------------------------------------------------------- | -------- | --------- |
| [H-01] | Incorrect Oracle Price Constraint Allows eBTC Minting During Asset Depeg and Blocks It When Asset Price Exceeds eBTC | High     | Confirmed |

# Detailed Findings

# [H-01] Incorrect Oracle Price Constraint Allows eBTC Minting During Asset Depeg and Blocks It When Asset Price Exceeds eBTC

## Summary

Users can still sell their asset tokens and mint eBTC even when the Asset token drops too much relative to eBtc. At the same time, users cant mint eBTC tokens if the asset price is way higher than than the eBTC price. This increases the overall system risk

## Finding Description

The protocol docs clearly states that :

> The Oracle Constraint pauses minting if the asset price drops too much relative to eBTC.

However, this is not the case in the protocol code, As shown below in the proof of concept, the `OraclePriceConstraint::canMint()` function passes when the price of the Asset token price is low relative to the eBTC price and fails when the Asset token price is high compared to the eBTC price. This is due to the incorrect check in the function.

## Impact Explanation

High, since minting continues and users purchase eBTC tokens at a discount if their asset token depegs. This increases the overall system risk

## Likelihood Explanation

Medium, this scenario only happens when the asset token depegs or price drops too much relative to eBTC price.

## Proof of Concept

```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.25;

import "forge-std/Test.sol";
import {tBTCChainlinkAdapter, AggregatorV3Interface} from "../src/tBTCChainlinkAdapter.sol";
import {MockAssetOracle} from "./mocks/MockAssetOracle.sol";
import {OraclePriceConstraint} from "src/OraclePriceConstraint.sol";
import {BSMBase} from "./BSMBase.sol";

contract AdapterTest_0xodus is Test, BSMBase {
    MockAssetOracle internal btcUsdAggregator;
    MockAssetOracle internal tBtcUsdAggregator;

    tBTCChainlinkAdapter internal tBTCchainlinkAdapter;
    OraclePriceConstraint internal priceConstraintMock;

    function setUp() public {
        // Test setup
        BSMBase.baseSetup();
        btcUsdAggregator = new MockAssetOracle(8);
        tBtcUsdAggregator = new MockAssetOracle(8);
        tBTCchainlinkAdapter = new tBTCChainlinkAdapter(tBtcUsdAggregator, btcUsdAggregator);

        priceConstraintMock = new OraclePriceConstraint(address(tBTCchainlinkAdapter), address(authority));
    }

    function testCanMintIfAssetDepegs() public {
        // This first scenario demonstrates if the asset price depegs/ drops much in relative to BTC price
        tBtcUsdAggregator.setLatestRoundId(110680464442257320247);
        tBtcUsdAggregator.setPrevRoundId(110680464442257320246);
        // Setting Asset price to 10,000
        tBtcUsdAggregator.setPrice(10000_00_000_000);
        tBtcUsdAggregator.setUpdateTime(block.timestamp);

        btcUsdAggregator.setLatestRoundId(110680464442257320665);
        btcUsdAggregator.setPrevRoundId(110680464442257320664);
        // Setting BTC Price to 80,000
        btcUsdAggregator.setPrice(8000000000000);
        btcUsdAggregator.setUpdateTime(block.timestamp);

        (, int256 answer,, uint256 updatedAt,) = tBTCchainlinkAdapter.latestRoundData();

        console.log("oracle answer", answer);
        console.log("current Block.timestamp = ", updatedAt);

        (bool result,) = priceConstraintMock.canMint(1, address(this));
        // Asserts that eBTC can be minted if asset price is low/depegs
        assertTrue(result);

        vm.warp(block.timestamp + 1 days);
        vm.roll(block.timestamp);

        // This second scenario demonstrates if the asset price is higher relative to BTC price
        tBtcUsdAggregator.setLatestRoundId(110680464442257320248);
        tBtcUsdAggregator.setPrevRoundId(110680464442257320247);
        // Setting Asset price to 100,000
        tBtcUsdAggregator.setPrice(100000_00_000_000);
        tBtcUsdAggregator.setUpdateTime(block.timestamp);

        // Setting BTC Price to 80,000
        btcUsdAggregator.setPrice(8000000000000);
        btcUsdAggregator.setLatestRoundId(110680464442257320666);
        btcUsdAggregator.setPrevRoundId(110680464442257320665);
        btcUsdAggregator.setUpdateTime(block.timestamp);
        (, int256 answer1,, uint256 updatedAt1,) = tBTCchainlinkAdapter.latestRoundData();
        console.log("oracle answer", answer1);
        console.log("current Block.timestamp = ", updatedAt1);

        (bool result1,) = priceConstraintMock.canMint(1, address(this));
        // Asserts that eBTC can't be minted if asset price is high
        assertFalse(result1);
    }
}


```

As shown above, eBTC minting is halted when asset price is higher and vice versa.

## Recommendation

- Consider reversing the check in OraclePriceConstraint::canMint() function to as shown below.

```diff
    function canMint(uint256 _amount, address _minter) external view returns (bool, bytes memory) {
        uint256 assetPrice = _getAssetPrice();
        uint256 minAcceptablePrice = (1e18 * minPriceBPS) / BPS;

-       if (minAcceptablePrice <= assetPrice) {
+       if (minAcceptablePrice >= assetPrice) {
            return (true, "");
        } else {
            return (false, abi.encodeWithSelector(BelowMinPrice.selector, assetPrice, minAcceptablePrice));
        }
    }

```
