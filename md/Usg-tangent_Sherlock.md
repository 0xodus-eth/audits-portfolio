# Introduction

A time-boxed security review of the **USG Tangent** protocol was done by **0xodus**, with a focus on the security aspects of the application's smart contracts implementation.

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

| ID     | Title                                                                                               | Severity | Status    |
| ------ | --------------------------------------------------------------------------------------------------- | -------- | --------- |
| [H-01] | Missing Control Tower Verification in Migration Functions Allows Unauthorized Position Manipulation | High     | Confirmed |
| [M-01] | Liquidation Fee Calculation Makes Some Liquidations Unprofitable                                    | Medium   | Confirmed |

# Detailed Findings

# [H-01] | Missing Control Tower Verification in Migration Functions Allows Unauthorized Position Manipulation

## Summary

The missing validation that `_controlTower` matches the protocol's actual `controlTower` in the `migrateFrom()` and `migrateTo()` functions will cause unauthorized position manipulation for users as an attacker will pass arbitrary control tower addresses to bypass the market's access controls.

## Root Cause

In `MarketCore.sol:594` the `_verifySenderMigrator()` function only verifies `_controlTower.isPositionMigrator(msg.sender)` but does not validate that `_controlTower == controlTower` (the protocol's actual control tower).

This affects the functions `migrateFrom()` and `migrateTo()` because of the assumption that they will always be called from the Migrator contract. However, since they are external, and fail to verify the control tower passed, this allows attackers to call the functions directly, manipulating positions in markets.

## Internal Pre-conditions

None required.

## External Pre-conditions

The attacker only needs to deploy their own Control Tower contract in order to pass the `_verifySenderMigrator()` check.

## Attack Path

1. Attacker calls `migrateFrom()` on a market, passing their own malicious control tower in which they are authorized and the receiver as their own address of choice
2. This allows them to withdraw collateral for a certain account as long as they respect the max LTV and minimum debt of the market
3. Similarly, the attacker can call `migrateTo()` to add unauthorized debt/collateral to positions, effectively breaking the intended core functionality

## Impact

Users suffer complete loss of their collateral and unauthorized debt manipulation. The attacker can steal all collateral from positions and manipulate debt balances.

## Proof of Concept

No response

## Recommendation

Verify the control tower address passed on both markets:

```solidity
function _verifySenderMigrator(IControlTower _controlTower) internal view {
    require(_controlTower == controlTower, "Invalid control tower");
    require(_controlTower.isPositionMigrator(msg.sender), "Sender is not authorized migrator");
}
```

# [M-01] | Liquidation Fee Calculation Makes Some Liquidations Unprofitable

## Summary

The incorrect liquidation fee calculation in `MarketCore._liquidate()` will cause liquidations to become unprofitable for liquidators as the fee is charged on the entire debt amount rather than the liquidator's profit, causing liquidators to avoid liquidating underwater positions leading to bad debt accumulation.

## Root Cause

In `MarketCore.sol:408` the liquidation fee is calculated as `_mulDiv(USGToRepay, liquidationFee, DENOMINATOR)`. However, according to the README:

> **Q: Are there any limitations on values set by admins (or other roles) in the codebase, including restrictions on array lengths?**
>
> **Collateral:**
>
> - 0 < maxLTV < 100%
> - maxLTV < liquidationThreshold < 100%
> - 0 < liquidationFee < 15%

The above parameters, as demonstrated in the PoC section, will lead to a scenario whereby liquidations are unprofitable, leading to the protocol accruing bad debt.

## Internal Pre-conditions

None required.

## External Pre-conditions

None required.

## Attack Path

1. Position becomes liquidatable due to collateral price drop
2. Liquidator calls `liquidate()` expecting to profit from liquidation premium
3. Protocol charges liquidation fee on entire debt amount (`USGToRepay`) instead of profit
4. Liquidator ends up paying more than the liquidation premium, making liquidation unprofitable
5. Liquidators avoid liquidating positions, leading to bad debt accumulation

## Impact

The protocol suffers from bad debt accumulation as liquidations become unprofitable.

## Proof of Concept

In our case, we take a scenario whereby the liquidation threshold is 91%, the fee is 15%, collateral price is $10,000, and debt is $9,000.

Position LTV will be: `(9000 * 100) / 10000 = 90%`

The position is liquidatable.

During liquidation, the liquidator gets the collateral and pays the debt in USG. However, during the calculation of the USG amount to repay, the fee is also included, so the liquidator should pay (including fees):

```
(9000 * 0.15) + 9000 = $10,350
```

**Final figures:**

- **Debt to repay:** $10,350
- **Collateral value:** $10,000

This shows that the liquidations will simply be unprofitable.

## Recommendation

Consider deducting fees from the profits instead of charging them on the entire debt amount:

```solidity
// Calculate liquidation profit first
uint256 liquidationProfit = collateralValue - USGToRepay;

// Charge fee only on the profit
uint256 liquidationFeeAmount = _mulDiv(liquidationProfit, liquidationFee, DENOMINATOR);

// Liquidator pays debt + fee on profit only
uint256 totalToRepay = USGToRepay + liquidationFeeAmount;
```
