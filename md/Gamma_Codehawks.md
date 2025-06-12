# Introduction

A time-boxed security review of the **Gamma-Liquidity Management** protocol was done by **0xodus**, with a focus on the security aspects of the application's smart contracts implementation.

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

| ID     | Title                                                                   | Severity | Status    |
| ------ | ----------------------------------------------------------------------- | -------- | --------- |
| [H-01] | Execution Fee refund via the `_handleReturn` function is never executed | High     | Confirmed |

# Detailed Findings

# [H-01] Execution Fee refund via the `_handleReturn` function is never executed

## Summary

The `refundExecutionFee` call in the `_handleReturn` function cannot execute

## Vulnerability Details

In the `_handleReturn` function in the PerpetualVault contract has a conditional statement if (refundFee) which is meant to refund the unused execution fee, however before the conditional statement is reached in the flow of the function, there is a call to the `_burn(depositId)` function which deletes the deposit Information maping for the `depositId` as show below

```solidity
    function _burn(uint256 depositId) internal {
        EnumerableSet.remove(userDeposits[depositInfo[depositId].owner], depositId);
        totalShares = totalShares - depositInfo[depositId].shares;
@>      delete depositInfo[depositId];
    }
​
```

```solidity
    function _handleReturn(uint256 withdrawn, bool positionClosed, bool refundFee) internal {
        (uint256 depositId) = flowData;
        // Skipped for simplicty
@>      _burn(depositId);
​
        if (refundFee) {
            uint256 usedFee = callbackGasLimit * tx.gasprice;
   @>   if (depositInfo[depositId].executionFee > usedFee) {
                try IGmxProxy(gmxProxy).refundExecutionFee(
                    depositInfo[counter].owner, depositInfo[counter].executionFee - usedFee
                ) {} catch {}
            }
        }
        // Skipped for simplicity
    }
```

As shown in the above illustration, after the call to the `_burn` function that deletes the mapping, and the `refundFee` bool is true, in the loop the `depositInfo[depositId].executionFee` statement will always return 0 since the mapping is non-existent, therefore the executionFee will never be `> usedFee` with is neccesary to trigger the execution fee refund function in the gmxProxy contract.
This will happen when the `_handleReturn` function is called in the `runSwap` function. The specific instance is given below:
https://github.com/CodeHawks-Contests/2025-02-gamma/blob/main/contracts/PerpetualVault.sol#L1007

## Impact

1. _Loss of User Funds_:

   Users who are entitled to a refund of excess execution fees (when depositInfo[depositId].executionFee > usedFee) will never receive it. The condition depositInfo[depositId].executionFee > usedFee can never evaluate to true post-deletion, causing the refundExecutionFee call to the GmxProxy contract to be skipped. This effectively results in users losing funds they should have reclaimed, undermining trust in the system.

2. _Permanent Underfunding of Refunds_ :

   The perpetual deletion of the depositInfo[depositId] mapping before the refund logic ensures that no execution fee refunds are processed, regardless of the actual gas usage (usedFee = callbackGasLimit \* tx.gasprice). This disrupts the intended economic model of the contract, where unused fees are returned to depositors, potentially leading to an accumulation of unclaimed funds within the system or misaligned incentives.

## Tools Used

Manual Review

## Recommendation

```diff
    function _handleReturn(uint256 withdrawn, bool positionClosed, bool refundFee) internal {
        (uint256 depositId) = flowData;
        // Skipped for simplicty
-       _burn(depositId);
​
        if (refundFee) {
            uint256 usedFee = callbackGasLimit * tx.gasprice;
               if (depositInfo[depositId].executionFee > usedFee) {
                try IGmxProxy(gmxProxy).refundExecutionFee(
                    depositInfo[counter].owner, depositInfo[counter].executionFee - usedFee
                ) {} catch {}
            }
        }
+      _burn(depositId);
        // Skipped for simplicity
    }
```
