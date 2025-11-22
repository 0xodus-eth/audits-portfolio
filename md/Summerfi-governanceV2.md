# Introduction

A time-boxed security review of the **Summer.fi Governance V2** protocol was done by **0xodus**, with a focus on the security aspects of the application's smart contracts implementation.

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

| ID     | Title                                                                                                   | Severity | Status    |
| ------ | ------------------------------------------------------------------------------------------------------- | -------- | --------- |
| [M-01] | Precision Loss in Reward Calculation Causes Partial or Complete Loss of Rewards Through Griefing Attack | Medium   | Confirmed |

# Detailed Findings

# [M-01] | Precision Loss in Reward Calculation Causes Partial or Complete Loss of Rewards Through Griefing Attack

## Summary

Precision loss in reward calculations will cause a partial or complete loss of reward yield for stakers as an attacker can repeatedly trigger reward updates at small time intervals, preventing rewards from being properly distributed.

## Root Cause

In `StakingRewardsManagerBase.sol:118-127` the reward calculation in `rewardPerToken` function divides by `totalSupply`, causing precision loss without tracking the remainder:

```solidity
function rewardPerToken(address rewardToken) public view returns (uint256) {
    if (totalSupply == 0) {
        return rewardData[rewardToken].rewardPerTokenStored;
    }
    return
        rewardData[rewardToken].rewardPerTokenStored +
        ((lastTimeRewardApplicable(rewardToken) -
            rewardData[rewardToken].lastUpdateTime) *
            rewardData[rewardToken].rewardRate) /
        totalSupply;
}
```

This will cause the residual amount `(lastTimeRewardApplicable - lastUpdateTime) * rewardRate * 1e18 % _totalSupply` to be unutilized and therefore the associated rewards become stuck in the contract, since only rewards that are accounted in `rewardPerTokenStored` can be claimed by stakers. As a consequence, these irrecoverable reward amounts accumulate over time within the SummerStaking contract.

There is an additional edge-case which allows for a griefing attack leading to zero reward yield of a given `rewardToken` for all stakers. Whenever the condition `(lastTimeRewardApplicable - lastUpdateTime) * rewardRate < _totalSupply` is satisfied, the value of `rewardPerTokenStored` will stay unchanged due to precision loss while `lastUpdateTime` is still updated, leading to a full loss of rewards for the duration `dt = lastTimeRewardApplicable - lastUpdateTime`.

While this attack requires a very high `totalSupply` and/or a very low `rewardRate` to be possible, the `dt` can be controlled by the attacker and could be as low as 2 seconds, since the `updateReward` modifier can be permissionlessly invoked through the `getRewardFor` method.

Potentially, this attack could be executed in every block for a whole `rewardDuration` to cause zero reward yield for stakers.

Note that even if the above condition leading to unchanged `rewardPerTokenStored` cannot be satisfied, an attacker could still amplify the general precision loss by frequently invoking `getRewardForUser` and therefore creating a small `dt`.

## Internal Pre-conditions

The `totalSupply` of staked tokens needs to be high relative to `rewardRate`.

## External Pre-conditions

None required.

## Attack Path

1. Attacker monitors the contract for reward distribution
2. Attacker calls `getReward()` or another function with the `updateReward` modifier every 1 block given a block time of about 2 seconds on Base
3. Each time the function is called, `lastUpdateTime` is updated but when `(timeElapsed * rewardRate) < totalSupply`, the calculated reward increment becomes zero due to integer division
4. The `rewardPerTokenStored` value remains unchanged while time passes, effectively making rewards unclaimable
5. Attacker can repeat this throughout a reward period, causing permanent loss of rewards

## Impact

The stakers suffer a partial or complete loss of rewards during staking periods. The rewards remain locked in the contract with no mechanism to claim them. The attacker doesn't gain these rewards but causes them to be permanently inaccessible.

The PoC below demonstrates an edge case where we have 100% loss.

## Proof of Concept

Paste the following function in `SummerStaking.lockup.unit.t.sol` and run `forge test --mt test_rewardPerTokenStored`:

```solidity
function test_rewardPerTokenStored() public {

    uint256 lockupPeriod = aMinLockupPeriod;
    uint256 rewardGriefDuration = 1 hours; // short reward grief duration to save test execution time
    uint256 stakingAmount = 21 ether;
    uint256 rewardAmount = 10 * rewardGriefDuration;
    _stake(aStaking, user1, stakingAmount, lockupPeriod);
    _addAndNotifyRewards(address(rewardToken), rewardAmount);



    uint256 rewardPerTokenStored;
    uint256 totalSupply = stakingAmount;
    (,,,, rewardPerTokenStored) = aStaking.rewardData(address(rewardToken));
        assertEq(rewardPerTokenStored, 0);
    // We can skip time without increasing `rewardPerTokenStored`
    // when `dt * rewardRate < _totalSupply`
    uint256 dt = totalSupply / (10e18); // dt = 2
    // Grief rewards for 1 hour duration
    uint256 nSkips = rewardGriefDuration / dt;
    for (uint256 i; i < nSkips; i++) {
        skip(dt);
        // Update reward
        aStaking.getRewardFor(address(0));
    }
    console.log("Skipped time:", dt * nSkips);
    // User1 is not earning, because `rewardPerTokenStored` is not increasing.
    uint256 lastUpdateTime;
    (,,, lastUpdateTime, rewardPerTokenStored) = aStaking.rewardData(address(rewardToken));
    aStaking.rewardData(address(rewardToken));
    assertEq(lastUpdateTime, block.timestamp);
    assertEq(rewardPerTokenStored, 0);
    assertEq(aStaking.earned(user1, address(rewardToken)), 0);
}
```

## Recommendation

The protocol can mitigate the issue by keeping track of the residual amount and re-applying it on the next invocation of `updateReward` to prevent the continuous accumulation of irrecoverable amounts:

```solidity
// Add storage variable to track residual
mapping(address => uint256) public rewardResidue;

function rewardPerToken(address rewardToken) public view returns (uint256) {
    if (totalSupply == 0) {
        return rewardData[rewardToken].rewardPerTokenStored;
    }

    // Include residue from previous calculation
    uint256 totalReward = ((lastTimeRewardApplicable(rewardToken) -
        rewardData[rewardToken].lastUpdateTime) *
        rewardData[rewardToken].rewardRate) + rewardResidue[rewardToken];

    uint256 rewardPerTokenIncrement = totalReward / totalSupply;

    // Store new residue for next calculation
    rewardResidue[rewardToken] = totalReward % totalSupply;

    return rewardData[rewardToken].rewardPerTokenStored + rewardPerTokenIncrement;
}
```
