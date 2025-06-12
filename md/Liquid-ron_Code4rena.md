# Introduction

A time-boxed security review of the **Liquid Ron** protocol was done by **0xodus**, with a focus on the security aspects of the application's smart contracts implementation.

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

| ID     | Title                                                                               | Severity | Status      |
| ------ | ----------------------------------------------------------------------------------- | -------- | ----------- |
| [M-01] | Incorrect logical operator in the `onlyOperator` modifier breaks the access control | Medium   | Aknowledged |

# Detailed Findings

# [M-01] Incorrect logical operator in the `onlyOperator` modifier breaks the access control

## Description

The onlyOperator modifier is designed to restrict access to certain functions, allowing only the contract owner or authorized operators to call them.

However, the logical `OR (||)` operator is used incorrectly here. The condition `msg.sender != owner() || operator[msg.sender]` will revert in the following cases:

- `msg.sender` is the owner, but `operator[msg.sender]` is true.
- `msg.sender` is not the owner, but `operator[msg.sender]` is true.
- `msg.sender` is not the owner, and `operator[msg.sender]` is false.

This in turn effectively prevents the operator from calling the restricted functions and sometimes even the owner.

## Proof of Concept

The following are proofs of code, that illustrate the behavior of the modifier under different circumstances. Copy the function and place them in the `LiquidRon.operator.t.sol`

1. When the `msg.sender` is not the `owner`, but `operator[msg.sender]` is true

```solidity
    function testRevertsWhenOperatorCalls() public {
        address operator = makeAddr("operator");
        liquidRon.updateOperator(operator, true);
        vm.expectRevert(LiquidRon.ErrInvalidOperator.selector);
        vm.prank(operator);
        liquidRon.harvest(0, consensusAddrs);
    }
```

2. When `msg.sender` is the owner, but `operator[msg.sender]` is true.

```solidity
    function testRevertsWhenOperatorCalls() public {
        address owner = makeAddr("owner");
        liquidRon.transferOwnership(owner);
        vm.startPrank(owner);
        liquidRon.updateOperator(owner, true);
        vm.expectRevert(LiquidRon.ErrInvalidOperator.selector);
        liquidRon.harvest(0, consensusAddrs);
        vm.stopPrank();
    }
```

The above scenarios have the following output:

```md
[⠊] Compiling...
No files changed, compilation skipped

Ran 1 test for test/LiquidRon.operator.t.sol:LiquidRonTest
[PASS] testRevertsWhenOperatorCalls() (gas: 49792)
Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 1.59ms (237.52µs CPU time)
This clearly shows that even though the modifier is supposed to restrict certain functions to be callable only by the owner or operators, the operator cannot call the functions and even in some instances the owner. This in turn breaks some of the intended functionality of the protocol therefore has a high impact and a high likelihood.
```

## Recommended mitigation steps

To ensure the modifier only allows the owner or the authorized operators, the logical AND(&&) operator should be used instead as follows

```solidity
modifier onlyOperator() {
    if (msg.sender != owner() && !operator[msg.sender]) revert ErrInvalidOperator();
    _;
}
```

The above condition will only revert if `msg.sender` is not the owner and `msg.sender` is not an authorized operator. This ensures that the function can only be called by either the owner or an authorized operator, but not anyone else.
