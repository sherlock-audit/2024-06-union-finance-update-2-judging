Prehistoric Caramel Ant

High

# any stakers who lent to borrowers can increase their rewards by a portion repayment

### Summary

In the `_repayBorrowFresh` function, the `lastRepay` will be set to 0 if the caller executes a full repayment and set to the current timestamp if the caller repays a portion of the borrowed amount. Since everyone can repay, any staker can repay a dust amount to update the `lastRepay` to accrue their rewards more than they deserve. The `stakerCoinAges.frozenCoinAge` and `stakerFrozen` in the `_getEffectiveAmounts` function won't increase if the `currTime - lastRepay > overdueTime` is false, and when the `lastRepay` gets updated, it will be false manually.


### Root Cause

In [`UToken.sol:742`](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UToken.sol#L742), the `lastRepay` gets updated every time a portion repayment is on. this will cause accruing rewards for any stakers
In [`UserManager:985`](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/user/UserManager.sol#L985-L1012) the `stakerFrozen` and `stakerCoinAges.frozenCoinAge` calculation does not increase when a portion repayment is on, leading to inaccurate reward distributions.

allowing any staker to repay any amount is a mistake as it enables manipulation of the `lastRepay` timestamp, resulting in unfair reward accrual.
when the `currTime - lastRepay > overdueTime` is true, the `stakerFrozen` and `stakerCoinAges.frozenCoinAge` get increase which leads to a decrease in the `effectiveStaked` and `effectiveLocked`. decreasing these two variables affects the reward multiplier lower which is true and correct but any stakers can increase those two variables which leads to more rewards for them

### Internal pre-conditions

1. the staker needs to trust a borrower
2. the borrower needs to borrow from the staker

### External pre-conditions

non

### Attack Path

1. Bob the borrower, borrows from Alice the staker who trusts Bob
2. Alice repays 1 wei for the loan that was given to Bob to update the `lastRepay` to the current timestamp. this will lead to more rewards for Alice and a loss of funds for the protocol

### Impact

Any staker can accrue their rewards more than they deserve

### PoC

   ```js
       function _getRewardsMultiplier(UserManagerAccountState memory user) internal pure returns (uint256) {
        if (user.isMember) {
            if (user.effectiveStaked == 0) {
                return memberRatio;
            }

            // @audit-high any staker can increase their rewards multiplier by repaying a dust amount because of lastRepay variable gets updated and leads to more `lendingRatio`
            uint256 lendingRatio = user.effectiveLocked.wadDiv(user.effectiveStaked);

            return lendingRatio + memberRatio;
        } else {
            return nonMemberRatio;
        }
    }
    
```

### Mitigation

just let the borrowers repay their loan