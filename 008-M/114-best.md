Quaint Golden Gecko

Medium

# Minimum borrow amount can be surpassed and borrower can be treated as being overdue earlier than their actual overdue time

## Summary

It is possible to borrow less than `_minBorrow` and preliminary be marked as overdue when `assetManager` have temporary fund access limitations.

## Vulnerability Detail

UToken's `borrow()` can be effectively run with lesser amount than `_minBorrow` when it is a liquidity shortage in the asset manager's underlying markets and they can return only some dust amount or nothing at all. In these cases `borrow()` call will still be concluded. Particularly, it is possible to run it with zero amount when `assetManager` cannot access liquidity.

In that case the borrower, if they borrow for the first time after full repay, will not have their `lastRepay` field reset on a subsequent material borrow operations as it will already be set on zero amount borrow before. As a result such borrowers can be effectively overdue for the system way before the actual overdue time passes for them.

## Impact

`_minBorrow` threshold can be violated when market conditions restrict `assetManager` withdrawals. A user can have `lastRepay` set earlier than time of obtaining the funds, which will mark them overdue before the actual overdue time comes by. This will have a material adverse impact both on such a borrower (for them `checkIsOverdue` will be true, so they won't be able to borrow or create vouches) and their lenders (for them `stakerFrozen` and `frozenCoinAge` will be increased and staking rewards diminished).

## Code Snippet

If current market conditions don't allow any material withdrawal then `borrow()` still can happen and `lastRepay` be set on any dust or even zero amount being lent out:

[UToken.sol#L611-L634](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UToken.sol#L611-L634)

```solidity
    function borrow(address to, uint256 amount) external override onlyMember(msg.sender) whenNotPaused nonReentrant {
        IAssetManager assetManagerContract = IAssetManager(assetManager);
        uint256 actualAmount = decimalScaling(amount, underlyingDecimal);
>>      if (actualAmount < _minBorrow) revert AmountLessMinBorrow();

        // Calculate the origination fee
        uint256 fee = calculatingFee(actualAmount);

        if (_borrowBalanceView(msg.sender) + actualAmount + fee > _maxBorrow) revert AmountExceedMaxBorrow();
        if (checkIsOverdue(msg.sender)) revert MemberIsOverdue();
        if (amount > assetManagerContract.getLoanableAmount(underlying)) revert InsufficientFundsLeft();
        if (!accrueInterest()) revert AccrueInterestFailed();

        uint256 borrowedAmount = borrowBalanceStoredInternal(msg.sender);

        // Initialize the last repayment date to the current block timestamp
>>      if (getLastRepay(msg.sender) == 0) {
            accountBorrows[msg.sender].lastRepay = getTimestamp();
        }

        // Withdraw the borrowed amount of tokens from the assetManager and send them to the borrower
>>      uint256 remaining = assetManagerContract.withdraw(underlying, to, amount);
>>      if (remaining > amount) revert WithdrawFailed();
>>      actualAmount -= decimalScaling(remaining, underlyingDecimal);
```

If market is such that `assetManagerContract.withdraw` can only withdraw dust or can't withdraw anything, a user can request to borrow an amount bigger than minimal, but `borrow()` will be executed with some dust or even zero amount effectively borrowed. This isn't fully covered by the `getLoanableAmount()` check since it measures total funds invested via `getSupplyView()` calls to the underlying markets.

As `_minBorrow` is for amount effectively borrowed, and not just for amount requested, it will be in a violation:

[UToken.sol#L141-L144](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UToken.sol#L141-L144)

```solidity
    /**
>>   *  @dev Min amount that can be borrowed by a single member
     */
    uint256 private _minBorrow;
```

Also, it will have a side effect of resetting `lastRepay` even with zero amount borrowed when the borrower had no debt as of time of the call. This will effectively mark a borrower as an overdue when time since they obtained any material debt is in fact much less than `overdueTime`:

[UToken.sol#L459-L465](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UToken.sol#L459-L465)

```solidity
    function checkIsOverdue(address account) public view override returns (bool isOverdue) {
        if (_getBorrowed(account) != 0) {
>>          uint256 lastRepay = getLastRepay(account);
>>          uint256 diff = getTimestamp() - lastRepay;
>>          isOverdue = overdueTime < diff;
        }
    }
```

[UToken.sol#L450-L452](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UToken.sol#L450-L452)

```solidity
    function getLastRepay(address account) public view override returns (uint256) {
        return accountBorrows[account].lastRepay;
    }
```

This can happen as subsequent `borrow()` calls will not set `lastRepay` as the logic is based on having empty `lastRepay`:

[UToken.sol#L627-L629](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UToken.sol#L627-L629)

```solidity
        if (getLastRepay(msg.sender) == 0) {
            accountBorrows[msg.sender].lastRepay = getTimestamp();
        }
```

## Tool used

Manual Review

## Recommendation

Consider controlling the effective amount being borrowed, e.g.:

[UToken.sol#L611-L634](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UToken.sol#L611-L634)

```diff
    function borrow(address to, uint256 amount) external override onlyMember(msg.sender) whenNotPaused nonReentrant {
        IAssetManager assetManagerContract = IAssetManager(assetManager);
        uint256 actualAmount = decimalScaling(amount, underlyingDecimal);
-       if (actualAmount < _minBorrow) revert AmountLessMinBorrow();

        // Calculate the origination fee
        uint256 fee = calculatingFee(actualAmount);

        if (_borrowBalanceView(msg.sender) + actualAmount + fee > _maxBorrow) revert AmountExceedMaxBorrow();
        if (checkIsOverdue(msg.sender)) revert MemberIsOverdue();
        if (amount > assetManagerContract.getLoanableAmount(underlying)) revert InsufficientFundsLeft();
        if (!accrueInterest()) revert AccrueInterestFailed();

        uint256 borrowedAmount = borrowBalanceStoredInternal(msg.sender);

        // Initialize the last repayment date to the current block timestamp
        if (getLastRepay(msg.sender) == 0) {
            accountBorrows[msg.sender].lastRepay = getTimestamp();
        }

        // Withdraw the borrowed amount of tokens from the assetManager and send them to the borrower
        uint256 remaining = assetManagerContract.withdraw(underlying, to, amount);
        if (remaining > amount) revert WithdrawFailed();
        actualAmount -= decimalScaling(remaining, underlyingDecimal);
+       if (actualAmount < _minBorrow) revert AmountLessMinBorrow();
```