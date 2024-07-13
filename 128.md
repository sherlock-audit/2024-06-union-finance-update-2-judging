Polite Topaz Swallow

High

# Incorrect value `BORROW_RATE_MAX_MANTISSA` used in contracts

## Summary
Incorrect value `BORROW_RATE_MAX_MANTISSA` used in contracts

## Vulnerability Detail

Both `UToken.sol` and `FixedInterestRateModel.sol` has used the value of `BORROW_RATE_MAX_MANTISSA` as below:

```solidity
    /**
     * @dev Maximum borrow rate that can ever be applied (.005% / 12 second)
     */
    uint256 internal constant BORROW_RATE_MAX_MANTISSA = 4_166_666_666_667; // 0.005e16 / 12
```

The issue is that, this calculated value by `0.005e16 / 12` is not correct. `BORROW_RATE_MAX_MANTISSA ` is actually referenced from Compound's [cToken](https://github.com/compound-finance/compound-protocol/blob/a3214f67b73310d547e00fc578e8355911c9d376/contracts/CTokenInterfaces.sol#L31) which is implemented as below:

```solidity
    // Maximum borrow rate that can ever be applied (.0005% / block)
    uint internal constant borrowRateMaxMantissa = 0.0005e16;
```

Note here that. the compound's Natspec for `borrowRateMaxMantissa` is not correct which was confirmed in openzeppelin's audit [here](https://blog.openzeppelin.com/compound-audit). Instead of `0.0005%/ block`, it should be `0.005%`. Now coming back to issue, There is huge difference of values of compound's `borrowRateMaxMantissa` and currently implemented `BORROW_RATE_MAX_MANTISSA ` in `Union` contracts.

After calculating the `BORROW_RATE_MAX_MANTISSA` in seconds:

1) Considering compound's `borrowRateMaxMantissa` = 0.0005e16 / 12 = `4_166_666_666_66` 

2) Considering currently implemented Union's `BORROW_RATE_MAX_MANTISSA ` = 0.005e16 / 12 = `4_166_666_666_666`

The difference is clearly of `3_750_000_000_000`.

This would be an incorrect value of `BORROW_RATE_MAX_MANTISSA` and would allow to set the value of `interestRatePerSecond`.

The following functions are greatly affected by this issue:

```solidity
    function setInterestRate(uint256 _interestRatePerSecond) external override onlyOwner {
@>        if (_interestRatePerSecond > BORROW_RATE_MAX_MANTISSA) revert BorrowRateExceeded();
        interestRatePerSecond = _interestRatePerSecond;

        emit LogNewInterestParams(_interestRatePerSecond);
    }
```

and 

```solidity
    function borrowRatePerSecond() public view override returns (uint256) {
        uint256 borrowRateMantissa = interestRateModel.getBorrowRate();
@>        if (borrowRateMantissa > BORROW_RATE_MAX_MANTISSA) revert BorrowRateExceedLimit();

        return borrowRateMantissa;
    }
```
`borrowRatePerSecond()` is further used in `_calculatingInterest()` and `accrueInterest()` functions and both of these functions have been extensively used across `union` contracts.

Another point is that, `Hundred finance` which is also deployed on `optimism` mainnet has used `borrowRateMaxMantissa` as below:

```solidity
    uint internal constant borrowRateMaxMantissa = 0.00004e16;
```

Upon, further calculations, its concluded that `0.00004e16 (0.0005e16/12)` is actually derived from `Compound's `borrowRateMaxMantissa` which is `0.0005e16` . Since compound uses `block number` to calculate interest so `borrowRateMaxMantissa` is calculated as `0.0005e16/ block` and Hundred finance has used `block timestamp` to calculate interest so `borrowRateMaxMantissa` is calculated as `0.0005e16/ second` therefore, `union` should also follow same as `Hundred finance` used `borrowRateMaxMantissa` on Optimisim mainnet.

## Impact
`BORROW_RATE_MAX_MANTISSA` is the maximum borrow rate that can ever be applied in `Union` contracts has been used incorrectly. This would break the `borrowRatePerSecond()` function which is used to calculate the borrow rate and this borrow rate is fetched while calulating interest and acrueing interest. Since, it would result in huge difference as said above so this break a maximum borrow rate mantissa as referred from Compound. 

## Code Snippet
https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/FixedInterestRateModel.sol#L18

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UToken.sol#L74

## Tool used
Manual Review

## Recommendation
Consider calculating the `BORROW_RATE_MAX_MANTISSA` from `0.0005e16` instead of `0.005e16` due to as explained above.

Consider below changes in both `UToken.sol` and `FixedInterestRateModel.sol`:

```diff
    /**
-     * @dev Maximum borrow rate that can ever be applied (0.005% / 12 second)
+    * @dev Maximum borrow rate that can ever be applied (0.05% / 12 second)
     */
-    uint256 public constant BORROW_RATE_MAX_MANTISSA = 4_166_666_666_667; // 0.005e16 / 12
+    uint256 public constant BORROW_RATE_MAX_MANTISSA = 0.00004e16;                  // 0.0005e16 / 12
```
