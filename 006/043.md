Rare Mossy Okapi

High

# Repaying a Loan with Permit in UErc20.sol Wrongly calculates the interest to be paid this Reduce/Increase profits for the protocol as interest calculations are not performed correctly.

## Summary


The function `_repayBorrowFresh` in `UErc20.sol` wrongly calculates the interest to be paid when repaying a loan with a permit. The issue arises because the amount to repay is scaled to 1e18, but the interest is not, leading to users passing incorrect interest amounts based on the token's decimal places. This can result in users paying significantly less interest than they should for tokens with fewer decimal places (e.g., USDC, USDT) or more than they should for tokens with more decimal places.

## Vulnerability Detail

The core of the problem lies in the different scaling applied to the amount and interest during the repayment process. In `UErc20.sol`, the function `_repayBorrowFresh` is called with the amount scaled to 1e18 but the interest remains unscaled, which causes incorrect interest calculations.
```solidity
 function repayBorrowWithERC20Permit(
        address borrower,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused {
        IERC20Permit erc20Token = IERC20Permit(underlying);
        erc20Token.permit(msg.sender, address(this), amount, deadline, v, r, s);

        if (!accrueInterest()) revert AccrueInterestFailed();
  @audit>> Wrong interest passed>> notscaled>>      uint256 interest = calculatingInterest(borrower);
        _repayBorrowFresh(msg.sender, borrower, decimalScaling(amount, underlyingDecimal), interest);
    }
```

### Example

For tokens like USDC or USDT (which have 6 decimal places):
- If the interest to be paid is $2,000,000, the expected interest should be scaled to 1e18, resulting in $2,000,000 * 1e18.
- However, since the interest is not scaled, it remains at $2,000,000 * 1e6, leading to the contract recording less interest than should, the excess amount remains in the pool and it is not shared accordingly.

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UToken.sol#L568-L570
we use the above instead of using 

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UToken.sol#L682



For less amount of interest used in calculation this funds are stuck in the contract since it is not assigned to anyone to claim.
https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UToken.sol#L705-L710



For tokens with more than 18 decimal places, the user would end up paying more interest than they should to the protocol and less funds will be available for all the lenders to claim their funds, resulting in overpayment.

This discrepancy creates an opportunity for the Wrong sharing of interest shares by protocol.


## Impact


The impact of this vulnerability includes:
- Users potentially paying incorrect interest amounts, leading to financial losses for the protocol.
- Reduced profits for the protocol as interest calculations are not performed correctly.


Here is the problematic code snippet from `UErc20.sol`:

```solidity
uint256 interest = calculatingInterest(borrower);
_repayBorrowFresh(msg.sender, borrower, decimalScaling(amount, underlyingDecimal), interest);
```

In `UDai.sol`, although it is less critical because DAI has 18 decimals, the same logic flaw exists.


Below is the Reference to the code if the user pays normally

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UToken.sol#L679-L684

Interest is scaled there properly and sent to the _repayBorrowFresh and use the permit because if the incorrect implementation.

## Code Snippet

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UErc20.sol#L8-L22

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UErc20.sol#L19-L21

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UToken.sol#L705-L710

This issue is absent in Dai because it decimal is 1e18
https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UDai.sol#L9-L23

## Tool used

Manual Review

## Recommendation

To address this issue, the interest should be scaled correctly according to the token's decimal places. The function call should ensure both the amount and the interest are appropriately scaled. Here's the recommended fix:

```solidity
function repayBorrowWithPermit(uint256 amount, ...) external {

 ...........................................................................................
    --       uint256 interest = calculatingInterest(borrower);
    ++     uint256 interest = _calculatingInterest(borrower);
              _repayBorrowFresh(msg.sender, borrower, decimalScaling(amount, underlyingDecimal), Interest);
}
```