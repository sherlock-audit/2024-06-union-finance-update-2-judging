Chilly Bone Hare

High

# Exchange Rate Manipulation via Supply and Redeemable Balance Distortion

## Summary
An attacker can manipulate the exchange rate in the token system by exploiting the relationship between `_totalRedeemable` and `totalSupply `in the `_exchangeRateStored()` function. This manipulation allows the attacker to artificially inflate the exchange rate, causing new users to receive fewer `uTokens` than expected when minting, and allowing the attacker to profit when redeeming their tokens.

## Vulnerability Detail

The vulnerability lies in the exchange rate calculation:
```solidity
function _exchangeRateStored() private view returns (uint256) {
    uint256 totalSupply_ = totalSupply();
    return totalSupply_ == 0 ? initialExchangeRateMantissa : (_totalRedeemable * WAD) / totalSupply_;
}
```
An attacker can exploit this by:

Minting a large amount of uTokens
Borrowing a significant portion of the underlying assets
Allowing interest to accrue
Repaying the loan with interest, increasing _totalRedeemable
Redeeming most of their uTokens, leaving a small totalSupply

This process results in a high _totalRedeemable value and a low totalSupply, artificially inflating the exchange rate.

Initial State:

initialExchangeRateMantissa = 1e18 (1:1 ratio)
_totalRedeemable = 1,000,000 tokens
totalSupply = 1,000,000 uTokens
Exchange Rate = 1e18 (1 token = 1 uToken)

Step 1: Attacker mints 10,000,000 uTokens

_totalRedeemable = 11,000,000 tokens
totalSupply = 11,000,000 uTokens
Exchange Rate = 1e18 (unchanged)

Step 2: Attacker borrows 9,900,000 tokens

_totalRedeemable = 11,000,000 tokens (unchanged)
totalSupply = 11,000,000 uTokens (unchanged)
Exchange Rate = 1e18 (unchanged)

Step 3: Interest accrues (20% APR over a year)

Accrued interest = 1,980,000 tokens

Step 4: Attacker repays loan with interest

Repayment amount = 11,880,000 tokens
_totalRedeemable = 22,880,000 tokens
totalSupply = 11,000,000 uTokens (unchanged)
New Exchange Rate = (22,880,000 * 1e18) / 11,000,000 ≈ 2.08e18

Step 5: Attacker redeems 10,900,000 uTokens

_totalRedeemable = 22,672,000 tokens
totalSupply = 100,000 uTokens
Final Exchange Rate = (22,672,000 * 1e18) / 100,000 ≈ 226.72e18

Impact on New Users

User A tries to mint with 1,000 tokens:

Expected: 1,000 uTokens
Received: 1,000 * 1e18 / 226.72e18 ≈ 4.41 uTokens
Loss: 995.59 uTokens worth of value


User B tries to mint with 10,000 tokens:

Expected: 10,000 uTokens
Received: 10,000 * 1e18 / 226.72e18 ≈ 44.11 uTokens
Loss: 9,955.89 uTokens worth of value



Attacker's Profit

Attacker mints again with 1,000,000 tokens:

Received: 1,000,000 * 1e18 / 226.72e18 ≈ 4,411 uTokens


Exchange rate returns to normal (assume 1:1 for simplicity):

Attacker redeems 4,411 uTokens
Received: 4,411 tokens


Profit: 4,411 - 1,000,000 = 3,411 tokens

## Impact
New users minting uTokens receive fewer tokens than they should, effectively losing value.
The attacker can later mint uTokens at the inflated rate, gaining more underlying tokens when they redeem.

## Code Snippet
https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UToken.sol#L810-#L835
```solidity
    /**
     * @dev Mint uTokens by depositing tokens
     * @param amountIn The amount of the underlying asset to supply
     */
    function mint(uint256 amountIn) external override whenNotPaused nonReentrant {
        if (amountIn < minMintAmount) revert AmountError();
        if (!accrueInterest()) revert AccrueInterestFailed();
        uint256 exchangeRate = _exchangeRateStored();
        IERC20Upgradeable assetToken = IERC20Upgradeable(underlying);
        uint256 balanceBefore = assetToken.balanceOf(address(this));
        assetToken.safeTransferFrom(msg.sender, address(this), amountIn);
        uint256 balanceAfter = assetToken.balanceOf(address(this));
        uint256 actualObtained = balanceAfter - balanceBefore;
        uint256 mintTokens = 0;
        uint256 totalAmount = decimalScaling(actualObtained, underlyingDecimal);
        uint256 mintFee = decimalScaling((actualObtained * mintFeeRate) / WAD, underlyingDecimal);
        if (mintFee > 0) {
            // Minter fee goes to the reserve
            _totalReserves += mintFee;
        }
        // Rest goes to minting UToken
        uint256 mintAmount = totalAmount - mintFee;
        _totalRedeemable += mintAmount;
        mintTokens = (mintAmount * WAD) / exchangeRate;
        _mint(msg.sender, mintTokens);
        // send all to asset manager
        _depositToAssetManager(balanceAfter - balanceBefore);

        emit LogMint(msg.sender, mintAmount, mintTokens);
    }
```

## Tool used

Manual Review

## Recommendation
1.) Implement slippage protection for minting and redemption operations.
2.) Imlement a maximum exchange 
```solidity

function _exchangeRateStored() private view returns (uint256) {
    uint256 totalSupply_ = totalSupply();
    if (totalSupply_ == 0) return initialExchangeRateMantissa;
    
    uint256 calculatedRate = (_totalRedeemable * WAD) / totalSupply_;
    uint256 maxAllowedRate = initialExchangeRateMantissa * 2;  // Max 100% increase
    
    return Math.min(calculatedRate, maxAllowedRate);
}
3.)
Use a time-weighted average price (TWAP) for the exchange rate calculation:
```solidity
struct ExchangeRateObservation {
    uint256 timestamp;
    uint256 rate;
}

ExchangeRateObservation[] private rateHistory;

function updateExchangeRate() public {
    uint256 currentRate = _calculateCurrentRate();
    rateHistory.push(ExchangeRateObservation(block.timestamp, currentRate));
    if (rateHistory.length > 10) {
        // Keep only last 10 observations
        for (uint i = 0; i < 9; i++) {
            rateHistory[i] = rateHistory[i+1];
        }
        rateHistory.pop();
    }
}

function getTWAP() public view returns (uint256) {
    require(rateHistory.length > 0, "No rate history");
    uint256 sum = 0;
    for (uint i = 0; i < rateHistory.length; i++) {
        sum += rateHistory[i].rate;
    }
    return sum / rateHistory.length;
}
```
```