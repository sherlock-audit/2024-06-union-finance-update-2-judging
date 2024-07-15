Rare Mossy Okapi

Medium

# Function Rebalance can deposit above Moneymarket ceiling

## Summary

The current implementation of the `rebalance` function in `AssetManager.sol` redistributes tokens among supported money markets. However, it fails to check if the amount to be deposited exceeds the ceiling of the money market, thereby potentially violating one of the core checks of the protocol.

## Vulnerability Detail
The `rebalance` function is designed to redistribute tokens among supported money markets according to specified percentages. However, it does not check if the amount being deposited exceeds the ceiling of any money market, which can lead to deposits above the ceiling limit. This breaks one of the core checks in the protocol that prevents deposits above a money market ceiling.

Here is the current implementation of the `rebalance` function:

```solidity
function rebalance(
    address tokenAddress,
    uint256[] calldata percentages
) external override onlyOwner whenNotPaused nonReentrant {
    IERC20Upgradeable token = IERC20Upgradeable(tokenAddress);
    uint256 tokenSupply = token.balanceOf(address(this));
    uint256 percentagesLength = percentages.length;
    uint256 supportedMoneyMarketsSize = supportedMoneyMarkets.length;

    require(percentagesLength == supportedMoneyMarketsSize, "AssetManager: mismatched input lengths");

    for (uint256 i = 0; i < percentagesLength; i++) {
        IMoneyMarketAdapter moneyMarket = supportedMoneyMarkets[i];
        uint256 amountToDeposit = (tokenSupply * percentages[i]) / 10000;
        if (amountToDeposit == 0) continue;

 @audit>>   amountToDeposit can be greater than  ceiling  >>      token.safeTransfer(address(moneyMarket), amountToDeposit);
        
moneyMarket.deposit(tokenAddress);
    }

    uint256 remainingTokens = token.balanceOf(address(this));

    IMoneyMarketAdapter lastMoneyMarket = supportedMoneyMarkets[supportedMoneyMarketsSize - 1];
    if (remainingTokens > 0) {

       @audit>>   remainingTokens can be greater than ceiling  >>     token.safeTransfer(address(lastMoneyMarket), remainingTokens);

        lastMoneyMarket.deposit(tokenAddress);
    }
}
```

## Impact

Failing to check if the amount to be deposited exceeds the ceiling of the money market can lead to deposits above the ceiling limit. This can result in potential overexposure and liquidity issues in the protocol.

## Code Snippet

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/asset/AssetManager.sol#L308

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/asset/AssetManager.sol#L561-L563

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/asset/AssetManager.sol#L570-L571

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/asset/AssetManager.sol#L525-L575
## Tool used

Manual Review

## Recommendation

Add a check to ensure that the amount to be deposited does not exceed the ceiling of the money market. If the amount exceeds the ceiling, the function should revert.

Here is the updated code:

```solidity
  function rebalance(
        address tokenAddress,
        uint256[] calldata percentages
    ) external override onlyAdmin checkMarketSupported(tokenAddress) {
        IERC20Upgradeable token = IERC20Upgradeable(tokenAddress);
        uint256 moneyMarketsLength = moneyMarkets.length;
        uint256 percentagesLength = percentages.length;

        IMoneyMarketAdapter[] memory supportedMoneyMarkets = new IMoneyMarketAdapter[](moneyMarketsLength);
        uint256 supportedMoneyMarketsSize;

        // Loop through each money market and withdraw all the tokens
        for (uint256 i = 0; i < moneyMarketsLength; i++) {
            IMoneyMarketAdapter moneyMarket = moneyMarkets[i];
            if (!moneyMarket.supportsToken(tokenAddress)) continue;
            supportedMoneyMarkets[supportedMoneyMarketsSize] = moneyMarket;
            supportedMoneyMarketsSize++;
            moneyMarket.withdrawAll(tokenAddress, address(this));
        }

        if (percentagesLength + 1 != supportedMoneyMarketsSize) revert NotParity();

        uint256 tokenSupply = token.balanceOf(address(this));

        for (uint256 i = 0; i < percentagesLength; i++) {
            IMoneyMarketAdapter moneyMarket = supportedMoneyMarkets[i];
            uint256 amountToDeposit = (tokenSupply * percentages[i]) / 10000;
            if (amountToDeposit == 0) continue;

 ++       uint256 currentSupply = moneyMarket.getSupply(tokenAddress); // which is 0 since we have withdrawn all
 ++     uint256 ceiling = moneyMarket.ceilingMap(tokenAddress);
 ++      if (currentSupply + amountToDeposit > ceiling) {
 ++         revert("AssetManager: deposit amount exceeds ceiling");
        }
            token.safeTransfer(address(moneyMarket), amountToDeposit);
            moneyMarket.deposit(tokenAddress);
        }

        uint256 remainingTokens = token.balanceOf(address(this));

        IMoneyMarketAdapter lastMoneyMarket = supportedMoneyMarkets[supportedMoneyMarketsSize - 1];
        if (remainingTokens > 0) {
     ++       uint256 currentSupply = lastMoneyMarket.getSupply(tokenAddress); // which is 0 since we have withdrawn all
     ++       uint256 ceiling = lastMoneyMarket.ceilingMap(tokenAddress);
     ++       if (currentSupply + remainingTokens > ceiling) {
     ++       revert("AssetManager: deposit amount exceeds ceiling");
          }
            token.safeTransfer(address(lastMoneyMarket), remainingTokens);
            lastMoneyMarket.deposit(tokenAddress);
        }

        emit LogRebalance(tokenAddress, percentages);
    }

```