Rare Mossy Okapi

Medium

# Current Implementation of deposit in Assetmanager.sol fails to iletarate to fill floor in the moneymarket and instead deposits all into one moneymarket

## Summary

The current implementation of the `deposit` function in `AssetManager.sol` does not properly distribute funds among money markets according to their floors and ceilings. This can result in all funds being deposited into a single money market, potentially bypassing the ceiling limits.

## Vulnerability Detail
https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/asset/AssetManager.sol#L307

The `deposit` function is intended to first fill the floors of supported money markets before distributing the remaining funds to the ceilings. However, the current implementation does not correctly iterate through the money markets to fill the floors, leading to all funds being deposited into a single money market. This could allow users to bypass the ceiling limits if they deposit a large amount of funds.

Here is the current implementation of the function:

```solidity
function deposit(
    address token,
    uint256 amount
) external override whenNotPaused onlyAuth(token) nonReentrant returns (bool) {
    IERC20Upgradeable poolToken = IERC20Upgradeable(token);
    if (amount == 0) revert AmountZero();

    if (!_isUToken(msg.sender, token)) {
        balances[msg.sender][token] += amount;
        totalPrincipal[token] += amount;
    }

    bool remaining = true;
    poolToken.safeTransferFrom(msg.sender, address(this), amount);
    if (isMarketSupported(token)) {
        uint256 moneyMarketsLength = moneyMarkets.length;
        for (uint256 i = 0; i < moneyMarketsLength && remaining; i++) {
            IMoneyMarketAdapter moneyMarket = moneyMarkets[i];
            if (!moneyMarket.supportsToken(token)) continue;
        @audit >> checks if floor has been reached >>>    if (moneyMarket.floorMap(token) <= moneyMarket.getSupply(token)) continue;
        @audit >> deposits all into one money market, risk that can allow for floor + amount>ceiling  >>>    poolToken.safeTransfer(address(moneyMarket), amount);
            if (moneyMarket.deposit(token)) {
                remaining = false;
            }
       ...................................................................
  
}
```

## Impact


The incorrect handling of the floors can lead to a single money market receiving more funds than its ceiling limit, resulting in potential overexposure and liquidity issues. This can negatively impact the stability and performance of the protocol. This is not submitted as a high because the admin can rebalance this but it should be implemented appropriately.

## Code Snippet

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/asset/AssetManager.sol#L291-L292

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/asset/AssetManager.sol#L293-L303

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/asset/AssetManager.sol#L268-L326

## Tool used

Manual Review

## Recommendation

Update the `deposit` function to correctly iterate through the money markets, ensuring that floors are filled before distributing the remaining funds to the ceilings. The function should check the amount needed to fill each money market to the floor before attempting to fill to the ceiling. Here is the updated code:

```solidity
function deposit(
    address token,
    uint256 amount
) external override whenNotPaused onlyAuth(token) nonReentrant returns (bool) {
    IERC20Upgradeable poolToken = IERC20Upgradeable(token);
    if (amount == 0) revert AmountZero();

    if (!_isUToken(msg.sender, token)) {
        balances[msg.sender][token] += amount;
        totalPrincipal[token] += amount;
    }

    poolToken.safeTransferFrom(msg.sender, address(this), amount);

    if (isMarketSupported(token)) {
        uint256 moneyMarketsLength = moneyMarkets.length;

        // Iterate markets to fill floors
        for (uint256 i = 0; i < moneyMarketsLength && amount > 0; i++) {
            IMoneyMarketAdapter moneyMarket = moneyMarkets[i];

            if (!moneyMarket.supportsToken(token)) continue;

            uint256 currentSupply = moneyMarket.getSupply(token);
            uint256 floor = moneyMarket.floorMap(token);
            if (currentSupply >= floor) continue;

   ++         uint256 amountToDeposit = floor - currentSupply;
   ++        if (amountToDeposit > amount) {
   ++            amountToDeposit = amount;
            }

   ++        poolToken.safeTransfer(address(moneyMarket), amountToDeposit);
            if (moneyMarket.deposit(token)) {
     ++           amount -= amountToDeposit;
    ++   if (amount==0){
         remaining = false;
            }
        }

 
}
```