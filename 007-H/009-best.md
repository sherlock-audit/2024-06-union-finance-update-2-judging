Rhythmic Bone Boa

High

# `AssetManager::deposit()` not handling the case where `remaining` still true, as a result the deposited token will be lost forever in manager contract

## Summary


## Vulnerability Detail

An user can deposit via `UserManager::stake()` function, the `amount` is transfer from user to the AssetManager contract which supply these funds to corresponding lending markets through adapters. 

If the deposit call below returns `true`, the txn is considered successful, 
https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/7ffe43f68a1b8e8de1dfd9de5a4d89c90fd6f710/union-v2-contracts/contracts/user/UserManager.sol#L756
```solidity
        if (!IAssetManager(assetManager).deposit(stakingToken, amount)) revert AssetManagerDepositFailed();

```
**Issue**

Aave3Adapter has an edge case, if the `supply()` call to lendingPool fails for any reason, it transferred back the token `amount` to the AssetManager, returning `false`,  

*File: AaveV3Adapter.sol* 
```solidity
    function deposit(
        address tokenAddress
    ) external override onlyAssetManager checkTokenSupported(tokenAddress) returns (bool) {
        IERC20Upgradeable token = IERC20Upgradeable(tokenAddress);
        uint256 amount = token.balanceOf(address(this));
        try lendingPool.supply(tokenAddress, amount, address(this), 0) {
            return true;
        } catch {    // <@ trigger on failure
            token.safeTransfer(assetManager, amount);
            return false;
        }
    }

```

This edge case is not handled by the AssetManager [`deposit()`](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/7ffe43f68a1b8e8de1dfd9de5a4d89c90fd6f710/union-v2-contracts/contracts/asset/AssetManager.sol#L274) function, it is expected to return `true` in case the user amount deposited successfully to the lendingPool. However, the issue is it always return `true` even when the deposit was unsuccessful. 

The following check in `UserManager::deposit()` which reverts for unsuccessful deposit get bypass, as a consequences, user deposited funds lost forever in the AssetManager contract. 

```solidity
        if (!IAssetManager(assetManager).deposit(stakingToken, amount)) revert AssetManagerDepositFailed();
```

## Impact
Deposited assets will be lost in the AssetManager 

## Code Snippet
https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/7ffe43f68a1b8e8de1dfd9de5a4d89c90fd6f710/union-v2-contracts/contracts/asset/AssetManager.sol#L325
## Tool used

Manual Review

## Recommendation
The AssetManager deposit function should return `!remaining`, instead of default `true`. 
https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/7ffe43f68a1b8e8de1dfd9de5a4d89c90fd6f710/union-v2-contracts/contracts/asset/AssetManager.sol#L325
```diff
-        return true;
+        return !remaining; 
    }
```

If the amount successfully deposited to the lendingPool, the `remaining` will be set false, means assets deposited. 
And if the amount transferred back to the AssetManager, the `remaining` still true, means assets didn't got deposited, the [check](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/7ffe43f68a1b8e8de1dfd9de5a4d89c90fd6f710/union-v2-contracts/contracts/user/UserManager.sol#L756) will revert the txn.    