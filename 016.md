Rare Lipstick Cod

Medium

# `AaveV3Adapter` is going to be heavily non-functional in some to-deploy chains


## Summary

`AaveV3Adapter` is going to be heavily non-functional in some to-deploy chains since on Arbitrum & Optimism, depositing/withdrawing to/fro the lending pool would be impossible.

## Vulnerability Detail

First note that from the readMe, the below has been hinted, which indicates that the protocol is to be deployed on any EVM compatible chain.

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/7ffe43f68a1b8e8de1dfd9de5a4d89c90fd6f710/README.md#L10-L12

```markdown
### Q: On what chains are the smart contracts going to be deployed?

Any EVM compatible network

---
```

Now there exist an implementation of the AAVEV3Adapter in scope, which the `AssetManager` always calls and it includes different functionalities including how deposits can be done as shown here: https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/7ffe43f68a1b8e8de1dfd9de5a4d89c90fd6f710/union-v2-contracts/contracts/asset/AaveV3Adapter.sol#L205-L217

```solidity
    function deposit(
        address tokenAddress
    ) external override onlyAssetManager checkTokenSupported(tokenAddress) returns (bool) {
        IERC20Upgradeable token = IERC20Upgradeable(tokenAddress);
        uint256 amount = token.balanceOf(address(this));
        try lendingPool.supply(tokenAddress, amount, address(this), 0) {
            return true;
        } catch {
            token.safeTransfer(assetManager, amount);
            return false;
        }
    }

```

Issue however is that this implementation would not work on Arbitrum and optimism chain, which is because from the [Aave V3 documentation](https://docs.aave.com/developers/getting-started/l2-optimization), _Arbitrum_ and _Optimism_ are using different pool contracts than the ones used on e.g. Ethereum main net. The difference is mainly that the arguments taken by the pool functions relevant to the AaveConnector (supply, borrow, repay, repayWithATokens and withdraw) take a bytes32 variable as an argument instead of multiple different arguments:

That's to say the supply function on Ethereum looks like [this](https://github.com/aave/aave-v3-core/blob/724a9ef43adf139437ba87dcbab63462394d4601/contracts/protocol/pool/Pool.sol#L143-L148):

```rust
function supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode)
function supply(bytes32 args) external

```

Whereas the same function in the optimized L2Pool contract looks like [this](https://github.com/aave/aave-v3-core/blob/724a9ef43adf139437ba87dcbab63462394d4601/contracts/protocol/pool/Pool.sol#L143-L148):

```rust
function supply(bytes32 args) external
```

Using any EVM signature database tool we can see how different these signatures are, i.e, see the disparity in the `supply()` for the ethereum mainnet and other L2s where the protocol would deploy to and why the attempts would never work.

| Function Name    | Sighash  | Function Signature                     |
| ---------------- | -------- | -------------------------------------- |
| Mainnet supply() | 617ba037 | supply(address,uint256,address,uint16) |
| L2 supply        | f7a73840 | supply(bytes32)                        |

## Impact

The `AaveV3Adapter` is going to be heavily non-functional since it's core functionalities would not function as intended and it would be impossible to deposit tokens into the lending pool.

> NB: The same thing is applicable to the withdrwal attempts too, i.e https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/7ffe43f68a1b8e8de1dfd9de5a4d89c90fd6f710/union-v2-contracts/contracts/asset/AaveV3Adapter.sol#L225-L255

```solidity
    function withdraw(
        address tokenAddress,
        address recipient,
        uint256 tokenAmount
    ) external override onlyAssetManager checkTokenSupported(tokenAddress) returns (bool) {
        if (_checkBal(tokenAddress)) {
            try lendingPool.withdraw(tokenAddress, tokenAmount, recipient) {
                return true;
            } catch {
                return false;
            }
        } else {
            return false;
        }
    }

    /**
     * @dev Withdraw all tokens from this adapter
     * @dev Only callable by the AssetManager
     * @param tokenAddress Token to withdraw
     * @param recipient Received by
     */
    function withdrawAll(
        address tokenAddress,
        address recipient
    ) external override onlyAssetManager checkTokenSupported(tokenAddress) {
        if (_checkBal(tokenAddress)) {
            lendingPool.withdraw(tokenAddress, type(uint256).max, recipient);
        }
    }

```

They would always revert since the signatures would never match with what's on the L2pool contract, see https://github.com/aave/aave-v3-core/blob/724a9ef43adf139437ba87dcbab63462394d4601/contracts/protocol/pool/L2Pool.sol#L43

## Code Snippet

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/7ffe43f68a1b8e8de1dfd9de5a4d89c90fd6f710/union-v2-contracts/contracts/asset/AaveV3Adapter.sol#L205-L217

## Tool used

- Manual Review
- AAVEV3 documentation

## Recommendation

Consider creating a separate contract for the `AaveV3Adapter` for Arbitrum & Optimism that correctly accounts for the native implementation on these chains.
