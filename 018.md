Rare Lipstick Cod

Medium

# Anyone can sidestep the whitelisting protection for token transfers


## Summary

See _title_.

## Vulnerability Detail

Take a look at https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/7ffe43f68a1b8e8de1dfd9de5a4d89c90fd6f710/union-v2-contracts/contracts/token/OpUNION.sol#L25-L31

```solidity
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal override {
        super._beforeTokenTransfer(from, to, amount);

        if (whitelistEnabled) {
            require(isWhitelisted(msg.sender) || to == address(0), "Whitelistable: address not whitelisted");
        }
    }
```

This is the overriden ERC20 hook that is called before any transfer of tokens.

The overriden implementation now includes a check to see if the sender is whitelisted before allowing the transfer, when `whitelistEnabled`.

Issue however is that this is wrongly done, this is because the the whitelisted check is done against the `msg.sender` and not the `from` where the tokens are being sent from.

This then allows someone that got unwhitelisted to just approve a whitelisted account their tokens and they can side step this check, since the `isWhitelisted()` check would no longer fail.

## Impact

Core functionality is broken because anyone can now sidestep the whitelisting protection for token transfers.

Would be key to note that it's been clearly [documented](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/7ffe43f68a1b8e8de1dfd9de5a4d89c90fd6f710/union-v2-contracts/contracts/token/Whitelistable.sol#L26-L27) that whenever the whitelist is enabled then transfers are only to be allowed from whitelisted accounts, which would not be the case as shown in this report anyone can sidestep the restriction.

## Code Snippet

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/7ffe43f68a1b8e8de1dfd9de5a4d89c90fd6f710/union-v2-contracts/contracts/token/OpUNION.sol#L25-L32.

## Tool used

Manual Review

## Recommendation

Consider applyting these changes https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/7ffe43f68a1b8e8de1dfd9de5a4d89c90fd6f710/union-v2-contracts/contracts/token/OpUNION.sol#L25-L32

```diff
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal override {
        super._beforeTokenTransfer(from, to, amount);

        if (whitelistEnabled) {
-            require(isWhitelisted(msg.sender) || to == address(0), "Whitelistable: address not whitelisted");
+            require(isWhitelisted(from) || to == address(0), "Whitelistable: address not whitelisted");
        }
    }

```
