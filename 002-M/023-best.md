Polite Topaz Swallow

Medium

# `ERC1155Voucher.onERC1155BatchReceived()` does not check the caller is the valid token therefore any unregistered token can invoke `onERC1155BatchReceived()`

## Summary
`ERC1155Voucher.onERC1155BatchReceived()` does not check the caller is the valid token therefore any unregistered token can invoke `onERC1155BatchReceived()`

## Vulnerability Detail
`ERC1155Voucher.sol` is the voucher contract that takes `ERC1155` tokens as deposits and gives a vouch. An ERC1155 token can invoke  two safe methods:

1) `onERC1155Received()` and
2) `onERC1155BatchReceived()`

An ERC1155-compliant smart contract must call above functions on the token recipient contract, at the end of a `safeTransferFrom` and `safeBatchTransferFrom` respectively, after the balance has been updated.

The `ERC1155Voucher` contract owner can set the valid token i.e ERC1155 token which can invoke both `onERC1155Received()` and `onERC1155BatchReceived()` functions.

```solidity
    mapping(address => bool) public isValidToken;
    
    
    function setIsValid(address token, bool isValid) external onlyOwner {
        isValidToken[token] = isValid;
        emit SetIsValidToken(token, isValid);
    }
```

The valid token i.e msg.sender calling the `onERC1155Received()` is checked in `ERC1155Voucher.onERC1155Received()` function

```solidity
    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata data
    ) external returns (bytes4) {
@>        require(isValidToken[msg.sender], "!valid token");
        _vouchFor(from);
        return bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"));
    }
```
This means that only the valid tokens set by contract owner can invoke the `ERC1155Voucher.onERC1155Received()`  function. However, this particular check is missing in `ERC1155Voucher.onERC1155BatchReceived()` function.

```solidity
    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external returns (bytes4) {
        _vouchFor(from);
        return bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"));
    }
```
`onERC1155BatchReceived()` does not check the `isValidToken[msg.sender]` which means any ERC1155 token can call `ERC1155Voucher.onERC1155BatchReceived()` to deposit the ERC1155 to receive the vouch. This is not intended behaviour by protocol and would break the intended design of setting valid tokens by contract owner. Any in-valid tokens can easily call `onERC1155BatchReceived()` and can bypass the check at [L-109](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/peripheral/ERC1155Voucher.sol#L109) implemented in `onERC1155Received()` function.

## Impact
Any in-valid or unregistered ERC1155 token can invoke the `onERC1155BatchReceived()` function which would make the check at L-109 of `onERC1155Received()` useless as batch function would allow to deposit ERC1155 to receive the vouch therefore bypassing the L-109 check in `onERC1155Received()`. This would break the design of protocol as valid tokens as msg.sender are not checked in `onERC1155BatchReceived()`.

## Code Snippet
https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/peripheral/ERC1155Voucher.sol#L121

## Tool used
Manual Review

## Recommendation
Consider checking `isValidToken[msg.sender]` in `onERC1155BatchReceived()` to invoke it from registered valid token only.

Consider below changes:

```diff
    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    ) external returns (bytes4) {
+       require(isValidToken[msg.sender], "!valid token");
        _vouchFor(from);
        return bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"));
    }
```