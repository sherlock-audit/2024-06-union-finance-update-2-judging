Polite Topaz Swallow

Medium

# Permit functions in `Union` contracts can be affected by DOS

## Summary
Permit functions in `Union` contracts can be affected by DOS

## Vulnerability Detail
The following inscope `Union` contracts supports ERC20 permit functionality by which users could spend the tokens by signing an approval off-chain.

1) In `UDai.repayBorrowWithPermit()`, , after the permit call is successful there is a call to `_repayBorrowFresh()`

```solidity
    function repayBorrowWithPermit(
        address borrower,
        uint256 amount,
        uint256 nonce,
        uint256 expiry,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused {
        IDai erc20Token = IDai(underlying);
@>        erc20Token.permit(msg.sender, address(this), nonce, expiry, true, v, r, s);

        if (!accrueInterest()) revert AccrueInterestFailed();
        uint256 interest = calculatingInterest(borrower);
        _repayBorrowFresh(msg.sender, borrower, decimalScaling(amount, underlyingDecimal), interest);
    }

```

2) In `UErc20.repayBorrowWithERC20Permit()`, , after the permit call is successful there is a call to `_repayBorrowFresh()`

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
@>        erc20Token.permit(msg.sender, address(this), amount, deadline, v, r, s);

        if (!accrueInterest()) revert AccrueInterestFailed();
        uint256 interest = calculatingInterest(borrower);
        _repayBorrowFresh(msg.sender, borrower, decimalScaling(amount, underlyingDecimal), interest);
    }
```

3) In `UserManager.registerMemberWithPermit()`, , after the permit call is successful there is a call to `registerMember()`

```solidity
    function registerMemberWithPermit(
        address newMember,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused {
@>        IUnionToken(unionToken).permit(msg.sender, address(this), value, deadline, v, r, s);
        registerMember(newMember);
    }

```

4) `UserManagerDAI.stakeWithPermit()`, , after the permit call is successful there is a call to `stake()`

```solidity
    function stakeWithPermit(
        uint256 amount,
        uint256 nonce,
        uint256 expiry,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused {
        IDai erc20Token = IDai(stakingToken);
@>        erc20Token.permit(msg.sender, address(this), nonce, expiry, true, v, r, s);

        stake(amount.toUint96());
    }
```

5) In `UserManagerERC20.stakeWithERC20Permit()`, , after the permit call is successful there is a call to `stake()`

```solidity
    function stakeWithERC20Permit(
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external whenNotPaused {
        IERC20Permit erc20Token = IERC20Permit(stakingToken);
        erc20Token.permit(msg.sender, address(this), amount, deadline, v, r, s);

        stake(amount.toUint96());
    }
```

The issue is that while the transactions for either of above permit functions is in mempool, anyone could extract the signature parameters from the call to front-run the transaction with direct permit call.

This issue is originally submitted by Trust security aka Trust to various on chain protocols and the issue is confirmed by reputed protocols like Open Zeppelin, AAVE, The Graph, Uniswap-V2

To understand the issue in detail, Please refer below link:

link: https://www.trust-security.xyz/post/permission-denied

> An attacker can extract the signature by observing the mempool, front-run the victim with a direct permit, and revert the function call for the user. "In the case that there is no fallback code path the DOS is long-term (there are bypasses through flashbots in some chains, but that's a really bad scenario to resort to)." as stated by Trust Security.

Since, the protocol would  be deployed on any EVM compatible chain so Ethereum mainnet has mempool with others chain too. This issue would indeed increase the approval for the user if the front-run got successful. But as the permit has already been used, the call to either of above permit functions will revert making whole transaction revert. Thus making the victim not able to make successful call to either of above permit functions to carry out borrow repay or stake or member registration.

Consider a normal scenario,

1) Bob wants to repay his loan with permit so he calls `UErc20.repayBorrowWithERC20Permit()` function.

2) Alice observes the transactions in mempool and extract the signature parameters from the call to front-run the transaction with direct permit call. Alice transaction got successful due to high gas fee paid by her to minor by front running the Bob's transaction.

3) This action by Alice would indeed increase the approval for the Bob since the front-run got successful.

4) But as the permit is already been used by Alice so the call to `UErc20.repayBorrowWithERC20Permit()` will revert making whole transaction revert.

5) Now, Bob will not able to make successful call to `UErc20.repayBorrowWithERC20Permit()` function to pay his loan by using ERC20 permit(). This is due to griefing attack by Alice. She keep repeating such attack as the intent is to grief the protocol users.

## Impact
Users will not be able to use the permit functions for important functions like `UDai.repayBorrowWithPermit()`, `UErc20.repayBorrowWithERC20Permit()`, `UserManager.registerMemberWithPermit()`, `UserManagerDAI.stakeWithPermit()` and `UserManagerERC20.stakeWithERC20Permit()` so these function would be practically unusable and users functionality would be affected due to above described issue

## Code Snippet
https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UDai.sol#L19

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UErc20.sol#L17

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/user/UserManager.sol#L711

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/user/UserManagerDAI.sol#L29

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/user/UserManagerERC20.sol#L27

## Tool used
Manual Review

## Recommendation
Wrap the `permit` calls in a try catch block in above functions using permit().