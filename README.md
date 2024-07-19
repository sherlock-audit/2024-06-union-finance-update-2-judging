# Issue H-1: `AssetManager::deposit()` not handling the case where `remaining` still true, as a result the deposited token will be lost forever in manager contract 

Source: https://github.com/sherlock-audit/2024-06-union-finance-update-2-judging/issues/9 

## Found by 
Nyxaris, blutorque
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

# Issue H-2: Wrong calculation of Accure Reward in Comptroller.sol 

Source: https://github.com/sherlock-audit/2024-06-union-finance-update-2-judging/issues/26 

## Found by 
Bigsam, Varun\_05
## Summary
Accure Reward calculates the global total staked before updating the total amount of token frozen hence, the globalTotalStaked used does not reflect the actual present globalTotalStaked value. Thus A user can claim the reward for recently frozen tokens due to this error. 

## Vulnerability Detail

Based on the calculation in Comptroller.sol and UserManager, 

function '_accrueReward' calculates the TotalStaked but gets the value of newly frozen totals and increments the _totalfrozen.
This allows us to pass in a Larger amount of globalTotalStaked than we should at the current time, here the user benefits from this since the globalTotalStaked is used to get the amount(REWARD) and calculate the gInflationIndex.

```solidity
 function _accrueRewards(address account, address token) private returns (uint256) {
        IUserManager userManager = _getUserManager(token);

@audit>>issue>>        // Lookup global state from UserManager
                                     uint256 globalTotalStaked = userManager.globalTotalStaked();

        // Lookup account state from UserManager
        UserManagerAccountState memory user = UserManagerAccountState(0, 0, false);
  @audit>>issue>>          (user.effectiveStaked, user.effectiveLocked, user.isMember) = userManager.onWithdrawRewards(account);

        uint256 amount = _calculateRewardsInternal(account, token, globalTotalStaked, user);

        // update the global states
        gInflationIndex = _getInflationIndexNew(globalTotalStaked, getTimestamp() - gLastUpdated);
        gLastUpdated = getTimestamp();
        users[account][token].inflationIndex = gInflationIndex;

        return amount;
    }
```


For Reference, please look at the same implementation when it is called directly from Usermanager.sol in function 'batchUpdateFrozenInfo'.

 

```solidity
 function batchUpdateFrozenInfo(address[] calldata stakerList) external whenNotPaused {
        uint256 stakerLength = stakerList.length;
     ------------------------------------------------------------------------
   @audit >>   update is done first >>      (, , uint256 memberTotalFrozen) = _getEffectiveAmounts(staker);

            uint256 memberFrozenBefore = _memberFrozen[staker];
            if (memberFrozenBefore != memberTotalFrozen) {
                _memberFrozen[staker] = memberTotalFrozen;
     @audit >>  totalfrozen is obtained>>           tmpTotalFrozen = tmpTotalFrozen - memberFrozenBefore + memberTotalFrozen;
            }
        }
        _totalFrozen = tmpTotalFrozen;

            @audit >> totalstaked - the present totalfrozen>>      comptroller.updateTotalStaked(stakingToken, _totalStaked - _totalFrozen);
    }
```

The present globalTotalStaked is correctly implement in another implementation (globalTotal = _totalStaked - _totalFrozen;)
```solidity
 function updateTotalStaked(
        address token,
        uint256 totalStaked
    ) external override whenNotPaused onlyUserManager(token) returns (bool) {
        if (totalStaked > 0) {
            gInflationIndex = _getInflationIndexNew(totalStaked, getTimestamp() - gLastUpdated);
            gLastUpdated = getTimestamp();
        }

        return true;
    }
```
From the second implementation by the protocol, it should be noted that globalTotalStaked should only be called after the _totalfrozen has been correctly updated and not before.

## Impact

Collection of Reward on newly frozen Tokens.

## Code Snippet

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/token/Comptroller.sol#L224

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/user/UserManager.sol#L1124-L1125

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/token/Comptroller.sol#L228

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/user/UserManager.sol#L1056

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/user/UserManager.sol#L1067

## Tool used

Manual Review

## Recommendation

Get 'globalTotalStaked' after calculating all frozen assets in the userManager for the user. 


```solidity

      --  // Lookup global state from UserManager
      --  uint256 globalTotalStaked = userManager.globalTotalStaked();
        
         // Lookup account state from UserManager
        UserManagerAccountState memory user = UserManagerAccountState(0, 0, false);
        (user.effectiveStaked, user.effectiveLocked, user.isMember) = userManager.onWithdrawRewards(account);
      
  ++   // Lookup global state from UserManager
  ++  uint256 globalTotalStaked = userManager.globalTotalStaked();
```

# Issue H-3: VouchFaucet can be immediately drained by anyone 

Source: https://github.com/sherlock-audit/2024-06-union-finance-update-2-judging/issues/33 

## Found by 
0xAadi, Bigsam, Bugvorus, Varun\_05, aua\_oo7, cryptphi, korok
## Summary

The `claimTokens` function in the VouchFaucet contract fails to properly enforce the `maxClaimable` limit because it does not update the value in the `claimedTokens` mapping. This allows any address to claim an arbitrary amount of any token, potentially draining the entire token balance of the contract, in a single transaction or through multiple transactions.

## Vulnerability Detail

Included below is the relevant code from the [VouchFaucet](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/7ffe43f68a1b8e8de1dfd9de5a4d89c90fd6f710/union-v2-contracts/contracts/peripheral/VouchFaucet.sol#L93-L97) followed by key insights:

```solidity
    /// @notice Token address to msg sender to claimed amount
    mapping(address => mapping(address => uint256)) public claimedTokens;

    /// @notice Token address to max claimable amount
    mapping(address => uint256) public maxClaimable;

    /// @notice Claim tokens from this contract
    function claimTokens(address token, uint256 amount) external {
        require(claimedTokens[token][msg.sender] <= maxClaimable[token], "amount>max");
        IERC20(token).transfer(msg.sender, amount);
        emit TokensClaimed(msg.sender, token, amount);
    }

    /// @notice Transfer ERC20 tokens
    function transferERC20(address token, address to, uint256 amount) external onlyOwner {
        IERC20(token).transfer(to, amount);
    }
```
- The claimedTokens mapping is never updated. It will always return 0 when looking up how much of any token has been claimed by any address. 

- The maxClaimable mapping will by default return 0 for any token the contract could ever receive. The contract owner can use the setMaxClaimable function but is only able to set the claimable amount for any token to 0 or greater.

- The transferERC20 function is protected by the onlyOwner modifier signaling the desire to restrict access to this type of transfer. 

- Currently no matter what the admin does the require statement in claimTokens will always pass because it evaluates an expression that will always effectively be:   `require(0 <= [uint256], "amount>max");` This makes claimTokens effectively equivalent to an unrestricted version of transferERC20.

### Proof of Concept

The proof of concept below imports and utilizes [the protcols own TestWrapper](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/test/foundry/TestWrapper.sol) for simplicity in setting up a realistic testing environment.

The test case demonstrates that despite the VouchFaucet containing mechanisms that clearly intend to disallow the faucet from being easily drained by a single address, such an outcome is possible with no effort. 


```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.16;

import {Test, console} from "forge-std/Test.sol";
import {TestWrapper} from "../TestWrapper.sol";
import {VouchFaucet} from "../../src/contracts/peripheral/VouchFaucet.sol";

import {IERC20} from "@openzeppelin/token/ERC20/IERC20.sol";

contract TestVouchFaucet is TestWrapper {
    VouchFaucet public vouchFaucet;
    uint256 public TRUST_AMOUNT = 10 * UNIT;

    function setUp() public {
        deployMocks();
        vouchFaucet = new VouchFaucet(address(userManagerMock), TRUST_AMOUNT);
    }

    function testDrainVouchFaucet() public {
        address bob = address(1234);

        erc20Mock.mint(address(vouchFaucet), 3 * UNIT);

        vouchFaucet.setMaxClaimable(address(erc20Mock), 1 * UNIT);
        assertEq(vouchFaucet.maxClaimable(address(erc20Mock)), 1 * UNIT);

        // Bob can claim any number of tokens despite maxClaimable set to 1 Unit
        vm.prank(bob);
        vouchFaucet.claimTokens(address(erc20Mock), 3 * UNIT);

        assertEq(IERC20(erc20Mock).balanceOf(bob), 3 * UNIT);
    }

}
```

## Impact

Without the intended enforcement provided by the require statement the claimTokens function provides unrestricted external access to an ERC20 transfer function. This is clearly not intended as demonstrated by the presence of the onlyOwner on the similar transferERC20 function. The result is that any caller can immediately transfer out any amount of any token.

This oversight completely undermines the token distribution model of the faucet. If deployed without modification it would render the contract useless for the intended purpose due to its inability to securely hold any amount of any token.  

## Code Snippet

https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/7ffe43f68a1b8e8de1dfd9de5a4d89c90fd6f710/union-v2-contracts/contracts/peripheral/VouchFaucet.sol#L93-L97

## Tool used

Manual Review

## Recommendation

The following correction ensures that any individual address can't claim more than the set claimable amount, maintaining the intended token distribution model of the faucet.

```diff

File: VouchFaucet.sol

    function claimTokens(address token, uint256 amount) external {
-        require(claimedTokens[token][msg.sender] <= maxClaimable[token], "amount>max");
+        uint256 newTotal = claimedTokens[token][msg.sender] + amount;
+        require(newTotal <= maxClaimable[token], "Exceeds max claimable amount");

+        claimedTokens[token][msg.sender] = newTotal;
        IERC20(token).transfer(msg.sender, amount);

        emit TokensClaimed(msg.sender, token, amount);
    }
```

The following additional recommendations should be considered. The suggestions won't impact legitimate users, but raise the effort required for an malicious actor to disrupt the intended functioning of the contract.

1. Ensure the claimedTokens mapping is updated before the transfer to avoid reentrancy risk, OpenZeppelin ReentrancyGuard could also be considered. 

1. Consider adding an admin adjustable global cap on total tokens that can be claimed across all addresses to help control faucet outflows. 

3. Consider implementing a time-based cooldown mechanism to limit the frequency of claims per address.

# Issue H-4: Exchange Rate Manipulation via Supply and Redeemable Balance Distortion 

Source: https://github.com/sherlock-audit/2024-06-union-finance-update-2-judging/issues/42 

## Found by 
Nyxaris, smbv-1923
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

# Issue H-5: Repaying a Loan with Permit in UErc20.sol Wrongly calculates the interest to be paid this Reduce/Increase profits for the protocol as interest calculations are not performed correctly. 

Source: https://github.com/sherlock-audit/2024-06-union-finance-update-2-judging/issues/43 

## Found by 
Bigsam, Varun\_05, hyh, trachev, twicek
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

# Issue H-6: Malicious user can steal all the funds in the `VouchFaucet` contract 

Source: https://github.com/sherlock-audit/2024-06-union-finance-update-2-judging/issues/96 

## Found by 
0xAadi, CFSecurity, snapishere, trachev
### Summary

A malicious user can steal all the tokens from the [`VouchFaucet`](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/peripheral/VouchFaucet.sol#L93), due to a flaw in the [`VouchFaucet::claimTokens()`](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/peripheral/VouchFaucet.sol#L93) function, which is designed to rescue the tokens sent to the contract itself.

### Root Cause

The [`VouchFaucet::claimTokens()`](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/peripheral/VouchFaucet.sol#L93) function contains a security flaw due to insufficient access control and lack of proper validation.

Key issues:

1. This function meant to be a used for recovering potentially lost tokens from the contract, lacks from a proper access control like an `onlyOwner` modifier. This omission allows any user to call it, rather than restricting access to the contract owner

2. There is no validation of the `amount` parameter specified by the use, allowing him so withdraw all the tokens in the contract.

3. The function fails to verify if the caller is entitled to the requested amount

This issues allow a malicious user to steal all the funds in the contract.

### Internal pre-conditions

1. Admin needs to set maxClaimable[token] to a number > 0.

### External pre-conditions

None

### Attack Path

1. Alice accidentally sent 10e18 tokens to the contract, likely intending to to something other with them but making a mistake in the transaction.

2. Bob, aware of a protocol flaw and anticipating such a mistake, noticed this transaction.

3. He exploited the vulnerability by calling the [`VouchFaucet::claimTokens()`](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/peripheral/VouchFaucet.sol#L93) with 10e18 tokens.

4. This action drained all the tokens, resulting in a loss for both Alice and the protocol.

Note:
>Check and run the coded PoC to understand better the vulnerability.

### Impact

Due to a flaw in the [`VouchFaucet::claimTokens()`](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/peripheral/VouchFaucet.sol#L93) function, anyone can steal all the tokens deposited in the contract. This vulnerability can be exploited by malicious actors, leading to significant financial losses.

### PoC

1. In order to run the test, go to the [`VouchFaucet.t.sol`](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/test/foundry/peripheral/VouchFaucet.t.sol) contract and replace its content with the one below:

```solidity
pragma solidity ^0.8.0;

import {TestWrapper} from "../TestWrapper.sol";
import {VouchFaucet} from "union-v2-contracts/peripheral/VouchFaucet.sol";

import "forge-std/console2.sol";

contract TestVouchFaucet is TestWrapper {
    VouchFaucet public vouchFaucet;

    uint256 public TRUST_AMOUNT = 10 * UNIT;
    address BOB = address(1);
    address ALICE = address(2);

    function setUp() public {
        deployMocks();
        vouchFaucet = new VouchFaucet(address(userManagerMock), TRUST_AMOUNT);

        erc20Mock.mint(ALICE, 100 ether);

        vm.startPrank(ALICE);
        erc20Mock.approve(address(vouchFaucet), type(uint256).max);
        vm.stopPrank();
    }

    function testConfig() public {
        assertEq(vouchFaucet.USER_MANAGER(), address(userManagerMock));
        assertEq(vouchFaucet.TRUST_AMOUNT(), TRUST_AMOUNT);
        assertEq(vouchFaucet.STAKING_TOKEN(), userManagerMock.stakingToken());
    }

    function testSetMaxClaimable(address token, uint256 amount) public {
        vouchFaucet.setMaxClaimable(token, amount);
        assertEq(vouchFaucet.maxClaimable(token), amount);
    }

    function testMaliciousUserCanClaimAllTheTokensInTheContract() public {
        setUp();

        //ALICE transfers tokens to the contract
        vm.startPrank(ALICE);
        erc20Mock.transfer(address(vouchFaucet), 10 ether);

        uint256 contractBalance = erc20Mock.balanceOf(address(vouchFaucet));
        assertEq(contractBalance, 10 ether);

        vm.stopPrank();

        vm.startPrank(BOB);

        uint256 bobBalanceBefore = erc20Mock.balanceOf(BOB);
        assertEq(bobBalanceBefore, 0);

        //BOB calls claimTokens() and gets all the tokens in the contract
        vouchFaucet.claimTokens(address(erc20Mock), 10 ether);

        uint256 bobBalanceAfter = erc20Mock.balanceOf(BOB);
        assertEq(bobBalanceAfter, 10 ether);
    }

    function testCannotSetMaxClaimableNonAdmin(address token, uint256 amount) public {
        vm.prank(address(1234));
        vm.expectRevert("Ownable: caller is not the owner");
        vouchFaucet.setMaxClaimable(token, amount);
    }

    function testClaimVouch() public {
        vouchFaucet.claimVouch();
        uint256 trust = userManagerMock.trust(address(vouchFaucet), address(this));
        assertEq(trust, vouchFaucet.TRUST_AMOUNT());
    }

    function testStake() public {
        erc20Mock.mint(address(vouchFaucet), 1 * UNIT);
        assertEq(userManagerMock.balances(address(vouchFaucet)), 0);
        vouchFaucet.stake();
        assertEq(userManagerMock.balances(address(vouchFaucet)), 1 * UNIT);
    }

    function testExit() public {
        erc20Mock.mint(address(vouchFaucet), 1 * UNIT);
        assertEq(userManagerMock.balances(address(vouchFaucet)), 0);
        vouchFaucet.stake();
        assertEq(userManagerMock.balances(address(vouchFaucet)), 1 * UNIT);
        vouchFaucet.exit();
        assertEq(userManagerMock.balances(address(vouchFaucet)), 0);
    }

    function testTransferERC20(address to, uint256 amount) public {
        vm.assume(
            to != address(0) && to != address(this) && to != address(vouchFaucet) && address(vouchFaucet) != address(0)
        );

        erc20Mock.mint(address(vouchFaucet), amount);
        uint256 balBefore = erc20Mock.balanceOf(address(vouchFaucet));
        vouchFaucet.transferERC20(address(erc20Mock), to, amount);
        uint256 balAfter = erc20Mock.balanceOf(address(vouchFaucet));
        assertEq(balBefore - balAfter, amount);
        assertEq(erc20Mock.balanceOf(to), amount);
    }
}

```

2. Run the coded PoC with the following command:
`forge test --match-test testMaliciousUserCanClaimAllTheTokensInTheContract -vvvv`

### Mitigation

Add a proper access control to the function like an `onlyOwner` modifier

# Issue H-7: The _totalStaked tracker calculation is incorrect and will be inflated due to the improper logic in the writeOffDebt function of the UserManager contract, leading to wrong Comptroller gInflationIndex being calculated and wrong user rewards being issued 

Source: https://github.com/sherlock-audit/2024-06-union-finance-update-2-judging/issues/105 

## Found by 
KungFuPanda, Varun\_05, hyh, trachev, twicek
### Summary

During `debtWriteOff` call in the `UserManager`, subtracting the `amount` instead of `realAmount` will lead to the whole `gInflationIndex` being inflated in the `Comptroller` contract, as well as general accounting inflation.

Due to the `UserManager`'s `_totalStaked` being coupled with the `Comptroller`'s `gInflationIndex`, the `userInfo` stake's `inflationIndex` will be calculated absolutely incorrectly:
```solidity
    /**
     *  @dev Calculate currently unclaimed rewards
     *  @param account Account address
     *  @param token Staking token address
     *  @param totalStaked Effective total staked
     *  @param user User account global state
     *  @return Unclaimed rewards
     */
    function _calculateRewardsInternal(
        address account,
        address token,
        uint256 totalStaked,
        UserManagerAccountState memory user
    ) internal view returns (uint256) {
        Info memory userInfo = users[account][token];
        uint256 startInflationIndex = userInfo.inflationIndex; // @@ <<< this internally depends on the UserManager's _totalStaked variable
```
And due to that, the whole user rewards calculation will be incorrect:
```solidity

        uint256 rewardMultiplier = _getRewardsMultiplier(user);

        uint256 curInflationIndex = _getInflationIndexNew(totalStaked, getTimestamp() - gLastUpdated);

        if (curInflationIndex < startInflationIndex) revert InflationIndexTooSmall();

        return
            userInfo.accrued +
            (curInflationIndex - startInflationIndex).wadMul(user.effectiveStaked).wadMul(rewardMultiplier);
    }
```
(https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/7ffe43f68a1b8e8de1dfd9de5a4d89c90fd6f710/union-v2-contracts/contracts/token/Comptroller.sol#L293)

Furthermore, during the reward accrual, there's another outcome of the miscalculated `_totalStaked` and `gInflationIndex` values:
```solidity
    function _accrueRewards(address account, address token) private returns (uint256) {
        IUserManager userManager = _getUserManager(token);

        // Lookup global state from UserManager
        uint256 globalTotalStaked = userManager.globalTotalStaked(); // @@ <<< here a wrong _totalStaked amount is retrieved!!!

        // Lookup account state from UserManager
        UserManagerAccountState memory user = UserManagerAccountState(0, 0, false);
        (user.effectiveStaked, user.effectiveLocked, user.isMember) = userManager.onWithdrawRewards(account);

        uint256 amount = _calculateRewardsInternal(account, token, globalTotalStaked, user); // @@ <<< here a wrong amount is passed down to the calculation!

        // update the global states
        gInflationIndex = _getInflationIndexNew(globalTotalStaked, getTimestamp() - gLastUpdated);
        gLastUpdated = getTimestamp();
        users[account][token].inflationIndex = gInflationIndex;

        return amount;
    }
```
Above is a reference from the `Comptroller` contract: https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/7ffe43f68a1b8e8de1dfd9de5a4d89c90fd6f710/union-v2-contracts/contracts/token/Comptroller.sol#L220C1-L238C6.

### References for the main problem:
- https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/7ffe43f68a1b8e8de1dfd9de5a4d89c90fd6f710/union-v2-contracts/contracts/token/Comptroller.sol#L276
- https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/7ffe43f68a1b8e8de1dfd9de5a4d89c90fd6f710/union-v2-contracts/contracts/token/Comptroller.sol#L287

### The culprit's details are further explained below.

This is due to using a non-scaled `amount` instead of the *scaled* `realAmount` in the `debtWriteOff` function here, in this line:
https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/7ffe43f68a1b8e8de1dfd9de5a4d89c90fd6f710/union-v2-contracts/contracts/user/UserManager.sol#L834

### Root Cause

In this update Union Finance adds distinct definitions for the `actualAmount` *being the **real** scaled token amount*, and the `amount` *being an unscaled nominal amount* that is to be scaled by `stakingTokenDecimal`, and is usually accepted as an argument for functions within the `UserManager` contract.

Both `stake` and `unstake` functions track the `totalStaked` balance as a **scaled** AND **real** token amount, as can be seen here: https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/7ffe43f68a1b8e8de1dfd9de5a4d89c90fd6f710/union-v2-contracts/contracts/user/UserManager.sol#L784. The snippet:
```solidity
    function unstake(uint96 amount) external whenNotPaused nonReentrant {
        Staker storage staker = _stakers[msg.sender];

        // Stakers can only unstaked stake balance that is unlocked. Stake balance
        // becomes locked when it is used to underwrite a borrow.
        if (staker.stakedAmount - staker.locked < decimalScaling(amount, stakingTokenDecimal))
            revert InsufficientBalance();

        comptroller.withdrawRewards(msg.sender, stakingToken);

        uint256 remaining = IAssetManager(assetManager).withdraw(stakingToken, msg.sender, amount);
        if (remaining > amount) {
            revert AssetManagerWithdrawFailed();
        }
        uint96 actualAmount = decimalScaling(uint256(amount) - remaining, stakingTokenDecimal).toUint96();

        staker.stakedAmount -= actualAmount;
        _totalStaked -= actualAmount; // @@ <<< the actualAmount is subtracted

        emit LogUnstake(msg.sender, amount - remaining.toUint96());
    }
```

And for `stake` it's `actualAmount` too (https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/7ffe43f68a1b8e8de1dfd9de5a4d89c90fd6f710/union-v2-contracts/contracts/user/UserManager.sol#L748), correspondingly:
```solidity
    function stake(uint96 amount) public whenNotPaused nonReentrant {
        IERC20Upgradeable erc20Token = IERC20Upgradeable(stakingToken);
        uint96 actualAmount = decimalScaling(uint256(amount), stakingTokenDecimal).toUint96();
        comptroller.withdrawRewards(msg.sender, stakingToken);

        Staker storage staker = _stakers[msg.sender];

        if (staker.stakedAmount + actualAmount > _maxStakeAmount) revert StakeLimitReached();

        staker.stakedAmount += actualAmount;
        _totalStaked += actualAmount; // @@ <<< here you can see it!

        erc20Token.safeTransferFrom(msg.sender, address(this), amount);
        uint256 currentAllowance = erc20Token.allowance(address(this), assetManager);
        if (currentAllowance < amount) {
            erc20Token.safeIncreaseAllowance(assetManager, amount - currentAllowance);
        }

        if (!IAssetManager(assetManager).deposit(stakingToken, amount)) revert AssetManagerDepositFailed();
        emit LogStake(msg.sender, amount);
    }
```

However, the `debtWriteOff` function doesn't subtract the `actualAmount`, but decreases the `_totalStaked` counter by a non-scaled `amount` value:
```solidity
        Staker storage staker = _stakers[stakerAddress];

        staker.stakedAmount -= actualAmount.toUint96();
        staker.locked -= actualAmount.toUint96();
        staker.lastUpdated = currTime.toUint64();

        _totalStaked -= amount;

        // update vouch trust amount
        vouch.trust -= actualAmount.toUint96();
        vouch.locked -= actualAmount.toUint96();
        vouch.lastUpdated = currTime.toUint64();
```

Then here later in the `batchUpdateFrozenInfo` function (that can be called by anyone and is unrestricted!), the `Comptroller` contract is notified of the new `_totalStaked` amount (https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/7ffe43f68a1b8e8de1dfd9de5a4d89c90fd6f710/union-v2-contracts/contracts/user/UserManager.sol#L1121):
```solidity
        comptroller.updateTotalStaked(stakingToken, _totalStaked - _totalFrozen);
    }

    function globalTotalStaked() external view returns (uint256 globalTotal) {
        globalTotal = _totalStaked - _totalFrozen;
    }
```

The problem lies in this change here: https://github.com/unioncredit/union-v2-contracts/pull/172/files#diff-e274f419b6384471f87c2b7d6a2c75150b95d37f3174a21d7d675ad20e3e4464R834

The `Comptroller`'s `updateTotalStaked` function gets called:
```solidity
    /**
     *  @dev When total staked change update inflation index
     *  @param totalStaked totalStaked amount
     *  @return Whether succeeded
     */
    function updateTotalStaked(
        address token,
        uint256 totalStaked
    ) external override whenNotPaused onlyUserManager(token) returns (bool) {
        if (totalStaked > 0) {
            gInflationIndex = _getInflationIndexNew(totalStaked, getTimestamp() - gLastUpdated);
            gLastUpdated = getTimestamp();
        }

        return true;
    }
```

And finally, the `gInflationIndex` value will be inflated.

### Internal pre-conditions

1. As far as I can tell, the attack will be unintentional in most cases, happening automatically on each `debtWriteOff` call, because the culprit is an improper calculation.
2. Or this can be utilized together with calling `batchUpdateFrozenInfo` to inflate the `gInflationIndex` value intentionally and cause the `Comptroller`'s `_getInflationIndexNew` to return incorrect results:
```solidity
            gInflationIndex = _getInflationIndexNew(totalStaked, getTimestamp() - gLastUpdated);
```

### External pre-conditions

None. The bug is just implicitly there.

### Attack Path

As it's a mistake in the `_totalStaked` calculation logic, there's no particular trigger for this attack, as it will happen if any user `write`'s`OffDebt`.

### Impact

The whole `gInflationIndex` will be inflated, and will be calculated incorrectly.

Besides that, tracking the wrong amount of the currently active staked tokens will be misleading for the external users that refer to that value.

### PoC

None. Please leave me a comment if you request one from me.

### Mitigation

Instead of subtracting `amount`, you should subtract the `actualAmount` from the `_totalStaked` variable here in `writeOffDebt`:
```diff

        Staker storage staker = _stakers[stakerAddress];

        staker.stakedAmount -= actualAmount.toUint96();
        staker.locked -= actualAmount.toUint96();
        staker.lastUpdated = currTime.toUint64();

-      _totalStaked -= amount;
+      _totalStaked -= actualAmount;

        // update vouch trust amount
        vouch.trust -= actualAmount.toUint96();
        vouch.locked -= actualAmount.toUint96();
        vouch.lastUpdated = currTime.toUint64();
```

# Issue H-8: Incorrect value `BORROW_RATE_MAX_MANTISSA` used in contracts 

Source: https://github.com/sherlock-audit/2024-06-union-finance-update-2-judging/issues/128 

## Found by 
MohammedRizwan
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

# Issue M-1: `ERC1155Voucher.onERC1155BatchReceived()` does not check the caller is the valid token therefore any unregistered token can invoke `onERC1155BatchReceived()` 

Source: https://github.com/sherlock-audit/2024-06-union-finance-update-2-judging/issues/23 

## Found by 
0xAadi, 0xmystery, KungFuPanda, MohammedRizwan, bareli, cryptphi, korok, trachev
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

# Issue M-2: Permit functions in `Union` contracts can be affected by DOS 

Source: https://github.com/sherlock-audit/2024-06-union-finance-update-2-judging/issues/65 

## Found by 
0xlucky, Matin, MohammedRizwan, Shawler, smbv-1923
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

# Issue M-3: Current Implementation of deposit in Assetmanager.sol fails to iletarate to fill floor in the moneymarket and instead deposits all into one moneymarket 

Source: https://github.com/sherlock-audit/2024-06-union-finance-update-2-judging/issues/98 

## Found by 
Bigsam
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

# Issue M-4: Function Rebalance can deposit above Moneymarket ceiling 

Source: https://github.com/sherlock-audit/2024-06-union-finance-update-2-judging/issues/109 

## Found by 
Bigsam
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

# Issue M-5: Minimum borrow amount can be surpassed and borrower can be treated as being overdue earlier than their actual overdue time 

Source: https://github.com/sherlock-audit/2024-06-union-finance-update-2-judging/issues/114 

## Found by 
Bigsam, hyh
## Summary

It is possible to borrow less than `_minBorrow` and preliminary be marked as overdue when `assetManager` have temporary fund access limitations.

## Vulnerability Detail

UToken's `borrow()` can be effectively run with lesser amount than `_minBorrow` when it is a liquidity shortage in the asset manager's underlying markets and they can return only some dust amount or nothing at all. In these cases `borrow()` call will still be concluded. Particularly, it is possible to run it with zero amount when `assetManager` cannot access liquidity.

In that case the borrower, if they borrow for the first time after full repay, will not have their `lastRepay` field reset on a subsequent material borrow operations as it will already be set on zero amount borrow before. As a result such borrowers can be effectively overdue for the system way before the actual overdue time passes for them.

## Impact

`_minBorrow` threshold can be violated when market conditions restrict `assetManager` withdrawals. A user can have `lastRepay` set earlier than time of obtaining the funds, which will mark them overdue before the actual overdue time comes by. This will have a material adverse impact both on such a borrower (for them `checkIsOverdue` will be true, so they won't be able to borrow or create vouches) and their lenders (for them `stakerFrozen` and `frozenCoinAge` will be increased and staking rewards diminished).

## Code Snippet

If current market conditions don't allow any material withdrawal then `borrow()` still can happen and `lastRepay` be set on any dust or even zero amount being lent out:

[UToken.sol#L611-L634](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UToken.sol#L611-L634)

```solidity
    function borrow(address to, uint256 amount) external override onlyMember(msg.sender) whenNotPaused nonReentrant {
        IAssetManager assetManagerContract = IAssetManager(assetManager);
        uint256 actualAmount = decimalScaling(amount, underlyingDecimal);
>>      if (actualAmount < _minBorrow) revert AmountLessMinBorrow();

        // Calculate the origination fee
        uint256 fee = calculatingFee(actualAmount);

        if (_borrowBalanceView(msg.sender) + actualAmount + fee > _maxBorrow) revert AmountExceedMaxBorrow();
        if (checkIsOverdue(msg.sender)) revert MemberIsOverdue();
        if (amount > assetManagerContract.getLoanableAmount(underlying)) revert InsufficientFundsLeft();
        if (!accrueInterest()) revert AccrueInterestFailed();

        uint256 borrowedAmount = borrowBalanceStoredInternal(msg.sender);

        // Initialize the last repayment date to the current block timestamp
>>      if (getLastRepay(msg.sender) == 0) {
            accountBorrows[msg.sender].lastRepay = getTimestamp();
        }

        // Withdraw the borrowed amount of tokens from the assetManager and send them to the borrower
>>      uint256 remaining = assetManagerContract.withdraw(underlying, to, amount);
>>      if (remaining > amount) revert WithdrawFailed();
>>      actualAmount -= decimalScaling(remaining, underlyingDecimal);
```

If market is such that `assetManagerContract.withdraw` can only withdraw dust or can't withdraw anything, a user can request to borrow an amount bigger than minimal, but `borrow()` will be executed with some dust or even zero amount effectively borrowed. This isn't fully covered by the `getLoanableAmount()` check since it measures total funds invested via `getSupplyView()` calls to the underlying markets.

As `_minBorrow` is for amount effectively borrowed, and not just for amount requested, it will be in a violation:

[UToken.sol#L141-L144](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UToken.sol#L141-L144)

```solidity
    /**
>>   *  @dev Min amount that can be borrowed by a single member
     */
    uint256 private _minBorrow;
```

Also, it will have a side effect of resetting `lastRepay` even with zero amount borrowed when the borrower had no debt as of time of the call. This will effectively mark a borrower as an overdue when time since they obtained any material debt is in fact much less than `overdueTime`:

[UToken.sol#L459-L465](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UToken.sol#L459-L465)

```solidity
    function checkIsOverdue(address account) public view override returns (bool isOverdue) {
        if (_getBorrowed(account) != 0) {
>>          uint256 lastRepay = getLastRepay(account);
>>          uint256 diff = getTimestamp() - lastRepay;
>>          isOverdue = overdueTime < diff;
        }
    }
```

[UToken.sol#L450-L452](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UToken.sol#L450-L452)

```solidity
    function getLastRepay(address account) public view override returns (uint256) {
        return accountBorrows[account].lastRepay;
    }
```

This can happen as subsequent `borrow()` calls will not set `lastRepay` as the logic is based on having empty `lastRepay`:

[UToken.sol#L627-L629](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UToken.sol#L627-L629)

```solidity
        if (getLastRepay(msg.sender) == 0) {
            accountBorrows[msg.sender].lastRepay = getTimestamp();
        }
```

## Tool used

Manual Review

## Recommendation

Consider controlling the effective amount being borrowed, e.g.:

[UToken.sol#L611-L634](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UToken.sol#L611-L634)

```diff
    function borrow(address to, uint256 amount) external override onlyMember(msg.sender) whenNotPaused nonReentrant {
        IAssetManager assetManagerContract = IAssetManager(assetManager);
        uint256 actualAmount = decimalScaling(amount, underlyingDecimal);
-       if (actualAmount < _minBorrow) revert AmountLessMinBorrow();

        // Calculate the origination fee
        uint256 fee = calculatingFee(actualAmount);

        if (_borrowBalanceView(msg.sender) + actualAmount + fee > _maxBorrow) revert AmountExceedMaxBorrow();
        if (checkIsOverdue(msg.sender)) revert MemberIsOverdue();
        if (amount > assetManagerContract.getLoanableAmount(underlying)) revert InsufficientFundsLeft();
        if (!accrueInterest()) revert AccrueInterestFailed();

        uint256 borrowedAmount = borrowBalanceStoredInternal(msg.sender);

        // Initialize the last repayment date to the current block timestamp
        if (getLastRepay(msg.sender) == 0) {
            accountBorrows[msg.sender].lastRepay = getTimestamp();
        }

        // Withdraw the borrowed amount of tokens from the assetManager and send them to the borrower
        uint256 remaining = assetManagerContract.withdraw(underlying, to, amount);
        if (remaining > amount) revert WithdrawFailed();
        actualAmount -= decimalScaling(remaining, underlyingDecimal);
+       if (actualAmount < _minBorrow) revert AmountLessMinBorrow();
```

# Issue M-6: any stakers who lent to borrowers can increase their rewards by a portion repayment 

Source: https://github.com/sherlock-audit/2024-06-union-finance-update-2-judging/issues/115 

## Found by 
0xJoyBoy03
### Summary

In the `_repayBorrowFresh` function, the `lastRepay` will be set to 0 if the caller executes a full repayment and set to the current timestamp if the caller repays a portion of the borrowed amount. Since everyone can repay, any staker can repay a dust amount to update the `lastRepay` to accrue their rewards more than they deserve. The `stakerCoinAges.frozenCoinAge` and `stakerFrozen` in the `_getEffectiveAmounts` function won't increase if the `currTime - lastRepay > overdueTime` is false, and when the `lastRepay` gets updated, it will be false manually.


### Root Cause

In [`UToken.sol:742`](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/market/UToken.sol#L742), the `lastRepay` gets updated every time a portion repayment is on. this will cause accruing rewards for any stakers
In [`UserManager:985`](https://github.com/sherlock-audit/2024-06-union-finance-update-2/blob/main/union-v2-contracts/contracts/user/UserManager.sol#L985-L1012) the `stakerFrozen` and `stakerCoinAges.frozenCoinAge` calculation does not increase when a portion repayment is on, leading to inaccurate reward distributions.

allowing any staker to repay any amount is a mistake as it enables manipulation of the `lastRepay` timestamp, resulting in unfair reward accrual.
when the `currTime - lastRepay > overdueTime` is true, the `stakerFrozen` and `stakerCoinAges.frozenCoinAge` get increase which leads to a decrease in the `effectiveStaked` and `effectiveLocked`. decreasing these two variables affects the reward multiplier lower which is true and correct but any stakers can increase those two variables which leads to more rewards for them

### Internal pre-conditions

1. the staker needs to trust a borrower
2. the borrower needs to borrow from the staker

### External pre-conditions

non

### Attack Path

1. Bob the borrower, borrows from Alice the staker who trusts Bob
2. Alice repays 1 wei for the loan that was given to Bob to update the `lastRepay` to the current timestamp. this will lead to more rewards for Alice and a loss of funds for the protocol

### Impact

Any staker can accrue their rewards more than they deserve

### PoC

   ```js
       function _getRewardsMultiplier(UserManagerAccountState memory user) internal pure returns (uint256) {
        if (user.isMember) {
            if (user.effectiveStaked == 0) {
                return memberRatio;
            }

            // @audit-high any staker can increase their rewards multiplier by repaying a dust amount because of lastRepay variable gets updated and leads to more `lendingRatio`
            uint256 lendingRatio = user.effectiveLocked.wadDiv(user.effectiveStaked);

            return lendingRatio + memberRatio;
        } else {
            return nonMemberRatio;
        }
    }
    
```

### Mitigation

just let the borrowers repay their loan

