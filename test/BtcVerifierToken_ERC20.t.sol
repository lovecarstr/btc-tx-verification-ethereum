// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {BtcVerifierToken} from "../src/BtcVerifierToken.sol";

/// @notice Test-only harness to access internal mint for ERC-20 tests (Task 3).
contract BtcVerifierTokenHarness is BtcVerifierToken {
    constructor(
        bytes32 checkpointHash,
        uint256 checkpointHeight,
        string memory name_,
        string memory symbol_,
        bytes20 targetPKH_
    ) BtcVerifierToken(checkpointHash, checkpointHeight, name_, symbol_, targetPKH_) {}

    function mintForTest(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract BtcVerifierTokenERC20Test is Test {
    BtcVerifierTokenHarness token;

    address alice;
    address bob;
    address carl;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function setUp() public {
        alice = makeAddr("alice");
        bob = makeAddr("bob");
        carl = makeAddr("carl");

        // ERC-20 tests don't depend on real Bitcoin headers.
        token =
            new BtcVerifierTokenHarness(bytes32(uint256(1)), 12345, "BTC Verifier Token", "BVT", bytes20(uint160(1)));
    }

    function test_metadata_and_initial_supply() public view {
        assertEq(token.totalSupply(), 0, "initial supply must be 0");
        assertEq(token.balanceOf(alice), 0, "initial balance must be 0");
        assertEq(token.name(), "BTC Verifier Token");
        assertEq(token.symbol(), "BVT");

        uint8 d = token.decimals();
        assertTrue(d == 8 || d == 18, "unexpected decimals");
    }

    function test_mintForTest_increases_supply_and_balance_and_emits() public {
        vm.expectEmit(true, true, false, true);
        emit Transfer(address(0), alice, 100);

        token.mintForTest(alice, 100);

        assertEq(token.totalSupply(), 100);
        assertEq(token.balanceOf(alice), 100);
    }

    function test_mintForTest_to_zero_reverts() public {
        vm.expectRevert("mint to zero");
        token.mintForTest(address(0), 1);
    }

    function test_transfer_reverts_on_insufficient_balance() public {
        vm.prank(alice);
        vm.expectRevert("insufficient balance");
        token.transfer(bob, 1);
    }

    function test_transfer_reverts_on_to_zero_address() public {
        token.mintForTest(alice, 10);

        vm.prank(alice);
        vm.expectRevert("transfer to zero");
        token.transfer(address(0), 1);
    }

    function test_transfer_success_updates_balances_and_emits() public {
        token.mintForTest(alice, 10);

        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit Transfer(alice, bob, 4);

        bool ok = token.transfer(bob, 4);
        assertTrue(ok);

        assertEq(token.balanceOf(alice), 6);
        assertEq(token.balanceOf(bob), 4);
        assertEq(token.totalSupply(), 10);
    }

    function test_approve_sets_allowance_and_emits() public {
        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit Approval(alice, bob, 7);

        bool ok = token.approve(bob, 7);
        assertTrue(ok);

        assertEq(token.allowance(alice, bob), 7);
    }

    function test_approve_to_zero_reverts_if_enforced() public {
        vm.prank(alice);
        vm.expectRevert("approve to zero");
        token.approve(address(0), 1);
    }

    function test_transferFrom_reverts_on_insufficient_allowance() public {
        token.mintForTest(alice, 10);

        vm.prank(bob);
        vm.expectRevert("insufficient allowance");
        token.transferFrom(alice, carl, 1);
    }

    function test_transferFrom_reverts_on_insufficient_balance() public {
        vm.prank(alice);
        token.approve(bob, 5);

        vm.prank(bob);
        vm.expectRevert("insufficient balance");
        token.transferFrom(alice, carl, 1);
    }

    function test_transferFrom_success_moves_balance_and_decreases_allowance() public {
        token.mintForTest(alice, 10);

        vm.prank(alice);
        token.approve(bob, 6);

        vm.prank(bob);
        vm.expectEmit(true, true, false, true);
        emit Transfer(alice, carl, 4);

        bool ok = token.transferFrom(alice, carl, 4);
        assertTrue(ok);

        assertEq(token.balanceOf(alice), 6);
        assertEq(token.balanceOf(carl), 4);
        assertEq(token.allowance(alice, bob), 2);
        assertEq(token.totalSupply(), 10);
    }

    function test_transferFrom_infinite_allowance_optional_behavior() public {
        token.mintForTest(alice, 10);

        vm.prank(alice);
        token.approve(bob, type(uint256).max);

        vm.prank(bob);
        token.transferFrom(alice, carl, 3);

        assertEq(token.allowance(alice, bob), type(uint256).max);
    }

    function test_burn_reverts_if_insufficient_balance() public {
        vm.prank(alice);
        vm.expectRevert("insufficient balance");
        token.burn(1);
    }

    function test_burn_success_decreases_balance_and_supply_and_emits() public {
        token.mintForTest(alice, 10);

        vm.prank(alice);
        vm.expectEmit(true, true, false, true);
        emit Transfer(alice, address(0), 4);

        bool ok = token.burn(4);
        assertTrue(ok);

        assertEq(token.balanceOf(alice), 6);
        assertEq(token.totalSupply(), 6);
    }

    function test_burnFrom_optional() public {
        token.mintForTest(alice, 10);

        vm.prank(alice);
        token.approve(bob, 5);

        vm.prank(bob);
        (bool ok,) = address(token).call(abi.encodeWithSignature("burnFrom(address,uint256)", alice, 4));

        if (!ok) {
            return;
        }

        assertEq(token.balanceOf(alice), 6);
        assertEq(token.totalSupply(), 6);
        assertEq(token.allowance(alice, bob), 1);
    }
}
