// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {BtcVerifierToken} from "../src/BtcVerifierToken.sol";

contract OracleFlowTest is Test {
    BtcVerifierToken token;

    address ORACLE = address(this);
    address ALICE = address(0xA11CE);
    address BOB = address(0xB0B);

    bytes32 CHECKPOINT = bytes32(uint256(1));
    uint256 HEIGHT = 123;

    function setUp() public {
        bytes20 targetPKH = bytes20(uint160(0xAAAA));
        token = new BtcVerifierToken(
            CHECKPOINT,
            HEIGHT,
            "BVT",
            "BVT",
            targetPKH
        );
    }

    function test_oracle_is_deployer() public {
        assertEq(token.oracle(), ORACLE);
    }

    function test_onlyOracle_can_setOracle() public {
        vm.prank(ALICE);
        vm.expectRevert("not oracle");
        token.setOracle(BOB);

        token.setOracle(BOB);
        assertEq(token.oracle(), BOB);
    }

    function test_oldOracle_loses_rights_after_rotation() public {
        token.setOracle(BOB);

        // old oracle can no longer call setOracle
        vm.expectRevert("not oracle");
        token.setOracle(ALICE);

        // new oracle CAN
        vm.prank(BOB);
        token.setOracle(ALICE);
        assertEq(token.oracle(), ALICE);
    }
}
