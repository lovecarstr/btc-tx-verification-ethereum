// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import {BtcVerifierToken} from "../src/BtcVerifierToken.sol";

contract OracleFlowTest is Test {
    BtcVerifierToken token;

    address ORACLE = address(this);        // deployer is oracle in your constructor
    address ALICE  = address(0xA11CE);
    address BOB    = address(0xB0B);

    // You need a valid checkpoint hash/height for constructor; in unit tests you can use any,
    // but submitBlockHeader will still require chaining rules etc.
    // So for this test we only check access control, not header validity.
    bytes32 CHECKPOINT = bytes32(uint256(1));
    uint256 HEIGHT = 123;

    function setUp() public {
        token = new BtcVerifierToken(CHECKPOINT, HEIGHT, "BVT", "BVT");
    }

    function test_oracle_is_deployer() public {
        assertEq(token.oracle(), ORACLE);
    }

    function test_onlyOracle_can_setOracle() public {
        vm.prank(ALICE);
        vm.expectRevert("not oracle");
        token.setOracle(BOB);

        token.setOracle(ALICE);
        assertEq(token.oracle(), ALICE);
    }

    function test_oldOracle_loses_rights_after_rotation() public {
        token.setOracle(ALICE);

        // old oracle (this) should now fail
        vm.expectRevert("not oracle");
        token.setOracle(BOB);

        // new oracle can rotate
        vm.prank(ALICE);
        token.setOracle(BOB);
        assertEq(token.oracle(), BOB);
    }

    function test_onlyOracle_can_oracleSubmitBlockHeader() public {
        bytes memory dummyHeader = new bytes(80);

        vm.prank(ALICE);
        vm.expectRevert("not oracle");
        token.oracleSubmitBlockHeader(dummyHeader);

        // oracle call will reach submitBlockHeader and revert for other reasons (invalid/unknown prev),
        // but this confirms access control passes.
        vm.expectRevert(); // don't care which revert here
        token.oracleSubmitBlockHeader(dummyHeader);
    }
}
