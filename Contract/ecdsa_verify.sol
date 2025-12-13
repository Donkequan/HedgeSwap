// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract TwoSigETHVaultUltraMin {
    address public immutable signer1;
    address public immutable signer2;

    constructor(address a, address b) payable {
        require(a != address(0) && b != address(0) && a != b);
        signer1 = a;
        signer2 = b;
    }

    receive() external payable {}

    function payAll(
        address payable to,
        uint256 deadline,
        uint8 v1,
        bytes32 r1,
        bytes32 s1,
        uint8 v2,
        bytes32 r2,
        bytes32 s2
    ) external {
        require(block.timestamp <= deadline);

        bytes32 inner = keccak256(abi.encodePacked(block.chainid, address(this), to, deadline));
        bytes32 d = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", inner));

        if (v1 < 27) v1 += 27;
        if (v2 < 27) v2 += 27;

        address a = ecrecover(d, v1, r1, s1);
        address b = ecrecover(d, v2, r2, s2);

        require((a == signer1 && b == signer2) || (a == signer2 && b == signer1));

        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok);
    }
}
