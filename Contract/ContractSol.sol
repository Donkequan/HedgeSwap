// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract HedgedEthHTLC {
    // roles
    address public immutable initiator;   // this-chain principal owner
    address public immutable participant; // can redeem by revealing secret; premium payer

    // amounts (ETH)
    uint256 public immutable principalAmount;
    uint256 public immutable premiumRequired;

    // hashlock
    bytes32 public immutable hashlock; // keccak256(secret)

    // deadlines (unix timestamps)
    uint256 public immutable premiumDeadline;   // latest time participant can deposit premium
    uint256 public immutable principalDeadline; // latest time initiator can deposit principal (requires premium already deposited)
    uint256 public immutable redeemDeadline;    // latest time participant can redeem

    // state
    bool public premiumDeposited;
    bool public principalDeposited;
    bool public redeemed;
    bool public refunded;
    bool public aborted;

    bytes32 public revealedSecret; // set on redeem for the other chain to read

    error NotInitiator();
    error NotParticipant();
    error BadValue();
    error TooLate();
    error TooEarly();
    error PremiumNotDeposited();
    error PremiumAlreadyDeposited();
    error PrincipalAlreadyDeposited();
    error PrincipalNotDeposited();
    error Finalized();
    error HashMismatch();
    error Aborted();

    event PremiumDeposited(address indexed from, uint256 amount);
    event PrincipalDeposited(address indexed from, uint256 amount);
    event Redeemed(address indexed by, bytes32 secret);
    event Refunded(address indexed by);
    event PremiumRefundedNoPrincipal(address indexed by, uint256 amount);

    constructor(
        address _initiator,
        address _participant,
        uint256 _principalAmount,
        uint256 _premiumRequired,
        bytes32 _hashlock,
        uint256 _premiumDeadline,
        uint256 _principalDeadline,
        uint256 _redeemDeadline
    ) {
        require(_initiator != address(0) && _participant != address(0), "BAD_ADDR");
        require(_principalAmount > 0, "BAD_PRINCIPAL");
        require(_premiumDeadline <= _principalDeadline && _principalDeadline <= _redeemDeadline, "BAD_DEADLINES");

        initiator = _initiator;
        participant = _participant;

        principalAmount = _principalAmount;
        premiumRequired = _premiumRequired;

        hashlock = _hashlock;

        premiumDeadline = _premiumDeadline;
        principalDeadline = _principalDeadline;
        redeemDeadline = _redeemDeadline;
    }

    modifier onlyInitiator() {
        if (msg.sender != initiator) revert NotInitiator();
        _;
    }

    modifier onlyParticipant() {
        if (msg.sender != participant) revert NotParticipant();
        _;
    }

    modifier notFinalized() {
        if (redeemed || refunded) revert Finalized();
        if (aborted) revert Aborted();
        _;
    }

    receive() external payable { revert("NO_DIRECT_PAY"); }

    // 1) participant deposits premium (ETH)
    function depositPremium() external payable onlyParticipant notFinalized {
        if (premiumDeposited) revert PremiumAlreadyDeposited();
        if (block.timestamp > premiumDeadline) revert TooLate();
        if (msg.value != premiumRequired) revert BadValue();

        premiumDeposited = true;
        emit PremiumDeposited(msg.sender, msg.value);
    }

    // 2) initiator escrows principal (ETH), only after premium is in
    function depositPrincipal() external payable onlyInitiator notFinalized {
        if (!premiumDeposited) revert PremiumNotDeposited();
        if (principalDeposited) revert PrincipalAlreadyDeposited();
        if (block.timestamp > principalDeadline) revert TooLate();
        if (msg.value != principalAmount) revert BadValue();

        principalDeposited = true;
        emit PrincipalDeposited(msg.sender, msg.value);
    }

    // abort: if initiator never escrowed principal by principalDeadline, participant can get premium back
    function refundPremiumIfNoPrincipal() external onlyParticipant notFinalized {
        if (!premiumDeposited) revert PremiumNotDeposited();
        if (principalDeposited) revert PrincipalAlreadyDeposited();
        if (block.timestamp <= principalDeadline) revert TooEarly();

        aborted = true;
        premiumDeposited = false;

        _pay(participant, premiumRequired);
        emit PremiumRefundedNoPrincipal(msg.sender, premiumRequired);
    }

    // 3) redeem with secret -> principal to participant, premium refunded to participant
    function redeem(bytes32 secret) external onlyParticipant notFinalized {
        if (!principalDeposited) revert PrincipalNotDeposited();
        if (block.timestamp > redeemDeadline) revert TooLate();
        if (keccak256(abi.encodePacked(secret)) != hashlock) revert HashMismatch();

        redeemed = true;
        revealedSecret = secret;

        _pay(participant, principalAmount);

        if (premiumRequired != 0 && premiumDeposited) {
            premiumDeposited = false;
            _pay(participant, premiumRequired);
        }

        emit Redeemed(msg.sender, secret);
    }

    // 4) timeout refund -> principal back to initiator, premium paid to initiator (compensation)
    function refund() external onlyInitiator notFinalized {
        if (!principalDeposited) revert PrincipalNotDeposited();
        if (block.timestamp <= redeemDeadline) revert TooEarly();

        refunded = true;

        _pay(initiator, principalAmount);

        if (premiumRequired != 0 && premiumDeposited) {
            premiumDeposited = false;
            _pay(initiator, premiumRequired);
        }

        emit Refunded(msg.sender);
    }

    function _pay(address to, uint256 amount) internal {
        (bool ok, ) = to.call{value: amount}("");
        require(ok, "PAY_FAIL");
    }
}
