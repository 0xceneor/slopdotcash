// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

interface IERC20 {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
    function decimals() external view returns (uint8);
}

/// @dev Bounds on the binding delay. Below one hour the owner cannot react; above 30 days a binding or a
/// committed award waits too long to be useful.
uint64 constant MIN_BINDING_DELAY = 1 hours;
uint64 constant MAX_BINDING_DELAY = 30 days;

/// @dev A monthly allocation for calendar UTC month M can be committed from MONTHLY_CUTOFF_DELAY after M ends
/// until MONTHLY_CUTOFF_DELAY after the next month ends (owner decision D1: 00:00 UTC on the 4th).
uint64 constant MONTHLY_CUTOFF_DELAY = 72 hours;

/// @notice What a vault holds funds for. One owner can hold one vault per project, token and purpose, so
/// ordinary awards and private bounties never share a balance (owner decision D13).
enum Purpose {
    Ordinary,
    Bounty
}

/// @notice Version 5, immutable single-project, single-asset, single-purpose escrow for any standard ERC-20.
/// @dev A binding needs the identity authority's transaction and the destination wallet's EIP-712 signature,
/// so the authority alone cannot point funds at a wallet it does not hold; it cannot change amounts. The
/// authority is read from the factory, which replaces it only through a public 7-day timelock. A new binding waits
/// bindingDelay before it can pay, and an award waits bindingDelay after it is committed, so a stolen
/// authority key cannot pay itself before the sponsor can react, even with a binding placed in advance.
/// Only the latest binding pays: while a newer binding waits out its delay or after the owner cancels it,
/// no payment goes to any earlier wallet, so a rotation away from a compromised wallet freezes payment
/// instead of racing it. The owner can cancel the latest binding only inside those windows, never after it
/// has paid, and at most MAX_CANCELS_BETWEEN_PAYMENTS times between two payments to the actor, so the owner
/// can delay a payout by a bounded number of delays but never retract it. That cap does not apply while the
/// factory has a pending authority rotation, which only the registrar can open: during the public notice of
/// a stolen key the owner cancels every attacker binding, however many cancels it had spent before, and those
/// cancels do not count. Fees accrue in the vault and are pulled separately, so a blocked fee recipient cannot
/// stop payouts or refunds.
/// Anyone may deposit; deposits join one free balance that only the owner commits or refunds to itself. An
/// ordinary vault also accepts one monthly allocation per calendar month from anyone, when the owner has
/// turned it on, the identity authority signed it, and its total is within the owner's monthly cap.
/// The payout fee and the unused-fund withdrawal fee are both 2% (floor(gross / 50)), so awarding
/// free funds to oneself costs the same as withdrawing them (#907); each fee rounds down once per award or
/// withdrawal. Tokens must have exact transfers: a fee-on-transfer deposit or payout reverts. Decimals are stored for display only; amounts are
/// token base units. No upgrade or reserve rescue exists.
contract ProjectEscrow {
    struct Award {
        uint64 actorId;
        uint128 gross;
        uint128 fee;
        bytes32 sourceDigest;
        uint64 committedAt;
        bool paid;
    }

    /// @notice One award of a monthly allocation, in the order the allocation root was built.
    struct MonthlyAward {
        uint64 actorId;
        uint128 gross;
        bytes32 sourceDigest;
    }

    /// @dev The latest authority binding for an actor. It is pending until activatesAt and is the only
    /// binding that can pay.
    struct Binding {
        address destination;
        uint64 version;
        bytes32 claimDigest;
        uint64 activatesAt;
        bool cancelled;
    }

    /// @notice Cancels the owner may make for an actor between two payments to that actor. Each cancel can
    /// only delay the actor by one more bindingDelay, so this bounds the owner's delay power. The cap is
    /// waived, and the count untouched, while the factory has a pending authority rotation, so an earlier
    /// cancel never shortens the cover the owner can give during a key compromise.
    uint8 public constant MAX_CANCELS_BETWEEN_PAYMENTS = 3;

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 private constant BINDING_TYPEHASH = keccak256(
        "DestinationBinding(uint64 actorId,address destination,uint64 expectedVersion,bytes32 claimDigest,uint64 expiresAt)"
    );
    bytes32 private constant MONTHLY_TYPEHASH = keccak256("MonthlyAllocation(uint32 period,bytes32 allocationRoot)");
    /// @dev Upper bound on s for a canonical secp256k1 signature (EIP-2).
    bytes32 private constant MAX_S = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    IERC20 public immutable token;
    /// @notice The token's decimals at vault creation, for display only. The vault never scales amounts.
    uint8 public immutable decimals;
    bytes32 public immutable projectId;
    address public immutable owner;
    Purpose public immutable purpose;
    address public immutable feeRecipient;
    /// @notice The factory that created this vault and holds the identity authority in force.
    EscrowFactory public immutable factory;
    uint64 public immutable bindingDelay;
    uint128 public freeBalance;
    uint128 public reservedPrincipal;
    uint128 public reservedFees;
    uint128 public totalDeposited;
    uint128 public totalPaid;
    uint128 public totalPayoutFees;
    uint128 public totalGrossWithdrawn;
    uint128 public totalWithdrawalFees;
    uint128 public accruedFees;
    /// @notice The most a monthly allocation may commit in gross, and whether anyone may submit one. Only
    /// the owner sets them; the owner turns monthly commitments off at any time.
    uint128 public monthlyCap;
    bool public monthlyEnabled;
    mapping(bytes32 => Award) public awards;
    mapping(bytes32 => bool) public consumedSources;
    mapping(uint64 => Binding) public bindings;
    /// @notice The binding version the last payment to an actor used; 0 before the first payment.
    mapping(uint64 => uint64) public paidVersion;
    mapping(uint64 => uint64) public lastCommittedAt;
    /// @notice Cancels recorded for an actor since the actor's last payment.
    mapping(uint64 => uint8) public cancelCount;
    /// @notice The allocation root committed for a period (YYYYMM); zero before its one commitment.
    mapping(uint32 => bytes32) public monthlyRoots;
    bool private entered;

    error Unauthorized();
    error InvalidInput();
    error InsufficientFreeBalance();
    error DuplicateAward();
    error InvalidBinding();
    error TransferFailed();
    error ReentrantCall();
    error WrongPurpose();
    error MonthlyDisabled();
    error MonthlyWindowClosed();
    error MonthlyAlreadyCommitted();
    error MonthlyCapExceeded();
    error InvalidAttestation();
    error AwardPending();
    error CancelLimit();
    error InvalidWalletSignature();

    event Deposited(address indexed depositor, uint128 amount);
    event AwardCommitted(bytes32 indexed id, uint64 indexed actorId, uint128 gross, uint128 fee, bytes32 sourceDigest);
    event DestinationBound(
        uint64 indexed actorId, address indexed destination, uint64 version, bytes32 claimDigest, uint64 activatesAt
    );
    event BindingCancelled(uint64 indexed actorId, uint64 version);
    event FeesClaimed(address indexed feeRecipient, uint128 amount);
    event Paid(
        bytes32 indexed id,
        uint64 indexed actorId,
        address indexed destination,
        uint64 version,
        uint128 gross,
        uint128 net,
        uint128 fee
    );
    event UnusedWithdrawn(address indexed destination, uint128 gross, uint128 net, uint128 fee);
    event MonthlyCommitmentSet(uint128 cap, bool enabled);
    event MonthlyCommitted(uint32 indexed period, bytes32 allocationRoot, uint128 gross, uint256 awards);

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }
    modifier nonReentrant() {
        if (entered) revert ReentrantCall();
        entered = true;
        _;
        entered = false;
    }

    /// @dev Only the factory creates vaults: the deployer is the factory, and reading its authority here
    /// reverts for any other deployer.
    constructor(
        bytes32 projectId_,
        IERC20 token_,
        address owner_,
        Purpose purpose_,
        address feeRecipient_,
        uint64 bindingDelay_
    ) {
        EscrowFactory factory_ = EscrowFactory(msg.sender);
        address identityAuthority_ = factory_.identityAuthority();
        // Free funds are refunded only to the owner, whoever deposited them.
        if (
            projectId_ == bytes32(0) || address(token_).code.length == 0 || owner_ == address(0)
                || owner_ == address(this) || feeRecipient_ == address(0) || identityAuthority_ == address(0)
                || owner_ == identityAuthority_ || feeRecipient_ == address(this) || bindingDelay_ < MIN_BINDING_DELAY
                || bindingDelay_ > MAX_BINDING_DELAY
        ) revert InvalidInput();
        projectId = projectId_;
        token = token_;
        decimals = readDecimals(token_);
        owner = owner_;
        purpose = purpose_;
        feeRecipient = feeRecipient_;
        factory = factory_;
        bindingDelay = bindingDelay_;
    }

    /// @notice The identity authority in force, held and rotated by the factory.
    function identityAuthority() public view returns (address) {
        return factory.identityAuthority();
    }

    /// @notice EIP-712 domain: the chain and this vault, so a wallet signature cannot be replayed elsewhere.
    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(DOMAIN_TYPEHASH, keccak256("SlopProjectEscrow"), keccak256("5"), block.chainid, address(this))
        );
    }

    /// @notice The digest the destination wallet signs to accept a binding. Every field must match the
    /// authority's call exactly.
    function bindingDigest(
        uint64 actorId,
        address destination,
        uint64 expectedVersion,
        bytes32 claimDigest,
        uint64 expiresAt
    ) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator(),
                keccak256(abi.encode(BINDING_TYPEHASH, actorId, destination, expectedVersion, claimDigest, expiresAt))
            )
        );
    }

    /// @notice The digest the identity authority signs to attest one month's allocation for this vault. The
    /// domain binds the chain and this vault.
    function monthlyDigest(uint32 period, bytes32 allocationRoot_) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01", domainSeparator(), keccak256(abi.encode(MONTHLY_TYPEHASH, period, allocationRoot_))
            )
        );
    }

    /// @notice The allocation root: a Merkle tree over the awards in order. A leaf is
    /// keccak256(0x00, actorId, gross, sourceDigest) and a node is keccak256(0x01, left, right), packed; an odd
    /// last node moves up unchanged. The 0x00 and 0x01 prefixes keep a node from passing as a leaf.
    function allocationRoot(MonthlyAward[] calldata entries) public pure returns (bytes32) {
        uint256 count = entries.length;
        if (count == 0) revert InvalidInput();
        bytes32[] memory level = new bytes32[](count);
        for (uint256 i; i < count; ++i) {
            level[i] =
                keccak256(abi.encodePacked(uint8(0), entries[i].actorId, entries[i].gross, entries[i].sourceDigest));
        }
        while (count > 1) {
            uint256 next = (count + 1) / 2;
            for (uint256 i; i < next; ++i) {
                uint256 left = 2 * i;
                level[i] = left + 1 < count
                    ? keccak256(abi.encodePacked(uint8(1), level[left], level[left + 1]))
                    : level[left];
            }
            count = next;
        }
        return level[0];
    }

    /// @notice When a period's allocation may be committed: from MONTHLY_CUTOFF_DELAY after the month ends
    /// until MONTHLY_CUTOFF_DELAY after the next month ends. The period is YYYYMM in UTC, year 2000 to 9999.
    /// Only one period is open at a time, so a stolen authority key can commit at most one cap per month.
    function monthlyWindow(uint32 period) public pure returns (uint64 opensAt, uint64 closesAt) {
        uint256 year = period / 100;
        uint256 month = period % 100;
        if (year < 2000 || year > 9999 || month == 0 || month > 12) revert InvalidInput();
        (uint256 nextYear, uint256 nextMonth) = month == 12 ? (year + 1, uint256(1)) : (year, month + 1);
        (uint256 afterYear, uint256 afterMonth) =
            nextMonth == 12 ? (nextYear + 1, uint256(1)) : (nextYear, nextMonth + 1);
        opensAt = uint64(monthStart(nextYear, nextMonth)) + MONTHLY_CUTOFF_DELAY;
        closesAt = uint64(monthStart(afterYear, afterMonth)) + MONTHLY_CUTOFF_DELAY;
    }

    /// @dev Unix time of 00:00 UTC on the first day of a month (proleptic Gregorian, days from civil).
    function monthStart(uint256 year, uint256 month) private pure returns (uint256) {
        uint256 y = month <= 2 ? year - 1 : year;
        uint256 era = y / 400;
        uint256 yearOfEra = y - era * 400;
        uint256 dayOfYear = (153 * (month > 2 ? month - 3 : month + 9) + 2) / 5;
        uint256 dayOfEra = yearOfEra * 365 + yearOfEra / 4 - yearOfEra / 100 + dayOfYear;
        return (era * 146097 + dayOfEra - 719468) * 1 days;
    }

    /// @dev Externally owned accounts only: a 65-byte canonical secp256k1 signature that recovers to the
    /// expected signer. A contract wallet cannot produce one, so it cannot be bound or attest in this version.
    function signedBy(bytes32 digest, address expected, bytes calldata signature) private pure returns (bool) {
        if (signature.length != 65) return false;
        bytes32 r = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);
        uint8 v = uint8(signature[64]);
        if (s > MAX_S || (v != 27 && v != 28)) return false;
        address signer = ecrecover(digest, v, r, s);
        return signer != address(0) && signer == expected;
    }

    /// @notice The only valid award ID for a source. Binding the chain and vault stops another vault from
    /// claiming the same ID first.
    function awardId(bytes32 sourceDigest) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), sourceDigest));
    }

    /// @notice The 2% fee deducted from a gross award, rounded down once per award.
    function payoutFee(uint128 gross) public pure returns (uint128) {
        return gross / 50;
    }

    /// @notice The fee on one unused-fund withdrawal: the same 2% as payoutFee, rounded down once per withdrawal
    /// (PRD section 18, #907).
    function withdrawalFee(uint128 gross) public pure returns (uint128) {
        return payoutFee(gross);
    }

    /// @notice Every counter in one call, so a reader gets one consistent block. Equal to the public getters.
    function totals()
        external
        view
        returns (
            uint128 deposited,
            uint128 paid,
            uint128 payoutFees,
            uint128 grossWithdrawn,
            uint128 withdrawalFees,
            uint128 free,
            uint128 principalReserved,
            uint128 feesReserved,
            uint128 feesAccrued,
            uint256 balance
        )
    {
        return (
            totalDeposited,
            totalPaid,
            totalPayoutFees,
            totalGrossWithdrawn,
            totalWithdrawalFees,
            freeBalance,
            reservedPrincipal,
            reservedFees,
            accruedFees,
            token.balanceOf(address(this))
        );
    }

    /// @notice Anyone may deposit. The amount joins the free balance, which only the owner can commit to awards
    /// or refund to itself; a depositor gets no refund right. Direct transfers are not credited.
    function deposit(uint128 amount) external nonReentrant {
        if (amount == 0) revert InvalidInput();
        uint256 beforeBalance = token.balanceOf(address(this));
        callToken(abi.encodeCall(IERC20.transferFrom, (msg.sender, address(this), amount)));
        if (token.balanceOf(address(this)) != beforeBalance + amount) revert TransferFailed();
        freeBalance += amount;
        totalDeposited += amount;
        emit Deposited(msg.sender, amount);
    }

    /// @param sourceDigest Unique per award origin (project/cycle/actor/allocation), not a whole-cycle digest.
    function commitAward(bytes32 id, uint64 actorId, uint128 gross, bytes32 sourceDigest) external onlyOwner {
        if (purpose != Purpose.Ordinary) revert WrongPurpose();
        commit(id, actorId, gross, sourceDigest, payoutFee(gross));
    }

    /// @notice Owner-approved private bounty: exactly 75% to the researcher and 25% to Slop. Only a bounty
    /// vault takes it. The source must be a random opaque commitment, never a digest of a private report.
    function commitBountyAward(bytes32 id, uint64 actorId, uint128 gross, bytes32 sourceDigest) external onlyOwner {
        if (purpose != Purpose.Bounty) revert WrongPurpose();
        if (gross % 4 != 0) revert InvalidInput();
        commit(id, actorId, gross, sourceDigest, gross / 4);
    }

    /// @notice The owner sets the monthly cap and turns monthly commitments on or off. While they are off,
    /// nobody can commit a monthly allocation; awards already committed stay committed.
    function setMonthlyCommitment(uint128 cap, bool enabled) external onlyOwner {
        if (purpose != Purpose.Ordinary) revert WrongPurpose();
        if (enabled && cap == 0) revert InvalidInput();
        monthlyCap = cap;
        monthlyEnabled = enabled;
        emit MonthlyCommitmentSet(cap, enabled);
    }

    /// @notice Anyone may commit one period's allocation inside its window, once per period, while the owner
    /// has monthly commitments on. The identity authority must have signed monthlyDigest(period, root) for
    /// exactly these awards, and their gross total must be within monthlyCap and the free balance. Each award
    /// takes the ordinary payout fee and pays through the ordinary binding and delay rules.
    function commitMonthly(uint32 period, MonthlyAward[] calldata entries, bytes calldata attestation) external {
        if (purpose != Purpose.Ordinary) revert WrongPurpose();
        if (!monthlyEnabled) revert MonthlyDisabled();
        (uint64 opensAt, uint64 closesAt) = monthlyWindow(period);
        if (block.timestamp < opensAt || block.timestamp >= closesAt) revert MonthlyWindowClosed();
        if (monthlyRoots[period] != bytes32(0)) revert MonthlyAlreadyCommitted();
        bytes32 root = allocationRoot(entries);
        if (!signedBy(monthlyDigest(period, root), factory.identityAuthority(), attestation)) {
            revert InvalidAttestation();
        }
        uint256 total;
        for (uint256 i; i < entries.length; ++i) {
            total += entries[i].gross;
        }
        if (total > monthlyCap) revert MonthlyCapExceeded();
        monthlyRoots[period] = root;
        for (uint256 i; i < entries.length; ++i) {
            MonthlyAward calldata entry = entries[i];
            commit(awardId(entry.sourceDigest), entry.actorId, entry.gross, entry.sourceDigest, payoutFee(entry.gross));
        }
        emit MonthlyCommitted(period, root, uint128(total), entries.length);
    }

    function commit(bytes32 id, uint64 actorId, uint128 gross, bytes32 sourceDigest, uint128 fee) private {
        if (actorId == 0 || gross == 0 || sourceDigest == bytes32(0) || id != awardId(sourceDigest)) {
            revert InvalidInput();
        }
        if (awards[id].actorId != 0 || consumedSources[sourceDigest]) revert DuplicateAward();
        if (gross > freeBalance) revert InsufficientFreeBalance();
        freeBalance -= gross;
        reservedPrincipal += gross - fee;
        reservedFees += fee;
        uint64 committedAt = uint64(block.timestamp);
        awards[id] = Award(actorId, gross, fee, sourceDigest, committedAt, false);
        lastCommittedAt[actorId] = committedAt;
        consumedSources[sourceDigest] = true;
        emit AwardCommitted(id, actorId, gross, fee, sourceDigest);
    }

    /// @notice Direct authority transaction plus the destination wallet's EIP-712 signature over the same
    /// fields; chain ID and target contract bind both. The service must verify the GitHub actor before
    /// signing; the wallet signature proves the destination accepts the binding. Expiry limits submission
    /// of both signatures, not claim lifetime. expectedVersion prevents stale or reordered wallet updates.
    function bindDestination(
        uint64 actorId,
        address destination,
        uint64 expectedVersion,
        bytes32 claimDigest,
        uint64 expiresAt,
        bytes calldata walletSignature
    ) external {
        if (msg.sender != factory.identityAuthority()) revert Unauthorized();
        if (
            actorId == 0 || destination == address(0) || destination == address(this) || claimDigest == bytes32(0)
                || expiresAt < block.timestamp || bindings[actorId].version != expectedVersion
        ) revert InvalidBinding();
        if (!signedBy(
                bindingDigest(actorId, destination, expectedVersion, claimDigest, expiresAt),
                destination,
                walletSignature
            )) {
            revert InvalidWalletSignature();
        }
        uint64 version = expectedVersion + 1;
        uint64 activatesAt = uint64(block.timestamp) + bindingDelay;
        bindings[actorId] = Binding(destination, version, claimDigest, activatesAt, false);
        emit DestinationBound(actorId, destination, version, claimDigest, activatesAt);
    }

    /// @notice The sponsor can stop the latest binding before it pays: while it waits out its own delay, or
    /// while an award committed to the actor is still inside its commit delay. A binding that has paid
    /// cannot be cancelled, and the owner can cancel at most MAX_CANCELS_BETWEEN_PAYMENTS times between two
    /// payments to the actor, except while the factory has a pending authority rotation: then every cancel
    /// is allowed and none is counted, because the registrar alone opens that window and the owner needs
    /// an unbounded number of cancels to outlast a stolen key's notice period. Only a new authority binding
    /// can follow a cancel; no payment goes out until it is ready.
    function cancelBinding(uint64 actorId, uint64 expectedVersion) external onlyOwner {
        Binding storage binding = bindings[actorId];
        if (
            binding.version == 0 || binding.version != expectedVersion || binding.cancelled
                || binding.version == paidVersion[actorId]
        ) revert InvalidBinding();
        uint64 committedAt = lastCommittedAt[actorId];
        bool pending = block.timestamp < binding.activatesAt;
        bool commitWindow = committedAt != 0 && block.timestamp < committedAt + bindingDelay;
        if (!pending && !commitWindow) revert InvalidBinding();
        if (factory.pendingIdentityAuthority() == address(0)) {
            if (cancelCount[actorId] >= MAX_CANCELS_BETWEEN_PAYMENTS) revert CancelLimit();
            cancelCount[actorId] += 1;
        }
        binding.cancelled = true;
        emit BindingCancelled(actorId, expectedVersion);
    }

    /// @notice The binding a payment to this actor would use now: the latest binding once its delay has
    /// passed and it is not cancelled. Version 0 means no binding can pay; an earlier binding never pays.
    function payableBinding(uint64 actorId) public view returns (address destination, uint64 version) {
        Binding storage binding = bindings[actorId];
        if (binding.version != 0 && !binding.cancelled && block.timestamp >= binding.activatesAt) {
            return (binding.destination, binding.version);
        }
        return (address(0), 0);
    }

    /// @notice Pays an award to its actor's payable binding once both the binding delay and the award's
    /// commit delay have passed. Anyone can call it, because the destination is fixed by the contract.
    function pay(bytes32 id, uint64 expectedBindingVersion) external nonReentrant {
        Award storage award = awards[id];
        if (award.actorId == 0 || award.paid) revert InvalidInput();
        if (block.timestamp < award.committedAt + bindingDelay) revert AwardPending();
        (address destination, uint64 version) = payableBinding(award.actorId);
        if (version == 0 || version != expectedBindingVersion) revert InvalidBinding();
        paidVersion[award.actorId] = version;
        cancelCount[award.actorId] = 0;
        uint128 net = award.gross - award.fee;
        award.paid = true;
        reservedPrincipal -= net;
        reservedFees -= award.fee;
        totalPaid += net;
        totalPayoutFees += award.fee;
        accruedFees += award.fee;
        sendExact(destination, net);
        emit Paid(id, award.actorId, destination, version, award.gross, net, award.fee);
    }

    /// @notice Refunds free funds to the owner less withdrawalFee(gross), 2% rounded down. A
    /// withdrawal under 50 base units pays no fee; splitting saves under one base unit per transaction.
    function withdrawUnused(uint128 gross) external onlyOwner nonReentrant {
        if (gross == 0) revert InvalidInput();
        if (gross > freeBalance) revert InsufficientFreeBalance();
        uint128 fee = withdrawalFee(gross);
        freeBalance -= gross;
        totalGrossWithdrawn += gross;
        totalWithdrawalFees += fee;
        accruedFees += fee;
        sendExact(owner, gross - fee);
        emit UnusedWithdrawn(owner, gross, gross - fee, fee);
    }

    /// @notice Anyone can move accrued fees to the fee recipient. Only this call depends on that address.
    function claimFees() external nonReentrant {
        uint128 amount = accruedFees;
        if (amount == 0) revert InvalidInput();
        accruedFees = 0;
        sendExact(feeRecipient, amount);
        emit FeesClaimed(feeRecipient, amount);
    }

    function sendExact(address destination, uint256 amount) private {
        if (amount == 0) return;
        uint256 beforeVault = token.balanceOf(address(this));
        uint256 beforeRecipient = token.balanceOf(destination);
        callToken(abi.encodeCall(IERC20.transfer, (destination, amount)));
        if (
            token.balanceOf(address(this)) != beforeVault - amount
                || token.balanceOf(destination) != beforeRecipient + amount
        ) revert TransferFailed();
    }

    /// @dev decimals() is optional in ERC-20 but every supported asset has it; a token without it is rejected.
    function readDecimals(IERC20 token_) private view returns (uint8) {
        (bool ok, bytes memory result) = address(token_).staticcall(abi.encodeCall(IERC20.decimals, ()));
        if (!ok || result.length != 32) revert InvalidInput();
        uint256 value = abi.decode(result, (uint256));
        if (value > type(uint8).max) revert InvalidInput();
        return uint8(value);
    }

    function callToken(bytes memory data) private {
        (bool ok, bytes memory result) = address(token).call(data);
        if (!ok || (result.length != 0 && (result.length != 32 || !abi.decode(result, (bool))))) {
            revert TransferFailed();
        }
    }
}

/// @notice Anyone creates a vault for itself: the caller is the owner, and there is one vault per (owner,
/// project ID, token, purpose) in this deployment. The token is a per-vault parameter, so one factory serves
/// every standard ERC-20 on its chain. A vault proves only who created it; the project registry decides
/// which owner's vault a project uses.
/// The registrar is not a money authority and creates no vaults. It holds the only mutable authority: the
/// identity authority every vault reads, replaced through a public 7-day timelock that the registrar
/// proposes and may cancel, and that the current authority cannot block.
/// The registrar, fee recipient and identity authority are explicit constructor parameters.
contract EscrowFactory {
    uint64 public constant AUTHORITY_ROTATION_DELAY = 7 days;
    address public immutable registrar;
    address public immutable feeRecipient;
    uint64 public immutable bindingDelay;
    address public identityAuthority;
    address public pendingIdentityAuthority;
    uint64 public identityAuthorityEffectiveAt;
    /// @notice The vault for vaultKey(owner, projectId, token, purpose), or zero.
    mapping(bytes32 => address) public vaults;

    error RotationPending();
    error NoRotationPending();
    error RotationNotReady();
    error DuplicateVault();

    event VaultCreated(
        bytes32 indexed projectId,
        address indexed token,
        address indexed vault,
        address owner,
        Purpose purpose,
        uint8 decimals
    );
    event IdentityAuthorityRotationProposed(address indexed current, address indexed proposed, uint64 effectiveAt);
    event IdentityAuthorityRotationCancelled(address indexed proposed);
    event IdentityAuthorityRotated(address indexed previous, address indexed current);

    modifier onlyRegistrar() {
        if (msg.sender != registrar) revert ProjectEscrow.Unauthorized();
        _;
    }

    constructor(address registrar_, address feeRecipient_, address identityAuthority_, uint64 bindingDelay_) {
        if (
            registrar_ == address(0) || feeRecipient_ == address(0) || identityAuthority_ == address(0)
                || identityAuthority_ == registrar_ || bindingDelay_ < MIN_BINDING_DELAY
                || bindingDelay_ > MAX_BINDING_DELAY
        ) revert ProjectEscrow.InvalidInput();
        registrar = registrar_;
        feeRecipient = feeRecipient_;
        identityAuthority = identityAuthority_;
        bindingDelay = bindingDelay_;
    }

    /// @notice The mapping key and CREATE2 salt of an owner's vault for a project, token and purpose.
    function vaultKey(address owner, bytes32 projectId, IERC20 token, Purpose purpose) public pure returns (bytes32) {
        return keccak256(abi.encode(owner, projectId, token, purpose));
    }

    /// @notice Permissionless: creates the caller's own vault for a project, token and purpose.
    function create(bytes32 projectId, IERC20 token, Purpose purpose) external returns (address vault) {
        bytes32 key = vaultKey(msg.sender, projectId, token, purpose);
        if (vaults[key] != address(0)) revert DuplicateVault();
        ProjectEscrow created =
            new ProjectEscrow{salt: key}(projectId, token, msg.sender, purpose, feeRecipient, bindingDelay);
        vault = address(created);
        vaults[key] = vault;
        emit VaultCreated(projectId, address(token), vault, msg.sender, purpose, created.decimals());
    }

    /// @notice Starts the public notice period for a replacement identity authority. One proposal at a time.
    function proposeIdentityAuthority(address next) external onlyRegistrar {
        if (next == address(0) || next == identityAuthority || next == registrar) revert ProjectEscrow.InvalidInput();
        if (pendingIdentityAuthority != address(0)) revert RotationPending();
        uint64 effectiveAt = uint64(block.timestamp) + AUTHORITY_ROTATION_DELAY;
        pendingIdentityAuthority = next;
        identityAuthorityEffectiveAt = effectiveAt;
        emit IdentityAuthorityRotationProposed(identityAuthority, next, effectiveAt);
    }

    /// @notice The registrar withdraws its own pending proposal; nobody else can.
    function cancelIdentityAuthorityRotation() external onlyRegistrar {
        address proposed = pendingIdentityAuthority;
        if (proposed == address(0)) revert NoRotationPending();
        delete pendingIdentityAuthority;
        delete identityAuthorityEffectiveAt;
        emit IdentityAuthorityRotationCancelled(proposed);
    }

    /// @notice Anyone may execute a proposal once its notice period has passed. Bindings never reference
    /// the authority, so every existing binding stays valid; only who may bind next changes.
    function executeIdentityAuthorityRotation() external {
        address next = pendingIdentityAuthority;
        if (next == address(0)) revert NoRotationPending();
        if (block.timestamp < identityAuthorityEffectiveAt) revert RotationNotReady();
        address previous = identityAuthority;
        identityAuthority = next;
        delete pendingIdentityAuthority;
        delete identityAuthorityEffectiveAt;
        emit IdentityAuthorityRotated(previous, next);
    }
}
