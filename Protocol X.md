**Protocol X**
**Scope:** Hybrid optimistic/pessimistic governance with dual-delegation staking vault, timelock bypass, veto mechanism, and selector allowlist.

**Prior Audits:** Audit A (Feb 2026), Audit B (May 2026)

**Finding: bypass-execute-single-role-grief**
_Source: Audit B (May 2026)_
_Original Severity: CRITICAL_
_Status: DUPLICATE of prior finding / Griefing mechanism invalid_

_Claimed mechanism:_ Attacker with only proposer role calls bypass function, writes timestamp to storage, internal execution reverts on missing executor role, timestamp persists permanently. Legitimate execution blocked.

_Prior finding:_ Audit A identified that an address holding both proposer and executor roles can call the bypass function directly, skipping governance entirely. Recommended restricting the function to the governor address. Severity: LOW.

_Why the griefing mechanism fails:_ The execution function is called via direct internal call. When an internal call reverts, the EVM unwinds all state changes in the entire transaction. The timestamp write does not durably persist.

```solidity
function bypass(address[] calldata targets, uint256[] calldata values, bytes[] calldata payloads, bytes32 salt)
    external
    onlyRole(PROPOSER_ROLE)
{
    bytes32 id = hashOperation(targets, values, payloads, salt);
    storagePointer.timestamps[id] = block.timestamp; // written BEFORE the check
    executeInternal(targets, values, payloads, salt); // internal call, reverts, state rolls back
}

function executeInternal(address[] calldata targets, uint256[] calldata values, bytes[] calldata payloads, bytes32 salt)
    external
    onlyRoleOrOpenRole(EXECUTOR_ROLE) // attacker lacks this
{
    // execution logic
}

```

```text
Trace:
  attacker (PROPOSER_ROLE only) -> bypass(params)
    -> timestamps[id] = now   // SSTOREs
    -> executeInternal(...)   // reverts (no EXECUTOR_ROLE)
    -> ALL STATE ROLLED BACK  // timestamps[id] == 0 again

  governor -> execute(proposalId) -> bypass(params)
    -> timestamps[id] == 0 check passes // was never durably written
    -> execution succeeds
```

What would make it work (not the case here):

```solidity
timestamps[id] = block.timestamp;
(bool ok,) = address(this).call(abi.encodeCall(this.executeInternal, (...)));
// ok == false, but timestamps[id] persists -> griefing works

```
Prior audit fix recommendation:

```solidity
function bypass(...) external {
    require(msg.sender == governor, "Unauthorized");
    // ... state writes and execution
}

```

**Finding: zero-supply-auto-cancel**
_Source: Audit B (May 2026)_
_Original Severity: HIGH_
_Status: INVALID_

_Claimed mechanism:_ When past supply is zero at snapshot, state function returns Canceled but the internal storage flag remains false. Creates state machine inconsistency.

```solidity
function state(uint256 proposalId) external view returns (ProposalState) {
    if (isOptimistic(proposalId)) {
        Proposal storage p = _proposals[proposalId];

        if (p.executed) return Executed;
        if (p.canceled) return Canceled; // storage flag

        uint256 snapshot = p.voteStart;
        uint256 pastSupply = token.getPastTotalSupply(snapshot);

        if (pastSupply == 0) {
            return ProposalState.Canceled; // view-only, p.canceled stays false
        }
        // ...
    }
}

```
_Why it's invalid:_ The behavior is documented in the protocol specification. The proposal cannot execute regardless of internal flag state. A redundant `cancel()` call would set the flag and emit an event, but this is purely cosmetic with no security impact. The zero-supply scenario requires all stakers to redeem, which is an extreme edge case.


**Finding: veto-threshold-floor-division**
_Source: Audit B (May 2026)_
_Original Severity: HIGH_
_Status: INVALID_

_Claimed mechanism:_ Specification says ceiling division, code uses floor division. Attacker can veto with fewer tokens than intended.

```solidity
// Spec: ceil(threshold * supply / SCALE)
// Code: floor(threshold * supply / SCALE)

uint256 thresholdTokens = (vetoThreshold * pastSupply) / 1e18;
thresholdTokens = max(thresholdTokens, 1);

```
_Why it's invalid:_ Maximum error is less than one token unit. With 18-decimal tokens and realistic supplies, the error is at most 1 wei. The max(..., 1) guard prevents zero thresholds. An attacker within 1 wei of the threshold already controls the threshold fraction of supply.

```text
threshold = 10%, supply = 1001:
  floor(0.1e18 * 1001 / 1e18) = 100
  ceil would be 101
  Difference: 1 token (0.1% of supply, 1 wei in practice)

```


**Finding: cancel-lock-reward-loss**
_Source: Audit B (May 2026)_
_Original Severity: MEDIUM_
_Status: INVALID_

_Claimed mechanism:_ User cancelling an unstaking lock loses rewards accrued during the delay window because the reward index cursor jumps forward without accruing the delta.

```solidity
function cancelLock(uint256 lockId) external {
    Lock storage lock = locks[lockId];
    delete locks[lockId];
    vault.deposit(lock.amount, lock.user);
}

function accrueUser(address user, address rewardToken) internal {
    uint256 deltaIndex = globalIndex - userIndex[user];
    uint256 delta = (balanceOf(user) * deltaIndex) / divisor;
    accruedRewards[user] += delta;
    userIndex[user] = globalIndex;
}

```
_Why it's invalid:_

```text
depositAndDelegate(1000): balance = 1000, userIndex = 50
unstake:                 shares burned, balance = 0
...                      globalIndex advances: 50 -> 150 ...
cancelLock -> deposit:   accrueUser called, balance = 0
    delta = (0 * (150 - 50)) / divisor = 0
    userIndex = 150 (synced, nothing to accrue)

```
During the unstaking window, `balanceOf(user) = 0`, so accrued delta is zero. The user earns no rewards because they hold no shares. This is share-proportional reward distribution working correctly.


**Finding: veto-denominator-mismatch**
_Source: Cross-audit analysis_
_Original Severity: N/A (new)_
_Status: INFORMATIONAL_

_Observation:_ The veto threshold uses total supply as denominator, but veto votes come from a delegate checkpoint that excludes non-delegated shares.

```solidity
// Threshold denominator: all shares
uint256 pastSupply = token.getPastTotalSupply(snapshot);
uint256 thresholdTokens = (vetoThreshold * pastSupply) / 1e18;

// Vote weight: delegated shares only
uint256 weight = isOptimistic(proposalId)
    ? token.getPastOptimisticVotes(account, snapshot)
    : token.getPastVotes(account, snapshot);

// Delegation routing: silently drops non-delegated shares
function moveDelegatedVotes(address src, address dst, uint256 amount) internal {
    if (src != address(0)) { /* subtract from src checkpoint */ }
    if (dst != address(0)) { /* add to dst checkpoint */ }
    // if dst == address(0), votes disappear
}

```
_Why it's informational:_

```text
Setup: vetoThreshold = 20%, supply = 100
  delegated:     15 tokens (can veto)
  non-delegated: 85 tokens (cannot veto)

  threshold  = 20% of 100 = 20
  maxVeto    = 15 + 0     = 15
  maxVeto < threshold -> mathematically unreachable

```
_Why the fix space is empty:_

```solidity
// Fix A: manipulable denominator
thresholdTokens = (vetoThreshold * pastOptimisticSupply) / 1e18;
// Attacker undelegates -> pastOptimisticSupply drops -> threshold collapses

// Fix B: liveness failure
require(pastOptimisticSupply >= thresholdFraction * pastTotalSupply);
// Non-delegated supply grows -> optimistic governance freezes permanently

```
The dual-delegation model intentionally separates voting streams. No fix exists that doesn't introduce a worse problem. Resolution is documentation.


**Finding: misleading-accounting-comment**
_Source: Cross-audit analysis_
_Original Severity: N/A (new)_
_Status: INFORMATIONAL_

_Observation:_ A comment in the withdrawal function declares an accounting correction as "redundant" when internal control flow makes it load-bearing.

```solidity
function _withdraw(address owner, uint256 assets, uint256 shares) internal {
    totalAssets -= assets;
    snapshot -= assets;
    // snapshot update is redundant, final value set at bottom of function // WRONG

    if (delay == 0) {
        super._withdraw(owner, assets, shares);
    } else {
        _burn(owner, shares);
        // _burn triggers _update -> accrueRewards -> snapshot = balanceOf(this)
        // balanceOf(this) is still PRE-TRANSFER at this point
        manager.createLock(receiver, assets, unlockTime);
        // tokens leave contract HERE
        emit Withdraw(owner, receiver, owner, assets, shares);
    }

    snapshot = token.balanceOf(address(this)); // NOT redundant, corrects burn overwrite
}

```
_Execution trace for delayed withdrawal:_

```text
1. snapshot -= assets               // correctly decreased
2. _burn(owner, shares)             // triggers accrual chain
3.   -> snapshot = balanceOf(this)  // overwrites step 1 with pre-transfer value
4. createLock(...)                  // safeTransferFrom -> tokens leave
5. snapshot = balanceOf(this)       // corrects step 3 to post-transfer value

```
If line 5 were removed based on the comment, snapshot would remain at the pre-transfer balance while `totalAssets` correctly reflects the post-transfer amount. The drift is self-correcting (next accrual resets snapshot to actual balance), making it low impact. The comment is the issue, not the code.
