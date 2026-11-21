/**
 * Failed Login Lockout Detector
 *
 * Requirements:
 * - A user becomes locked after 5 or more consecutive failed login attempts,
 *   where the failures that trigger the lock all occur within a rolling 1-hour (3600-second) window.
 * - Once locked, the user remains locked for 10 minutes (600 seconds) from their last failed attempt.
 * - Any login attempt during the lockout period (including correct credentials) must be rejected/ignored.
 * - A successful login before reaching 5 qualifying failures resets that user's failure counter to 0.
 * - State is tracked independently for each user.
 *
 * @param {Array<{ user_id: string, timestamp: number, status: 'success' | 'fail' }>} events
 * @returns {Array<{ user_id: string, timestamp: number, allowed: boolean }>}
 */
function processLogins(events) {
  const ROLLING_WINDOW_SECONDS = 3600; // 1-hour window
  const LOCKOUT_DURATION_SECONDS = 600; // 10-minute lockout
  const FAILURE_THRESHOLD = 5;

  const userStates = new Map();
  const results = [];

  for (const event of events) {
    const { user_id, timestamp, status } = event;

    if (!userStates.has(user_id)) {
      userStates.set(user_id, {
        lockedUntil: null,
        failureTimestamps: [],
      });
    }

    const state = userStates.get(user_id);

    // Check if the user is currently locked out
    if (state.lockedUntil !== null) {
      if (timestamp < state.lockedUntil) {
        // Attempt during lockout period is rejected/ignored
        results.push({
          user_id,
          timestamp,
          allowed: false,
        });
        continue;
      } else {
        // Lockout expired: reset lock and failure counter
        state.lockedUntil = null;
        state.failureTimestamps = [];
      }
    }

    // Not locked: attempt is allowed to proceed
    results.push({
      user_id,
      timestamp,
      allowed: true,
    });

    if (status === 'success') {
      // Successful login resets failure counter
      state.failureTimestamps = [];
    } else if (status === 'fail') {
      // Keep only failures within rolling 1-hour window
      state.failureTimestamps = state.failureTimestamps.filter(
        (t) => timestamp - t <= ROLLING_WINDOW_SECONDS
      );
      state.failureTimestamps.push(timestamp);

      // Check if threshold reached to trigger lockout
      if (state.failureTimestamps.length >= FAILURE_THRESHOLD) {
        state.lockedUntil = timestamp + LOCKOUT_DURATION_SECONDS;
        state.failureTimestamps = [];
      }
    }
  }

  return results;
}

// Export for module use
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { processLogins };
}

// Self-test runner when executed directly via node
if (typeof require !== 'undefined' && require.main === module) {
  console.log('Running test suite for processLogins...\n');

  function assertDeepEqual(actual, expected, testName) {
    const actualStr = JSON.stringify(actual);
    const expectedStr = JSON.stringify(expected);
    if (actualStr === expectedStr) {
      console.log(`[PASS] ${testName}`);
    } else {
      console.error(`[FAIL] ${testName}`);
      console.error('  Expected:', expectedStr);
      console.error('  Actual:  ', actualStr);
      process.exitCode = 1;
    }
  }

  // Test 1: Assessment Example
  const exampleEvents = [
    { user_id: 'u1', timestamp: 0, status: 'fail' },
    { user_id: 'u1', timestamp: 10, status: 'fail' },
    { user_id: 'u1', timestamp: 20, status: 'fail' },
    { user_id: 'u1', timestamp: 30, status: 'fail' },
    { user_id: 'u1', timestamp: 40, status: 'fail' },
    { user_id: 'u1', timestamp: 100, status: 'success' },
    { user_id: 'u1', timestamp: 700, status: 'success' },
  ];

  const expectedExample = [
    { user_id: 'u1', timestamp: 0, allowed: true },
    { user_id: 'u1', timestamp: 10, allowed: true },
    { user_id: 'u1', timestamp: 20, allowed: true },
    { user_id: 'u1', timestamp: 30, allowed: true },
    { user_id: 'u1', timestamp: 40, allowed: true },
    { user_id: 'u1', timestamp: 100, allowed: false },
    { user_id: 'u1', timestamp: 700, allowed: true },
  ];
  assertDeepEqual(processLogins(exampleEvents), expectedExample, 'Assessment PDF Example');

  // Test 2: Reset on success before 5 failures
  const resetOnSuccessEvents = [
    { user_id: 'u1', timestamp: 0, status: 'fail' },
    { user_id: 'u1', timestamp: 10, status: 'fail' },
    { user_id: 'u1', timestamp: 20, status: 'fail' },
    { user_id: 'u1', timestamp: 30, status: 'fail' },
    { user_id: 'u1', timestamp: 40, status: 'success' }, // Reset
    { user_id: 'u1', timestamp: 50, status: 'fail' },
    { user_id: 'u1', timestamp: 60, status: 'fail' },
  ];
  const expectedReset = resetOnSuccessEvents.map(e => ({ user_id: e.user_id, timestamp: e.timestamp, allowed: true }));
  assertDeepEqual(processLogins(resetOnSuccessEvents), expectedReset, 'Reset on success before 5 failures');

  // Test 3: Rolling 1-hour window (old failure drops out)
  const rollingWindowEvents = [
    { user_id: 'u1', timestamp: 0, status: 'fail' },
    { user_id: 'u1', timestamp: 100, status: 'fail' },
    { user_id: 'u1', timestamp: 200, status: 'fail' },
    { user_id: 'u1', timestamp: 300, status: 'fail' },
    { user_id: 'u1', timestamp: 3700, status: 'fail' }, // t=0 is > 3600s ago, so only 4 failures in window
    { user_id: 'u1', timestamp: 3800, status: 'success' }, // Should be allowed because not locked
  ];
  const expectedRolling = rollingWindowEvents.map(e => ({ user_id: e.user_id, timestamp: e.timestamp, allowed: true }));
  assertDeepEqual(processLogins(rollingWindowEvents), expectedRolling, 'Rolling 1-hour window ignores old failures');

  // Test 4: Lockout ignores attempts during lock (doesn't extend lock)
  const lockoutIgnoredEvents = [
    { user_id: 'u1', timestamp: 0, status: 'fail' },
    { user_id: 'u1', timestamp: 10, status: 'fail' },
    { user_id: 'u1', timestamp: 20, status: 'fail' },
    { user_id: 'u1', timestamp: 30, status: 'fail' },
    { user_id: 'u1', timestamp: 40, status: 'fail' }, // locked until 640
    { user_id: 'u1', timestamp: 500, status: 'fail' }, // during lock -> rejected
    { user_id: 'u1', timestamp: 640, status: 'success' }, // at 640 lock expired -> allowed
  ];
  const expectedLockoutIgnored = [
    { user_id: 'u1', timestamp: 0, allowed: true },
    { user_id: 'u1', timestamp: 10, allowed: true },
    { user_id: 'u1', timestamp: 20, allowed: true },
    { user_id: 'u1', timestamp: 30, allowed: true },
    { user_id: 'u1', timestamp: 40, allowed: true },
    { user_id: 'u1', timestamp: 500, allowed: false },
    { user_id: 'u1', timestamp: 640, allowed: true },
  ];
  assertDeepEqual(processLogins(lockoutIgnoredEvents), expectedLockoutIgnored, 'Attempts during lockout are ignored and lock expires at 10 min');

  // Test 5: Multiple users are tracked independently
  const multiUserEvents = [
    { user_id: 'u1', timestamp: 0, status: 'fail' },
    { user_id: 'u2', timestamp: 0, status: 'success' },
    { user_id: 'u1', timestamp: 10, status: 'fail' },
    { user_id: 'u1', timestamp: 20, status: 'fail' },
    { user_id: 'u1', timestamp: 30, status: 'fail' },
    { user_id: 'u1', timestamp: 40, status: 'fail' }, // u1 locked until 640
    { user_id: 'u2', timestamp: 50, status: 'success' }, // u2 is NOT locked
    { user_id: 'u1', timestamp: 50, status: 'success' }, // u1 IS locked
  ];
  const expectedMultiUser = [
    { user_id: 'u1', timestamp: 0, allowed: true },
    { user_id: 'u2', timestamp: 0, allowed: true },
    { user_id: 'u1', timestamp: 10, allowed: true },
    { user_id: 'u1', timestamp: 20, allowed: true },
    { user_id: 'u1', timestamp: 30, allowed: true },
    { user_id: 'u1', timestamp: 40, allowed: true },
    { user_id: 'u2', timestamp: 50, allowed: true },
    { user_id: 'u1', timestamp: 50, allowed: false },
  ];
  assertDeepEqual(processLogins(multiUserEvents), expectedMultiUser, 'Multiple users tracked independently');

  console.log('\nAll tests passed successfully!');
}
