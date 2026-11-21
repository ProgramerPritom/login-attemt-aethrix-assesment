# login-attemt-aethrix-assesment

Failed Login Lockout Detector implementation in JavaScript (Node.js).

---

## Overview

The `processLogins(events)` function processes a stream of login events in chronological order and determines whether each login attempt should be allowed based on lockout rules.

### Input Event Shape
```javascript
{ user_id: string, timestamp: number, status: "success" | "fail" }
```

### Return Value Shape
```javascript
{ user_id: string, timestamp: number, allowed: boolean }
```

---

## Lockout Rules

1. **Lockout Trigger**: A user becomes locked after **5 or more consecutive failed login attempts**, where all 5 qualifying failures occur within a **rolling 1-hour (3600-second) window**.
2. **Lockout Duration**: Once locked, the user remains locked for **10 minutes (600 seconds)** from the last qualifying failed attempt (`lockedUntil = timestamp + 600`).
3. **Behavior During Lockout**: Any login attempt during the lockout period (including correct credentials or further failed attempts) is rejected (`allowed: false`) and ignored (does not extend or alter the lockout timer).
4. **Reset on Success**: A successful login before reaching 5 qualifying failures resets that user's failure counter to 0.
5. **Lock Expiry**: Once the lockout duration has passed (`timestamp >= lockedUntil`), the user is no longer locked, and the failure counter resets.
6. **Independent State**: State is tracked independently for each user.

---

## Assumptions

- **Chronological Order**: Events are provided in chronological order by `timestamp`.
- **Timestamp Unit**: Timestamps are numeric values measured in seconds.
- **Lock Expiration Boundary**: An attempt arriving exactly at `timestamp = lockedUntil` occurs when the full 10-minute duration has completed, so the lockout is considered expired and the attempt is allowed to proceed.
- **No Side Effects During Lockout**: Attempts occurring while locked do not modify the failure count or extend the lockout period.

---

## Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/ProgramerPritom/login-attemt-aethrix-assesment.git
cd login-attemt-aethrix-assesment
```

### 2. Run Tests
The built-in test suite verifies all scenarios (example from assessment, reset-on-success, rolling 1-hour window, attempts during lockout, and multiple users):
```bash
npm test
```
or
```bash
node login-attemt.js
```
