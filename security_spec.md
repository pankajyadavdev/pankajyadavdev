# Security Specification for Firestore

## Data Invariants
1. **Immutable Records**: Once a transmission is created, it cannot be modified or deleted by anyone.
2. **Strict Document Creation**: Transmissions can only be created by providing exactly the required schema keys. No custom, hidden, or "ghost" fields are allowed.
3. **Temporal Integrity**: The `createdAt` timestamp must be equal to `request.time` (the Firestore server time). No client-provided timestamps are trusted.
4. **Data Size Bounds**: All fields must have strict size limitations to prevent "Denial of Wallet" resource exhaustion attacks:
   - `name`: string, 1 to 100 chars
   - `email`: string, 1 to 100 chars
   - `message`: string, 1 to 5000 chars
   - `transmissionId`: string, 1 to 32 chars
   - `timestampString`: string, 1 to 100 chars
5. **No Exposure**: Read (get, list) access is strictly forbidden for all standard users. Only designated admins (if any) or cloud server environments can view submissions.

---

## The "Dirty Dozen" Payloads
The following payloads attempt to violate security invariants and must be rejected with `PERMISSION_DENIED`.

1. **Payload 1: Shadow Update / Ghost Field Injection**
   ```json
   {
     "transmissionId": "TX-123456",
     "name": "Attacker",
     "email": "attacker@evil.com",
     "message": "Spam",
     "timestampString": "12:00 PM",
     "createdAt": "request.time",
     "isAdmin": true
   }
   ```
2. **Payload 2: Missing Required Field (`name`)**
   ```json
   {
     "transmissionId": "TX-123456",
     "email": "attacker@evil.com",
     "message": "Spam",
     "timestampString": "12:00 PM",
     "createdAt": "request.time"
   }
   ```
3. **Payload 3: Malicious Long String (Denial of Wallet)**
   ```json
   {
     "transmissionId": "TX-123456",
     "name": "A".repeat(5000),
     "email": "attacker@evil.com",
     "message": "Spam",
     "timestampString": "12:00 PM",
     "createdAt": "request.time"
   }
   ```
4. **Payload 4: Spoofed Client Timestamp**
   ```json
   {
     "transmissionId": "TX-123456",
     "name": "Attacker",
     "email": "attacker@evil.com",
     "message": "Spam",
     "timestampString": "12:00 PM",
     "createdAt": "2021-01-01T00:00:00Z"
   }
   ```
5. **Payload 5: Attempting Update of Existing Record**
   ```json
   {
     "message": "Updated Message text"
   }
   ```
6. **Payload 6: Attempting Deletion of Transmission**
   - Operation: DELETE `/transmissions/TX-123456`
7. **Payload 7: Unauthenticated Read of All Submissions**
   - Operation: LIST `/transmissions`
8. **Payload 8: Authenticated Non-Admin Read of Document**
   - Operation: GET `/transmissions/TX-123456`
9. **Payload 9: Invalid ID Pattern Poisoning**
   - Document Path: `/transmissions/INVALID_ID_#$@!`
10. **Payload 10: Value Type Poisoning (Number instead of String)**
    ```json
    {
      "transmissionId": 123456,
      "name": "Attacker",
      "email": "attacker@evil.com",
      "message": "Spam",
      "timestampString": "12:00 PM",
      "createdAt": "request.time"
    }
    ```
11. **Payload 11: Extra field in document keys**
    ```json
    {
      "transmissionId": "TX-123456",
      "name": "Attacker",
      "email": "attacker@evil.com",
      "message": "Spam",
      "timestampString": "12:00 PM",
      "createdAt": "request.time",
      "someOtherField": "extra"
    }
    ```
12. **Payload 12: Invalid Email Format**
    ```json
    {
      "transmissionId": "TX-123456",
      "name": "Attacker",
      "email": "not-an-email",
      "message": "Spam",
      "timestampString": "12:00 PM",
      "createdAt": "request.time"
    }
    ```

---

## Test Runner Mock representation
```typescript
// firestore.rules.test.ts representation (conceptual spec)
import { assertFails, assertSucceeds } from '@firebase/rules-unit-testing';

describe('Firestore Security Rules', () => {
  it('denies reads and updates to transmissions', async () => {
    // Tests for payloads 5, 6, 7, 8
  });

  it('allows creation with strict payload structure', async () => {
    // Test valid payload succeeds
  });

  it('denies creation with dirty payloads', async () => {
    // Tests for payloads 1, 2, 3, 4, 10, 11, 12
  });
});
```
