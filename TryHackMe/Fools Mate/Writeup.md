# Fools Mate - TryHackMe Writeup

**Category:** Web Application Security / API Security  
**Platform:** TryHackMe  
**Vulnerability:** Client-Side Validation Bypass  
**Flag:** `THM{cl13nt_s1d3_ch3ckm4t3}`  

---

## Connected Investigations
- **Web Application Vulnerabilities:** Compare with [CyberDefenders: XXE Infiltration Lab](<../../CyberDefenders/XXE Infiltration Lab/Writeup.md>), which explores server-side XML injection leading to web shell deployment.
- **Client-Side Control Bypasses:** Classic example of trusting the client where critical game logic / validation exists only in frontend JavaScript.

---

## Overview

**Fools Mate** presents an interactive web-based chess endgame trainer. When the user attempts to execute the winning checkmate move (`Ra1` to `Ra8#`), a client-side JavaScript popup blocks the action with a humorous intimidation message: `"/usr/lib32: I'll shut down your PC if you play that."`

By inspecting the network activity and client-side source code (`app.js`), we observe that the restriction is enforced entirely in browser JavaScript before sending the move. The underlying backend API (`/api/move`) accepts move coordinates directly via HTTP POST requests without backend restriction. By sending the winning move directly to the API endpoint using `curl`, we bypass the client-side blocker, trigger server-side checkmate validation, and capture the flag.

---

## Walkthrough

### 1. Identifying the Client-Side Restriction

Navigating to the web interface in the browser with Developer Tools open (`Inspect Element > Network` with *Disable Cache* and *Persist Logs* enabled), the board presents a rook endgame where White can deliver back-rank checkmate by moving the Rook from `a1` to `a8`.

Attempting the move triggers an alert modal:

![Client-side restriction popup](images/Pasted%20image%2020260821234045.png)

Crucially, the Network tab shows that **no HTTP request was sent** to the server when the move was blocked. This confirms that the restriction is purely client-side logic in the browser.

---

### 2. Inspecting Client Architecture & `app.js`

Reviewing the application structure reveals a classic four-tier frontend design:

![Application architecture diagram](images/Pasted%20image%2020260821235222.png)

- **UI Layer:** DOM elements, mouse dragging, click handlers.
- **Game Controller:** `doMove()`, `select()`, `reset()`.
- **Frontend Validator (`chess.js`):** Validates board state and triggers UI warnings.
- **Backend API (`/api/move`):** Evaluates moves and tracks computer AI turns.

Searching through `app.js` for the `/api/move` endpoint reveals the `sendMove()` function:

![app.js sendMove definition](images/Pasted%20image%2020260822001040.png)

```javascript
async function sendMove(from, to, promotion) {
  locked = true;
  let data;
  try {
    const res = await fetch('/api/move', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ from, to, promotion: promotion || undefined })
    });
    data = await res.json();
  } catch (e) {
    locked = false;
    renderFull();
    return;
  }
...
```

The frontend sends a JSON payload with `from` and `to` coordinates (e.g. `{"from": "a1", "to": "a8"}`) to `/api/move`.

---

### 3. Bypassing the Filter via Direct API Request

Because the backend server does not enforce the checkmate prohibition, we can bypass the frontend restriction completely by submitting the POST request directly via `curl`:

```bash
curl -X POST http://10.64.140.159/api/move \
  -H "Content-Type: application/json" \
  -d '{"from":"a1","to":"a8"}'
```

![Executing curl request to /api/move](images/Pasted%20image%2020260822011419.png)

**Server Response:**
```json
{
  "ok": true,
  "move": "a1a8",
  "fen": "R5k1/5ppp/8/8/8/5PPP/6K1 b - - 1 1",
  "status": "checkmate",
  "turn": "b",
  "winner": "white",
  "flag": "THM{cl13nt_s1d3_ch3ckm4t3}"
}
```

The backend processes the winning move, evaluates the board position as checkmate, sets `winner: "white"`, and returns the flag.

---

## Key Takeaways

- **Security Principle:** Never rely on client-side JavaScript for business logic enforcement, validation, or access control.
- **Vulnerability:** The API endpoint `/api/move` assumed all submitted moves complied with application constraints without re-validating the rules server-side.
