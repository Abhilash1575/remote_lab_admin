# Testing the Master-side migration (before blocking pages on the Lab Pi)

This checks the work described in `lab-pi/MASTER_UI_MIGRATION_PLAN.md`: every page a
student sees should now come from the Master, with the Master relaying to whichever
Lab Pi is running that session. Go through this on real hardware before firewalling
the Lab Pi to Master-only — nothing here can be fully verified without it.

## 0. Before anything else — check for the known mismatch trap

`MASTER_API_KEY` must be the **exact same value** in the Master's `.env` and in
*every* Lab Pi's `.env`. If it's unset on either side, things fail open with a loud
warning in the console (not silently). If it's set but doesn't match, requests get
rejected with 401 and nothing works — and the error can look like "Lab Pi
unreachable" rather than "wrong key," which is confusing to debug blind. Check both
files line up before testing anything else.

## 1. Install the new dependencies

On the **Master**:
```bash
cd remote_lab_admin
source venv/bin/activate   # or however you activate your venv
pip install -r requirements.txt
```

Two things new in `requirements.txt` need attention:
- `python-socketio[client]` — pure Python, should install cleanly.
- `aiortc` + `av` (for the new audio relay) — `av` compiles against FFmpeg. If this
  fails to build, the Master needs the same system packages `lab-pi`'s install script
  already installs for the same libraries:
  ```bash
  sudo apt-get install -y libavformat-dev libavcodec-dev libavdevice-dev \
      libavutil-dev libavfilter-dev libswscale-dev libswresample-dev ffmpeg
  ```
  `remote_lab_admin/install/setup_admin_pi.sh` doesn't install these yet — worth
  adding there once this is confirmed working, so a fresh Master install doesn't hit
  this the hard way.

## 2. Start the Master and check it comes up clean

```bash
python app.py
```

Watch the startup output for import errors (most likely from aiortc/av if step 1 had
issues) — if it starts and reaches "Server ready", the new modules (`lab_pi_relay.py`,
`audio_relay.py`) loaded fine.

## 3. Confirm one Lab Pi is actually online

In the Master's admin panel (`/admin/lab-pi` or wherever your fleet list lives),
confirm at least one Lab Pi shows **ONLINE** with a recent heartbeat, and that it's
assigned to an experiment you can book. If none are online, nothing below will work —
that's a Lab Pi registration/heartbeat problem, not something this migration touches.

## 4. Single-session walkthrough (do this first, before touching a second Lab Pi)

Book that test experiment as a student and start the session, then work through:

| Check | What to look for |
|---|---|
| **URL never changes to the Lab Pi** | Watch the browser's address bar the whole time. It should stay on the Master's host (`http://master-host:5000/...`) — if it ever jumps to the Lab Pi's own IP, that's the exact thing this migration was supposed to fix, and something regressed. |
| **Serial connect** | Pick a port, connect — should see `serial_status: connected` and live `feedback` lines appear in the log panel. |
| **Send a command** | Type a command / drag a slider — confirm the board actually reacts (or the feedback log shows it was sent). |
| **Live chart** | Sensor readings should be plotting in real time on the chart card. |
| **Flash firmware** | Upload a real firmware file, watch the progress log — should show the same avrdude/esptool output the Lab Pi produces, streamed live. |
| **Factory reset** | Same, with the default firmware path. |
| **Relay / power toggle** | Click the power button, confirm the physical relay actually clicks / the board powers on. |
| **Camera** | Open the camera tab — live video should appear (this is the new MJPEG proxy). |
| **Oscilloscope** | Open the oscilloscope tab (new "CRO" button next to the chart) — waveform should render if your test board is the scope-capable one. |
| **Audio** | Click "Start Audio" — you should hear the Lab Pi's mic. This is the newest and least-proven piece (real two-hop WebRTC relay) — if it fails, check the Master's console for `[AudioRelay]` lines first. |
| **End the session normally** | Let the booking end (or end it early if your admin panel supports that) — then check the Master's console shows it notifying the Lab Pi and tearing down the relay (see §6 below for what that looks like). |

If all of that works end to end on one Lab Pi, the core relay logic is sound.

## 5. Multi-experiment test — the one that actually matters for production

This is the test for "does the Master correctly keep two students' experiments
separate." You need **two Lab Pis** online, each assigned to a different experiment
(or the same experiment twice, doesn't matter, as long as they're two distinct Lab
Pi devices).

1. Log in as **User A** in one browser (or a private/incognito window), book
   Experiment 1 (→ Lab Pi #1), and start the session.
2. Log in as **User B** in a different browser (or a second private window), book
   Experiment 2 (→ Lab Pi #2), and start that session too — so both are active on the
   Master at the same time.
3. In User A's tab: send a serial command, toggle the relay, watch the chart.
4. In User B's tab, at the same time: confirm **none** of User A's activity shows up
   — different feedback log, different chart data, relay state independent of A's.
5. Toggle User B's relay — confirm Lab Pi #1's hardware (User A's board) does **not**
   react. This is the concrete check that routing is per-session, not shared/global
   state left over from the old single-device code.
6. End User A's session while User B's is still running — confirm User B's session
   keeps working uninterrupted (their relay connection shouldn't get torn down just
   because a different session ended).

If that all holds, the "which Lab Pi does this action go to" routing — the thing you
originally flagged as the open question — is working correctly.

## 6. What to watch in the Master's console while testing

The relay code prints as it works, so keep an eye on the terminal running `app.py`:
- `[EXPERIMENT] Found Lab Pi: ...` — confirms session-start resolved the right device.
- `[LabPiRelay] Could not connect to Lab Pi at ... ` — relay couldn't reach that
  session's Lab Pi (network/firewall/Lab Pi down).
- `[AudioRelay] ...` — anything here means the WebRTC relay hit a problem; the message
  usually says which leg (Lab Pi side vs. browser side).
- `[Session] Could not notify Lab Pi ... that session ... ended` — session-end
  webhook to the Lab Pi failed (Lab Pi unreachable at cleanup time — relay still gets
  torn down locally either way).

## 7. Don't flip the Lab Pi firewall switch until this all passes

Until you've run through §4 and §5 successfully on real hardware, leave the Lab Pi's
own pages reachable as a fallback (per the phased rollout in
`MASTER_UI_MIGRATION_PLAN.md`) — that's the safety net if something above doesn't
work and you need students back on the old path immediately while you fix it.
