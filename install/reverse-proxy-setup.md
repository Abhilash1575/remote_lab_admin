# Admin PC as the only externally-visible node — reverse proxy setup

This makes the Admin PC the single point of contact from outside the campus
network. Every Lab Pi stays on the private network and is only ever reached
*through* the Admin PC, never directly. This is what shrinks a VAPT (security
audit) from "100+ separate targets" down to "one gateway + one shared Lab Pi
image."

Two things need to happen together — neither one alone is enough:

1. **Firewall each Lab Pi** so it only accepts connections from the Admin
   PC's IP, not from the rest of the campus network.
2. **Put a reverse proxy on the Admin PC** (Caddy) that terminates HTTPS and
   forwards requests to the right Lab Pi over the private network.

## Prerequisites (need to be confirmed before this can actually be deployed)

- A domain name you control (e.g. `yourcollege.edu`), so each Lab Pi can get
  its own subdomain like `pi047.lab.yourcollege.edu`. Without a domain, the
  fallback is IP-based access with a self-signed certificate (browsers show a
  warning) — workable for a closed pilot, not for a real institutional rollout.
- Ability to add a **wildcard DNS record**: `*.lab.yourcollege.edu` pointing
  at the Admin PC's public IP.
- The Admin PC needs a public IP (or the institution's router needs to port-
  forward 443 to it) — nothing else should be port-forwarded.

## 1. Firewall rule on every Lab Pi

Only accept port 10000 (the Lab Pi's Flask/SocketIO port) from the Admin PC's
private IP. Replace `<ADMIN_PC_PRIVATE_IP>` with the real one.

```bash
sudo ufw allow from <ADMIN_PC_PRIVATE_IP> to any port 10000 proto tcp
sudo ufw deny 10000/tcp
sudo ufw enable
```

Worth folding this into `install-lab-pi.sh` once the Admin PC's IP is fixed,
so every new Pi gets it automatically instead of it being a manual step.

## 2. Caddy on the Admin PC

Caddy over nginx here specifically because it gets HTTPS certificates
automatically (no manual certbot/Let's Encrypt steps), and it correctly
proxies WebSockets by default — this project's camera/oscilloscope/serial
views all rely on Flask-SocketIO (WebSockets), which a naive HTTP-only proxy
config silently breaks.

```
# /etc/caddy/Caddyfile — one block per Lab Pi, plus the Admin Pi itself.
# This is illustrative; in practice generate this file from the LabPi table
# (models.py) instead of hand-writing 100+ blocks — see note below.

admin.lab.yourcollege.edu {
    reverse_proxy localhost:5000
}

pi047.lab.yourcollege.edu {
    reverse_proxy 10.0.5.47:10000
}

pi048.lab.yourcollege.edu {
    reverse_proxy 10.0.5.48:10000
}
# ... one block per registered Lab Pi
```

Caddy auto-issues and renews the HTTPS certificate for every hostname listed
the first time it starts, as long as the wildcard DNS record above resolves
to this machine.

### Generating the Caddyfile instead of hand-writing it

Since Lab Pis are already registered in the `LabPi` table (`ip_address`,
`lab_pi_id` columns — see `models.py`), a short script reading that table and
writing `Caddyfile` blocks (then `sudo systemctl reload caddy`) is the
practical way to keep 100+ entries in sync as Pis are added — worth writing
once the domain is confirmed, so it's not attempted against made-up values.

## What this does *not* yet cover

- Students' browsers currently talk to a Lab Pi's own IP:port directly for
  the live experiment page. Once this is in place, those links need to point
  at `https://pi047.lab.yourcollege.edu` instead — a small change in how the
  Admin Pi builds the URL it hands students when a session starts, not a
  Lab Pi code change.
- The Admin Pi's own booking/login pages move behind `admin.lab.yourcollege.edu`
  the same way.
