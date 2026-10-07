# Collecting Real Attacker Traffic

The corpus in `sample_logs/` is synthetic. It is adversarially designed, but I wrote
both the attacks and the detections, which is a closed loop. Running against real
attacker traffic is what makes the metrics mean something — and it is the single
change that most improves this project.

## Safety first

A honeypot is a machine you are deliberately letting strangers attack. Treat it as
hostile from the moment it is online.

- **Isolate it.** A separate cloud account or a VLAN with no route to anything you
  care about. Never your home network, never a machine with your SSH keys.
- **Use medium-interaction emulation.** Cowrie emulates a shell; it does not give
  attackers a real one. Do not run a real vulnerable system.
- **Move real SSH off 22 first,** and confirm you can still get in before exposing
  anything.
- **Check your provider's terms.** Most clouds permit research honeypots; some
  require notification. Check before, not after.
- **Set billing alerts.** Compromised instances get used for mining, and the bill
  arrives before the notification.
- **Tear it down when finished.** A honeypot you stopped watching is just an
  attacked machine.

## Setup

```bash
# On an isolated VPS, move real SSH to 2022 first and verify access
sudo sed -i 's/^#\?Port 22/Port 2022/' /etc/ssh/sshd_config
sudo systemctl restart sshd      # reconnect on 2022 BEFORE continuing

# Run Cowrie on 22 via the compose profile
docker compose --profile honeypot up -d cowrie
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
```

Within hours — often minutes — botnets will find it. A week typically yields tens of
thousands of login attempts from hundreds of sources.

## Analysing the capture

```bash
python -m siem.cli analyze \
  --cowrie sample_logs/cowrie-live/cowrie.json \
  --html out/honeypot-dashboard.html
```

What to pull out and put in your README:

- Total attempts, unique source IPs, geographic distribution
- The top 20 credential pairs attempted — compare them against your own passwords
- Post-compromise command sequences: what attackers run in the first 60 seconds
- Payload URLs and file hashes, which are submittable to VirusTotal and AbuseIPDB
- Timing distribution: automation is obvious in the inter-arrival times

## What to claim honestly

Good: *"Validated against 47,000 real SSH authentication events captured over 7
days, from 1,284 unique sources across 61 countries. The ruleset produced 94 alerts
at 11 alerts/day sustained."*

Not: *"100% detection rate against real attacks."* Without labelled ground truth you
cannot compute recall on live traffic — you do not know what you missed. Report
alert volume, source counts and what you found; be explicit that recall is measured
only against the labelled corpus.

That distinction is exactly the kind of thing an interviewer notices.

## Alternatives without a VPS

- **Atomic Red Team** — run controlled, labelled attack techniques on a local VM and
  collect the telemetry. Gives real logs with known ground truth, which is the best
  of both worlds for metrics.
- **Public datasets** — Secrepo, the Boss of the SOC dataset, and published honeypot
  captures. Note the licence and attribute the source.
- **Your own server's logs** — any internet-facing box already has real brute-force
  traffic in `/var/log/auth.log`. That is free, real data with zero additional risk.
