# Automate EC2 Forensics via VPC Flow Logs — Writeup By Taylor Christian Newsome ClumsyLulz

**Lab ID:** `yx73mo` · **Region:** `us-west-2` · **Difficulty:** Beginner · **Focus:** Blue

---

## Scenario

NxTrade Corp runs **TradeEngine-Alpha** (`10.1.0.50`) in a private VPC with no internet gateway. SSH is reachable from the entire internal CIDR and password authentication is enabled. A compromised internal host, **InternalScanner** (`10.1.0.134`), is brute-forcing the victim's port 22 while we work.

Three objectives: identify the attack, preserve host evidence with chain of custody, and build an event-driven pipeline that detects SSH attack traffic and snapshots the victim's disk automatically — before containing both hosts.

All access is through the AWS Console and EC2 Instance Connect; the instances have no public IP, so the browser terminal routes through an Instance Connect Endpoint inside the private subnet.

---

## 1. Detection from VPC Flow Logs

VPC Flow Logs record metadata for every connection touching the VPC. Each line has 14 space-delimited fields; the relevant ones are field 4 (source), field 5 (destination), field 7 (destination port) and field 13 (action).

In **CloudWatch → Logs → Log groups → `/vpc/flowlogs/nxtrd-yx73mo`**, the newest stream shows a repeating pattern: `10.1.0.134 → 10.1.0.50` on port 22, many times per second, every entry `ACCEPT`. A legitimate administrator logs in once; hundreds of connections per second is password guessing. The `ACCEPT` is expected — the security group permits SSH from the whole VPC CIDR, so the brute force is never stopped at the network layer. The authentication failures happen one layer up, in OpenSSH.

**IOCs:** attacker `10.1.0.134`, victim `10.1.0.50`, vector SSH brute force on tcp/22, allowed at network level.

---

## 2. Evidence preservation with chain of custody

Before collecting host logs, the instance needs write access to the evidence bucket. Permissions are attached as an instance role:

**EC2 → Instances → TradeEngine-Alpha → Actions → Security → Modify IAM role** → select `nxtrd-yx73mo-ForensicExport-Profile` → **Update IAM role**. Wait ~20 seconds for credentials to propagate; skipping this makes the later `s3 cp` fail with a misleading permissions error.

A shell is opened via **Connect → EC2 Instance Connect Endpoint** tab (user `ec2-user`, lab endpoint selected). The login banner corroborates the flow-log evidence immediately:

```
Last failed login: ... from 10.1.0.134 on ssh:notty
There were 506 failed login attempts since the last successful login.
```

The count climbs while we work, because the attack is live.

Three artefacts are collected:

```bash
# 1. Capture the system journal
sudo journalctl --no-pager > /tmp/system_journal.log

# 2. Upload to the evidence bucket with chain-of-custody metadata
aws s3 cp /tmp/system_journal.log s3://ir-evidence-yx73mo/case-IR2026/host-logs/ \
  --metadata incident-id=IR-2026-0529,collector=responder

# 3. Corroborate the attack from the system's own perspective
grep "Failed password" /tmp/system_journal.log | tail -5
sudo lastb | grep 10.1.0.134 | head
```

The upload succeeding proves two independent controls: the `ForensicExport` role grants S3 write, and the S3 gateway endpoint gives the subnet a path to S3 despite having no IGW or NAT.

The grep output returns genuine OpenSSH failures against usernames like `admin` and `root`, and `lastb` corroborates them against the binary failed-login database — the attack is confirmed from two independent sources, not just the network logs.

Scrolling further up the journal reveals post-exploitation activity: a successful key-based login, a `sudo` invocation reading `/etc/shadow`, and outbound requests to `198.51.100.77`. The investigation phase is complete.

---

## 3. Building the automated pipeline

Three values are needed:

| Value | Source |
|---|---|
| Volume ID (`vol-…`) | EC2 → TradeEngine-Alpha → **Storage** tab |
| SNS topic ARN | SNS → Topics → `nxtrd-yx73mo-security-alerts` |
| Lambda name | `nxtrd-yx73mo-auto-forensic` (empty shell, pre-created) |

The Lambda shell exists for a reason: creating a function normally requires `iam:PassRole`, a privilege-escalation primitive. The lab instead provides a shell pre-bound to a boundary-capped execution role, and we still do all the meaningful work — code, environment, policy, trigger.

### 3.1 The function

The code reads `TARGET_VOLUME_ID` and `SNS_TOPIC_ARN` from environment variables so it stays reusable. Two guards are the interesting part:

- **Guard 1** verifies the invocation came from a real CloudWatch Logs subscription delivery — gzip-compressed and base64-encoded under `event['awslogs']['data']`, which a console **Test** click cannot produce.
- **Guard 2** ignores the `CONTROL_MESSAGE` connectivity ping AWS sends once when a filter is first attached.

Together they ensure a capture is only produced by a genuine attack event traversing the whole pipeline. On a real event the function parses field 4 of the log line for the actor IP, checks for an existing flagged snapshot (deduplication), creates an EBS snapshot tagged with `Name`, `CapturedBy`, `CaptureTime`, `SourceVolume`, `FindingType`, `ActorIP`, `ChainOfCustody` and `Flag`, and publishes an SNS alert.

Paste the code in **one** operation — the editor's auto-indent mangles Python if entered piecemeal — then **Deploy**.

### 3.2 Environment variables

**Configuration → Environment variables → Edit**: add `TARGET_VOLUME_ID` and `SNS_TOPIC_ARN`.

### 3.3 Inline IAM policy

Code and permission are separate by design. On role `nxtrd-yx73mo-auto-forensic-role` → **Add permissions → Create inline policy → JSON**, named `forensic-capture-perms`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowForensicCapture",
      "Effect": "Allow",
      "Action": [
        "ec2:CreateSnapshot",
        "ec2:CreateTags",
        "ec2:DescribeVolumes",
        "ec2:DescribeSnapshots"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AllowSNSNotify",
      "Effect": "Allow",
      "Action": ["sns:Publish"],
      "Resource": "*"
    }
  ]
}
```

`"Resource": "*"` looks broad — alone, it would be. The role carries a **permissions boundary** capping `ec2:CreateSnapshot` to volumes tagged with this deployment's LabID and `sns:Publish` to the lab's own topic. Effective permission is the intersection, so a broad inline grant stays inside a predefined blast radius. Two editor gotchas: the JSON editor auto-closes brackets, so a stray trailing `}` triggers *Unexpected close marker*; and a red access-analyzer banner may appear because the responder identity can't auto-review — it does not block creation.

### 3.4 Wiring the trigger

Navigate **into** the log group first (`/vpc/flowlogs/nxtrd-yx73mo`) → **Subscription filters → Create → Create Lambda subscription filter**. Reaching the form any other way leaves it without a target log group and it fails validation.

- **Destination:** `nxtrd-yx73mo-auto-forensic`
- **Log format:** Other
- **Pattern:**

```
[version, account, eni, srcaddr, dstaddr=10.1.0.50, srcport, dstport=22, protocol, packets, bytes, start, end, action, status]
```

`srcaddr` is deliberately unconstrained — the Lambda reads the attacker's address out of whatever matched, so the capture is provably derived from real traffic rather than a value we typed. Name the filter `nxtrd-yx73mo-ssh-traffic-to-lambda` and **Start streaming**.

Creating the filter via the console also attaches the resource-based policy allowing `logs.amazonaws.com` to invoke the function; built over the CLI, `aws lambda add-permission` must run first or creation is rejected. Skip the **Test pattern** button — the responder lacks `logs:TestMetricFilter`; validating the pattern in the log group's own search bar uses a permission we do hold.

### 3.5 Smoke test

Run the Lambda's **Test** tab with the default event. Result: *Executing function: succeeded*, with `[GUARD-1] Not a real log delivery - refusing to generate a flag.` That is correct — no flag, but a plain un-flagged snapshot is created, proving the snapshot machinery and IAM permissions work.

---

## 4. Letting the attack fire the pipeline

Nothing to do but wait. Flow records aggregate over a 60-second window, CloudWatch delivers them to the subscription, then the Lambda runs; IAM changes need ~15 seconds to propagate. Allow two to four minutes.

The capture **must happen before containment**, because containment cuts the very traffic the automation depends on — a real judgment call weighing ongoing damage against the forensic value still being generated.

Confirm under **EC2 → Snapshots** that a snapshot tagged `CapturedBy = auto-forensic-lambda` with a non-empty `Flag` tag exists. Ignore the un-flagged smoke-test snapshot.

---

## 5. Containment

Two pre-built groups do the work:

- `nxtrd-yx73mo-Lockdown-SG` — zero inbound, zero outbound: total isolation.
- `nxtrd-yx73mo-ForensicAccess-SG` — SSH from `10.1.0.200` only, no egress: held for investigation without phoning home.

**Victim:** EC2 → TradeEngine-Alpha → Actions → Security → Change security groups → swap in **Lockdown-SG**. This terminates our own SSH session, which is the point — everything needed was collected first. Console access is unaffected.

**Attacker:** same flow on InternalScanner → swap in **ForensicAccess-SG**. It can reach nothing but the forensic workstation, but stays available for analysis.

Both instances are verified in the **Security group** column of the Instances list. The responder can swap security groups but is denied `AuthorizeSecurityGroupIngress`/`Egress` — quarantine controls can be applied but not weakened. The attack is over, the attacker's path is cut, both hosts held.

---

## 6. The flag

Read it from the snapshot's **Tags** tab: **EC2 → Snapshots → Elastic Block Store**, open the snapshot tagged `CapturedBy = auto-forensic-lambda` that also carries a non-empty `Flag` tag.

- `Flag` → **`68d098e5da59d19767ed72d7adcd76c7`**
- `ActorIP` → `10.1.0.134`
- `FindingType` → `VPCFlowLog:SSHTrafficPort22/ACCEPT`

`ActorIP` and `FindingType` together confirm the capture was driven by genuine port-22 flow-log traffic rather than by anything typed in. The flag exists only because the entire chain fired: the network recorded the attack, the subscription filter caught it, the Lambda ran, and it stamped the snapshot.

**Flag:** `68d098e5da59d19767ed72d7adcd76c7`

---

## 7. Defence — four independent weaknesses

**Broad SSH ingress.** Port 22 open to the whole VPC CIDR let one compromised host reach every SSH listener. Limit interactive access to approved control planes plus a time-bound forensic `/32`, and disable password auth entirely with `PasswordAuthentication no`. Apply via reusable security-group modules or launch templates so new hosts don't reintroduce the exposure.

**Over-scoped evidence role.** `s3:*` on `*` turns a response helper into a data-access risk — the role that preserves evidence could read or destroy unrelated data. Scope to the evidence bucket (`PutObject`, `PutObjectTagging`, `GetObject`, `ListBucket`), attach only to the affected asset, remove after collection, and pair with bucket versioning and Object Lock.

**Over-scoped automation role.** Unrestricted `ec2:CreateSnapshot` exposes unrelated systems and creates cost and confidentiality risk. A permissions boundary constraining snapshots to volumes tagged with the lab ID is precisely why the lab can safely let an operator author a `"Resource": "*"` policy — the production pattern for authoring automation inside a fixed blast radius.

**Unprotected containment controls.** If a responder can edit the rules inside the quarantine groups, containment can be bypassed — by accident or by an attacker holding stolen responder credentials. Allow `ModifyInstanceAttribute`/`ModifyNetworkInterfaceAttribute`; deny `AuthorizeSecurityGroupIngress`, `AuthorizeSecurityGroupEgress`, `DeleteSecurityGroup` and `logs:DeleteSubscriptionFilter`. Quarantine groups should be centrally managed and applied through runbooks or automation, never hand-edited mid-incident.

---

## Key takeaways

- Flow logs prove *traffic*, not *outcome*; pairing them with `journalctl` and `lastb` proves the authentication failures actually occurred. Two sources, one conclusion.
- Evidence export depends on instance identity **and** a network path to S3 — in a no-IGW subnet, the gateway endpoint does the work, and it's easy to forget.
- Guards are what make the capture meaningful: without them, anyone clicking **Test** would mint a "capture" that proves nothing.
- A permissions boundary is what lets you grant broadly without granting dangerously.
- Timing: capture before containment. Containment is irreversible with respect to evidence still being generated.

**Further reading:** AWS VPC Flow Logs · EBS snapshot creation · Lambda + CloudWatch Logs · IAM permissions boundaries · EC2 security groups · S3 gateway endpoints · Session Manager · AWS Security Incident Response Guide.


## 8. Logs
```bash
root@internal:~# mkdir pwnedlabs
root@internal:~# cd pwnedlabs
root@internal:~/pwnedlabs# nano pwnvpn.conf
root@internal:~/pwnedlabs# root@internal:~/pwnedlabs# sudo wg-quick up ./pwnvpn.conf
Warning: `/root/pwnedlabs/pwnvpn.conf' is world accessible
[#] echo c2V0ICtlCmlwIHJvdXRlIGRlbCAxMC42Ni4wLjEvMzIgMj4vZGV2L251bGwKaXAgcm91dGUgZGVsIDEuMS4xLjEvMzIgMj4vZGV2L251bGwKaXAgcm91dGUgZGVsIDEuMC4wLjEvMzIgMj4vZGV2L251bGwKaXAgcm91dGUgZGVsIDguOC44LjgvMzIgMj4vZGV2L251bGwKaXAgcm91dGUgZGVsIDguOC40LjQvMzIgMj4vZGV2L251bGwKaXAgcm91dGUgZGVsIDkuOS45LjkvMzIgMj4vZGV2L251bGwKaXAgcm91dGUgZGVsIDE0OS4xMTIuMTEyLjExMi8zMiAyPi9kZXYvbnVsbAppcCByb3V0ZSBkZWwgMjA4LjY3LjIyMi4yMjIvMzIgMj4vZGV2L251bGwKaXAgcm91dGUgZGVsIDIwOC42Ny4yMjAuMjIwLzMyIDI+L2Rldi9udWxsCmlwIHJvdXRlIGRlbCA5NC4xNDAuMTQuMTQvMzIgMj4vZGV2L251bGwKaXAgcm91dGUgZGVsIDk0LjE0MC4xNS4xNS8zMiAyPi9kZXYvbnVsbApbIC1mIC9ydW4vcHdudnBuLmRucy5waWQgXSAmJiBraWxsICIkKGNhdCAvcnVuL3B3bnZwbi5kbnMucGlkKSIgMj4vZGV2L251bGwKcm0gLWYgL3J1bi9wd252cG4uZG5zLnBpZApleGl0IDAK | base64 -d | bash
[#] ip link add pwnvpn type wireguard
[#] wg setconf pwnvpn /dev/fd/63
[#] ip -4 address add 10.66.0.3/32 dev pwnvpn
[#] ip link set mtu 1200 up dev pwnvpn
[#] ip -4 route add 94.140.15.15/32 dev pwnvpn
[#] ip -4 route add 94.140.14.14/32 dev pwnvpn
[#] ip -4 route add 9.9.9.9/32 dev pwnvpn
[#] ip -4 route add 8.8.8.8/32 dev pwnvpn
[#] ip -4 route add 8.8.4.4/32 dev pwnvpn
[#] ip -4 route add 208.67.222.222/32 dev pwnvpn
[#] ip -4 route add 208.67.220.220/32 dev pwnvpn
[#] ip -4 route add 149.112.112.112/32 dev pwnvpn
[#] ip -4 route add 10.66.0.1/32 dev pwnvpn
[#] ip -4 route add 1.1.1.1/32 dev pwnvpn
[#] ip -4 route add 1.0.0.1/32 dev pwnvpn
[#] ip -4 route add 10.1.9.0/24 dev pwnvpn
[#] ip -4 route add 10.1.8.0/24 dev pwnvpn
[#] ip -4 route add 10.1.7.0/24 dev pwnvpn
[#] ip -4 route add 10.1.6.0/24 dev pwnvpn
[#] ip -4 route add 10.1.5.0/24 dev pwnvpn
[#] ip -4 route add 10.1.4.0/24 dev pwnvpn
[#] ip -4 route add 10.1.3.0/24 dev pwnvpn
[#] ip -4 route add 10.1.2.0/24 dev pwnvpn
[#] ip -4 route add 10.1.1.0/24 dev pwnvpn
[#] ip -4 route add 10.1.0.0/24 dev pwnvpn
[#] ip -4 route add 100.64.0.0/16 dev pwnvpn
[#] echo c2V0ICtlClBJTj0xMjcuMC4wLjkKQkFLPS9ldGMvcHdudnBuLnJlc29sdi5iYWsKRE5TQT0iMTAuNjYuMC4xIjsgRE5TQj0iMy4xNDguMjAxLjY3IgpVUD0kKGdyZXAgLUUgJ15uYW1lc2VydmVyJyAvZXRjL3Jlc29sdi5jb25mIDI+L2Rldi9udWxsIHwgYXdrICd7cHJpbnQgJDJ9JyB8IGdyZXAgLXZFICdeMTI3XC4nIHwgaGVhZCAtMSkKWyAteiAiJFVQIiBdICYmIFVQPSQocmVzb2x2ZWN0bCBkbnMgMj4vZGV2L251bGwgfCB0ciAnICcgJ1xuJyB8IGdyZXAgLUUgJ14oWzAtOV17MSwzfVwuKXszfVswLTldezEsM30kJyB8IGdyZXAgLXZFICdeMTI3XC4nIHwgaGVhZCAtMSkKaWYgWyAteiAiJFVQIiBdICYmIFsgLWUgIiRCQUsiIF07IHRoZW4KICBVUD0kKGdyZXAgLUUgJ15uYW1lc2VydmVyJyAiJEJBSyIgMj4vZGV2L251bGwgfCBhd2sgJ3twcmludCAkMn0nIHwgZ3JlcCAtdkUgJ14xMjdcLicgfCBoZWFkIC0xKQpmaQpbIC16ICIkVVAiIF0gJiYgVVA9IjQuMi4yLjIiCmlmICEgZ3JlcCAtcUUgJ15uYW1lc2VydmVyW1s6c3BhY2U6XV0rMTI3XC4wXC4wXC45JyAvZXRjL3Jlc29sdi5jb25mIDI+L2Rldi9udWxsOyB0aGVuCiAgY3AgLWZQIC9ldGMvcmVzb2x2LmNvbmYgIiRCQUsiIDI+L2Rldi9udWxsCmZpClsgLWUgIiRCQUsiIF0gfHwgcHJpbnRmICduYW1lc2VydmVyICVzXG4nICIkVVAiID4gIiRCQUsiCkRNPQpETlNNQVNRPSQoY29tbWFuZCAtdiBkbnNtYXNxIDI+L2Rldi9udWxsIHx8IGVjaG8gL3Vzci9zYmluL2Ruc21hc3EpClsgLXggIiRETlNNQVNRIiBdICYmICIkRE5TTUFTUSIgLS1waWQtZmlsZT0vcnVuL3B3bnZwbi5kbnMucGlkIC0tY29uZi1maWxlPS9kZXYvbnVsbCAtLW5vLWhvc3RzIC0tbGlzdGVuLWFkZHJlc3M9JFBJTiAtLWJpbmQtaW50ZXJmYWNlcyAtLW5vLXJlc29sdiAtLXNlcnZlcj0xMC42Ni4wLjEgLS1zZXJ2ZXI9My4xNDguMjAxLjY3IDI+L2Rldi9udWxsICYmIERNPW9rCnJtIC1mIC9ldGMvcmVzb2x2LmNvbmYKaWYgWyAiJERNIiA9IG9rIF07IHRoZW4KICBwcmludGYgJ25hbWVzZXJ2ZXIgJXNcbm5hbWVzZXJ2ZXIgJXNcbicgIiRQSU4iICIkVVAiID4gL2V0Yy9yZXNvbHYuY29uZgplbHNlCiAgcHJpbnRmICduYW1lc2VydmVyICVzXG5uYW1lc2VydmVyICVzXG5uYW1lc2VydmVyICVzXG4nICIkRE5TQSIgIiRETlNCIiAiJFVQIiA+IC9ldGMvcmVzb2x2LmNvbmYKZmkKZXhpdCAwCg== | base64 -d | bash
root@internal:~/pwnedlabs# wg show
interface: pwnvpn
  public key: 65CSen2+1xvAc3eeWlAF6YEYjfhOiopACV7VXavi9FM=
  private key: (hidden)
  listening port: 47015

peer: IiqezO9Ajh2ZO8FsTkSRa3odgIARKKo72RfMuPboKmA=
  endpoint: 3.148.201.67:51820
  allowed ips: 100.64.0.0/16, 10.66.0.1/32, 1.1.1.1/32, 1.0.0.1/32, 8.8.8.8/32, 8.8.4.4/32, 9.9.9.9/32, 149.112.112.112/32, 208.67.222.222/32, 208.67.220.220/32, 94.140.14.14/32, 94.140.15.15/32, 10.1.0.0/24, 10.1.1.0/24, 10.1.2.0/24, 10.1.3.0/24, 10.1.4.0/24, 10.1.5.0/24, 10.1.6.0/24, 10.1.7.0/24, 10.1.8.0/24, 10.1.9.0/24
  latest handshake: 16 seconds ago
  transfer: 92 B received, 180 B sent
  persistent keepalive: every 25 seconds
root@internal:~/pwnedlabs# nc -vz 10.1.0.50 22
Connection to 10.1.0.50 22 port [tcp/ssh] succeeded!
root@internal:~/pwnedlabs# printf %s 10.1.0.134 | md5sum | cut -d' ' -f1
68d098e5da59d19767ed72d7adcd76c7
root@internal:~/pwnedlabs#
```
