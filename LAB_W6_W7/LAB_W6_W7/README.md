# Lab Week 6 & 7 — File Analysis (Scanning Result)

**Subject:** Vulnerability Analysis (IKB21004 & IKB21403)
**Task:** File Analysis – Scanning Result
**Name:** Muhammad Hayat Bin Abdullah
**Date:** November 2026

---

## Overview

This write-up documents my analysis of two packet captures, an Nmap output, OS fingerprinting from TTL values, and a Nessus scan. The two captures and the Nessus scan all relate to the same lab host (`192.168.232.139`, a Metasploitable 2 box). The goal for each task was either to recover a hidden flag or to interpret a scanning result.

**Tools used:** Wireshark, Kali Linux terminal (`base64`, `strings`), Nessus Essentials, Firefox.

---

## Question 1 — Analyse `packet1.pcap` and find the flag

### Method

The capture is only 41 packets and every one is an ICMP echo (ping) between `172.24.20.31` and `171.64.20.62`. It looks like a normal ping exchange, but ICMP is a classic place to hide data because the echo payload can be anything.

![ICMP overview in Wireshark](images/q1-icmp-overview.png)

All the normal pings are 98 bytes long and carry the usual Linux padding (`!"#$%&'()*+,-./01234567`). I looked for the odd one out. **Frame 37** stands out — it is only 70 bytes, has a different ICMP identifier (`id=0x0001` instead of `0x7a93`), and its 28-byte data field holds readable Base64 instead of padding.

![Frame 37 data field](images/q1-frame37-data.png)

Reading the Data field as text gives `U1VDVEYyMDIze2FpX2lzX2Nvb2x9`, which is Base64. I decoded it in the terminal:

```bash
echo 'U1VDVEYyMDIze2FpX2lzX2Nvb2x9' | base64 -d
```

![Base64 decode to the flag](images/q1-flag-decode.png)

### Answer

```
Flag: SUCTF2023{ai_is_cool}
```

The technique is **data exfiltration hidden inside an ICMP payload** (ICMP tunnelling) — one crafted ping is buried among normal ones so it blends into the traffic.

---

## Question 2 — Analyse `packet2.pcap` and find the flag

### Method

This capture is larger (794 packets). Most of it is ICMP pings used as noise. Filtering with `tcp` shows what actually matters. There are a few short TCP "chats" on odd ports (4444, 8888, 9999…) that quote dialogue from the movie *WarGames* — those are a distraction.

The real payload is an **FTP session**:

- Anonymous login with a blank password
- `RETR global_thermonuclear_war.gamerules.txt`

I followed the FTP-DATA stream (Follow → TCP Stream). The downloaded file contains a single line — a shortened link `https://tinyurl.com/yr5zprz4`. Opening it redirects to a Google Doc titled **"Club Tux"**, which leads to the final flag.

![FTP data stream showing the TinyURL and the Club Tux doc](images/q2-ftp-clubtux.png)

### Answer

The FTP download leads to `https://tinyurl.com/yr5zprz4` → Google Doc ("Club Tux") → the final flag.

The chain is: **ICMP noise → FTP file → URL shortener → Google Doc → final flag.**

> The Google Doc shows the text in a symbol font; decoding the underlying `char()` codes resolves to `EXMACHINAAVA` (ties back to the AI theme of Question 1).

---

## Question 3 — Interpret an Nmap output

```
PORT     STATE SERVICE      VERSION
21/tcp   open  ftp          vsftpd 2.3.4
22/tcp   open  ssh          OpenSSH 5.3p1
80/tcp   open  http         Apache 2.2.8
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds Windows 7 Professional 7601 Service Pack 1
```

### 1. What an attacker can do with each port

| Port | Service | What an attacker can do |
|------|---------|--------------------------|
| 21 | vsftpd 2.3.4 | Log in / pull files, and trigger the known backdoor for a root shell |
| 22 | OpenSSH 5.3p1 | Brute-force credentials, enumerate valid usernames |
| 80 | Apache 2.2.8 | Map the web app, run directory & vuln scanners, look for web flaws |
| 139 | NetBIOS-ssn | Enumerate shares, users, null sessions (`enum4linux`) |
| 445 | microsoft-ds (Win7 SP1) | SMB attacks — remote code execution |

### 2. Likely vulnerabilities based on version

- **vsftpd 2.3.4** → famous backdoor **CVE-2011-2523**. A username ending in `:)` opens a root shell on port 6200.
- **OpenSSH 5.3p1** → outdated; username enumeration (CVE-2018-15473), weak to brute force.
- **Apache 2.2.8** → end-of-life; Range-header DoS "Apache Killer" (CVE-2011-3192).
- **NetBIOS 139** → information disclosure via SMB enumeration.
- **Windows 7 SP1 / SMB 445** → **MS17-010 "EternalBlue" (CVE-2017-0144)**.

### 3. Highest risk and why

**Port 21 — the vsftpd 2.3.4 backdoor (CVE-2011-2523)** is the highest risk. It gives an **unauthenticated root shell** and is trivial to trigger: simply log in with a username ending in `:)` and a root shell opens on port 6200. There is a ready Metasploit module for it, and it needs no exploit development at all, which makes it an effective CVSS ~10 (Critical). **SMB EternalBlue (MS17-010) on port 445 is also critical** — it is wormable and also gives SYSTEM-level RCE — so it should be treated with the same urgency.

### 4. Attack path that can be built from this

1. Confirm the service: `nmap -p21 -sV <target>` shows vsftpd 2.3.4
2. Exploit: `exploit/unix/ftp/vsftpd_234_backdoor` in Metasploit
3. Get a **root shell** directly
4. Establish persistence / dump credentials
5. Pivot to the SMB host and run `exploit/windows/smb/ms17_010_eternalblue` for a second foothold

### 5. Remediation

- **Upgrade vsftpd** to a current, supported version and **disable anonymous FTP.**
- Patch **MS17-010**, or migrate off Windows 7 (end-of-life); **disable SMBv1** and block 139/445 at the firewall.
- Upgrade **OpenSSH and Apache**; enforce SSH key authentication and deploy `fail2ban`.
- Restrict unused services and keep all software patched.

> Observation: a single host can't realistically run Linux services (21/22) *and* be Windows 7 (445) at once, so this is best treated as a sample/combined port list for the exercise.

---

## Question 4 — OS fingerprinting from TTL

Different operating systems set a different **default initial TTL**, so the TTL in a ping reply is a quick way to guess the OS.

| Default TTL | Operating System |
|-------------|------------------|
| 64 | Linux / Unix |
| 128 | Windows |
| 255 | Network device (Cisco router / Unix variant) |

**Image 1 — TTL = 64 → Linux.** The ping replies show `ttl=64`, and the host is confirmed as Fedora 34.

![TTL 64 Linux](images/q4-ttl64-linux.png)

**Image 2 — TTL = 255 → Network device (router).** The device is sending ICMP "Time-to-live exceeded" messages with an IP TTL of 255. (The `TTL = 1` shown *inside* the quoted packet is just the traceroute probe that expired — not the OS fingerprint.)

![TTL 255 router](images/q4-ttl255-router.png)

**Image 3 — TTL = 128 → Windows.** The replies show `ttl=128`, the Windows default.

![TTL 128 Windows](images/q4-ttl128-windows.png)

---

## Question 5 — Analyse the Nessus file (Ghostcat)

I imported `Network_Scan.nessus` into Nessus Essentials. The scan has one host, `192.168.232.139` (Ubuntu 8.04 / Metasploitable 2), with multiple critical and high findings. Auth shows **Fail** (unauthenticated scan), so these are all remote findings.

![Nessus host summary](images/q5-nessus-host.png)

![Critical/High vulnerabilities](images/q5-nessus-vulns.png)

The **Remediations** tab lists Ghostcat directly:

![Remediations tab](images/q5-remediations.png)

Opening the Ghostcat plugin (ID **134862**) gives the full detail — description, solution, CVE, and VPR:

![Ghostcat plugin detail](images/q5-ghostcat-detail.png)

The Output panel proves Nessus exploited it, listing the affected port **8009 / tcp / ajp13**:

![Ghostcat output — port 8009 / ajp13](images/q5-ghostcat-output.png)

Scrolling the output shows the actual exploit result: the crafted AJP request asked for `/WEB-INF/web.xml` and the **server leaked the file back** (the returned XML is visible). This is exactly the file-read that Ghostcat is known for.

![Ghostcat file-read proof — server leaked /WEB-INF/web.xml](images/q5-ghostcat-fileread.png)

### Answers

**1. Affected port number:** `8009` (shown as `8009 / tcp / ajp13`)

**2. Affected protocol:** **AJP13** — the Apache JServ Protocol connector, over TCP.

**3. CVSS score:** **CVSS v3 base = 9.8 (Critical)**. Supporting values: CVSSv3 Impact Score 5.9, CVSS v2 base 7.5, VPR 9.6.

**4. Exploit available?** **Yes.** Nessus marks Exploit Code Maturity = **PoC** and exploited it during the scan (the Output panel shows the server returning `/WEB-INF/web.xml`). Public exploits:
- Metasploit: `auxiliary/admin/http/tomcat_ghostcat`
- Exploit-DB: **48143** (`searchsploit ghostcat`)

**5. CVE:** **CVE-2020-1938** (primary), with related **CVE-2020-1745**.

### Why it matters

Ghostcat is a file read / inclusion flaw in the AJP connector. A remote, unauthenticated attacker can read web application files such as `WEB-INF/web.xml`, and if the server allows file uploads, it escalates to **remote code execution** via a malicious JSP.

**Fix:** upgrade Tomcat to 7.0.100 / 8.5.51 / 9.0.31 or later, and if the AJP connector isn't needed, disable it or bind it to localhost and require a `secret`.

---

## Summary

| Task | Result |
|------|--------|
| Q1 — packet1.pcap | `SUCTF2023{ai_is_cool}` |
| Q2 — packet2.pcap | FTP → `https://tinyurl.com/yr5zprz4` → Google Doc → final flag |
| Q3 — Nmap | Highest risk: vsftpd 2.3.4 backdoor (CVE-2011-2523), EternalBlue also critical |
| Q4 — TTL | 64 = Linux, 128 = Windows, 255 = network device |
| Q5 — Nessus (Ghostcat) | Port 8009 / AJP13, CVSS 9.8, exploit available, CVE-2020-1938 |

---

## References

- Hayat — LAB_W6_W7: https://github.com/yatmoraxx/LAB_W6_W7/blob/main/README.md
