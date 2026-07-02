# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/baco604/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “bacman” downloaded a tor installer, did something that resulted in many tor related files being copied in the desktop and the creation of a file called “tor-shopping-list.txt” on the desktop

These events began at: 6/29/2026, 6:27:15.009 AM

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName == "bacman"
| where FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1593" height="445" alt="Screenshot 2026-07-02 at 1 56 48 PM" src="https://github.com/user-attachments/assets/6cd9472f-07db-4cb4-9e1b-be7281b3a5ef" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-15.0.16.exe  /S.”

On June 29, 2026, at 6:32:41 AM UTC, the user bacman started the Tor Browser installer on the computer threat-hunt-lab. The installer was launched from the user's Downloads folder using a silent installation option (/S), which installs the software without displaying the normal setup wizard.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where InitiatingProcessAccountName == "bacman"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.16.exe  /S"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1615" height="342" alt="Screenshot 2026-07-02 at 1 59 07 PM" src="https://github.com/user-attachments/assets/2ecf5bbe-fef1-4462-be25-36917b305a0e" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “bacman” actually opened the tor browser. There was evidence that they did open it at 6/29/2026, 6:33:08.791 AM. There were several other instances of firefox.exe(Tor) as well as tor.exe spawned afterwards

```kql
DeviceProcessEvents
| where DeviceName == "threat-hunt-lab"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1589" height="725" alt="Screenshot 2026-07-02 at 2 00 47 PM" src="https://github.com/user-attachments/assets/98bd7d91-0c30-49d3-ae1c-8f5d0453dca8" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Search the DeviceNetworkEvents table for any indication that tor browser was used to establish a connection using any of the known tor ports. On June 29, 2026, at 06:34:40 UTC, the user bacman successfully launched Tor Browser (tor.exe) on the threat-hunt-lab machine. The application established a successful outbound connection to the remote IP address 173.212.200.241 over TCP port 9001, which is commonly used by the Tor network to communicate with relay nodes. This activity indicates that the Tor client successfully connected to the Tor network. There were a few other connections over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "threat-hunt-lab"
| where InitiatingProcessAccountName != "System"
| where RemotePort in ("9001","9030","9050","9051","9150")
| project Timestamp, DeviceName,ActionType, RemoteIP, RemotePort,InitiatingProcessAccountName,RemoteUrl, InitiatingProcessFileName
```
<img width="1601" height="394" alt="Screenshot 2026-07-02 at 2 06 31 PM" src="https://github.com/user-attachments/assets/39ec3769-4328-44ca-b950-4c36310eeb83" />

---

## Chronological Event Timeline 

6:32:41.191 AM — Process Created
bacman executed the installer from the Downloads folder:

tor-browser-windows-x86_64-portable-15.0.16.exe  /S

The /S flag performs a silent installation — no setup wizard is shown to the user.


6:32:53.601 AM – 6:32:53.998 AM — File Created (installer extraction)
Tor-Launcher.txt → ...\Tor Browser\Browser\TorBrowser\Docs\Licenses\
Torbutton.txt → same folder
tor.txt → same folder
tor.exe → C:\Users\BACMAN\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe SHA256: 3480b027e2eeda0b6bfaf2f28bde7f3f7038ecf4de3c3862ee9536d1d8451537


6:32:59.305 AM — File Created
Tor Browser.lnk shortcut created on the Desktop — installation complete; portable app extracted to C:\Users\BACMAN\Desktop\Tor Browser\.


6:33:08.791 AM — Process Created
firefox.exe (Tor Browser's browser component) launched for the first time — Tor Browser opened.


6:33:09.047 AM – 6:33:21.316 AM — Process Created (x7)
Multiple firefox.exe child processes spawned (gpu, rdd, utility, and tab content processes 2–10) — normal multi-process browser startup sequence.


6:33:17.855 AM — File Created
storage.sqlite created in the Tor Browser default profile — browser profile initializing.
6:33:20.611 AM — File Created
storage-sync-v2.sqlite created in the Tor Browser default profile.


6:33:23.735 AM — Process Created
tor.exe executed with the following config:

tor.exe -f torrc  DataDirectory ...\TorBrowser\Data\Tor  ControlPort 127.0.0.1:9151  SocksPort 127.0.0.1:9150

The Tor client daemon starts, beginning negotiation with the Tor network.


6:33:51.035 AM — Network: Connection Failed
firefox.exe attempted to reach 127.0.0.1:9150 (local Tor SOCKS proxy) but failed — Tor circuit not yet established.


6:34:17.424 AM – 6:34:19.015 AM — Network: Relay Connections (Batch 1 & 2)
Time (UTC)
Action
Remote IP:Port
Remote URL (TLS SNI)
6:34:17.424 AM
ConnectionSuccess
94.100.6.30:9001
—
6:34:17.672 AM
ConnectionAcknowledged
94.100.6.30:9001
—
6:34:18.389 AM
ConnectionSuccess
167.86.67.112:9001
—
6:34:18.438 AM
ConnectionAcknowledged
167.86.67.112:9001
—
6:34:18.802 AM
ConnectionSuccess
94.100.6.30:9001
wp7jddk7xskvtaj.com
6:34:19.015 AM
ConnectionSuccess
167.86.67.112:9001
42opsvojl572lpt.com


These "RemoteUrl" values are TLS SNI hostnames used for Tor relay certificate obfuscation — not sites the user actually visited.


6:34:40.236 AM – 6:34:40.690 AM — Network: Relay Connection (Batch 3)
Time (UTC)
Action
Remote IP:Port
Remote URL (TLS SNI)
6:34:40.236 AM
ConnectionSuccess
173.212.200.241:9001
—
6:34:40.531 AM
ConnectionAcknowledged
173.212.200.241:9001
—
6:34:40.690 AM
ConnectionSuccess
173.212.200.241:9001
yszyypq.com



6:34:45.505 AM — Network: Connection Success ✅
firefox.exe successfully connected to the local Tor SOCKS proxy at 127.0.0.1:9150.

Tor circuit established — Tor Browser is now online and routing traffic through the Tor network.


6:34:46.567 AM – 6:42:15.049 AM — Process Created (x10) — Active Browsing
Sequential firefox.exe tab-content processes spawned for tabs 11 through 20:

6:34:46 → 6:36:08 → 6:36:56 → 6:37:35 → 6:37:52 → 6:38:10 → 6:40:40 → 6:40:51 → 6:42:06 → 6:42:15

Naturally spaced (1–3 minute intervals) — indicates active, ongoing human browsing across numerous tabs over ~8 minutes.


6:47:16.003 AM — File Created 🔎
tor-shopping-list.txt created directly on C:\Users\BACMAN\Desktop\ SHA256: 067d83642a45da492b3e51c4ad9c71ac223264ad8cdb00094af99447f3f57c07
6:47:16.007 AM — File Created
tor-shopping-list.lnk created in AppData\Roaming\Microsoft\Windows\Recent\ — a Windows "Recent Items" shortcut automatically generated when a file is opened/saved, confirming the shopping-list file was actively opened by the user.


6:54:07.687 AM — File Created
formhistory.sqlite created in the Tor Browser profile — form/autofill data began being recorded, consistent with the user typing into web forms/search fields during the session.


8:03:14.970 AM – 8:03:15.105 AM — File Modified (session end)
Time (UTC)
File
8:03:14.970 AM
storage-sync-v2.sqlite
8:03:15.037 AM
formhistory.sqlite
8:03:15.105 AM
storage.sqlite


Last observed activity in the Tor Browser profile, marking the end of the observed session (~1 hour 30 minutes after installation began).


---

## Summary

At 6:32:41 AM UTC on June 29, 2026, user bacman silently installed the Tor Browser portable application on threat-hunt-lab directly from the Downloads folder. The installer extracted its files, and by 6:33:08 AM the user had launched the browser. The bundled Tor client (tor.exe) started at 6:33:23 AM and, within a little over a minute, successfully established connections to three separate Tor relay nodes over port 9001, with the local Firefox process successfully connecting to the Tor SOCKS proxy at 6:34:45 AM — confirming the browser was live on the Tor network. The user then actively browsed, opening a total of 20 tabs between 6:33 AM and 6:42 AM. At 6:47:16 AM, a file named tor-shopping-list.txt was created and opened on the Desktop. Browser activity (form history and storage database writes) continued until 8:03:15 AM, marking the end of the session — approximately 90 minutes after the Tor Browser was first installed.
Bottom line: This is a complete, successful lifecycle of Tor Browser install → launch → successful Tor network connection → active multi-tab browsing → creation of a locally-saved text file → extended usage, all performed by user bacman on threat-hunt-lab within a single continuous session on June 29, 2026.


---

## Response Taken

TOR usage was confirmed on endpoint threat-hunt-lab. The device was isolated and the user's direct manager was notified.

---
