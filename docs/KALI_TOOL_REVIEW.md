# Kali metapackage candidate review

Reviewed on 2026-11-14 against the 679-entry toolkit registry before this change.
The supplied unmatched-package list contains 227 distinct names: 95 from
`kali-linux-headless`, eight from `kali-linux-default`, and 124 from
`kali-linux-large`. This reviews project coverage, not software installed on a
particular operator's machine.

Kali metapackages include dependencies, services, desktop applications and
specialist tools. Their package names cannot be compared directly with this
project's registry names. Kali also describes `kali-linux-large` as its previous
default selection, rather than a list of mandatory additions. See the official
[metapackage documentation](https://www.kali.org/docs/general-use/metapackages/).

## Added in this change

| Registry name | Module | Primary MCP command | Reason |
| --- | --- | --- | --- |
| `libhivex-bin` | forensics | `hivexml` | Read Windows registry hives as XML; complements RegRipper's artifact-specific plugins. |
| `pst-utils` | forensics | `readpst` | Extract Outlook PST mail for subsequent analysis. |
| `mdbtools` | forensics | `mdb-tables` | Inspect Microsoft Access database tables without a desktop database application. |
| `ssldump` | networking | `ssldump` | Analyze TLS records and decrypt captured traffic with suitable key material. |

All four use the existing package installer. Module command metadata covers
verification; MCP package aliases cover local and remote command resolution.
Normal package update and removal paths consume the module arrays and distro
mappings. Registry size after the change: **683**.

| Debian / Kali name | Fedora | Arch official repositories | openSUSE | Termux |
| --- | --- | --- | --- | --- |
| `libhivex-bin` | `hivex` | `hivex` | `hivex` | skip |
| `pst-utils` | `libpst` | `libpst` | `libpst` | skip |
| `mdbtools` | `mdbtools` | skip | `mdbtools` | `mdbtools` |
| `ssldump` | `ssldump` | skip | `ssldump` | skip |

These are package-name mappings, not a claim that every historical distro release
ships the package. No additional repositories or AUR helpers are enabled.
Package and command evidence:
[hivex upstream](https://libguestfs.org/hivex.3.html),
[libpst upstream](https://github.com/pst-format/libpst),
[MDB Tools upstream](https://github.com/mdbtools/mdbtools),
[ssldump upstream](https://github.com/adulau/ssldump),
[Fedora hivex](https://packages.fedoraproject.org/pkgs/hivex/hivex/),
[Fedora libpst](https://packages.fedoraproject.org/pkgs/libpst/libpst/),
[Fedora mdbtools](https://packages.fedoraproject.org/pkgs/mdbtools/mdbtools/),
[Fedora ssldump](https://packages.fedoraproject.org/pkgs/ssldump/ssldump/),
[Arch hivex](https://archlinux.org/packages/extra/x86_64/hivex/),
[Arch libpst](https://archlinux.org/packages/extra/x86_64/libpst/),
[openSUSE package documentation](https://manpages.opensuse.org/Tumbleweed/),
[SUSE ssldump](https://packagehub.suse.com/packages/ssldump/), and
[Termux mdbtools recipe](https://github.com/termux/termux-packages/blob/master/packages/mdbtools/build.sh).

### MCP behavior

- `run_tool("libhivex-bin", "case/SYSTEM")` resolves to the read-only `hivexml`
  command, rather than an interactive registry editor.
- `run_tool("mdbtools", "case/database.mdb")` resolves to `mdb-tables`.
- `run_tool("pst-utils", "-r -o case/mail case/archive.pst")` extracts mail into an
  existing output directory. The policy checks output and debug paths, including
  bundled options, and blocks `-w`, which can delete existing files when combined
  with `-S`. Argument validation does not confine paths derived from PST contents;
  file extraction still relies on the execution sandbox for isolation. See the
  [readpst manual](https://manpages.debian.org/trixie/pst-utils/readpst.1.en.html).
- `run_tool("ssldump", "-n -r case/capture.pcap -l case/tls.keys")` analyzes an
  existing capture. MCP requires offline input and numeric output, rejects live
  capture and BPF filter operands, and checks `-w` destinations. The restrictions
  apply with external networking enabled too. Capture-record reverse DNS and
  filter hostname resolution are separate mechanisms; disabling the former alone
  does not disable the latter. See the
  [upstream argument parser](https://github.com/adulau/ssldump/blob/master/base/pcap-snoop.c.in).

## Useful candidates deferred

| Candidate | Assessment and remaining integration work |
| --- | --- |
| `swaks` | Useful SMTP testing gap. Needs explicit destination handling, config/environment review, output-path checks and rejection of command transports such as `--pipe`. |
| `cadaver` | Useful WebDAV client. Interactive commands and startup command files need a dedicated execution policy. |
| `davtest` | Useful WebDAV validation, including uploads and execution checks; needs explicit remote-write and target handling. |
| `pdfid`, `pdf-parser` | Useful PDF triage/object analysis alongside existing `peepdf-3`. Review URL inputs, file lists, expression/plugin execution and output options before enabling MCP execution. |
| `7zip` | Useful archive dependency. Debian bookworm's `7zip` provides `7zz`; trixie's package provides `7z`. A single static binary alias would misreport one as missing. |
| `xxd` | Useful hex dump and reverse-hex utility. Already permitted as an MCP system utility, but that permission does not install it; distro package mapping remains to be added. |
| `afflib-tools`, `readpe`, `reglookup` | Useful specialist artifact formats and queries. Review package-to-command mappings and existing forensics overlap when prioritizing the next additions. |
| `arpwatch` | Useful passive address-change detection, with daemon defaults, capture privileges and lifecycle to review. |
| `ike-scan` | Useful IKE-specific protocol support. Add with target-file and option handling reviewed, plus distro availability checked. |
| `wapiti` | Potentially useful crawling web scanner; overlaps existing web scanning and needs its own MCP policy review. |
| `ddrescue` | The supplied Kali package is Kurt Garloff's `dd_rescue`, not GNU `ddrescue`. Prefer a deliberate GNU `gddrescue` decision for recovery work; never treat the two package names as an alias. |

Sources:
[Swaks manual](https://jetmore.org/john/code/swaks/),
[cadaver upstream](https://notroj.github.io/cadaver/),
[PDFiD options](https://www.kali.org/tools/pdfid/),
[pdf-parser options](https://www.kali.org/tools/pdf-parser/),
[bookworm 7zip files](https://packages.debian.org/bookworm/amd64/7zip/filelist),
[trixie 7zip files](https://packages.debian.org/trixie/amd64/7zip/filelist),
[IKE Scan upstream](https://github.com/royhills/ike-scan),
[Wapiti upstream](https://github.com/wapiti-scanner/wapiti),
[Kali ddrescue](https://www.kali.org/tools/ddrescue/), and
[GNU ddrescue](https://www.gnu.org/software/ddrescue/).

## Existing coverage and interpretation

An existing registry entry means the installer already manages that tool. A
functional alternative is a different tool and may not reproduce every option.
MCP system-utility permission alone does not install a package.

Examples of existing names are `impacket`, `PEASS-ng`, `empire`, `wifite2`,
`dnsutils` and `hexedit`. Existing `binwalk` does not guarantee Binwalk v3 on every
distro. Existing `faraday-cli` is a client and does not install the Faraday server;
`pypykatz` is not the Windows `mimikatz` executable.

The Debian-only `forensics-extra` metapackage can also pull in candidates such as
`cabextract`, `dmitry`, `ethtool`, `gdisk`, `mc` and `sipcrack` indirectly. That is
not individual registry support or a portable installation guarantee. Its GNU
`gddrescue` dependency is distinct from the supplied Kali `ddrescue` package. See
the [Debian dependency list](https://packages.debian.org/trixie/forensics-extra).

PowerSploit's upstream is explicitly archived, and Python 2 has reached end of
support. Other omitted tools are classified by overlap, packaging or project
scope; age alone does not prove a tool is unusable. Sources:
[PowerSploit archive](https://github.com/PowerShellMafia/PowerSploit),
[Python 2 sunset](https://www.python.org/doc/sunset-python-2/),
[MDK4 replacing MDK3](https://www.kali.org/tools/mdk4/),
[Rifiuti2](https://www.kali.org/tools/rifiuti2/), and
[Wifite2](https://github.com/derv82/wifite2).

## Validation

`make check` passed: 411 Bats tests, 1,799 Python tests and 68 sandbox tests,
alongside lint and data validators. The final package metadata also passed strict
registry, MCP sync and distro validation, shellcheck, Bash syntax checks and the
forensics/networking module dry run. No real package installation was performed.

## Complete candidate inventory

Every supplied name appears once below. These are project-priority decisions,
not a declaration that omitted tools have no value. Package aliases, transitive
dependencies and functional alternatives are kept separate.

### Added (4)

| Supplied package | Assessment |
| --- | --- |
| `ssldump` | Adds dedicated TLS protocol and handshake dissection; complements tcpdump/tshark. |
| `libhivex-bin` | Adds dedicated offline Windows Registry hive inspection and export commands; RegRipper provides a different plugin-oriented workflow. |
| `mdbtools` | Adds dedicated Microsoft Access database inspection and export; not explicitly registered previously. |
| `pst-utils` | Adds dedicated Outlook PST mailbox extraction; not explicitly registered previously. |

### Existing package names and integrations (6)

| Supplied package | Assessment |
| --- | --- |
| `bind9-dnsutils` | Debian/Kali package naming for DNS utilities already represented by dnsutils in modules/networking.sh; distro mapping uses bind-utils/bind elsewhere. |
| `impacket-scripts` | Kali packaging of example programs already installed by the impacket pipx entry in modules/enterprise.sh; binary mapping checks impacket-secretsdump. |
| `peass` | PEASS-ng is already cloned by modules/misc.sh; distribution packaging differs from the existing resource clone. |
| `powershell-empire` | Empire already exists as bcsecurity/empire Docker installation in modules/misc.sh, gated by INCLUDE_C2 and ENABLE_DOCKER. |
| `wifite` | Already represented by the wifite2 Git resource in modules/wireless.sh; cloning is not identical to Kali package setup. |
| `libsmali-java` | Java library packaging associated with the already registered smali tool in modules/mobile.sh; not an independent new tool capability. |

### Existing coverage with caveats (7)

| Supplied package | Assessment |
| --- | --- |
| `binwalk3` | The project already registers apt binwalk; distro package versions can be v2 or v3, so this does not prove binwalk v3 is installed. |
| `iputils-arping` | The project registers arping, a different implementation; both perform ARP probes, but flags and binaries are not interchangeable across distributions. |
| `ncurses-hexedit` | Separate hexeditor executable, not an alias of the registered hexedit package. Hexedit/hexyl/ImHex cover related editing and viewing workflows; no need for another editor by default. |
| `python3-virtualenv` | Shared dependencies already install python3-venv and the project uses isolated Python environments; virtualenv itself is not explicitly registered and offers additional behavior. |
| `wordlists` | SecLists, PayloadsAllTheThings, hashcat rules and cupp/crunch cover wordlist workflows; Kali wordlists and rockyou content are not guaranteed. |
| `mdk3` | The wireless module explicitly includes mdk4; this covers the newer tool family without guaranteeing every mdk3 behavior. |
| `rifiuti` | The project explicitly registers rifiuti2 in modules/forensics.sh; it covers recycle-bin analysis with different packaging and version behavior. |

### Indirect Debian-only dependencies (6)

| Supplied package | Assessment |
| --- | --- |
| `dmitry` | Already pulled transitively by forensics-extra on Debian trixie; not an independent registry entry and not guaranteed on other distributions or when the forensics module is not selected. General reconnaissance aggregation overlaps whois, nmap, dnsrecon and existing recon suites. |
| `ethtool` | Already pulled transitively by forensics-extra on Debian trixie; not an independent registry entry and not guaranteed on other distributions or when the forensics module is not selected. Network interface administration; useful for host setup but not a missing assessment capability by itself. |
| `gdisk` | Already pulled transitively by forensics-extra on Debian trixie; not an independent registry entry and not guaranteed on other distributions or when the forensics module is not selected. Partition administration; existing forensic tooling covers analysis and this adds disk-modification capabilities unrelated to the present gaps. |
| `cabextract` | Already pulled transitively by forensics-extra on Debian trixie; not an independent registry entry and not guaranteed on other distributions or when the forensics module is not selected. Useful CAB extraction; review against 7zip/libarchive coverage and safe extraction policy in a focused archive-support change. |
| `mc` | Already pulled transitively by forensics-extra on Debian trixie; not an independent registry entry and not guaranteed on other distributions or when the forensics module is not selected. File manager/editor preference; host productivity utility. |
| `sipcrack` | Already pulled transitively by forensics-extra on Debian trixie; not an independent registry entry and not guaranteed on other distributions or when the forensics module is not selected. SIP authentication cracking niche; hashcat/John and sipvicious cover overlapping workflows. |

### Useful candidates for a later integration (12)

| Supplied package | Assessment |
| --- | --- |
| `7zip` | Useful archive support, but 7z versus 7zz binary names and package availability vary by distro/version; add only with an explicit compatibility and MCP adapter plan. |
| `cadaver` | Useful WebDAV client, but URL connection and command/local-file options need policy review before adding executable exposure. |
| `davtest` | Useful WebDAV validation; performs file uploads and may test execution, so requires a deliberate network and filesystem adapter. |
| `pdf-parser` | Useful dedicated PDF object analysis; defer until parser executable naming and MCP file/code execution arguments are reviewed. |
| `pdfid` | Useful dedicated PDF triage; defer until binary aliases and MCP file/code execution arguments are reviewed. |
| `swaks` | Useful SMTP testing; defer until target, port, TLS, message data and local file options have an explicit governed MCP policy adapter. |
| `xxd` | Useful standard hexdump and reverse-hexdump command; hexyl and hexedit exist but are not drop-in equivalents. Consider a small utility addition with explicit distro package/binary mappings. |
| `afflib-tools` | Useful AFF forensic image support; add when actual AFF acquisition or analysis requirements justify the dependency and binary mapping. |
| `arpwatch` | Useful passive address-change detection; review daemon installation defaults, capture privileges and lifecycle before adding. |
| `ddrescue` | Candidate ddrescue refers to dd_rescue and must not be conflated with GNU ddrescue (gddrescue), which is a Debian forensics-extra dependency. A dedicated recovery addition requires package/binary identity and raw-device output policy review. |
| `readpe` | Useful PE-specific inspection; complements generic binutils and capa; review exact distro package/binary mapping before adding. |
| `reglookup` | Useful offline Windows Registry queries; complements libhivex/RegRipper but adds overlap, so a later focused forensics change is preferable. |

### Infrastructure and dependencies (42)

| Supplied package | Assessment |
| --- | --- |
| `apache2` | HTTP server infrastructure for a lab; install explicitly when a workflow needs a server rather than adding it to default security tooling. |
| `atftpd` | TFTP server infrastructure; not a required default toolkit dependency. |
| `axel` | Download accelerator; curl and wget already exist in shared dependencies. |
| `cifs-utils` | SMB filesystem mounting utilities; smbclient and SMB security tools exist, while kernel mounting is a separate infrastructure requirement. |
| `cryptsetup` | Disk encryption administration; install for an explicit encrypted-volume workflow rather than as a generic security-tool default. |
| `cryptsetup-initramfs` | Boot/initramfs integration for cryptsetup; not an independent assessment tool. |
| `cryptsetup-nuke-password` | Specialized encrypted-system recovery/destruction integration; unsuitable as a default toolkit addition. |
| `default-mysql-server` | Database server infrastructure; not necessary for normal assessment tooling. |
| `expect` | CLI automation runtime; add as a declared dependency only where an installer or tool actually requires it. |
| `gss-ntlmssp` | Authentication library/provider; add only as a dependency of a concrete workflow. |
| `i2c-tools` | Hardware bus administration and probing; niche hardware requirement rather than a general default. |
| `ifenslave` | Linux interface bonding administration; infrastructure configuration. |
| `minicom` | Serial terminal for hardware workflows; useful on demand, not required by the current tool modules. |
| `miredo` | IPv6 Teredo tunneling service; infrastructure requirement rather than a general toolkit default. |
| `netbase` | Base network service/protocol definitions; OS dependency, not a security tool to register. |
| `offsec-awae-python2` | Course-specific legacy runtime bundle; outside a general multi-distro toolkit's default requirements. |
| `openvpn` | VPN client/server infrastructure; install when the target lab or engagement requires it. |
| `php` | Language/runtime for PHP workflows; add on demand or as an actual declared dependency rather than count it as a security tool. |
| `php-mysql` | PHP database extension; not an independent assessment tool. |
| `powershell` | PowerShell runtime can support Windows/AD scripts; integration needs explicit distro/repository and script-execution design. |
| `python2` | End-of-life runtime; do not introduce a general default merely to support old tools. |
| `rake` | Ruby build task runner; add as a dependency only when required by a chosen tool. |
| `sakis3g` | Cellular connectivity setup helper; host infrastructure. |
| `samba` | SMB server stack; SMB clients and assessment tools already exist, while hosting an SMB service is a separate opt-in lab requirement. |
| `samba-common-bin` | Samba administration/support binaries; consider a specific missing command instead of adding the whole package speculatively. |
| `screen` | Terminal multiplexer preference; host productivity utility, not a security-tool coverage gap. |
| `snmpd` | SNMP server/agent infrastructure; snmp clients and onesixtyone already cover assessment workflows. |
| `telnet` | Legacy interactive protocol client; netcat/socat cover basic TCP interaction, with explicit telnet negotiation needs left to the operator. |
| `tftp-hpa` | TFTP client; add if an actual workflow needs it, with remote and local path policy first. |
| `vboot-kernel-utils` | Verified-boot/Chromebook platform utilities; specialized platform administration. |
| `vboot-utils` | Verified-boot/Chromebook platform utilities; specialized platform administration. |
| `vim-nox` | Editor variant; host preference, not a security capability gap. |
| `vlan` | Legacy VLAN configuration utilities; host networking administration. |
| `vpnc` | Specific VPN connectivity client; install only for an actual compatible VPN requirement. |
| `cgpt` | ChromeOS partition administration; specialized platform infrastructure. |
| `chirp` | Radio programming GUI/application; specialized hardware requirement outside current defaults. |
| `chromium` | Browser runtime; install as an explicit dependency where screenshot/browser tooling requires it. |
| `libfindrtp` | RTP support library; not an independent tool addition. |
| `mercurial` | Version-control dependency; Git is already installed, and Mercurial should be added only if a selected source needs it. |
| `subversion` | Version-control dependency; add only for a chosen source that needs SVN. |
| `vim-gtk3` | GUI editor variant; host preference, not a toolkit capability gap. |
| `zerofree` | Filesystem zeroing administration utility; not a general forensic-analysis default. |

### Optional desktop and platform tools (20)

| Supplied package | Assessment |
| --- | --- |
| `cutycapt` | Screenshotting alternative; gowitness and EyeWitness already cover web screenshot workflows without another Qt GUI helper. |
| `dirbuster` | GUI content discovery; dirsearch, ffuf, gobuster and feroxbuster already cover discovery. |
| `faraday` | Full collaboration platform; faraday-cli already exists, but the server/UI is a distinct deployment rather than a missing CLI alias. |
| `hydra-gtk` | Graphical frontend for the already registered hydra. |
| `legion` | GUI assessment orchestration; existing nmap and orchestration/recon tools provide substantial overlapping workflows. |
| `sqlitebrowser` | GUI for SQLite inspection; optional analyst workstation tool rather than a default CLI toolkit requirement. |
| `starkiller` | Empire GUI frontend; Empire is already an opt-in Docker component and the GUI is a separate optional deployment. |
| `zenmap` | Graphical frontend for the already registered nmap. |
| `armitage` | Metasploit GUI/collaboration frontend; metasploit already exists, with separate deployment needs for this interface. |
| `bytecode-viewer` | GUI reverse-engineering suite; jadx, Krakatau, jd-gui and Ghidra already cover major JVM/DEX analysis paths. |
| `dbeaver` | Database GUI; optional workstation deployment rather than a missing focused CLI analysis capability. |
| `dradis` | Collaboration/reporting platform; install separately when a team adopts its workflow. |
| `johnny` | Graphical frontend for the already registered john. |
| `jsql-injection` | GUI SQL injection alternative; sqlmap, ghauri and other SQL testing tools already exist. |
| `maltego` | Commercial/community GUI investigation platform; maltego-trx is present but is a transform library, not the GUI. Add only through a deliberate licensed desktop workflow. |
| `ncat-w32` | Windows payload/client binary; Linux ncat/netcat availability does not supply this artifact, which belongs in an explicit Windows resource workflow. |
| `netwag` | GUI network toolbox; nmap, hping3 and protocol clients already cover the principal workflows. |
| `ollydbg` | Windows-native debugger; separate Windows lab requirement rather than a Linux/Termux default. |
| `tftpd32` | Windows-native server/client application; separate Windows lab infrastructure. |
| `zim` | Desktop wiki/note-taking application; report and note workflow preference. |

### Overlapping and specialist tools (130)

| Supplied package | Assessment |
| --- | --- |
| `creddump7` | Offline Windows credential extraction overlaps impacket, pypykatz and registered forensic tools; no need for a second default without a specific format gap. |
| `cryptcat` | Encrypted netcat alternative; socat, stunnel, chisel and other current tunnels already cover encrypted channels. |
| `dbd` | Encrypted/backdoor connection utility; socat and existing tunnel/C2 tooling already cover the principal workflow. |
| `dirb` | Content discovery overlaps ffuf, dirsearch, gobuster and feroxbuster. |
| `exe2hexbat` | Windows executable-to-script transport utility; specialized artifact workflow, not a broad capability gap. |
| `fierce` | DNS reconnaissance alternative; dnsrecon, dnsenum, dnsx, amass and subfinder already exist. |
| `hash-identifier` | Hash identification overlaps hashid and name-that-hash. |
| `hotpatch` | Process injection/patching utility; specialized workflow with explicit privilege and process policy needs. |
| `ike-scan` | Potentially useful IKE fingerprinting niche; nmap already covers portions, while a dedicated adapter and confirmed VPN-testing demand should drive addition. |
| `laudanum` | Server-side payload collection; overlaps PayloadsAllTheThings and existing web shell frameworks, with a separate deliberate payload-resource workflow. |
| `lbd` | Load-balancer detection niche; HTTP fingerprinting and existing recon suites overlap. |
| `mimikatz` | Native Windows credential tooling is distinct from pypykatz; add only through a deliberate Windows payload-resource and binary provenance design. |
| `msfpc` | Metasploit payload convenience wrapper; metasploit already exists. |
| `multimac` | MAC manipulation alternative; macchanger already exists. |
| `netmask` | Address/netmask conversion alternative; mapcidr and standard networking capabilities already cover the workflow. |
| `netsed` | Packet-stream mutation niche; existing proxy/MITM tooling overlaps and a precise protocol need should justify it. |
| `passing-the-hash` | Additional pass-the-hash wrappers overlap impacket and NetExec. |
| `powersploit` | PowerShell post-exploitation resource library; overlap with existing AD/post-exploitation tools and requires a deliberate Windows script-resource workflow. |
| `proxytunnel` | HTTP CONNECT tunnel alternative; existing chisel, gost, socat and proxy tooling overlap. |
| `ptunnel` | ICMP tunnel niche; evaluate separately if an authorized workflow specifically requires that transport. |
| `qsslcaudit` | Specialized TLS client audit workflow; existing TLS tools cover server-side testing, so add only for confirmed client-side testing requirements. |
| `rebind` | DNS rebinding exploitation niche; existing web/DNS tooling provides foundations, but a concrete supported workflow should drive addition. |
| `rsmangler` | Wordlist mutation alternative; hashcat rules, cupp, crunch and kwprocessor already exist. |
| `sbd` | Encrypted/backdoor connection alternative; socat, stunnel and existing C2/tunnel tooling overlap. |
| `sendemail` | SMTP sender alternative; prefer a future governed swaks integration rather than two mail clients. |
| `skipfish` | Web scanner alternative; nuclei, ZAP, nikto and existing scanners already cover broad scanning. |
| `snmpcheck` | SNMP enumeration convenience wrapper; snmp, onesixtyone and nmap already cover enumeration. |
| `sslh` | Protocol multiplexer for hosted services; useful for a specific infrastructure design, not a required assessment default. |
| `tcpick` | TCP stream reconstruction alternative; tcpflow and tshark already exist. |
| `thc-ipv6` | Broad IPv6 attack suite; useful in a dedicated IPv6 engagement, but adds many executables and requires a deliberate scope/policy review. |
| `thc-pptp-bruter` | PPTP-specific brute-force niche; existing cracking tools cover general protocols and a concrete PPTP requirement should drive addition. |
| `udptunnel` | UDP tunnel alternative; existing tunnel/proxy tooling overlaps. |
| `unar` | Archive extractor alternative; review together with broader 7zip/libarchive support rather than add multiple extractors independently. |
| `unix-privesc-check` | Local privilege-escalation enumeration overlaps PEASS-ng, linux-smart-enumeration and SUDO_KILLER. |
| `voiphopper` | Voice-VLAN probing niche; specialized enterprise network engagement requirement. |
| `wce` | Native Windows credential-editor artifact; requires a deliberate Windows payload/provenance workflow, not a Linux tool default. |
| `webshells` | Payload collection rather than a single executable; existing payload resources overlap, but do not assume identical Kali contents. |
| `weevely` | Web-shell management alternative; existing PhpSploit, Penelope and C2 tooling overlap; requires explicit remote execution policy if added. |
| `wfuzz` | Fuzzing alternative; ffuf, x8, boofuzz and existing discovery tools cover principal workflows. |
| `windows-binaries` | Collection of Windows artifacts rather than a single tool; needs a distinct resource/provenance review. |
| `0trace` | Firewall-aware path discovery niche; nmap/traceroute and existing network tooling overlap. |
| `amap` | Application fingerprinting alternative; nmap service detection and existing HTTP/TLS fingerprint tools overlap. |
| `apache-users` | Apache user enumeration niche; existing HTTP discovery tools can cover the principal checks. |
| `bed` | Protocol fuzzing alternative; boofuzz, radamsa and other registered fuzzers already exist. |
| `bluelog` | Classic Bluetooth discovery/logging niche; bluez and existing wireless tools provide foundations, but not identical functionality. |
| `blueranger` | Bluetooth proximity/ranging niche; specialized hardware engagement requirement. |
| `bluesnarfer` | Bluetooth data-access niche; requires compatible hardware/targets and a dedicated authorized workflow. |
| `braa` | SNMP query alternative; snmp, onesixtyone and nmap already exist. |
| `btscanner` | Bluetooth discovery interface alternative; bluez and existing wireless tooling overlap. |
| `cisco-auditing-tool` | Vendor-specific assessment wrapper; nmap, RouterSploit and current enterprise tooling overlap. |
| `cisco-global-exploiter` | Vendor-specific exploit collection; prefer maintained scanner/exploit tooling and add individual concrete missing checks when justified. |
| `cisco-ocs` | Vendor-specific scanning niche; nmap and RouterSploit overlap. |
| `cisco-torch` | Vendor-specific enumeration wrapper; nmap and RouterSploit overlap. |
| `cmospwd` | Firmware password recovery niche; platform-specific requirement rather than general defaults. |
| `copy-router-config` | SNMP router configuration-copy helper; credential and write-operation workflow needs deliberate scope handling. |
| `cymothoa` | Process backdoor/injection niche; existing post-exploitation tooling overlaps and process policy needs separate review. |
| `dhcpig` | DHCP exhaustion/disruption workflow; unsuitable as an incidental default without a specific authorized testing need. |
| `dnsmap` | DNS brute-force alternative; puredns, shuffledns, dnsx and existing DNS discovery tools cover it. |
| `dnstracer` | DNS delegation/path inspection niche; dnsutils and dnsrecon cover much of the workflow. |
| `dnswalk` | DNS zone consistency checking niche; dnsutils/dnsrecon provide overlapping analysis. |
| `doona` | Protocol fuzzing alternative; boofuzz, radamsa and existing fuzzers already exist. |
| `dotdotpwn` | Traversal fuzzing alternative; ffuf and nuclei provide overlapping workflow foundations. |
| `driftnet` | Passive HTTP image display niche; tshark/tcpflow cover capture/extraction, while the graphical display is optional. |
| `dsniff` | Credential/protocol interception suite; PCredz, Responder, bettercap, tshark and existing interception tools overlap, with multiple executables needing policy review. |
| `dumpzilla` | Firefox artifact extraction alternative; firefox_decrypt and existing browser/forensic frameworks overlap. |
| `eapmd5pass` | EAP-MD5-specific credential recovery niche; hashcat/John and existing wireless cracking tools overlap. |
| `enumiax` | IAX/VoIP enumeration niche; dedicated protocol need should drive addition. |
| `ferret-sidejack` | HTTP session extraction/hijacking workflow; tshark, mitmproxy and existing interception tooling overlap. |
| `fiked` | IKE-related interception niche; dedicated VPN engagement requirement with careful policy review. |
| `fragrouter` | Packet fragmentation/evasion workflow; existing network tooling overlaps and authorized IDS testing should drive addition. |
| `framework2` | Specialized fuzzing framework; boofuzz, AFLplusplus, honggfuzz and existing fuzzers already exist. |
| `ftester` | Firewall/IDS test suite; existing packet generators and scanners overlap. |
| `hamster-sidejack` | Browser/session hijacking interface; existing proxy and interception tools overlap. |
| `hexinject` | Raw packet injection niche; scapy, hping3 and existing packet tooling overlap. |
| `httrack` | Website mirroring alternative; wget, katana, Photon and existing crawlers cover common workflows, but are not identical mirrors. |
| `iaxflood` | IAX flooding/disruption niche; requires a specific authorized resilience-testing requirement. |
| `intrace` | Path discovery alternative; nmap/traceroute and existing packet tooling overlap. |
| `inviteflood` | SIP flooding/disruption niche; requires a specific authorized resilience-testing requirement. |
| `irpas` | Router/network attack suite; existing nmap, yersinia, RouterSploit and packet tooling overlap, with many executables needing review. |
| `javasnoop` | Java runtime inspection alternative; Frida, Ghidra and existing JVM tooling provide overlapping workflows. |
| `jboss-autopwn` | JBoss exploitation wrapper; metasploit and nuclei provide overlapping checks and exploitation foundations. |
| `joomscan` | Joomla-specific scanner; CMSmap, nuclei and existing web scanners overlap. |
| `kismet-logtools` | Kismet log helpers; review the selected distro's kismet package outputs before adding an independent tool entry. |
| `missidentify` | File-extension/executable mismatch inspection niche; file, binutils and existing forensic tools cover related analysis without identical behavior. |
| `nipper-ng` | Network-device configuration auditing niche; add only with a concrete supported configuration format and a verified upstream/integration plan. |
| `nishang` | PowerShell post-exploitation resource collection; existing AD/C2 tools overlap and Windows script resources need a deliberate integration. |
| `ohrwurm` | RTP fuzzing niche; dedicated VoIP testing requirement should drive addition. |
| `oscanner` | Oracle enumeration niche; nmap and existing database assessment tooling provide overlapping foundations. |
| `pack` | Password analysis/mask generation overlaps pipal, statsprocessor and hashcat tooling; verify exact package identity before adding. |
| `pack2` | Password analysis/mask generation niche; verify relationship to pack and overlap with existing analysis tools first. |
| `paros` | Web proxy/scanner alternative; ZAP, mitmproxy and existing scanners already exist. |
| `perl-cisco-copyconfig` | Router configuration-copy helper; overlaps copy-router-config and requires explicit authenticated write-operation policy. |
| `polenum` | Windows password-policy enumeration alternative; NetExec and impacket provide overlapping workflows. |
| `protos-sip` | SIP robustness test corpus; specialized protocol testing resource rather than a generic default executable. |
| `rainbowcrack` | Rainbow-table workflow; hashcat and John already cover general cracking, while precomputed-table use is a specific requirement. |
| `rcracki-mt` | Indexed rainbow-table workflow; add only for an actual compatible table corpus and requirement. |
| `redfang` | Bluetooth address discovery niche; requires specialized hardware/target demand. |
| `rtpbreak` | RTP stream extraction niche; tshark and existing capture tools overlap. |
| `rtpflood` | RTP flooding/disruption niche; requires a specific authorized resilience-testing requirement. |
| `rtpinsertsound` | RTP media injection niche; requires a concrete authorized VoIP test and explicit network policy. |
| `rtpmixsound` | RTP media manipulation niche; requires a concrete authorized VoIP test and explicit network policy. |
| `safecopy` | Media recovery alternative; prefer resolving GNU ddrescue integration first rather than adding two recovery tools together. |
| `sctpscan` | SCTP scanning niche; nmap has SCTP scanning support, so dedicated expansion should follow a concrete gap. |
| `sfuzz` | Protocol fuzzing alternative; boofuzz, radamsa and existing fuzzers overlap. |
| `sidguesser` | Oracle SID enumeration niche; nmap and existing database testing tools provide overlapping foundations. |
| `siege` | HTTP load generation; separate authorized performance-testing requirement rather than vulnerability-tool coverage. |
| `siparmyknife` | SIP assessment alternative; sipvicious and existing packet/protocol tools overlap. |
| `sipp` | SIP traffic/load generation; useful for dedicated VoIP protocol/resilience testing, not a generic default requirement. |
| `smtp-user-enum` | SMTP enumeration helper; nmap scripts cover the common workflow, and a future swaks integration is the broader mail-testing priority. |
| `sniffjoke` | Traffic manipulation/evasion suite; dedicated IDS testing requirement and explicit network policy needed. |
| `sqldict` | Database credential attack niche; hydra, medusa, patator and existing database tooling overlap. |
| `sqlninja` | SQL Server exploitation alternative; sqlmap, NetExec, impacket and metasploit cover overlapping workflows. |
| `sqlsus` | SQL injection alternative; sqlmap and ghauri already exist. |
| `sslsniff` | TLS interception alternative; mitmproxy, sslsplit and bettercap already exist. |
| `t50` | Packet flooding/stress tooling; existing packet generators overlap and authorized resilience testing should drive addition. |
| `termineter` | Smart-meter protocol testing niche; dedicated hardware/industrial protocol requirement. |
| `thc-ssl-dos` | TLS denial-of-service workflow; requires a specific authorized resilience-testing need rather than incidental defaults. |
| `tlssled` | TLS test wrapper; testssl.sh, sslyze and sslscan already exist. |
| `tnscmd10g` | Oracle TNS management niche; nmap and existing Oracle/database testing tooling overlap. |
| `truecrack` | Encrypted-volume password recovery niche; hashcat and John cover overlapping formats and workflows. |
| `twofi` | Social-text wordlist generation niche; cupp, cewl and existing wordlist generators overlap. |
| `unicornscan` | Scanner alternative; nmap, masscan, naabu, zmap and rustscan already exist. |
| `uniscan` | Web scanning alternative; nuclei, ZAP, nikto and existing scanners already exist. |
| `urlcrazy` | Domain typo/permutation analysis alternative; dnstwist and existing recon tooling overlap. |
| `wapiti` | General web scanner with useful features, but ZAP, nuclei and existing scanners already provide broad coverage; add only for a demonstrated testing gap. |
| `webacoo` | Web-shell management alternative; PhpSploit, Penelope and existing C2 tooling overlap, with remote execution policy needing separate review. |
| `webscarab` | Web proxy/testing alternative; ZAP and mitmproxy already exist. |
| `wifi-honey` | Wi-Fi honeypot workflow; existing rogue-AP tools overlap, and a dedicated detection/lab requirement should drive addition. |
| `xspy` | X11 event/input monitoring niche; specialized local/remote desktop security workflow. |
| `xsser` | XSS testing alternative; dalfox, XSStrike and existing web scanners already exist. |
