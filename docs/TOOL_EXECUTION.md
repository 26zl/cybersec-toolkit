# Tool discovery and execution

The MCP catalog exposes all 682 entries in `tools_config.json`. Installation method describes how a package is obtained; it does not determine whether the package has a command-line interface. Git CLI entries have explicit executable metadata instead of a blanket `method == "git"` rejection.

## Discover, inspect, run

1. For target work, start with `guided_assessment`, `suggest_for_ctf` or `suggest_for_bounty` and establish the authorized scope.
2. Search with `list_tools(query="commix")`, filter with `module`/`method`, or page with `limit`/`offset`. `executable_only=True` selects supported CLI routes; it does not prove installation.
3. Call `get_tool_info` or `check_installed` and inspect `execution`. `executable` identifies a registered route, `binary_candidates` lists known launcher names, and `ready` means a matching executable was found in PATH. Neither a clone directory nor a `.versions` record proves that a CLI can start.
4. Invoke the registry name or an unambiguous executable alias with `run_tool`. The same launcher resolution and argument policies apply to pipeline steps and remote execution. Missing launchers require installation/setup; external opt-in does not bypass prohibited argument modes.
5. For data, rule, payload and wordlist repositories, use `execution.location_candidates` from the detailed lookup to locate the installed files. Read a selected file with governed `file`/`ls`/`cat`/`grep`, or pass its absolute path to the appropriate CLI. Candidate locations are hints until checked. Services, plugins, GUIs and multi-entry suites retain their upstream URL and setup guidance in the catalog.

Git wrappers normally inherit the execution working directory so relative input/output paths keep their meaning; Nipe's relative runtime files require its own clone directory. Scripts receive their installed source path; asset lookup remains dependent on the upstream program. Use absolute paths when sharing file references across the client, VM or remote host. Package/build setup uses `_as_builder`, which drops to the original sudo user when available; a direct root/container invocation retains root privileges. Setup can run upstream build code and fetch dependencies, and retains the trust limitations documented in [AGENTS.md](../AGENTS.md#important-patterns).

Network classification drives preflight target checks, alongside each tool's argument policy. It is not a complete inventory of every connection an upstream program can make. `CYBERSEC_MCP_ALLOW_EXTERNAL=1` is an explicit external-scope opt-in; the sandbox firewall still provides the network boundary. See [SANDBOX.md](SANDBOX.md).

A registered CLI route can require a separate opt-in. `usbkill` and `nipe` expose their complete functionality after their individual host-control switches are enabled; listing either CLI never enables that switch.

The optional client shell guard reads CLI names and aliases from the same registry metadata, preserving its advisor-clearance window and ordinary development commands. It does not import the MCP server or initialize operator state. This hook remains a client-side routing aid; tool execution policy and the sandbox are enforced at the server.

## Host-control functionality

Both tools remain in the registry and can be inspected without enabling their operational modes. Set the applicable variable in the MCP server environment and restart that server. Only the value `1` enables a switch; `true`, `yes`, `0` and an unset variable do not. The launcher forwards both switches into Kata, and the startup audit record includes their settings. `get_tool_info` reports the required switch and its effective state under `execution.activation`.

| Tool | Explicit activation | Functionality |
| --- | --- | --- |
| `usbkill` | `CYBERSEC_MCP_ALLOW_USBKILL=1` | USB monitoring, configured shutdown/commands/wiping, `--no-shut-down` and `--cs` |
| `nipe` | `CYBERSEC_MCP_ALLOW_NIPE=1` | `install`, `start`, `stop`, `restart` and `status` |

### usbkill

[usbkill](https://github.com/hephaest0s/usbkill) monitors USB ports and can shut down its machine when a device is connected or removed. Its configuration can also run commands or wipe files, RAM and swap; those actions depend on configuration and the installed dependencies. `--no-shut-down` still runs the configured destructive commands; it only suppresses shutdown. `--cs` copies its settings into `/etc/usbkill/settings.ini`. Help/version remain available without the operational opt-in.

### Nipe

[Nipe](https://github.com/htrgouvea/nipe) configures Tor routing through IPv4/IPv6 firewall rules. `install` prepares dependencies, `start` enables routing, `restart` restarts it and `status` checks the public exit IP. These operations also require `CYBERSEC_MCP_ALLOW_EXTERNAL=1`. `stop` performs local cleanup and therefore remains available with the Nipe switch even when external access is disabled.

Nipe's stop routine flushes OUTPUT rules, including rules that were present before Nipe started. Routing/firewall changes can interrupt network and SSH connections. The installed wrapper uses the Nipe clone as its working directory because its Perl modules and `.configs` paths are relative; other Git wrappers preserve the caller's working directory.

These switches grant permission in the MCP policy, not OS privileges or a sandbox escape. Actual operations still require operator authorization, suitable permissions, dependencies and access to the relevant devices/network namespace. Kata affects the guest; a remote invocation affects the selected remote host. Enabling either tool does not enable `run_script` or relax the policies of other `run_tool` routes. usbkill's configured commands are arbitrary code, including possible network access outside argv target validation; the sandbox scope firewall remains the network boundary.

## Git catalog evidence

Inventory date: 2026-11-19. 194 git entries: 156 cli, 24 framework, 1 gui, 11 resource, 1 service, 1 suite. Categories and canonical launcher names below mirror `mcp_server/tools_db.py`; the live MCP result is authoritative after later changes.

An upstream file link verifies that the named source or packaging declaration exists. Build commands come from the linked upstream build file or documentation. A linked source path, registered launcher or passing mocked test does not establish a successful installed execution. Installation, dependency compatibility, privileged/hardware operation and real-target execution were not exercised for this inventory. Entries without a verified launcher identify that gap explicitly.

`cli` means there is a supported invocation route once its launcher and runtime exist. `suite`/`framework`/`service` can contain executable programs but need a chosen entry point or their own setup; these labels do not claim that their contents cannot execute.

| Tool | Module | MCP kind | Canonical launcher | Upstream entry point/evidence | Setup/runtime |
| --- | --- | --- | --- | --- | --- |
| `atomic-red-team` | blueteam | resource | — | [Upstream](https://github.com/redcanaryco/atomic-red-team) | Use installed files as data; no single project-named CLI. |
| `maltrail` | blueteam | framework | — | [Upstream](https://github.com/stamparm/maltrail) | Follow upstream setup and select its client/entry point; no single registered launcher. |
| `MISP-docker` | blueteam | framework | — | [Upstream](https://github.com/MISP/misp-docker) | Follow upstream setup and select its client/entry point; no single registered launcher. |
| `sigma-rules` | blueteam | resource | — | [Upstream](https://github.com/SigmaHQ/sigma) | Use installed files as data; no single project-named CLI. |
| `wazuh-docker` | blueteam | framework | — | [Upstream](https://github.com/wazuh/wazuh-docker) | Follow upstream setup and select its client/entry point; no single registered launcher. |
| `cloud_enum` | cloud | cli | `cloud_enum` | [`cloud_enum.py`](https://github.com/initstring/cloud_enum/blob/HEAD/cloud_enum.py) | Python environment and upstream dependencies; install the wrapper. |
| `CloudBrute` | cloud | cli | `cloudbrute` | [`CloudBrute`](https://github.com/0xsha/CloudBrute/blob/HEAD/README.md) | `go build -o CloudBrute main.go`; Go; retain repository config and wordlists. |
| `cloudmapper` | cloud | cli | `cloudmapper` | [`cloudmapper.py`](https://github.com/duo-labs/cloudmapper/blob/HEAD/cloudmapper.py) | cloudmapper.py CLI; AWS credentials/config for collection; separate webserver subcommand. |
| `enumerate-iam` | cloud | cli | `enumerate-iam` | [`enumerate-iam.py`](https://github.com/andresriancho/enumerate-iam/blob/HEAD/enumerate-iam.py) | Python environment and upstream dependencies; install the wrapper. |
| `GCPBucketBrute` | cloud | cli | `gcpbucketbrute` | [`gcpbucketbrute.py`](https://github.com/RhinoSecurityLabs/GCPBucketBrute/blob/HEAD/gcpbucketbrute.py) | Python environment and upstream dependencies; install the wrapper. |
| `PurplePanda` | cloud | cli | `purplepanda` | [`main.py`](https://github.com/carlospolop/PurplePanda/blob/HEAD/main.py) | main.py CLI; provider credentials and Neo4j/setup as required by the selected mode. |
| `deepce` | containers | cli | `deepce` | [`deepce.sh`](https://github.com/stealthcopter/deepce/blob/HEAD/deepce.sh) | Shell and upstream companion commands; install the wrapper. |
| `docker-bench-security` | containers | cli | `docker-bench-security` | [`docker-bench-security.sh`](https://github.com/docker/docker-bench-security/blob/HEAD/docker-bench-security.sh) | Shell and upstream companion commands; install the wrapper. |
| `peirates` | containers | cli | `peirates` | [`peirates`](https://github.com/inguardians/peirates/blob/HEAD/Makefile) | `go build -o peirates ./cmd/peirates`; Go; builds for the native Go target rather than the upstream amd64 default. |
| `changeme` | cracking | cli | `changeme` | [`changeme.py`](https://github.com/ztgrace/changeme/blob/HEAD/changeme.py) | Python environment and upstream dependencies; install the wrapper. |
| `crowbar` | cracking | cli | `crowbar` | [`crowbar.py`](https://github.com/galkan/crowbar/blob/HEAD/crowbar.py) | Python environment and upstream dependencies; install the wrapper. |
| `cupp` | cracking | cli | `cupp` | [`cupp.py`](https://github.com/Mebus/cupp/blob/HEAD/cupp.py) | Python environment and upstream dependencies; install the wrapper. |
| `DefaultCreds-cheat-sheet` | cracking | cli | `defaultcreds-cheat-sheet` | [`creds`](https://github.com/ihebski/DefaultCreds-cheat-sheet/blob/HEAD/creds) | creds Python CLI; update/proxy modes use the network. |
| `gpp-decrypt` | cracking | cli | `gpp-decrypt` | [`gpp-decrypt.py`](https://github.com/t0thkr1s/gpp-decrypt/blob/HEAD/gpp-decrypt.py) | Python environment and upstream dependencies; install the wrapper. |
| `Hob0Rules` | cracking | resource | — | [Upstream](https://github.com/praetorian-inc/Hob0Rules) | Use installed files as data; no single project-named CLI. |
| `kwprocessor` | cracking | cli | `kwprocessor` | [`kwp`](https://github.com/hashcat/kwprocessor/blob/HEAD/Makefile) | `make`; C compiler; retain keymaps/basechars/routes. |
| `OneRuleToRuleThemStill` | cracking | resource | — | [Upstream](https://github.com/stealthsploit/OneRuleToRuleThemStill) | Use installed files as data; no single project-named CLI. |
| `Pantagrule` | cracking | resource | — | [Upstream](https://github.com/rarecoil/pantagrule) | Use installed files as data; no single project-named CLI. |
| `pipal` | cracking | cli | `pipal` | [`pipal.rb`](https://github.com/digininja/pipal/blob/HEAD/pipal.rb) | Ruby and upstream gems; install the wrapper. |
| `username-anarchy` | cracking | cli | `username-anarchy` | [`username-anarchy`](https://github.com/urbanadventurer/username-anarchy/blob/HEAD/username-anarchy) | Install its interpreter/build dependencies and wrapper; runtime not exercised. |
| `featherduster` | crypto | cli | `featherduster` | [`featherduster/featherduster.py`](https://github.com/nccgroup/featherduster/blob/HEAD/featherduster/featherduster.py) | Legacy Python 2 syntax; compatible interpreter and crypto dependencies required. |
| `RsaCtfTool` | crypto | cli | `rsactftool` | [`RsaCtfTool / rsacrack`](https://github.com/RsaCtfTool/RsaCtfTool/blob/HEAD/pyproject.toml) | Isolated project installation; console entry `RsaCtfTool.main:main`. |
| `rsatool` | crypto | cli | `rsatool` | [`rsatool.py`](https://github.com/ius/rsatool/blob/HEAD/rsatool.py) | Python environment and upstream dependencies; install the wrapper. |
| `abuseACL` | enterprise | cli | `abuseacl` | [`abuseACL.py`](https://github.com/AetherBlack/abuseACL/blob/HEAD/abuseACL.py) | Python environment and upstream dependencies; install the wrapper. |
| `asrepcatcher` | enterprise | cli | `asrepcatcher` | [`ASRepCatcher`](https://github.com/Yaxxine7/ASRepCatcher/blob/HEAD/setup.py) | Isolated project installation; console entry `ASRepCatcher.ASRepCatcher:main`. |
| `bqm` | enterprise | cli | `bqm` | [`bin/bqm`](https://github.com/Acceis/bqm/blob/HEAD/bin/bqm) | Install its interpreter/build dependencies and wrapper; runtime not exercised. |
| `cmloot` | enterprise | cli | `cmloot` | [`cmloot.py`](https://github.com/shelltrail/cmloot/blob/HEAD/cmloot.py) | Python environment and upstream dependencies; install the wrapper. |
| `conpass` | enterprise | cli | `conpass` | [`conpass`](https://github.com/login-securite/conpass/blob/HEAD/pyproject.toml) | Isolated project installation; console entry `conpass.cli:app`. |
| `cypheroth` | enterprise | cli | `cypheroth` | [`cypheroth.sh`](https://github.com/seajaysec/cypheroth/blob/HEAD/cypheroth.sh) | Shell and upstream companion commands; install the wrapper. |
| `dfscoerce` | enterprise | cli | `dfscoerce` | [`dfscoerce.py`](https://github.com/Wh04m1001/dfscoerce/blob/HEAD/dfscoerce.py) | Python environment and upstream dependencies; install the wrapper. |
| `enum4linux-ng` | enterprise | cli | `enum4linux-ng` | [`enum4linux-ng.py`](https://github.com/cddmp/enum4linux-ng/blob/HEAD/enum4linux-ng.py) | Python environment and upstream dependencies; install the wrapper. |
| `ExtractBitlockerKeys` | enterprise | cli | `extractbitlockerkeys` | [`python/ExtractBitlockerKeys.py`](https://github.com/p0dalirius/ExtractBitlockerKeys/blob/HEAD/python/ExtractBitlockerKeys.py) | Python environment and upstream dependencies; install the wrapper. |
| `freeipscanner` | enterprise | cli | `freeipscanner` | [`freeipscanner.sh`](https://github.com/scrt/freeipscanner/blob/HEAD/freeipscanner.sh) | Shell and upstream companion commands; install the wrapper. |
| `gmsadumper` | enterprise | cli | `gmsadumper` | [`gMSADumper.py`](https://github.com/micahvandeusen/gMSADumper/blob/HEAD/gMSADumper.py) | Python environment and upstream dependencies; install the wrapper. |
| `goldencopy` | enterprise | cli | `goldencopy` | [`goldencopy`](https://github.com/Dramelac/GoldenCopy/blob/HEAD/setup.py) | Isolated project installation; console entry `goldencopy:main`. |
| `GPOddity` | enterprise | cli | `gpoddity` | [`gpoddity.py`](https://github.com/synacktiv/GPOddity/blob/HEAD/gpoddity.py) | Python environment and upstream dependencies; install the wrapper. |
| `keytabextract` | enterprise | cli | `keytabextract` | [`keytabextract.py`](https://github.com/sosdave/KeyTabExtract/blob/HEAD/keytabextract.py) | Python environment and upstream dependencies; install the wrapper. |
| `krbrelayx` | enterprise | cli | `krbrelayx` | [`krbrelayx.py`](https://github.com/dirkjanm/krbrelayx/blob/HEAD/krbrelayx.py) | Python environment and upstream dependencies; install the wrapper. |
| `ldaprelayscan` | enterprise | cli | `ldaprelayscan` | [`LdapRelayScan.py`](https://github.com/zyn3rgy/LdapRelayScan/blob/HEAD/LdapRelayScan.py) | Python environment and upstream dependencies; install the wrapper. |
| `LDAPWordlistHarvester` | enterprise | cli | `ldapwordlistharvester` | [`LDAPWordlistHarvester.py`](https://github.com/p0dalirius/pyLDAPWordlistHarvester/blob/HEAD/LDAPWordlistHarvester.py) | Python environment and upstream dependencies; install the wrapper. |
| `linWinPwn` | enterprise | cli | `linwinpwn` | [`linWinPwn.sh`](https://github.com/lefayjey/linWinPwn/blob/HEAD/linWinPwn.sh) | Shell and upstream companion commands; install the wrapper. |
| `lnkup` | enterprise | cli | `lnkup` | [`generate.py`](https://github.com/Plazmaz/lnkUp/blob/HEAD/generate.py) | Python environment and upstream dependencies; install the wrapper. |
| `noPac` | enterprise | cli | `nopac` | [`noPac.py`](https://github.com/Ridter/noPac/blob/HEAD/noPac.py) | Python environment and upstream dependencies; install the wrapper. |
| `ntlm_theft` | enterprise | cli | `ntlm_theft` | [`ntlm_theft.py`](https://github.com/Greenwolf/ntlm_theft/blob/HEAD/ntlm_theft.py) | Python environment and upstream dependencies; install the wrapper. |
| `ntlmv1-multi` | enterprise | cli | `ntlmv1-multi` | [`ntlmv1.py`](https://github.com/evilmog/ntlmv1-multi/blob/HEAD/ntlmv1.py) | Python environment and upstream dependencies; install the wrapper. |
| `PassTheCert` | enterprise | cli | `passthecert` | [`Python/passthecert.py`](https://github.com/AlmondOffSec/PassTheCert/blob/HEAD/Python/passthecert.py) | Python environment and upstream dependencies; install the wrapper. |
| `PCredz` | enterprise | cli | `pcredz` | [`Pcredz`](https://github.com/lgandx/PCredz/blob/HEAD/Pcredz) | Pcredz entry point; capture-file analysis differs from privileged live capture. |
| `petitpotam` | enterprise | cli | `petitpotam` | [`PetitPotam.py`](https://github.com/topotam/PetitPotam/blob/HEAD/PetitPotam.py) | Python environment and upstream dependencies; install the wrapper. |
| `pkinittools` | enterprise | cli | `pkinittools` | [`gettgtpkinit.py`](https://github.com/dirkjanm/PKINITtools/blob/HEAD/gettgtpkinit.py) | Primary gettgtpkinit.py obtains a Kerberos ticket; related scripts remain a distinct suite. |
| `privexchange` | enterprise | cli | `privexchange` | [`privexchange.py`](https://github.com/dirkjanm/PrivExchange/blob/HEAD/privexchange.py) | Python environment and upstream dependencies; install the wrapper. |
| `PXEThief` | enterprise | cli | `pxethief` | [`pxethief.py`](https://github.com/blurbdust/PXEThief/blob/HEAD/pxethief.py) | Python environment and upstream dependencies; install the wrapper. |
| `pywsus` | enterprise | cli | `pywsus` | [`pywsus.py`](https://github.com/GoSecure/pywsus/blob/HEAD/pywsus.py) | Python environment and upstream dependencies; install the wrapper. |
| `RemoteMonologue` | enterprise | cli | `remotemonologue` | [`RemoteMonologue.py`](https://github.com/3lp4tr0n/RemoteMonologue/blob/HEAD/RemoteMonologue.py) | Python front end and Windows target components; verify its platform dependencies. |
| `Responder` | enterprise | cli | `responder` | [`Responder.py`](https://github.com/lgandx/Responder/blob/HEAD/Responder.py) | Python environment and upstream dependencies; install the wrapper. |
| `roastinthemiddle` | enterprise | cli | `roastinthemiddle` | [`ritm / roastinthemiddle`](https://github.com/Tw1sm/RITM/blob/HEAD/pyproject.toml) | Isolated project installation; console entry `ritm.__main__:app`. |
| `ruler` | enterprise | cli | `ruler` | [`ruler`](https://github.com/sensepost/ruler/blob/HEAD/Makefile) | `make build`; Go; primary target builds ruler.go. |
| `sccmsecrets` | enterprise | cli | `sccmsecrets` | [`SCCMSecrets.py`](https://github.com/synacktiv/SCCMSecrets/blob/HEAD/SCCMSecrets.py) | Python environment and upstream dependencies; install the wrapper. |
| `sccmwtf` | enterprise | cli | `sccmwtf` | [`sccmwtf.py`](https://github.com/xpn/sccmwtf/blob/HEAD/sccmwtf.py) | Python environment and upstream dependencies; install the wrapper. |
| `shadowcoerce` | enterprise | cli | `shadowcoerce` | [`shadowcoerce.py`](https://github.com/ShutdownRepo/shadowcoerce/blob/HEAD/shadowcoerce.py) | Python environment and upstream dependencies; install the wrapper. |
| `spraykatz` | enterprise | cli | `spraykatz` | [`spraykatz.py`](https://github.com/aas-n/spraykatz/blob/HEAD/spraykatz.py) | Python environment and upstream dependencies; install the wrapper. |
| `targetedKerberoast` | enterprise | cli | `targetedkerberoast` | [`targetedKerberoast.py`](https://github.com/ShutdownRepo/targetedKerberoast/blob/HEAD/targetedKerberoast.py) | Python environment and upstream dependencies; install the wrapper. |
| `zerologon` | enterprise | cli | `zerologon` | [`zerologon_tester.py`](https://github.com/bvcyber/CVE-2020-1472/blob/HEAD/zerologon_tester.py) | Python environment and upstream dependencies; install the wrapper. |
| `ctf-usb-keyboard-parser` | forensics | cli | `ctf-usb-keyboard-parser` | [`usbkeyboard.py`](https://github.com/TeamRocketIst/ctf-usb-keyboard-parser/blob/HEAD/usbkeyboard.py) | Python environment and upstream dependencies; install the wrapper. |
| `Depix` | forensics | cli | `depix` | [`depix.py`](https://github.com/spipm/Depixelization_poc/blob/HEAD/depix.py) | Python environment and upstream dependencies; install the wrapper. |
| `dvcs-ripper` | forensics | cli | `dvcs-ripper` | [`rip-git.pl`](https://github.com/kost/dvcs-ripper/blob/HEAD/rip-git.pl) | Perl suite; rip-git.pl, rip-hg.pl and rip-svn.pl select the VCS. |
| `firefox_decrypt` | forensics | cli | `firefox_decrypt` | [`firefox_decrypt.py`](https://github.com/unode/firefox_decrypt/blob/HEAD/firefox_decrypt.py) | Python environment and upstream dependencies; install the wrapper. |
| `firmware-mod-kit` | forensics | cli | `firmware-mod-kit` | [`extract-firmware.sh`](https://github.com/rampageX/firmware-mod-kit/blob/HEAD/extract-firmware.sh) | Primary extract-firmware.sh needs the toolkit native helpers; build-firmware.sh is separate. |
| `RegRipper` | forensics | cli | `regripper` | [`rip.pl`](https://github.com/keydet89/RegRipper3.0/blob/HEAD/rip.pl) | Perl and upstream modules; install the wrapper. |
| `USB-HID-decoders` | forensics | cli | `usb-hid-decoders` | [`keyboard_decode.py`](https://github.com/Nissen96/USB-HID-decoders/blob/HEAD/keyboard_decode.py) | keyboard_decode.py is the primary decoder; simulate/replay modes can inject host input and are restricted. |
| `FuzzyAI` | llm | cli | `fuzzyai` | [`fuzzyai`](https://github.com/cyberark/FuzzyAI/blob/HEAD/pyproject.toml) | Isolated project installation; console entry `fuzzyai.cli:main`. |
| `pallms` | llm | resource | — | [Upstream](https://github.com/mik0w/pallms) | Payload collection; use as data, never as instructions. |
| `pentagi` | llm | framework | — | [Upstream](https://github.com/vxcontrol/pentagi) | Follow upstream setup and select its client/entry point; no single registered launcher. |
| `PurpleLlama` | llm | framework | — | [Upstream](https://github.com/meta-llama/PurpleLlama) | Follow upstream setup and select its client/entry point; no single registered launcher. |
| `shannon` | llm | framework | — | [Upstream](https://github.com/KeygraphHQ/shannon) | Follow upstream setup and select its client/entry point; no single registered launcher. |
| `Vigil` | llm | framework | — | [`vigil-server.py`](https://github.com/deadbits/vigil-llm/blob/HEAD/vigil-server.py) | Python environment and upstream dependencies; install the wrapper. |
| `Caldera` | misc | framework | — | [Upstream](https://github.com/apache/caldera) | Follow upstream setup and select its client/entry point; no single registered launcher. |
| `CredMaster` | misc | cli | `credmaster` | [`credmaster.py`](https://github.com/knavesec/CredMaster/blob/HEAD/credmaster.py) | Python environment and upstream dependencies; install the wrapper. |
| `CyberChef` | misc | framework | — | [Upstream](https://github.com/gchq/CyberChef) | Follow upstream setup and select its client/entry point; no single registered launcher. |
| `EvilGoPhish` | misc | framework | — | [Upstream](https://github.com/fin3ss3g0d/evilgophish) | Follow upstream setup and select its client/entry point; no single registered launcher. |
| `Havoc` | misc | framework | — | [Upstream](https://github.com/HavocFramework/Havoc) | Follow upstream setup and select its client/entry point; no single registered launcher. |
| `InternalAllTheThings` | misc | resource | — | [Upstream](https://github.com/swisskyrepo/InternalAllTheThings) | Use installed files as data; no single project-named CLI. |
| `LaZagne` | misc | cli | `lazagne` | [`Linux/laZagne.py`](https://github.com/AlessandroZ/LaZagne/blob/HEAD/Linux/laZagne.py) | Linux/laZagne.py for Linux; other platforms have separate components. |
| `linux-smart-enumeration` | misc | cli | `linux-smart-enumeration` | [`lse.sh`](https://github.com/diego-treitos/linux-smart-enumeration/blob/HEAD/lse.sh) | Shell and upstream companion commands; install the wrapper. |
| `Loki-C2` | misc | framework | — | [Upstream](https://github.com/boku7/Loki) | Follow upstream setup and select its client/entry point; no single registered launcher. |
| `merlin` | misc | framework | — | [Upstream](https://github.com/Ne0nd0g/merlin) | Follow upstream setup and select its client/entry point; no single registered launcher. |
| `mimipenguin` | misc | cli | `mimipenguin` | [`mimipenguin.py`](https://github.com/huntergregal/mimipenguin/blob/HEAD/mimipenguin.py) | Python environment and upstream dependencies; install the wrapper. |
| `Modlishka` | misc | cli | `modlishka` | [`dist/proxy`](https://github.com/drk1wi/Modlishka/blob/HEAD/Makefile) | `make build`; Go; this target builds without invoking upstream tests. |
| `Mythic` | misc | framework | — | [Upstream](https://github.com/its-a-feature/Mythic) | Follow upstream setup and select its client/entry point; no single registered launcher. |
| `PayloadsAllTheThings` | misc | resource | — | [Upstream](https://github.com/swisskyrepo/PayloadsAllTheThings) | Use installed files as data; no single project-named CLI. |
| `PEASS-ng` | misc | resource | — | [Upstream](https://github.com/peass-ng/PEASS-ng) | Use installed files as data; no single project-named CLI. |
| `PoshC2` | misc | framework | — | [Upstream](https://github.com/nettitude/PoshC2) | Follow upstream setup and select its client/entry point; no single registered launcher. |
| `PyExfil` | misc | framework | — | [Upstream](https://github.com/ytisf/PyExfil) | Follow upstream setup and select its client/entry point; no single registered launcher. |
| `SecLists` | misc | resource | — | [Upstream](https://github.com/danielmiessler/SecLists) | Use installed files as data; no single project-named CLI. |
| `SET` | misc | cli | `set` | [`setoolkit`](https://github.com/trustedsec/social-engineer-toolkit/blob/HEAD/setoolkit) | Interactive setoolkit framework; runtime configuration and privileges may be required. |
| `SquarePhish` | misc | cli | `squarephish` | [`squish.py`](https://github.com/secureworks/squarephish/blob/HEAD/squish.py) | squish.py entry point; configured provider credentials and phishing scope required. |
| `SUDO_KILLER` | misc | cli | `sudo_killer` | [`SUDO_KILLERv3.sh`](https://github.com/TH3xACE/SUDO_KILLER/blob/HEAD/SUDO_KILLERv3.sh) | Shell and upstream companion commands; install the wrapper. |
| `usbkill` | misc | cli | `usbkill` | [`usbkill/usbkill.py`](https://github.com/hephaest0s/usbkill/blob/HEAD/usbkill/usbkill.py) | Full functionality requires its explicit USBKILL opt-in, configuration and host permissions. |
| `Zphisher` | misc | cli | `zphisher` | [`zphisher.sh`](https://github.com/htr-tech/zphisher/blob/HEAD/zphisher.sh) | Shell and upstream companion commands; install the wrapper. |
| `medusa-frida` | mobile | cli | `medusa-frida` | [`medusa.py`](https://github.com/Ch0pin/medusa/blob/HEAD/medusa.py) | Python environment and upstream dependencies; install the wrapper. |
| `bettercap` | networking | cli | `bettercap` | [`bettercap`](https://github.com/bettercap/bettercap/blob/HEAD/Makefile) | `make build`; Go, libpcap/libusb development dependencies; build resources before compiling. |
| `dnscat2` | networking | cli | `dnscat2` | [`server/dnscat2.rb`](https://github.com/iagox86/dnscat2/blob/HEAD/server/dnscat2.rb) | Ruby server/dnscat2.rb plus gems; separately built client and interactive service setup. |
| `dnschef` | networking | cli | `dnschef` | [`dnschef.py`](https://github.com/iphelix/dnschef/blob/HEAD/dnschef.py) | Python environment and upstream dependencies; install the wrapper. |
| `nipe` | networking | cli | `nipe` | [`nipe.pl`](https://github.com/htrgouvea/nipe/blob/HEAD/nipe.pl) | Full functionality requires its NIPE opt-in and OS permissions; network operations also need external opt-in. |
| `PRET` | networking | cli | `pret` | [`pret.py`](https://github.com/RUB-NDS/PRET/blob/HEAD/pret.py) | Python environment and upstream dependencies; install the wrapper. |
| `pwnat` | networking | cli | `pwnat` | [`pwnat`](https://github.com/samyk/pwnat/blob/HEAD/Makefile) | `make`; C compiler; raw socket privileges for active use. |
| `yersinia` | networking | cli | `yersinia` | [`src/yersinia`](https://github.com/tomac/yersinia/blob/HEAD/INSTALL) | `./autogen.sh --disable-gtk && make`; Autoconf/Automake, libpcap/libnet; CLI build omits GTK. |
| `DNSExfiltrator` | pwn | cli | `dnsexfiltrator` | [`dnsexfiltrator.py`](https://github.com/Arno0x/DNSExfiltrator/blob/HEAD/dnsexfiltrator.py) | Legacy Python 2 server; compatible interpreter/dependencies and DNS listener privileges. |
| `Egress-Assess` | pwn | cli | `egress-assess` | [`Egress-Assess.py`](https://github.com/RedSiege/Egress-Assess/blob/HEAD/Egress-Assess.py) | Python environment and upstream dependencies; install the wrapper. |
| `eviltree` | pwn | cli | `eviltree` | [`eviltree.py`](https://github.com/t3l3machus/eviltree/blob/HEAD/eviltree.py) | Python environment and upstream dependencies; install the wrapper. |
| `exploitdb` | pwn | cli | `searchsploit` | [`searchsploit`](https://gitlab.com/exploit-database/exploitdb/-/blob/main/searchsploit) | Install its interpreter/build dependencies and wrapper; runtime not exercised. |
| `Hoaxshell` | pwn | cli | `hoaxshell` | [`hoaxshell.py`](https://github.com/t3l3machus/hoaxshell/blob/HEAD/hoaxshell.py) | Python environment and upstream dependencies; install the wrapper. |
| `libc-database` | pwn | cli | `libc-database` | [`find`](https://github.com/niklasb/libc-database/blob/HEAD/find) | Offline find script queries the installed database; the toolkit wrapper avoids a system find alias collision. |
| `nanodump` | pwn | cli | `nanodump` | [Upstream](https://github.com/fortra/nanodump) | Build/run the Windows native executable on a compatible host; cloning is insufficient. |
| `Penelope` | pwn | cli | `penelope` | [`penelope.py`](https://github.com/brightio/penelope/blob/HEAD/penelope.py) | Python environment and upstream dependencies; install the wrapper. |
| `preeny` | pwn | framework | — | [Upstream](https://github.com/zardus/preeny) | LD_PRELOAD libraries; not a project-named executable. |
| `ropium` | pwn | cli | `ropium` | [`cli-tool/ropium`](https://github.com/Boyan-MILANOV/ropium/blob/HEAD/Makefile) | `make`; C++/Capstone/Python development dependencies, compiled bin/ropium.so and isolated prompt_toolkit/ROPgadget. The launcher supplies the module search path. |
| `RouterSploit` | pwn | cli | `routersploit` | [`rsf.py`](https://github.com/threat9/routersploit/blob/HEAD/rsf.py) | Python environment and upstream dependencies; install the wrapper. |
| `ShellNoob` | pwn | cli | `shellnoob` | [`shellnoob.py`](https://github.com/reyammer/shellnoob/blob/HEAD/shellnoob.py) | Python environment and upstream dependencies; install the wrapper. |
| `unicorn` | pwn | cli | `unicorn` | [`unicorn.py`](https://github.com/trustedsec/unicorn/blob/HEAD/unicorn.py) | Python environment and upstream dependencies; install the wrapper. |
| `Villain` | pwn | cli | `villain` | [`Villain.py`](https://github.com/t3l3machus/Villain/blob/HEAD/Villain.py) | Python environment and upstream dependencies; install the wrapper. |
| `axiom` | recon | framework | — | [Upstream](https://github.com/pry0cc/axiom) | Follow upstream setup and select its client/entry point; no single registered launcher. |
| `blackbird` | recon | cli | `blackbird` | [`blackbird.py`](https://github.com/antoniaci/blackbird/blob/HEAD/blackbird.py) | Python environment and upstream dependencies; install the wrapper. |
| `certSniff` | recon | cli | `certsniff` | [`certSniff.py`](https://github.com/A-poc/certSniff/blob/HEAD/certSniff.py) | certSniff.py subscribes to a public certificate-transparency stream. |
| `EyeWitness` | recon | cli | `eyewitness` | [`Python/EyeWitness.py`](https://github.com/RedSiege/EyeWitness/blob/HEAD/Python/EyeWitness.py) | Python environment and upstream dependencies; install the wrapper. |
| `FavFreak` | recon | cli | `favfreak` | [`favfreak.py`](https://github.com/devanshbatham/FavFreak/blob/HEAD/favfreak.py) | Python environment and upstream dependencies; install the wrapper. |
| `GooFuzz` | recon | cli | `goofuzz` | [`GooFuzz`](https://github.com/m3n0sd0n4ld/GooFuzz/blob/HEAD/GooFuzz) | Install its interpreter/build dependencies and wrapper; runtime not exercised. |
| `iKy` | recon | framework | — | [Upstream](https://github.com/kennbroorg/iKy) | Follow upstream setup and select its client/entry point; no single registered launcher. |
| `linkedin2username` | recon | cli | `linkedin2username` | [`linkedin2username.py`](https://github.com/initstring/linkedin2username/blob/HEAD/linkedin2username.py) | Python environment and upstream dependencies; install the wrapper. |
| `LinkFinder` | recon | cli | `linkfinder` | [`linkfinder.py`](https://github.com/GerbenJavado/LinkFinder/blob/HEAD/linkfinder.py) | Python environment and upstream dependencies; install the wrapper. |
| `nmapAutomator` | recon | cli | `nmapautomator` | [`nmapAutomator.sh`](https://github.com/21y4d/nmapAutomator/blob/HEAD/nmapAutomator.sh) | Shell and upstream companion commands; install the wrapper. |
| `osmedeus` | recon | cli | `osmedeus` | [`osmedeus`](https://github.com/j3ssie/osmedeus/blob/HEAD/Makefile) | `go build -o osmedeus ./cmd/osmedeus`; Go; the selected build avoids the upstream install-to-GOBIN step. |
| `Photon` | recon | cli | `photon` | [`photon.py`](https://github.com/s0md3v/Photon/blob/HEAD/photon.py) | Python environment and upstream dependencies; install the wrapper. |
| `recon-ng` | recon | cli | `recon-ng` | [`recon-ng`](https://github.com/lanmaster53/recon-ng/blob/HEAD/recon-ng) | Install its interpreter/build dependencies and wrapper; runtime not exercised. |
| `reconftw` | recon | cli | `reconftw` | [`reconftw.sh`](https://github.com/six2dez/reconftw/blob/HEAD/reconftw.sh) | Shell and upstream companion commands; install the wrapper. |
| `robin` | recon | service | — | [Upstream](https://github.com/apurvsinghgautam/robin) | Current upstream exposes Streamlit UI and an MCP service; no standalone robin executable. |
| `SecretFinder` | recon | cli | `secretfinder` | [`SecretFinder.py`](https://github.com/m4ll0k/SecretFinder/blob/HEAD/SecretFinder.py) | Python environment and upstream dependencies; install the wrapper. |
| `Sn1per` | recon | cli | `sn1per` | [`sniper`](https://github.com/1N3/Sn1per/blob/HEAD/sniper) | Install its interpreter/build dependencies and wrapper; runtime not exercised. |
| `spiderfoot` | recon | cli | `spiderfoot` | [`sf.py`](https://github.com/smicallef/spiderfoot/blob/HEAD/sf.py) | Python environment and upstream dependencies; install the wrapper. |
| `stringcheese` | recon | cli | `stringcheese` | [`stringcheese`](https://github.com/MathisHammel/stringcheese/blob/HEAD/setup.py) | Isolated project installation; console entry `stringcheese.stringcheese:main`. Compiles its bundled native extension. |
| `Telepathy` | recon | cli | `telepathy` | [`telepathy`](https://github.com/prose-intelligence-ltd/Telepathy-Community/blob/HEAD/setup.py) | Isolated project installation; console entry `telepathy.telepathy:cli`. |
| `theHarvester` | recon | cli | `theHarvester` | [`bin/theHarvester`](https://github.com/laramies/theHarvester/blob/HEAD/bin/theHarvester) | Install its interpreter/build dependencies and wrapper; runtime not exercised. |
| `vulscan` | recon | resource | — | [Upstream](https://github.com/scipag/vulscan) | Use installed files as data; no single project-named CLI. |
| `decomp2dbg` | reversing | framework | — | [Upstream](https://github.com/mahaloz/decomp2dbg) | Debugger/decompiler plugins; configure both sides. |
| `GEF` | reversing | framework | — | [Upstream](https://github.com/hugsy/gef) | GDB plugin; load through a configured debugger. |
| `Krakatau` | reversing | cli | `krakatau` | [`target/release/krak2`](https://github.com/Storyyeller/Krakatau/blob/HEAD/README.md) | `cargo build --release`; Rust toolchain supporting edition 2024; Java bytecode CLI. |
| `peda` | reversing | framework | — | [Upstream](https://github.com/longld/peda) | GDB plugin; load through a configured debugger. |
| `pwndbg` | reversing | framework | — | [Upstream](https://github.com/pwndbg/pwndbg) | GDB/LLDB integration; install the supported debugger front end before use. |
| `pyinstxtractor` | reversing | cli | `pyinstxtractor` | [`pyinstxtractor.py`](https://github.com/extremecoders-re/pyinstxtractor/blob/HEAD/pyinstxtractor.py) | Python environment and upstream dependencies; install the wrapper. |
| `Qiling` | reversing | cli | `qiling` | [`qltool`](https://github.com/qilingframework/qiling/blob/HEAD/qltool) | qltool front end plus emulator dependencies and an appropriate root filesystem. |
| `openstego` | stego | cli | `openstego` | [`build/libs/openstego.jar`](https://github.com/syvaidya/openstego/blob/HEAD/build.gradle) | `./gradlew jar`; JDK for build, Java runtime for CLI; GUI is optional. |
| `stegextract` | stego | cli | `stegextract` | [`stegextract`](https://github.com/evyatarmeged/stegextract/blob/HEAD/stegextract) | Install its interpreter/build dependencies and wrapper; runtime not exercised. |
| `stegosaurus` | stego | cli | `stegosaurus` | [`stegosaurus.py`](https://github.com/AngelKitty/stegosaurus/blob/HEAD/stegosaurus.py) | Python environment and upstream dependencies; install the wrapper. |
| `stegsolve` | stego | gui | — | [Upstream](https://github.com/Giotino/stegsolve) | Java desktop GUI; no reviewed non-interactive CLI. |
| `CMSmap` | web | cli | `cmsmap` | [`cmsmap.py`](https://github.com/dionach/CMSmap/blob/HEAD/cmsmap.py) | Python environment and upstream dependencies; install the wrapper. |
| `commix` | web | cli | `commix` | [`commix.py`](https://github.com/commixproject/commix/blob/HEAD/commix.py) | Python environment and upstream dependencies; install the wrapper. |
| `Corsy` | web | cli | `corsy` | [`corsy.py`](https://github.com/s0md3v/Corsy/blob/HEAD/corsy.py) | Python environment and upstream dependencies; install the wrapper. |
| `ghauri` | web | cli | `ghauri` | [`ghauri`](https://github.com/r0oth3x49/ghauri/blob/HEAD/setup.py) | Isolated project installation; console entry `ghauri.scripts.ghauri:main`. |
| `Gopherus` | web | cli | `gopherus` | [`gopherus.py`](https://github.com/tarunkant/Gopherus/blob/HEAD/gopherus.py) | Legacy Python 2 syntax; compatible interpreter and dependencies required. |
| `graphw00f` | web | cli | `graphw00f` | [`main.py`](https://github.com/dolevf/graphw00f/blob/HEAD/main.py) | Python environment and upstream dependencies; install the wrapper. |
| `h2csmuggler` | web | cli | `h2csmuggler` | [`h2csmuggler.py`](https://github.com/BishopFox/h2csmuggler/blob/HEAD/h2csmuggler.py) | Python environment and upstream dependencies; install the wrapper. |
| `jwt_tool` | web | cli | `jwt_tool` | [`jwt_tool.py`](https://github.com/ticarpi/jwt_tool/blob/HEAD/jwt_tool.py) | Python environment and upstream dependencies; install the wrapper. |
| `nikto` | web | cli | `nikto` | [`program/nikto.pl`](https://github.com/sullo/nikto/blob/HEAD/program/nikto.pl) | Perl and upstream modules; install the wrapper. |
| `NoSQLMap` | web | cli | `nosqlmap` | [`nosqlmap.py`](https://github.com/codingo/NoSQLMap/blob/HEAD/nosqlmap.py) | Legacy Python 2 syntax; compatible interpreter and dependencies required. |
| `Oralyzer` | web | cli | `oralyzer` | [`oralyzer`](https://github.com/r0075h3ll/Oralyzer/blob/HEAD/pyproject.toml) | Isolated project installation; console entry `oralyzer.cli:main`. |
| `PadBuster` | web | cli | `padbuster` | [`padBuster.pl`](https://github.com/strozfriedberg/PadBuster/blob/HEAD/padBuster.pl) | Perl and upstream modules; install the wrapper. |
| `paramspider` | web | cli | `paramspider` | [`paramspider`](https://github.com/devanshbatham/ParamSpider/blob/HEAD/setup.py) | Isolated project installation; console entry `paramspider.main:main`. |
| `phpggc` | web | cli | `phpggc` | [`phpggc`](https://github.com/ambionics/phpggc/blob/HEAD/phpggc) | Install its interpreter/build dependencies and wrapper; runtime not exercised. |
| `PhpSploit` | web | cli | `phpsploit` | [`phpsploit`](https://github.com/nil0x42/phpsploit/blob/HEAD/phpsploit) | Install its interpreter/build dependencies and wrapper; runtime not exercised. |
| `pp-finder` | web | cli | `pp-finder` | [`dist/cli.cjs`](https://github.com/yeswehack/pp-finder/blob/HEAD/Makefile) | `yarn install --immutable && yarn run build`; Node and the declared Yarn version; the launcher invokes Node for the compiled CLI. |
| `smuggler` | web | cli | `smuggler` | [`smuggler.py`](https://github.com/defparam/smuggler/blob/HEAD/smuggler.py) | Python environment and upstream dependencies; install the wrapper. |
| `SSRFmap` | web | cli | `ssrfmap` | [`ssrfmap.py`](https://github.com/swisskyrepo/SSRFmap/blob/HEAD/ssrfmap.py) | Python environment and upstream dependencies; install the wrapper. |
| `symfony-exploits` | web | suite | — | [`secret_fragment_exploit.py`](https://github.com/ambionics/symfony-exploits/blob/HEAD/secret_fragment_exploit.py) | Separate secret_fragment_exploit.py and symfony-secret-fragments-v2.py. |
| `testssl.sh` | web | cli | `testssl.sh` | [`testssl.sh`](https://github.com/testssl/testssl.sh/blob/HEAD/testssl.sh) | Shell and upstream companion commands; install the wrapper. |
| `tomcatwardeployer` | web | cli | `tomcatwardeployer` | [`tomcatWarDeployer.py`](https://github.com/mgeeky/tomcatwardeployer/blob/HEAD/tomcatWarDeployer.py) | Python environment and upstream dependencies; install the wrapper. |
| `tplmap` | web | cli | `tplmap` | [`tplmap.py`](https://github.com/epinna/tplmap/blob/HEAD/tplmap.py) | Python environment and upstream dependencies; install the wrapper. |
| `XSStrike` | web | cli | `xsstrike` | [`xsstrike.py`](https://github.com/s0md3v/XSStrike/blob/HEAD/xsstrike.py) | Python environment and upstream dependencies; install the wrapper. |
| `XXEinjector` | web | cli | `xxeinjector` | [`XXEinjector.rb`](https://github.com/enjoiz/XXEinjector/blob/HEAD/XXEinjector.rb) | Ruby and upstream gems; install the wrapper. |
| `airgeddon` | wireless | cli | `airgeddon` | [`airgeddon.sh`](https://github.com/v1s1t0r1sh3r3/airgeddon/blob/HEAD/airgeddon.sh) | Compatible wireless hardware/drivers and privileges; install/build its runtime. |
| `eaphammer` | wireless | cli | `eaphammer` | [`eaphammer`](https://github.com/s0lst1c3/eaphammer/blob/HEAD/eaphammer) | Compatible wireless hardware/drivers and privileges; install/build its runtime. |
| `fluxion` | wireless | cli | `fluxion` | [`fluxion.sh`](https://github.com/FluxionNetwork/fluxion/blob/HEAD/fluxion.sh) | Compatible wireless hardware/drivers and privileges; install/build its runtime. |
| `hostapd-mana` | wireless | cli | `hostapd-mana` | [`hostapd/hostapd`](https://github.com/sensepost/hostapd-mana/blob/HEAD/hostapd/Makefile) | `make -C hostapd`; Create hostapd/.config from defconfig only when absent; libnl/OpenSSL development dependencies and wireless runtime. |
| `libnfc-crypto1-crack` | wireless | cli | `libnfc-crypto1-crack` | [`miLazyCracker.sh`](https://github.com/SnoopyTools/acr122uNFC/blob/HEAD/miLazyCracker.sh) | miLazyCracker.sh requires NFC hardware and the upstream MiFare cracking environment. |
| `mfdread` | wireless | cli | `mfdread` | [`mfdread.py`](https://github.com/zhovner/mfdread/blob/HEAD/mfdread.py) | mfdread.py parses an existing MIFARE dump; file analysis needs no attached reader. |
| `mousejack` | wireless | framework | — | [Upstream](https://github.com/BastilleResearch/mousejack) | Multiple hardware-specific scripts/firmware components, not one launcher. |
| `proxmark3` | wireless | cli | `proxmark3` | [`client/proxmark3`](https://github.com/RfidResearchGroup/proxmark3/blob/HEAD/Makefile) | `make client`; Native client dependencies and runtime assets; supported RFID device for hardware operations. |
| `PSKracker` | wireless | cli | `pskracker` | [`pskracker`](https://github.com/andrewjlamarche/PSKracker/blob/HEAD/Makefile) | `make`; C compiler; offline candidate generation. |
| `wifiphisher` | wireless | cli | `wifiphisher` | [`bin/wifiphisher`](https://github.com/wifiphisher/wifiphisher/blob/HEAD/bin/wifiphisher) | Compatible wireless hardware/drivers and privileges; install/build its runtime. |
| `wifipumpkin3` | wireless | cli | `wifipumpkin3` | [`wifipumpkin3 / wp3`](https://github.com/P0cL4bs/wifipumpkin3/blob/HEAD/setup.py) | Isolated project installation; console entry `wifipumpkin3.__main__:main`. |
| `wifite2` | wireless | cli | `wifite2` | [`Wifite.py`](https://github.com/derv82/wifite2/blob/HEAD/Wifite.py) | Compatible wireless hardware/drivers and privileges; install/build its runtime. |

## Source-build launchers

Every one of the 25 source-method registry entries declares executable outputs in its module `BUILD_BINS` metadata. A successful compilation must produce those executable files before setup can publish them to PATH; a cloned tree alone is insufficient. Build and lifecycle operations share that metadata. ELFkickers also publishes `elfls`, `objres`, `rebind`, `elftoc`, `ebfc` and `infect`; pycdc also publishes `pycdas`.

YAFU uses the current unified `Makefile` target `yafu`; the removed `Makefile.gcc` is not a valid build route. AzureHound uses an explicit lowercase output name so Go module capitalization cannot change the launcher. These mappings were inspected against the linked source and module build declarations; the upstream builds were not executed.

| Tool | Primary launcher | Artifact inside the source tree | Evidence |
| --- | --- | --- | --- |
| `AFLplusplus` | `afl-fuzz` | `afl-fuzz` | [Build declaration](https://github.com/AFLplusplus/AFLplusplus/blob/HEAD/GNUmakefile) |
| `azurehound` | `azurehound` | `azurehound` | [Build declaration](https://github.com/SpecterOps/AzureHound/blob/HEAD/go.mod) |
| `Donut` | `donut` | `donut` | [Build declaration](https://github.com/TheWover/donut/blob/HEAD/Makefile) |
| `duplicut` | `duplicut` | `duplicut` | [Build declaration](https://github.com/nil0x42/duplicut/blob/HEAD/Makefile) |
| `ELFkickers` | `sstrip` | `bin/sstrip` | [Build declaration](https://github.com/BR903/ELFkickers/blob/HEAD/Makefile) |
| `fastcoll` | `fastcoll` | `fastcoll` | [Build declaration](https://github.com/upbit/clone-fastcoll/blob/HEAD/Makefile) |
| `Freeze` | `Freeze` | `Freeze` | [Build declaration](https://github.com/Tylous/Freeze/blob/HEAD/README.md) |
| `GoExec` | `GoExec` | `GoExec` | [Build declaration](../modules/enterprise.sh) |
| `GoMapEnum` | `GoMapEnum` | `GoMapEnum` | [Build declaration](../modules/enterprise.sh) |
| `gosecretsdump` | `gosecretsdump` | `gosecretsdump` | [Build declaration](https://github.com/c-sto/gosecretsdump/blob/HEAD/go.mod) |
| `hash_extender` | `hash_extender` | `hash_extender` | [Build declaration](https://github.com/iagox86/hash_extender/blob/HEAD/Makefile) |
| `honggfuzz` | `honggfuzz` | `honggfuzz` | [Build declaration](https://github.com/google/honggfuzz/blob/HEAD/Makefile) |
| `Ivy` | `Ivy` | `Ivy` | [Build declaration](https://github.com/optiv/Ivy/blob/HEAD/README.md) |
| `kernel-hardening-checker` | `kernel-hardening-checker` | `.venv/bin/kernel-hardening-checker` | [Build declaration](../modules/blueteam.sh) |
| `massdns` | `massdns` | `bin/massdns` | [Build declaration](https://github.com/blechschmidt/massdns/blob/HEAD/Makefile) |
| `pemcrack` | `pemcrack` | `bin/pemcrack` | [Build declaration](https://github.com/robertdavidgraham/pemcrack/blob/HEAD/Makefile) |
| `PkCrack` | `pkcrack` | `bin/pkcrack` | [Build declaration](https://github.com/keyunluo/pkcrack/blob/HEAD/CMakeLists.txt) |
| `pycdc` | `pycdc` | `build/pycdc` | [Build declaration](../modules/reversing.sh) |
| `QueenSono` | `QueenSono` | `QueenSono` | [Build declaration](https://github.com/ariary/QueenSono/blob/HEAD/README.md) |
| `radamsa` | `radamsa` | `bin/radamsa` | [Build declaration](https://gitlab.com/akihe/radamsa/-/blob/master/Makefile) |
| `rappel` | `rappel` | `bin/rappel` | [Build declaration](https://github.com/yrp604/rappel/blob/HEAD/Makefile) |
| `rusthound` | `rusthound` | `target/release/rusthound` | [Build declaration](https://github.com/NH-RED-TEAM/RustHound/blob/HEAD/Cargo.toml) |
| `rusthound-ce` | `rusthound-ce` | `target/release/rusthound-ce` | [Build declaration](https://github.com/g0h4n/RustHound-CE/blob/HEAD/Cargo.toml) |
| `ScareCrow` | `ScareCrow` | `ScareCrow` | [Build declaration](https://github.com/optiv/ScareCrow/blob/HEAD/README.md) |
| `yafu` | `yafu` | `yafu` | [Build declaration](https://github.com/bbuhrow/yafu/blob/HEAD/Makefile) |

## Maintenance checks

### Installation-method migrations

[`scripts/stale_artefacts.sh`](../scripts/stale_artefacts.sh) is shared migration code for older installations: commix's former pipx environment, the former manspider package name and apktool's former Git clone. These can otherwise shadow the current CLI or leave misleading `.versions` records. `install.sh` runs it before installing replacements; full `remove.sh` uses it for provenance, dry-run output and cleanup. `update.sh` preserves these installations until the installer can replace them.

The helper is source code, not a generated artifact to delete. Its logic could be moved to another shared file, but removing it alone breaks its callers. Installations without a matching old-method record and records explicitly marked `existing` are kept; dirty clones/worktrees and those whose Git status cannot be read are also kept. Install-record write failures are reported instead of claiming successful cleanup.

When adding or changing a git tool, keep its installer launcher, `GIT_BIN_NAMES`, known native aliases, network classification and argument policy consistent. Classify non-CLI catalog entries explicitly and preserve their usable access route. Add regression coverage for the local/remote/pipeline invocation affected by the change and for scope or argument bypasses.

Run the focused MCP tests, installer launcher tests, `scripts/validate_mcp_sync.py`, `scripts/validate_tools_config.py --strict`, formatting/lint checks and the relevant repository validators. A source update can change command names or runtimes, so repeat the upstream entry-point check when these mappings change.
