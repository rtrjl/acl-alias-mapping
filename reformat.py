import re

regex = r"^\s+(\S+)\s+.+\((\d+)"

test_str = (
    "  bgp          Border Gateway Protocol (179)\n"
    "  chargen      Character generator (19)\n"
    "  cmd          Remote commands (rcmd, 514)\n"
    "  daytime      Daytime (13)\n"
    "  discard      Discard (9)\n"
    "  domain       Domain Name Service (53)\n"
    "  echo         Echo (7)\n"
    "  exec         Exec (rsh, 512)\n"
    "  finger       Finger (79)\n"
    "  ftp          File Transfer Protocol (21)\n"
    "  ftp-data     FTP data connections (20)\n"
    "  gopher       Gopher (70)\n"
    "  hostname     NIC hostname server (101)\n"
    "  ident        Ident Protocol (113)\n"
    "  irc          Internet Relay Chat (194)\n"
    "  klogin       Kerberos login (543)\n"
    "  kshell       Kerberos shell (544)\n"
    "  login        Login (rlogin, 513)\n"
    "  lpd          Printer service (515)\n"
    "  msrpc        MS Remote Procedure Call (135)\n"
    "  nntp         Network News Transport Protocol (119)\n"
    "  onep-plain   Onep Cleartext (15001)\n"
    "  onep-tls     Onep TLS (15002)\n"
    "  pim-auto-rp  PIM Auto-RP (496)\n"
    "  pop2         Post Office Protocol v2 (109)\n"
    "  pop3         Post Office Protocol v3 (110)\n"
    "  smtp         Simple Mail Transport Protocol (25)\n"
    "  sunrpc       Sun Remote Procedure Call (111)\n"
    "  syslog       Syslog (514)\n"
    "  tacacs       TAC Access Control System (49)\n"
    "  talk         Talk (517)\n"
    "  telnet       Telnet (23)\n"
    "  time         Time (37)\n"
    "  uucp         Unix-to-Unix Copy Program (540)\n"
    "  whois        Nicname (43)\n"
    "  www          World Wide Web (HTTP, 80)"
)

matches = re.finditer(regex, test_str, re.MULTILINE)

aliases = dict()
for match in matches:
    aliases[match.group(2)] = match.group(1)

print(aliases)

for matchNum, match in enumerate(matches, start=1):

    print(
        "Match {matchNum} was found at {start}-{end}: {match}".format(
            matchNum=matchNum, start=match.start(), end=match.end(), match=match.group()
        )
    )

    for groupNum in range(0, len(match.groups())):
        groupNum = groupNum + 1

        print(
            "Group {groupNum} found at {start}-{end}: {group}".format(
                groupNum=groupNum,
                start=match.start(groupNum),
                end=match.end(groupNum),
                group=match.group(groupNum),
            )
        )
