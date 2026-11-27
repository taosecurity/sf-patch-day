# SPDX-License-Identifier: MIT
# SPDX-FileCopyrightText: 2026 Richard Bejtlich
"""risk: what a DLL's imports say it can call, sorted into four kinds of evidence.

The four kinds are network, process launch, runtime DLL loading and code patching. An import shows what the DLL
can call, not what it does: this is evidence for a reader, never a verdict, and it never changes a verdict or an
exit code. Only names from the fixed tables below (and ordinals as numbers) are ever printed, so no text from the
DLL reaches the terminal through this module. Names are matched exactly, in any imported DLL (API-set DLLs such
as api-ms-win-core-processthreads-l1-1-0.dll make the DLL name unreliable), except network, which goes by DLL name.
"""
import re

from . import log, pe

KINDS = ("network", "process_launch", "dll_loading", "code_patching")
LABELS = {"network": "network", "process_launch": "process launch", "dll_loading": "runtime DLL loading",
          "code_patching": "code patching"}
SHOWN = 4  # names shown per kind (per DLL for network) before "+N more"

NETWORK_DLLS = ("ws2_32.dll", "wsock32.dll", "mswsock.dll", "winhttp.dll", "wininet.dll", "urlmon.dll",
                "dnsapi.dll", "httpapi.dll", "websocket.dll")
# Winsock's fixed ordinals (ws2_32.dll and wsock32.dll share 1-23 and 51-57; the rest are ws2_32's).
WS_ORDINALS = {
    1: "accept", 2: "bind", 3: "closesocket", 4: "connect", 5: "getpeername", 6: "getsockname", 7: "getsockopt",
    8: "htonl", 9: "htons", 10: "ioctlsocket", 11: "inet_addr", 12: "inet_ntoa", 13: "listen", 14: "ntohl",
    15: "ntohs", 16: "recv", 17: "recvfrom", 18: "select", 19: "send", 20: "sendto", 21: "setsockopt",
    22: "shutdown", 23: "socket", 51: "gethostbyaddr", 52: "gethostbyname", 53: "getprotobyname",
    54: "getprotobynumber", 55: "getservbyname", 56: "getservbyport", 57: "gethostname", 101: "WSAAsyncSelect",
    111: "WSAGetLastError", 112: "WSASetLastError", 115: "WSAStartup", 116: "WSACleanup", 151: "__WSAFDIsSet"}
_AW = lambda *names: tuple(n + s for n in names for s in "AW")  # noqa: E731
NETWORK_FUNCS = frozenset(WS_ORDINALS.values()) | frozenset((
    "getaddrinfo", "freeaddrinfo", "GetAddrInfoW", "GetAddrInfoExW", "FreeAddrInfoW", "getnameinfo", "GetNameInfoW",
    "inet_pton", "inet_ntop", "InetPtonW", "InetNtopW", "WSAConnect", "WSASend", "WSASendTo", "WSARecv",
    "WSARecvFrom", "WSAIoctl", "WSAPoll", "WSAEventSelect", "WSAAsyncSelect", "WSACreateEvent", "WSACloseEvent",
    "WSAWaitForMultipleEvents", "WSAEnumNetworkEvents", "WSASetLastError", "WSAGetOverlappedResult", "AcceptEx",
    "GetAcceptExSockaddrs", "TransmitFile", "WSARecvEx",
    "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest", "WinHttpReceiveResponse",
    "WinHttpReadData", "WinHttpWriteData", "WinHttpQueryHeaders", "WinHttpQueryDataAvailable", "WinHttpCloseHandle",
    "WinHttpSetOption", "WinHttpCrackUrl", "WinHttpSetTimeouts", "WinHttpAddRequestHeaders",
    "WinHttpWebSocketCompleteUpgrade", "WinHttpWebSocketSend", "WinHttpWebSocketReceive",
    "InternetReadFile", "InternetWriteFile", "InternetCloseHandle", "InternetGetConnectedState",
    "DnsQuery_A", "DnsQuery_W", "DnsQuery_UTF8", "DnsQueryEx", "DnsRecordListFree", "DnsFree",
    "HttpInitialize", "HttpTerminate", "HttpCreateHttpHandle", "HttpCreateServerSession", "HttpCloseServerSession",
    "HttpCreateUrlGroup", "HttpAddUrl", "HttpAddUrlToUrlGroup", "HttpReceiveHttpRequest", "HttpSendHttpResponse",
    "HttpSendResponseEntityBody",
    "WebSocketCreateClientHandle", "WebSocketCreateServerHandle", "WebSocketBeginClientHandshake",
    "WebSocketEndClientHandshake", "WebSocketSend", "WebSocketReceive", "WebSocketGetAction",
    "WebSocketCompleteAction", "WebSocketDeleteHandle", "WebSocketAbortHandle")
    + _AW("WSASocket", "WSAAddressToString", "WSAStringToAddress", "InternetOpen", "InternetConnect",
          "InternetOpenUrl", "InternetCrackUrl", "InternetSetOption", "InternetQueryOption", "InternetCheckConnection",
          "HttpOpenRequest", "HttpSendRequest", "HttpQueryInfo", "FtpOpenFile", "FtpGetFile", "FtpPutFile",
          "URLDownloadToFile", "URLDownloadToCacheFile", "URLOpenStream", "URLOpenBlockingStream"))

SHELL = _AW("ShellExecute", "ShellExecuteEx")
PROCESS = _AW("CreateProcess", "CreateProcessAsUser") + ("CreateProcessWithLogonW", "CreateProcessWithTokenW",
                                                         "WinExec") + SHELL + (
    "system", "_wsystem", "_popen", "_wpopen") + tuple(
    f"_{w}{fam}{suffix}" for fam in ("exec", "spawn") for w in ("", "w")
    for suffix in ("l", "le", "lp", "lpe", "v", "ve", "vp", "vpe"))
LOADING = _AW("LoadLibrary", "LoadLibraryEx") + ("LoadPackagedLibrary", "LdrLoadDll", "GetProcAddress")
CRT_LOADING = ("LoadLibraryExW", "GetProcAddress")  # the static C runtime imports these itself
PATCH_OWN = ("VirtualProtect", "NtProtectVirtualMemory", "ZwProtectVirtualMemory", "FlushInstructionCache")
COMMON_PATCH = ("VirtualProtect", "FlushInstructionCache")
PATCH_OTHER = ("VirtualProtectEx", "WriteProcessMemory", "NtWriteVirtualMemory", "ZwWriteVirtualMemory",
               "VirtualAllocEx", "CreateRemoteThread", "CreateRemoteThreadEx")
# Text that code-patching libraries leave: Xbyak's RTTI names and MinHook's status names. Bounded, so linear.
PATCH_TEXT = (("Xbyak", re.compile(rb"\.\?A[VUW][A-Za-z0-9_@?$]{1,200}@Xbyak@@")),
              ("MinHook", re.compile(rb"MH_ERROR_[A-Z_]{3,40}")))

ORDINAL = re.compile(r"#\d{1,5}")  # how pe.PE.imports names an import by ordinal

NOTE_SHELL ="also opens web pages and folders"
NOTE_CRT = "the C runtime imports these itself"
NOTE_PATCH = "most SFSE plugins have this (SFSE's hooks need it)"


def clean(name):
    """A name from the file, safe to show: every character outside [A-Za-z0-9_.-] as \\xNN."""
    return re.sub(r"[^A-Za-z0-9_.-]", lambda m: f"\\x{ord(m.group(0)):02x}", name)


def _plural(n, one, many):
    return f"{n} {one if n == 1 else many}"


def imports_summary(entries, skipped, stopped=None):
    """The JSON 'imports' part: DLL names (cleaned), function count, delay-loaded DLLs and the problem, if any
    (damaged entries skipped, and why reading stopped early: pe.PE.imports' third value)."""
    names = list(dict.fromkeys(clean(dll) for dll, _f, _d in entries))
    delayed = list(dict.fromkeys(clean(dll) for dll, _f, d in entries if d))
    problem = ([_plural(skipped, "entry", "entries") + " skipped"] if skipped else []) + ([stopped] if stopped else [])
    return {"dlls": names, "count": sum(len(f) for _d, f, _x in entries), "delayed": delayed,
            "problem": "; ".join(problem) or None}


def assess(entries, data=b""):
    """The four kinds for one DLL's imports (from pe.PE.imports) and its bytes (for the patching-library text)."""
    have = {}  # table function name -> first DLL (cleaned) it was imported from
    network = {}  # network DLL (table name) -> [(shown name or '#n')], unlisted count
    for dll, funcs, _delayed in entries:
        key = dll if dll.endswith(".dll") else dll + ".dll"
        net = key if key in NETWORK_DLLS else None
        if net:
            shown, unlisted = network.setdefault(net, ([], [0]))
        for f in funcs:
            if net:
                name, ordinal = f, ORDINAL.fullmatch(f)
                if ordinal and net in ("ws2_32.dll", "wsock32.dll"):
                    name = WS_ORDINALS.get(int(f[1:]), f)
                if name in NETWORK_FUNCS or ordinal:  # an ordinal is shown as our own '#n' (digits only)
                    if name not in shown:
                        shown.append(name)
                else:
                    unlisted[0] += 1
            have.setdefault(f, clean(dll))

    def found(table):
        return [n for n in table if n in have]

    def tagged(names):
        return [f"{have[n]}!{n}" for n in names]

    proc, load, own, other = found(PROCESS), found(LOADING), found(PATCH_OWN), found(PATCH_OTHER)
    text = [name for name, rx in PATCH_TEXT if data and rx.search(data)]
    return {
        "network": {"imports": [f"{dll}!{n}" for dll, (shown, _u) in network.items() for n in shown],
                    "unlisted": {dll: u[0] for dll, (_s, u) in network.items() if u[0]},
                    "dlls": list(network), "note": None},
        "process_launch": {"imports": tagged(proc),
                           "note": NOTE_SHELL if proc and all(n in SHELL for n in proc) else None},
        "dll_loading": {"imports": tagged(load),
                        "note": NOTE_CRT if load and all(n in CRT_LOADING for n in load) else None},
        "code_patching": {"imports": tagged(own), "other_process": tagged(other), "text": text,
                          "note": NOTE_PATCH if own and all(n in COMMON_PATCH for n in own) and not other
                          and not text else None},
    }


def found_kinds(risk):
    """The kinds with any evidence, in KINDS order."""
    out = []
    for k in KINDS:
        r = risk[k]
        if r["imports"] or (k == "network" and r["dlls"]) or r.get("other_process") or r.get("text"):
            out.append(k)
    return out


def _names(tagged):
    """'dll!name' -> 'name', for the text line."""
    return [t.rsplit("!", 1)[1] for t in tagged]


def _cut(names, extra=0):
    shown = names[:SHOWN]
    more = len(names) - len(shown) + extra
    return ", ".join(shown + ([f"+{more} more"] if more else []))


def text_line(risk, problem=None):
    """The 'risk evidence' line under one DLL in the text report."""
    parts = []
    for k in found_kinds(risk):
        r = risk[k]
        if k == "network":
            groups = []
            for dll in r["dlls"]:
                names = [t.rsplit("!", 1)[1] for t in r["imports"] if t.rsplit("!", 1)[0] == dll]
                unlisted = r["unlisted"].get(dll, 0)
                if names:
                    groups.append(f"{dll}: {_cut(names, unlisted)}")
                elif unlisted:
                    groups.append(f"{dll}: {_plural(unlisted, 'function', 'functions')}")
                else:
                    groups.append(dll)
            inner = "; ".join(groups)
        elif k == "code_patching":
            bits = [_cut(_names(r["imports"]))] if r["imports"] else []
            if r["other_process"]:
                bits.append("other processes: " + _cut(_names(r["other_process"])))
            if r["text"]:
                bits.append("text: " + ", ".join(r["text"]))
            inner = "; ".join(bits)
        else:
            inner = _cut(_names(r["imports"]))
        parts.append(f"{LABELS[k]} ({inner})" + (f" [{r['note']}]" if r["note"] else ""))
    none = "none of the four kinds in the imports read" if problem else "none of the four kinds in its imports"
    line = "    risk evidence (not a verdict): " + ("; ".join(parts) or none)
    if problem:
        line += f" (import table not fully read: {problem})"
    return line


def summary_line(counts, read, not_full=0):
    """The 'Risk evidence:' summary; not_full = DLLs whose import table wasn't fully read."""
    return ("Risk evidence: " + ", ".join(f"{LABELS[k]} {counts[k]}" for k in KINDS) +
            f" (of {_plural(read, 'DLL', 'DLLs')} read" +
            (f"; {not_full} with the import table not fully read" if not_full else "") + ")")


def read(data, label):
    """(imports summary, risk) for one readable DLL's bytes. Raises pe.PEError when it isn't a program file."""
    entries, skipped, stopped = pe.PE(data, label).imports()
    summary, risk = imports_summary(entries, skipped, stopped), assess(entries, data)
    log.info("risk", f"{label}: {len(entries)} import DLL entries, {summary['count']} functions, "
                     f"{skipped} skipped{'; ' + stopped if stopped else ''}; "
                     f"kinds: {', '.join(found_kinds(risk)) or 'none'}")
    return summary, risk
