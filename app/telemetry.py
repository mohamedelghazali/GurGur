from __future__ import annotations
import hashlib, io, ipaddress, json, socket
from datetime import datetime, timezone
from typing import Any
import dpkt

MAX_TEXT_BYTES = 16 * 1024 * 1024
MAX_PCAP_BYTES = 64 * 1024 * 1024
MAX_EVENTS_PER_IMPORT = 10_000
MAX_PCAP_PACKETS = 100_000
SUPPORTED_ZEEK_LOGS = {"conn", "dns", "http"}

class TelemetryInputError(ValueError):
    pass

def _timestamp(value: Any) -> str | None:
    if value in (None, "", "-"): return None
    try:
        number = float(value)
        if number < 0: return None
        return datetime.fromtimestamp(number, timezone.utc).isoformat(timespec="milliseconds")
    except (TypeError, ValueError, OverflowError, OSError):
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if parsed.tzinfo is None: parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds")
        except ValueError: return None

def _safe_ip(value: Any) -> str | None:
    if not isinstance(value, str) or value in ("", "-"): return None
    try: return str(ipaddress.ip_address(value))
    except ValueError: return None

def _base(source: str, event_type: str, timestamp: str | None, fields: dict[str, Any]) -> dict[str, Any]:
    return {"schema_version": 1, "source": source, "event_type": event_type, "timestamp": timestamp, "fields": fields}

def _zeek_unescape(value: str) -> str:
    out=[]; i=0
    while i<len(value):
        if value[i]=="\\" and i+1<len(value):
            c=value[i+1]
            if c=="x" and i+3<len(value):
                try: out.append(chr(int(value[i+2:i+4],16))); i+=4; continue
                except ValueError: pass
            repl={"t":"\t","n":"\n","r":"\r","\\":"\\"}
            if c in repl: out.append(repl[c]); i+=2; continue
        out.append(value[i]); i+=1
    return "".join(out)

def _int(value):
    try: return int(value) if value not in (None,"","-") else None
    except (TypeError,ValueError): return None

def _float(value):
    try:
        v=float(value) if value not in (None,"","-") else None
        return v if v is not None and v>=0 else None
    except (TypeError,ValueError): return None

def _str(value, limit):
    return value[:limit] if isinstance(value,str) and value not in ("","-") else None

def parse_zeek(data: bytes, log_type: str) -> list[dict[str, Any]]:
    if log_type not in SUPPORTED_ZEEK_LOGS: raise TelemetryInputError("Supported Zeek logs are conn, dns, and http.")
    if len(data)>MAX_TEXT_BYTES: raise TelemetryInputError("Zeek input exceeds the 16 MiB limit.")
    try: text=data.decode("utf-8-sig")
    except UnicodeDecodeError as exc: raise TelemetryInputError("Zeek log must be UTF-8 text.") from exc
    sep="\t"; unset="-"; empty="(empty)"; columns=None; events=[]
    for n,line in enumerate(text.splitlines(),1):
        if not line: continue
        if line.startswith("#separator "): sep=_zeek_unescape(line[len("#separator "):]); continue
        if line.startswith("#empty_field "): empty=_zeek_unescape(line[len("#empty_field "):]); continue
        if line.startswith("#unset_field "): unset=_zeek_unescape(line[len("#unset_field "):]); continue
        if line.startswith("#fields"): columns=line.split("\t")[1:]; continue
        if line.startswith("#") or columns is None: continue
        vals=[_zeek_unescape(x) for x in line.split(sep)]
        if len(vals)!=len(columns): raise TelemetryInputError(f"Zeek line {n} has an invalid field count.")
        row={k:(None if v==unset else "" if v==empty else v) for k,v in zip(columns,vals)}
        ts=_timestamp(row.get("ts"))
        if ts is None: raise TelemetryInputError(f"Zeek line {n} has an invalid timestamp.")
        if log_type=="conn":
            kind="connection"; f={"uid":row.get("uid"),"src_ip":_safe_ip(row.get("id.orig_h")),"src_port":_int(row.get("id.orig_p")),"dest_ip":_safe_ip(row.get("id.resp_h")),"dest_port":_int(row.get("id.resp_p")),"proto":row.get("proto"),"service":row.get("service"),"duration":_float(row.get("duration")),"orig_bytes":_int(row.get("orig_bytes")),"resp_bytes":_int(row.get("resp_bytes")),"conn_state":row.get("conn_state")}
        elif log_type=="dns":
            kind="dns"; answers=row.get("answers"); f={"uid":row.get("uid"),"src_ip":_safe_ip(row.get("id.orig_h")),"dest_ip":_safe_ip(row.get("id.resp_h")),"query":_str(row.get("query"),253),"qtype_name":row.get("qtype_name"),"rcode_name":row.get("rcode_name"),"answers":[str(x)[:253] for x in str(answers).split(",")[:20]] if answers not in (None,"","-") else None}
        else:
            kind="http"; f={"uid":row.get("uid"),"src_ip":_safe_ip(row.get("id.orig_h")),"dest_ip":_safe_ip(row.get("id.resp_h")),"method":_str(row.get("method"),16),"host":_str(row.get("host"),253),"status_code":_int(row.get("status_code")),"status_msg":_str(row.get("status_msg"),128)}
        events.append(_base("zeek",kind,ts,{k:v for k,v in f.items() if v is not None}))
        if len(events)>MAX_EVENTS_PER_IMPORT: raise TelemetryInputError("Import exceeds the 10,000-event limit.")
    if columns is None: raise TelemetryInputError("Zeek #fields header was not found.")
    return events

def parse_suricata(data: bytes) -> list[dict[str, Any]]:
    if len(data)>MAX_TEXT_BYTES: raise TelemetryInputError("Suricata input exceeds the 16 MiB limit.")
    try: text=data.decode("utf-8-sig")
    except UnicodeDecodeError as exc: raise TelemetryInputError("Suricata EVE input must be UTF-8 JSON Lines.") from exc
    events=[]
    for n,line in enumerate(text.splitlines(),1):
        if not line.strip(): continue
        try: row=json.loads(line)
        except json.JSONDecodeError as exc: raise TelemetryInputError(f"Invalid Suricata JSON on line {n}.") from exc
        if not isinstance(row,dict) or not isinstance(row.get("event_type"),str): raise TelemetryInputError(f"Suricata line {n} is not an EVE object.")
        kind=row["event_type"]
        if kind not in {"alert","flow","dns","http","tls"}: continue
        f={"src_ip":_safe_ip(row.get("src_ip")),"src_port":_int(row.get("src_port")),"dest_ip":_safe_ip(row.get("dest_ip")),"dest_port":_int(row.get("dest_port")),"proto":_str(row.get("proto"),16),"app_proto":_str(row.get("app_proto"),32)}
        detail=row.get(kind) if isinstance(row.get(kind),dict) else {}
        if kind=="alert": f.update({"signature":_str(detail.get("signature"),256),"category":_str(detail.get("category"),128),"severity":_int(detail.get("severity")),"signature_id":_int(detail.get("signature_id")),"action":_str(detail.get("action"),32)})
        elif kind=="dns": f.update({"rrname":_str(detail.get("rrname"),253),"rrtype":_str(detail.get("rrtype"),16),"rcode":_str(detail.get("rcode"),16)})
        elif kind=="http": f.update({"hostname":_str(detail.get("hostname"),253),"http_method":_str(detail.get("http_method"),16),"status":_int(detail.get("status"))})
        elif kind=="tls": f.update({"sni":_str(detail.get("sni"),253),"version":_str(detail.get("version"),32)})
        elif kind=="flow": f.update({"pkts_toserver":_int(detail.get("pkts_toserver")),"pkts_toclient":_int(detail.get("pkts_toclient")),"bytes_toserver":_int(detail.get("bytes_toserver")),"bytes_toclient":_int(detail.get("bytes_toclient")),"state":_str(detail.get("state"),32)})
        ts=_timestamp(row.get("timestamp"))
        if ts is None: raise TelemetryInputError(f"Suricata line {n} has an invalid timestamp.")
        events.append(_base("suricata",kind,ts,{k:v for k,v in f.items() if v is not None}))
        if len(events)>MAX_EVENTS_PER_IMPORT: raise TelemetryInputError("Import exceeds the 10,000-event limit.")
    return events

def parse_pcap(data: bytes) -> list[dict[str, Any]]:
    """Offline metadata-only PCAP parser. It never opens a network socket."""
    if len(data)>MAX_PCAP_BYTES: raise TelemetryInputError("PCAP input exceeds the 64 MiB limit.")
    if len(data)<4: raise TelemetryInputError("PCAP file is truncated.")
    try:
        stream=io.BytesIO(data)
        reader=dpkt.pcapng.Reader(stream) if data[:4]==b"\x0a\x0d\x0d\x0a" else dpkt.pcap.Reader(stream)
        if reader.datalink()!=dpkt.pcap.DLT_EN10MB: raise TelemetryInputError("Only Ethernet-link PCAP/PCAPNG captures are supported.")
        events=[]
        for index,(stamp,frame) in enumerate(reader):
            if index>=MAX_PCAP_PACKETS: raise TelemetryInputError("PCAP exceeds the 100,000-packet limit.")
            try:
                packet=dpkt.ethernet.Ethernet(frame).data
                if isinstance(packet,dpkt.ip.IP): src=socket.inet_ntop(socket.AF_INET,packet.src); dst=socket.inet_ntop(socket.AF_INET,packet.dst); proto=packet.p; transport=packet.data
                elif isinstance(packet,dpkt.ip6.IP6): src=socket.inet_ntop(socket.AF_INET6,packet.src); dst=socket.inet_ntop(socket.AF_INET6,packet.dst); proto=packet.nxt; transport=packet.data
                else: continue
                f={"src_ip":src,"dest_ip":dst,"ip_protocol":int(proto),"captured_length":len(frame)}
                if isinstance(transport,dpkt.tcp.TCP): f.update({"protocol":"tcp","src_port":int(transport.sport),"dest_port":int(transport.dport),"tcp_flags":int(transport.flags)})
                elif isinstance(transport,dpkt.udp.UDP): f.update({"protocol":"udp","src_port":int(transport.sport),"dest_port":int(transport.dport)})
                else: f["protocol"]="other"
                ts=datetime.fromtimestamp(stamp,timezone.utc).isoformat(timespec="milliseconds")
                events.append(_base("pcap","packet_metadata",ts,f))
            except (dpkt.UnpackError,ValueError,OSError): continue
        return events
    except TelemetryInputError: raise
    except (dpkt.UnpackError,ValueError,TypeError,OSError,EOFError) as exc: raise TelemetryInputError("PCAP file is malformed or unsupported.") from exc

def source_digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
