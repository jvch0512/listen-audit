# listen-audit: reads ss -tulpn or netstat -tulpn listings; prints "rank<TAB>severity<TAB>rule<TAB>where<TAB>message".
function classify(proto, port,    p) {
    p = port + 0
    if (p == 23 || p == 21 || (p == 69 && proto == "udp") || p == 512 || p == 513 || p == 514 || (p >= 5900 && p <= 5905) || (p >= 6000 && p <= 6005))
        return "1 high LS001 cleartext or legacy remote access"
    if (p == 6379 || p == 11211 || p == 27017 || p == 9200 || p == 9300 || p == 5984 || p == 2379 || p == 2375 || p == 10250)
        return "1 high LS002 data store or control API without authentication by default"
    if (p == 3389 || p == 445 || p == 139 || p == 5985 || p == 3306 || p == 5432 || p == 1433 || p == 1521)
        return "2 medium LS003 remote administration or database on a network interface"
    if ((p == 161 && proto == "udp") || p == 111 || p == 2049)
        return "3 low LS004 infrastructure service that rarely needs to face the network"
    return ""
}
function service(port) {
    if (port == 23) return "telnet"; if (port == 21) return "ftp"; if (port == 69) return "tftp"
    if (port >= 512 && port <= 514) return "r-services"; if (port >= 5900 && port <= 5905) return "vnc"
    if (port >= 6000 && port <= 6005) return "x11"; if (port == 6379) return "redis"; if (port == 11211) return "memcached"
    if (port == 27017) return "mongodb"; if (port == 9200 || port == 9300) return "elasticsearch"; if (port == 5984) return "couchdb"
    if (port == 2379) return "etcd"; if (port == 2375) return "docker api"; if (port == 10250) return "kubelet"
    if (port == 3389) return "rdp"; if (port == 445 || port == 139) return "smb"; if (port == 5985) return "winrm"
    if (port == 3306) return "mysql"; if (port == 5432) return "postgresql"; if (port == 1433) return "sql server"
    if (port == 1521) return "oracle"; if (port == 161) return "snmp"; if (port == 111) return "rpcbind"; if (port == 2049) return "nfs"
    return "port " port
}
function split_addr(s,    i, a, p) {
    # sets ADDR and PORT from "addr:port", "[v6]:port", "*:port", ":::port", "addr%if:port"
    i = match(s, /:[0-9]+$/)
    if (!i) { ADDR = ""; PORT = ""; return 0 }
    PORT = substr(s, i + 1) + 0
    a = substr(s, 1, i - 1)
    sub(/^\[/, "", a); sub(/\]$/, "", a); sub(/%.*$/, "", a)
    ADDR = a
    return 1
}
function loopback(a) { return (a ~ /^127\./ || a == "::1") }
function wildcard(a) { return (a == "0.0.0.0" || a == "::" || a == "*" || a == "" || a == ":") }
{
    if ($1 !~ /^(tcp|tcp6|udp|udp6)$/) next
    proto = ($1 ~ /^tcp/) ? "tcp" : "udp"
    proc = "-"
    if ($2 ~ /^[0-9]+$/) {                       # netstat -tulpn
        local = $4
        if (proto == "tcp" && $6 != "LISTEN") next
        pp = (proto == "tcp") ? $7 : $6
        if (pp ~ /\//) { sub(/^[0-9]+\//, "", pp); proc = pp }
    } else {                                     # ss -tulpn
        local = $5
        if (proto == "tcp" && $2 != "LISTEN") next
        if (match($0, /\(\("[^"]+"/)) proc = substr($0, RSTART + 3, RLENGTH - 4)
    }
    if (!split_addr(local)) next
    listeners++
    if (loopback(ADDR)) next
    c = classify(proto, PORT)
    if (c == "") next
    n = split(c, parts, " ")
    rest = ""
    for (k = 4; k <= n; k++) rest = rest (k > 4 ? " " : "") parts[k]
    where = HOST ":" PORT "/" proto
    key = where
    if (seen[key]++) next                        # dual-stack duplicates
    exposure = wildcard(ADDR) ? "on every interface" : "on " ADDR
    printf "%s\t%s\t%s\t%s\t%s (%s, process %s) %s\n", parts[1], parts[2], parts[3], where, service(PORT), rest, proc, exposure
    found++
}
END { printf "0\tsummary\t-\t%s\t%d listeners, %d findings\n", HOST, listeners + 0, found + 0 }
