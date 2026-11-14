#!/bin/sh
# Test suite: fixtures are built in a temp dir; runs once per available awk implementation.
cd "$(dirname "$0")/.." || exit 1
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
pass=0; fail=0
ok() { if [ "$1" = 0 ]; then pass=$((pass+1)); else fail=$((fail+1)); echo "FAIL: $2"; fi; }
run() { f=$1; shift; ./bin/listen-audit "$f" --tsv "$@" 2>/dev/null; }
has() { run "$1" | grep -q "^$2	$3	"; }       # file severity rule
not() { ! has "$@"; }
mk() { printf 'Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process\n%s\n' "$2" > "$T/$1.txt"; }
ssl() { printf 'tcp   LISTEN 0      128   %s   0.0.0.0:*   users:(("%s",pid=1,fd=3))' "$1" "$2"; }

for AWK_BIN in gawk mawk awk; do
  command -v "$AWK_BIN" >/dev/null 2>&1 || continue
  export AWK="$AWK_BIN"
  tag="[$AWK_BIN]"
  # ss format
  mk t1 "$(ssl 0.0.0.0:23 telnetd)"; has "$T/t1.txt" high LS001; ok $? "$tag telnet on wildcard"
  mk t2 "$(ssl '[::]:23' telnetd)"; has "$T/t2.txt" high LS001; ok $? "$tag telnet on ipv6 wildcard"
  mk t3 "$(ssl '*:23' telnetd)"; has "$T/t3.txt" high LS001; ok $? "$tag telnet on star"
  mk t4 "$(ssl 127.0.0.1:23 telnetd)"; run "$T/t4.txt" | grep -q "^high"; [ $? -ne 0 ]; ok $? "$tag loopback is safe"
  mk t5 "$(ssl '[::1]:6379' redis)"; run "$T/t5.txt" | grep -q "^high"; [ $? -ne 0 ]; ok $? "$tag ipv6 loopback is safe"
  mk t6 "$(ssl 127.0.0.53%lo:53 resolved)"; run "$T/t6.txt" | grep -q "^high"; [ $? -ne 0 ]; ok $? "$tag loopback with interface suffix"
  mk t7 "$(ssl 10.0.0.5:6379 redis-server)"; has "$T/t7.txt" high LS002; ok $? "$tag specific address still reported"
  run "$T/t7.txt" | grep -q "on 10.0.0.5"; ok $? "$tag message names the address"
  mk t8 "$(ssl 0.0.0.0:2375 dockerd)"; has "$T/t8.txt" high LS002; ok $? "$tag docker api"
  mk t9 "$(ssl 0.0.0.0:3389 xrdp)"; has "$T/t9.txt" medium LS003; ok $? "$tag rdp medium"
  mk t10 "$(ssl 0.0.0.0:5432 postgres)"; has "$T/t10.txt" medium LS003; ok $? "$tag postgres medium"
  mk t11 "$(ssl 0.0.0.0:111 rpcbind)"; has "$T/t11.txt" low LS004; ok $? "$tag rpcbind low"
  mk t12 "$(ssl 0.0.0.0:22 sshd)"; run "$T/t12.txt" | grep -qE "^(high|medium|low)"; [ $? -ne 0 ]; ok $? "$tag ssh is not reported"
  mk t13 "$(ssl 0.0.0.0:443 nginx)"; run "$T/t13.txt" | grep -qE "^(high|medium|low)"; [ $? -ne 0 ]; ok $? "$tag https is not reported"
  mk t14 "$(ssl 0.0.0.0:5901 vnc)"; has "$T/t14.txt" high LS001; ok $? "$tag vnc range"
  mk t15 "$(ssl 0.0.0.0:6003 Xorg)"; has "$T/t15.txt" high LS001; ok $? "$tag x11 range"
  mk t16 "$(ssl 0.0.0.0:9200 java)"; has "$T/t16.txt" high LS002; ok $? "$tag elasticsearch"
  mk t17 "$(ssl 0.0.0.0:21 vsftpd)"; has "$T/t17.txt" high LS001; ok $? "$tag ftp"
  run "$T/t17.txt" | grep -q "process vsftpd"; ok $? "$tag process name extracted"
  printf 'udp UNCONN 0 0 0.0.0.0:161 0.0.0.0:* users:(("snmpd",pid=1,fd=6))\n' > "$T/u1.body"; mk u1 "$(cat "$T/u1.body")"
  has "$T/u1.txt" low LS004; ok $? "$tag snmp udp"
  printf 'udp UNCONN 0 0 0.0.0.0:69 0.0.0.0:* users:(("tftpd",pid=1,fd=6))\n' > "$T/u2.body"; mk u2 "$(cat "$T/u2.body")"
  has "$T/u2.txt" high LS001; ok $? "$tag tftp udp"
  printf 'tcp ESTAB 0 0 10.0.0.5:23 10.0.0.9:5555\n' > "$T/e.body"; mk e "$(cat "$T/e.body")"
  run "$T/e.txt" | grep -q "^high"; [ $? -ne 0 ]; ok $? "$tag established connections ignored"
  mk d "$(ssl 0.0.0.0:23 telnetd)
$(ssl '[::]:23' telnetd)"
  [ "$(run "$T/d.txt" | grep -c '^high')" = 1 ]; ok $? "$tag dual stack counted once"
  mk np "$(printf 'tcp   LISTEN 0 128 0.0.0.0:23 0.0.0.0:*')"
  run "$T/np.txt" | grep -q "process -"; ok $? "$tag missing process shows dash"

  # netstat format
  printf 'Proto Recv-Q Send-Q Local Address Foreign Address State PID/Program name\ntcp 0 0 0.0.0.0:3306 0.0.0.0:* LISTEN 1450/mysqld\ntcp6 0 0 :::11211 :::* LISTEN 1610/memcached\nudp 0 0 0.0.0.0:111 0.0.0.0:* 455/rpcbind\ntcp 0 0 127.0.0.1:631 0.0.0.0:* LISTEN 990/cupsd\ntcp 0 0 10.0.0.5:80 10.0.0.9:4000 ESTABLISHED 1/x\n' > "$T/n.txt"
  has "$T/n.txt" medium LS003; ok $? "$tag netstat mysql"
  has "$T/n.txt" high LS002; ok $? "$tag netstat ipv6 memcached"
  has "$T/n.txt" low LS004; ok $? "$tag netstat udp rpcbind"
  run "$T/n.txt" | grep -q "process mysqld"; ok $? "$tag netstat process name"

  # summary and output
  run examples/web01.txt | head -1 | grep -q "^# 1 files, 9 listeners, 3 findings"; ok $? "$tag summary line"
  [ "$(./bin/listen-audit examples/web01.txt | head -1)" = "1 files, 9 listeners, 3 findings" ]; ok $? "$tag text summary"
  run examples/web01.txt examples/db01.txt | grep -c . | grep -q "^8$"; ok $? "$tag two files merged"
  first=$(./bin/listen-audit examples/web01.txt examples/db01.txt --tsv | sed -n 2p | cut -f1); [ "$first" = high ]; ok $? "$tag sorted by severity"
  cat examples/web01.txt | ./bin/listen-audit - --tsv | grep -q "stdin:23/tcp"; ok $? "$tag stdin input"

  # exit codes
  ./bin/listen-audit examples/web01.txt >/dev/null; [ $? -eq 0 ]; ok $? "$tag exit 0 by default"
  ./bin/listen-audit examples/web01.txt --fail-on high >/dev/null; [ $? -eq 1 ]; ok $? "$tag exit 1 on high"
  ./bin/listen-audit "$T/t12.txt" --fail-on medium >/dev/null; [ $? -eq 0 ]; ok $? "$tag exit 0 when clean"
  ./bin/listen-audit "$T/t9.txt" --fail-on high >/dev/null; [ $? -eq 0 ]; ok $? "$tag medium does not trip high"
  ./bin/listen-audit "$T/t9.txt" --fail-on medium >/dev/null; [ $? -eq 1 ]; ok $? "$tag medium trips medium"
done
./bin/listen-audit /no/such/file >/dev/null 2>&1; [ $? -eq 2 ]; ok $? "missing file exits 2"
./bin/listen-audit >/dev/null 2>&1; [ $? -eq 2 ]; ok $? "no args exits 2"
./bin/listen-audit examples/web01.txt --bogus >/dev/null 2>&1; [ $? -eq 2 ]; ok $? "bad flag exits 2"
./bin/listen-audit examples/web01.txt --fail-on nope >/dev/null 2>&1; [ $? -eq 2 ]; ok $? "bad fail-on exits 2"

echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
