### Updated Debugging and Fixing Strategy for Slow Failover Detection in Rsyslog Load-Balancer

Thank you for the clarification that RELP is not supported by LogPoint. Since RELP (Reliable Event Logging Protocol) isn’t an option, we’ll focus on optimizing the existing TCP/TLS setup with omfwd to address the slow failover detection during abrupt connection cuts (e.g., firewall drops or network failures). The previous issue with buffering being resolved due to filesystem permissions is a positive step, and now we’ll tackle the failover detection challenge where rsyslog struggles to detect brutal cuts (e.g., takes minutes or fails to detect) compared to graceful shutdowns (e.g., stopping the syslog service, detected promptly).

Based on the "ESA_rsyslog_Load-Balancer_Implementation_FIPS_final.md" document (pages 5-6), rsyslog’s omfwd action relies on TCP/TLS with GnuTLS, and the current configuration includes `action.resumeRetryCount="-1"` and `action.resumeInterval="30"`. The slow detection likely stems from default TCP keepalive settings or lack of proactive connection checks, especially under abrupt failures. I’ll propose a fix using TCP keepalive tuning (supported by rsyslog) and provide updated test steps, avoiding RELP.

#### Cause of the Issue
- **Graceful vs Abrupt Detection**: Graceful shutdowns (e.g., stopping the backend syslog service) send TCP FIN/RST packets, which rsyslog detects quickly via socket closure. Abrupt cuts (e.g., firewall drop) leave the connection in an indeterminate state (e.g., "SYN_SENT" or "ESTABLISHED" with no response), relying on OS-level TCP timeouts (often 2-15 minutes by default) to detect failure. Rsyslog’s omfwd doesn’t proactively probe without configuration.
- **Configuration Impact**: The `action.resumeInterval=30` triggers retries every 30 seconds after initial detection, but the initial detection delay is governed by TCP keepalive or connection check settings. The default `extendedConnectionCheck="on"` (implicitly true) uses API calls to check connection status, but this may not suffice for abrupt cuts, especially with FIPS-enforced GnuTLS (Doc page 1, 9).
- **Research Insight**: Rsyslog documentation and community forums (e.g., rsyslog mailing lists, Red Hat KB) indicate that enabling and tuning TCP keepalive (via `KeepAlive` and related parameters) significantly improves detection of dead peers for TCP-based outputs like omfwd. Without this, rsyslog waits for OS timeouts, causing delays.

#### Suggested Fixes
Update the omfwd action in `/etc/rsyslog.d/10-esa-lb.conf` (Doc page 5) to enhance failover detection for abrupt cuts. Add or modify these parameters within the `action` block:

```
action(
  name="lp_tls_rr"
  type="omfwd" protocol="tcp"
  StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="anon"
  target=["<BACKEND_1>","<BACKEND_2>"]
  port="6514"
  template="RSYSLOG_SyslogProtocol23Format"
  KeepAlive="on"  # Enable TCP keepalive to detect dead peers
  KeepAlive.Time="10"  # Idle time before first keepalive probe (10s; default OS often 7200s)
  KeepAlive.Interval="5"  # Interval between probes (5s)
  KeepAlive.Probes="3"  # Number of unacknowledged probes before marking dead (~15-20s total detection)
  extendedConnectionCheck="on"  # Ensure active connection checking (default true, confirm)
  action.resumeRetryCount="-1"  # Keep infinite retries
  action.resumeInterval="10"  # Reduce retry interval to 10s (was 30s, min to avoid DoS)
  # Existing queue params...
)
```

- **Rationale**: 
  - `KeepAlive="on"` activates TCP keepalive probes, overriding OS defaults to detect abrupt cuts faster.
  - `KeepAlive.Time=10` starts probing after 10 seconds of inactivity.
  - `KeepAlive.Interval=5` and `KeepAlive.Probes=3` result in ~15-20 seconds total detection time (10s + 3*5s), much faster than default timeouts.
  - `action.resumeInterval=10` ensures quicker retries post-detection, aligning with the new detection window.
- **Application**: After editing, run `rsyslogd -N1` (syntax check), then `systemctl restart rsyslog`. Monitor with impstats (`jq -r 'select(.suspended==true) | .timegenerated' /var/log/rsyslog_stats.json`) to measure suspension timing.
- **FIPS Consideration**: These settings inherit system TCP policies, which are FIPS-compliant if enabled (Doc page 9). No custom ciphers are affected.

#### Updated Test Steps for Failover Detection
Integrate these into Phase 7 (Load-Balancing and Failover Tests) of the test plan to validate abrupt cut detection with the new configuration:

| Step | Commands/Tests | Expected Outcome | Debugging if Failure | Estimated Time |
|------|----------------|------------------|----------------------|----------------|
| 7.5 | Abrupt Cut Detection (One Backend): Simulate abrupt cut (e.g., `firewall-cmd --add-rich-rule='rule family=ipv4 source address=<RELAY_IP> port port=6514 protocol=tcp drop'` on backend1); Send traffic: `for i in {1..100}; do logger -n 127.0.0.1 -P 514 -H client1.example.com "Abrupt test $i"; sleep 1; done`; Monitor failover time via impstats: `tail -f /var/log/rsyslog_stats.json | jq -r 'select(.suspended==true) | .timegenerated'` and check backend2. | Detection within 15-20s; traffic shifts to backend2; impstats shows failed>0 briefly, then suspended=true for backend1. | Use `rsyslogd -d -n | grep -E 'SYN_SENT|keepalive'` (hung state or probe logs); `tcpdump -i any port 6514` for keepalive packets. If slow (>30s), increase KeepAlive.Probes or reduce Interval. | 15 min |
| 7.6 | Abrupt Cut Recovery: Remove firewall rule; Send more traffic: `for i in {1..50}; do logger -n 127.0.0.1 -P 514 -H client1.example.com "Recovery test $i"; sleep 1; done`; Monitor resume time via impstats: `tail -f /var/log/rsyslog_stats.json | jq -r 'select(.suspended==false) | .timegenerated'`. | Resumes within 10-20s (resumeInterval); alternation restarts on both backends; impstats failed=0. | Check `journalctl -u rsyslog -f | grep resume` for delays; reduce resumeInterval if needed. | 10 min |
| 7.7 | Abrupt Full Outage: Abrupt cut both backends; Test buffering: `for i in {1..100}; do logger -n 127.0.0.1 -P 514 -H client1.example.com "Outage test $i"; sleep 1; done`; Monitor suspension via impstats. | Immediate suspension (<20s) on both; queues grow (Phase 8.1). | If slow: Verify KeepAlive settings in config; debug with `rsyslogd -d -n | grep queue`. | 15 min |

**Explanation**: These steps simulate abrupt cuts (firewall drop mimics network failure). Timing is tracked with impstats/jq, leveraging the new keepalive settings. The expected 15-20s detection aligns with the tuned parameters.

#### Debugging the Issue
Use the cheat sheet (Phase 7/8/11) with these enhancements:
- **Impstats**: 
  - `jq -r 'select(.failed>0) | .timegenerated' /var/log/rsyslog_stats.json` (time of failure detection).
  - `jq -r 'max_by(.queuesize) | .queuesize' /var/log/rsyslog_stats.json` (queue impact during delay).
- **Journal**: `journalctl -u rsyslog -f | grep -E 'suspended|retry|gtls'` (TLS errors or retry intervals).
- **Buffers**: If detection is slow, buffers may delay activation—check `ls -lh /var/spool/rsyslog/` for growth lag.
- **Advanced**:
  - `ss -t -o state established` (TCP states like SYN_SENT).
  - `rsyslogd -d -n | grep -E 'connection|keepalive'` (connection handling details).
  - `tcpdump -i any port 6514` (confirm keepalive probes, e.g., TCP keepalive packets with no ACK).

#### Additional Considerations
- **FIPS Compliance**: The keepalive settings are TCP-level and should remain FIPS-compliant as they don’t alter crypto policies (Doc page 9).
- **Persistent Issues**: If detection remains slow (>30s), consider backend-side logging to confirm if it’s sending FIN/RST late, or test with a lower `KeepAlive.Time` (e.g., 5s) at the risk of more probes.
- **Validation**: Post-fix, re-run all Phase 7/8 tests to ensure no regression.

Let me know if you need a config snippet or further assistance with tcpdump/jq analysis! Current time is 11:03 AM CEST, so we can schedule testing soon.