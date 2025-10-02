## Action Plan for Resolving Rsyslog Failover and Buffer Draining Issues

**Overview**: This action plan addresses two key issues identified in the rsyslog load-balancer configuration based on the "ESA_rsyslog_Load-Balancer_Implementation_FIPS_final.md" document and recent meeting feedback:
1. **Slow Failover Detection for Abrupt Failures**: Rsyslog detects graceful shutdowns (e.g., stopping the backend syslog service) quickly but is slow or fails to detect abrupt cuts (e.g., firewall drop or network interruption), leading to delays in switching targets.
2. **Buffer Draining to Only One Backend After Restoration**: After a full suspension (both backends down) and buffer fill, restoring both backends results in the queue draining to only one backend instead of using round-robin across both.

For each problem, the plan includes:
- **Current Configuration (Before)**: Excerpt from the existing setup (Doc pages 5-6).
- **Proposed Changes (After)**: Specific modifications to `/etc/rsyslog.d/10-esa-lb.conf`.
- **Implications of Changes**: Benefits, risks, and performance impacts.
- **Test Scenarios**: Step-by-step tests with full debug commands to validate the fix, integrated with the existing test plan (e.g., Phases 7-8).

**Assumptions**: 
- Rsyslog version >=8.2408 (ideally 8.2502+ from Adiscon, Doc page 1).
- FIPS mode enabled; changes inherit system crypto policies (no custom ciphers, Doc page 9).
- Test in a non-production environment; replace `<BACKEND_1>` and `<BACKEND_2>` with actual IPs.
- After changes, always run `rsyslogd -N1` (syntax check) and `systemctl restart rsyslog`.

**General Recommendations**:
- Backup current configs: `cp -r /etc/rsyslog.d/ /etc/rsyslog.d.bak`.
- Monitor during tests with impstats: `tail -f /var/log/rsyslog_stats.json | jq -r 'select(.name=="action" and .actionName=="lp_tls_rr") | "\(.timegenerated) submitted=\(.submitted) failed=\(.failed) suspended=\(.suspended) queuesize=\(.queuesize)"'`.
- If issues persist, update rsyslog to the latest Adiscon daily build (Doc page 2) for potential bug fixes.

### Problem 1: Slow Failover Detection for Abrupt Failures

#### Current Configuration (Before)
The omfwd action lacks explicit TCP keepalive probes, relying on default OS timeouts (often 2+ minutes) for abrupt failure detection. This causes delays in suspension and failover (Doc page 6: "If any backend is down, omfwd skips it").

Excerpt from `/etc/rsyslog.d/10-esa-lb.conf`:
```
action(
  name="lp_tls_rr"
  type="omfwd" protocol="tcp"
  StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="anon"
  target=["<BACKEND_1>","<BACKEND_2>"]
  port="6514"
  template="RSYSLOG_SyslogProtocol23Format"
  action.resumeRetryCount="-1"
  action.resumeInterval="30"
  # No KeepAlive or pool.resumeinterval
  # Queue params...
)
```

#### Proposed Changes (After)
Add TCP keepalive parameters to enable proactive probing of connections, reducing detection time to ~15-20 seconds for abrupt cuts. Also, add `pool.resumeinterval="5"` for faster target retry in the pool.

Updated Excerpt:
```
action(
  name="lp_tls_rr"
  type="omfwd" protocol="tcp"
  StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="anon"
  target=["<BACKEND_1>","<BACKEND_2>"]
  port="6514"
  template="RSYSLOG_SyslogProtocol23Format"
  KeepAlive="on"  # Enable TCP keepalive for dead peer detection
  KeepAlive.Time="10"  # Idle time before first probe (10s)
  KeepAlive.Interval="5"  # Interval between probes (5s)
  KeepAlive.Probes="3"  # Unacknowledged probes before failure (~15-20s detection)
  pool.resumeinterval="5"  # Retry unavailable targets every 5s
  action.resumeRetryCount="-1"
  action.resumeInterval="10"  # Reduced from 30s for quicker retries
  # Existing queue params...
)
```

#### Implications of Changes
- **Before**: Detection relies on OS TCP timeouts (2-15 minutes), leading to long hangs in "SYN_SENT" state during abrupt failures. Failover is slow, potentially causing message delays or temporary loss if queues overflow.
- **After**: Detection time reduces to ~15-20s with keepalive probes, enabling faster suspension and failover. Pool retries every 5s ensure quicker target activation. Performance impact: Minor increase in network probes (keepalive packets every 5s during idle), but negligible on modern hardware. Risk: Too low intervals could cause excessive probing if backends are unstable—monitor for DoS-like behavior. FIPS compliance unaffected (TCP-level, not crypto). Overall, improves reliability without major overhead.

#### Test Scenarios with Full Debug Commands
Integrate into Phase 7 of the test plan. Use `logger -n 127.0.0.1 -P 514 -H client1.example.com "Test"` for traffic.

1. **Graceful Shutdown Detection (Baseline)**:
   - **Steps**: Stop syslog service on backend1 (e.g., `systemctl stop rsyslog` on backend1); Send 50 messages; Monitor failover to backend2.
   - **Expected**: Immediate detection (<5s); traffic to backend2.
   - **Full Debug Commands**:
     - Impstats: `tail -f /var/log/rsyslog_stats.json | jq -r 'select(.failed>0) | .timegenerated'` (failure time).
     - Journal: `journalctl -u rsyslog -f | grep -E 'suspended|retry'`.
     - Buffers: `ls -lh /var/spool/rsyslog/` (no growth needed).
     - Advanced: `rsyslogd -d -n | grep -E 'SYN_SENT|keepalive'` (after service stop).

2. **Abrupt Cut Detection (One Backend)**:
   - **Steps**: Simulate abrupt cut (e.g., `firewall-cmd --add-rich-rule='rule family=ipv4 source address=<RELAY_IP> port port=6514 protocol=tcp drop'` on backend1); Send 100 messages with 1s sleep; Time failover.
   - **Expected**: Detection in 15-20s; traffic shifts.
   - **Full Debug Commands**:
     - Impstats: `jq -r 'select(.suspended==true) | .timegenerated' /var/log/rsyslog_stats.json` (static detection time).
     - Journal: `journalctl -u rsyslog -f | grep -E 'suspended|gtls|retry'`.
     - Buffers: `watch -n 1 'ls -lh /var/spool/rsyslog/'` (minor if any).
     - Advanced: `tcpdump -i any port 6514` (keepalive probes); `ss -t -o state established` (TCP states).

3. **Abrupt Full Outage and Recovery**:
   - **Steps**: Abrupt cut both; Send traffic to fill queue; Restore one, then the other; Monitor suspension/resumption.
   - **Expected**: Suspension <20s; failover/resume as above.
   - **Full Debug Commands**: Same as above, plus `tail -f /var/log/esa_fallback-buffer.log` (fallback during outage).

### Problem 2: Buffer Draining to Only One Backend After Restoration

#### Current Configuration (Before)
The omfwd pool lacks explicit resume interval for targets, leading to sequential activation during drain (default 30s), causing the queue to empty to the first available backend (Doc page 6: "If all are down... events buffer until a target returns").

Excerpt:
```
action(
  # ... (no pool.resumeinterval)
  action.resumeRetryCount="-1"
  action.resumeInterval="30"
  # Queue params...
)
```

#### Proposed Changes (After)
Add `pool.resumeinterval="5"` to reduce target retry delay, ensuring both backends activate quickly for distributed drain. Include keepalive for consistent detection.

Updated Excerpt:
```
action(
  name="lp_tls_rr"
  type="omfwd" protocol="tcp"
  StreamDriver="gtls" StreamDriverMode="1" StreamDriverAuthMode="anon"
  target=["<BACKEND_1>","<BACKEND_2>"]
  port="6514"
  template="RSYSLOG_SyslogProtocol23Format"
  pool.resumeinterval="5"  # New: Retry targets every 5s for faster activation
  KeepAlive="on"  # Enable for consistent detection
  KeepAlive.Time="10"
  KeepAlive.Interval="5"
  KeepAlive.Probes="3"
  action.resumeRetryCount="-1"
  action.resumeInterval="10"
  # Existing queue params...
)
```

#### Implications of Changes
- **Before**: Drain prioritizes first available target, completing before second activates (30s default), leading to single-backend overload and uneven load post-outage.
- **After**: Targets retry every 5s, enabling near-simultaneous activation for round-robin drain. Detection consistent with keepalive. Performance: Slight increase in probes (5s intervals), but low overhead; faster recovery reduces downtime risk. Risk: Aggressive retries could strain unstable backends—monitor for errors. FIPS unaffected. Overall, enhances load-balancing without structural changes.

#### Test Scenarios with Full Debug Commands
Integrate into Phase 8. Use logger for traffic.

1. **Full Outage Buffer Fill**:
   - **Steps**: Abrupt cut both; Send 60,000 messages to fill queue.
   - **Expected**: Suspension; queue grows.
   - **Full Debug Commands**:
     - Impstats: `tail -f /var/log/rsyslog_stats.json | jq -r 'select(.suspended==true) | .queuesize'` (growth >40000).
     - Journal: `journalctl -u rsyslog -f | grep suspended`.
     - Buffers: `watch -n 1 'du -sh /var/spool/rsyslog'` (size increase).

2. **Drain Distribution on Recovery**:
   - **Steps**: Restore both; Wait 1 min; Check backend logs for split.
   - **Expected**: Drain to both (near-even).
   - **Full Debug Commands**:
     - Impstats: `jq -r 'select(.suspended==false) | .timegenerated' /var/log/rsyslog_stats.json` (resume time).
     - Journal: `journalctl -u rsyslog -f | grep -E 'resume|drain|pool'`.
     - Buffers: `watch -n 1 'ls -lh /var/spool/rsyslog/'` (files shrink).
     - Advanced: `tcpdump -i any port 6514` (traffic to both); `ss -t -p | grep 6514` (connections).

3. **Concurrent Drain and Traffic**:
   - **Steps**: After outage, restore; Send 1,000 messages during drain.
   - **Expected**: Drained + new messages use both.
   - **Full Debug Commands**: Same as above, plus `jq -r '.[].submitted' /var/log/rsyslog_stats.json` (rising submitted).

### Next Steps
1. **Implementation**: Apply changes in test env; validate with above tests.
2. **Monitoring**: Use impstats/jq for 24h post-prod rollout.
3. **Rollback**: Revert to original if issues (Doc page 8).
4. **Timeline**: Test today; deploy tomorrow if OK.

Let me know for config files or calls!