import subprocess
import time
import pandas as pd
from sklearn.ensemble import IsolationForest
from cve_detector import detect_cve_patterns, format_cve_alert

# ==============================
# CONFIG
# ==============================
CONTAINER_NAME = "dvwa"
TRAINING_ROUNDS = 25  # Reduced for faster startup
DETECTION_INTERVAL = 1  # Faster detection
CVE_DETECTION_THRESHOLD = 1  # Lower threshold for better sensitivity

# ==============================
# STEP 1: Capture container activity (Enhanced approach)
# ==============================
def capture_syscalls(duration=1):
    """
    Capture container activity using multiple monitoring techniques
    """
    try:
        # Method 1: Get container stats
        stats_cmd = [
            "docker", "stats", CONTAINER_NAME, 
            "--no-stream", "--format", 
            "table {{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}\t{{.PIDs}}"
        ]
        
        stats_result = subprocess.run(stats_cmd, capture_output=True, text=True)
        stats_log = stats_result.stdout.lower()
        
        # Method 2: Get recent logs (more comprehensive)
        logs_cmd = [
            "docker", "logs", CONTAINER_NAME, 
            "--tail", "100", "--since", f"{duration*2}s"
        ]
        
        logs_result = subprocess.run(logs_cmd, capture_output=True, text=True)
        logs_data = logs_result.stdout.lower() + logs_result.stderr.lower()
        
        # Method 3: Get detailed process info
        ps_cmd = [
            "docker", "exec", CONTAINER_NAME,
            "sh", "-c", "ps auxww && netstat -tuln 2>/dev/null || ss -tuln 2>/dev/null || true"
        ]
        
        ps_result = subprocess.run(ps_cmd, capture_output=True, text=True)
        ps_data = ps_result.stdout.lower()
        
        # Method 4: Check for recent file changes and webshells
        find_cmd = [
            "docker", "exec", CONTAINER_NAME,
            "sh", "-c", "find /tmp -name '*.php' -o -name '*.sh' -o -name '*shell*' 2>/dev/null; find /var/log /var/www -type f -newer /proc/uptime 2>/dev/null | head -10 || true"
        ]
        
        find_result = subprocess.run(find_cmd, capture_output=True, text=True)
        find_data = find_result.stdout.lower()
        
        # Method 5: Monitor network connections
        net_cmd = [
            "docker", "exec", CONTAINER_NAME,
            "sh", "-c", "cat /proc/net/tcp /proc/net/udp 2>/dev/null | wc -l || echo 0"
        ]
        
        net_result = subprocess.run(net_cmd, capture_output=True, text=True)
        net_data = net_result.stdout.lower()
        
        # Method 6: Check running processes count
        proc_cmd = [
            "docker", "exec", CONTAINER_NAME,
            "sh", "-c", "ps aux | wc -l"
        ]
        
        proc_result = subprocess.run(proc_cmd, capture_output=True, text=True)
        proc_count = proc_result.stdout.strip()
        
        # Method 7: Check for attack patterns in real-time
        attack_cmd = [
            "docker", "exec", CONTAINER_NAME,
            "sh", "-c", "ls -la /tmp/*.php /tmp/*.sh 2>/dev/null | wc -l; ps aux | grep -E '(shell|php|eval|system)' | wc -l"
        ]
        
        attack_result = subprocess.run(attack_cmd, capture_output=True, text=True)
        attack_data = attack_result.stdout.lower()
        
        # Combine all data for analysis
        log = f"{stats_log} {logs_data} {ps_data} {find_data} {net_data} {attack_data} processes:{proc_count}"
        
        print("RAW:", log[:300])

        # 🔍 DEBUG (very important)
        if log.strip() == "":
            print("[WARNING] No container data captured")
            print(f"Stats stderr: {stats_result.stderr}")
            print(f"Logs stderr: {logs_result.stderr}")
            print(f"PS stderr: {ps_result.stderr}")

        return log

    except Exception as e:
        print(f"[ERROR] Container monitoring failed: {e}")
        return ""

# ==============================
# STEP 2: Feature extraction (Enhanced for better detection)
# ==============================
def extract_features(log):
    """
    Extract features from enhanced Docker monitoring data
    """
    # Extract process count from log
    proc_count = 0
    for line in log.split('\n'):
        if 'processes:' in line:
            try:
                proc_count = int(line.split('processes:')[1].strip())
            except:
                pass
    
    return {
        # Process-based features
        "total_processes": proc_count,
        "apache_processes": log.count("apache") + log.count("httpd"),
        "php_processes": log.count("php"),
        "mysql_processes": log.count("mysql") + log.count("mariadb"),
        "shell_processes": log.count("/bin/sh") + log.count("/bin/bash") + log.count("dash"),
        
        # Suspicious process patterns
        "root_shells": log.count("root") * (log.count("bash") + log.count("sh")),
        "suspicious_commands": log.count("whoami") + log.count("id ") + log.count("uname") + log.count("cat /etc/passwd"),
        
        # Log-based features  
        "error_logs": log.count("error") + log.count("warning") + log.count("fail"),
        "access_logs": log.count("get ") + log.count("post ") + log.count("request"),
        "login_attempts": log.count("login") + log.count("password") + log.count("auth"),
        
        # File system activity
        "file_changes": log.count("/var/log") + log.count("/tmp") + log.count("/var/www"),
        "tmp_files": log.count("/tmp/"),
        "log_files": log.count("/var/log/"),
        
        # Network activity indicators
        "network_connections": log.count("established") + log.count("listen") + log.count("tcp") + log.count("udp"),
        "network_activity": log.count(":80") + log.count(":443") + log.count(":22"),
        
        # Memory and CPU indicators (from stats)
        "high_cpu": 1 if any(word for word in log.split() if word.endswith("%") and "." in word and float(word[:-1]) > 1.0) else 0,
        "memory_usage": log.count("mib") + log.count("gib"),
        "pid_count": log.count("pid"),
        
        # Enhanced anomaly patterns with webshell detection
        "webshell_files": log.count(".php") + log.count("shell") + log.count("webshell") + log.count("backdoor"),
        "command_injection": log.count("system") + log.count("exec") + log.count("eval") + log.count("`;") + log.count("&&") + log.count("<?php"),
        "privilege_escalation": log.count("sudo") + log.count("su ") + log.count("chmod +s") + log.count("whoami") + log.count("/etc/passwd"),
        "reconnaissance": log.count("nmap") + log.count("netstat") + log.count("ps aux") + log.count("find /") + log.count("uname") + log.count("id "),
        
        # CVE-specific patterns
        "cve_patterns": log.count("cat /etc/passwd") + log.count("jndi:") + log.count("ldap://") + log.count("<?php system")
    }

# ==============================
# STEP 3: Build baseline
# ==============================
def train_model():
    print("[+] Preparing for baseline model training...")
    
    print("[+] Training baseline model on clean behavior...")
    data = []

    for i in range(TRAINING_ROUNDS):
        log = capture_syscalls(duration=1)
        features = extract_features(log)
        data.append(features)

        print(f"[TRAIN] Sample {i+1}: {features}")
        time.sleep(1)

    df = pd.DataFrame(data)

    model = IsolationForest(contamination=0.2, random_state=42)  # More sensitive to anomalies
    model.fit(df)

    print("[+] Model training complete - baseline established on clean data\n")
    return model

# ==============================
# STEP 4: Detection loop with CVE analysis
# ==============================
def detect(model):
    print("[+] Starting real-time syscall monitoring with CVE detection...\n")

    while True:
        log = capture_syscalls(duration=1)
        features = extract_features(log)

        df = pd.DataFrame([features])
        prediction = model.predict(df)[0]

        print(f"[DATA] {features}")

        # Check for critical behavior patterns that should trigger immediate alerts
        critical_threshold_met = (
            features.get("webshell_files", 0) >= 5 or
            features.get("command_injection", 0) >= 3 or
            features.get("privilege_escalation", 0) >= 2 or
            (features.get("tmp_files", 0) >= 3 and features.get("php_processes", 0) >= 1) or
            features.get("total_processes", 0) >= 20
        )

        # Force anomaly detection if critical thresholds are met
        if critical_threshold_met:
            prediction = -1
            print("[FORCED-ANOMALY] 🚨 Critical behavior thresholds exceeded - forcing anomaly detection!")

        if prediction == -1:
            print("[ALERT] 🚨 Syscall anomaly detected! Possible attack")
            
            # Perform CVE analysis on detected anomaly
            print("\n[CVE-ANALYSIS] Checking for known vulnerability patterns...")
            potential_cves = detect_cve_patterns(log, features)
            
            if potential_cves:
                print(format_cve_alert(potential_cves))
                
                # Log high-risk CVEs to separate alert
                critical_cves = [cve for cve in potential_cves if cve['risk'] == 'CRITICAL']
                high_cves = [cve for cve in potential_cves if cve['risk'] == 'HIGH']
                
                if critical_cves:
                    print(f"\n🔥 CRITICAL ALERT: {len(critical_cves)} CRITICAL CVE(s) detected!")
                    for cve in critical_cves:
                        print(f"   • {cve['cve_id']}: {cve['description']}")
                
                if high_cves and len(high_cves) >= 2:
                    print(f"\n⚠️  HIGH RISK ALERT: {len(high_cves)} HIGH severity CVE(s) detected!")
                    for cve in high_cves[:3]:  # Show top 3
                        print(f"   • {cve['cve_id']}: {cve['description']}")
            else:
                print("No specific CVE patterns identified, but anomalous behavior detected.")
            
            print()
        else:
            # Also check for CVE patterns in normal behavior (early warning)
            potential_cves = detect_cve_patterns(log, features)
            if potential_cves:
                high_risk_cves = [cve for cve in potential_cves if cve['risk'] in ['HIGH', 'CRITICAL']]
                if high_risk_cves:
                    print(f"[WARNING] ⚠️  Suspicious patterns detected (not anomalous yet)")
                    for cve in high_risk_cves[:2]:  # Show top 2
                        print(f"   • {cve['cve_id']} [{cve['risk']}]: {cve['description']}")
                    print("[OK] Normal behavior (with warning patterns)\n")
                else:
                    print("[OK] Normal behavior\n")
            else:
                print("[OK] Normal behavior\n")

        time.sleep(DETECTION_INTERVAL)

# ==============================
# MAIN
# ==============================
if __name__ == "__main__":
    model = train_model()
    detect(model)