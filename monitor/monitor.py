import subprocess
import time
import pandas as pd
import logging
import os
from datetime import datetime
from sklearn.ensemble import IsolationForest
from cve_detector import detect_cve_patterns, format_cve_alert

# ==============================
# CONFIG
# ==============================
CONTAINER_NAME = "case1_exception_handling-victim-1"  # Monitor the victim container
TRAINING_ROUNDS = 25  # Reduced for faster startup
DETECTION_INTERVAL = 1  # Faster detection
CVE_DETECTION_THRESHOLD = 1  # Lower threshold for better sensitivity

# ==============================
# LOGGING SETUP
# ==============================

# Create logs directory if it doesn't exist
log_dir = '/Users/tanjinwei/Documents/MSSD/TERM_2/Systems_Security/PROJECT/Demo/logs'
if not os.path.exists(log_dir):
    os.makedirs(log_dir, exist_ok=True)

# Security alerts logger
security_logger = logging.getLogger('security')
security_logger.setLevel(logging.INFO)
security_handler = logging.FileHandler(f'{log_dir}/security_alerts.log')
security_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
security_handler.setFormatter(security_formatter)
security_logger.addHandler(security_handler)

# Performance monitoring logger
perf_logger = logging.getLogger('performance')
perf_logger.setLevel(logging.INFO)
perf_handler = logging.FileHandler(f'{log_dir}/performance_data.log')
perf_formatter = logging.Formatter('%(asctime)s,%(levelname)s,%(message)s')
perf_handler.setFormatter(perf_formatter)
perf_logger.addHandler(perf_handler)

# CVE-specific logger
cve_logger = logging.getLogger('cve_detection')
cve_logger.setLevel(logging.INFO)
cve_handler = logging.FileHandler(f'{log_dir}/cve_detections.log')
cve_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
cve_handler.setFormatter(cve_formatter)
cve_logger.addHandler(cve_handler)

# Console logger (keep existing output)
console_logger = logging.getLogger('console')
console_logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler()
console_formatter = logging.Formatter('%(message)s')
console_handler.setFormatter(console_formatter)
console_logger.addHandler(console_handler)

# ==============================
# STEP 1: Capture container activity (Enhanced approach)
# ==============================
def capture_syscalls(duration=1):
    """
    Capture container performance metrics using only sysbench statistics
    """
    try:
        # Sysbench CPU performance test
        sysbench_cpu_cmd = [
            "docker", "exec", CONTAINER_NAME,
            "sh", "-c", "sysbench cpu --cpu-max-prime=2000 --time=1 --threads=1 run 2>/dev/null | grep -E '(events per second|total time|min:|avg:|max:)' || echo 'sysbench_unavailable'"
        ]
        
        sysbench_cpu_result = subprocess.run(sysbench_cpu_cmd, capture_output=True, text=True)
        sysbench_cpu_data = sysbench_cpu_result.stdout.lower()
        
        # Sysbench memory performance test
        sysbench_mem_cmd = [
            "docker", "exec", CONTAINER_NAME, 
            "sh", "-c", "sysbench memory --memory-total-size=10M --time=1 run 2>/dev/null | grep -E '(MiB transferred|total time)' || echo 'sysbench_mem_unavailable'"
        ]
        
        sysbench_mem_result = subprocess.run(sysbench_mem_cmd, capture_output=True, text=True)
        sysbench_mem_data = sysbench_mem_result.stdout.lower()
        
        # Sysbench file I/O performance test
        sysbench_fileio_cmd = [
            "docker", "exec", CONTAINER_NAME,
            "sh", "-c", "sysbench fileio --file-total-size=10M --time=1 --file-test-mode=rndrw prepare >/dev/null 2>&1 && sysbench fileio --file-total-size=10M --time=1 --file-test-mode=rndrw run 2>/dev/null | grep -E '(reads/s|writes/s|fsyncs/s|read, MiB/s|written, MiB/s)' && sysbench fileio --file-total-size=10M cleanup >/dev/null 2>&1 || echo 'sysbench_fileio_unavailable'"
        ]
        
        sysbench_fileio_result = subprocess.run(sysbench_fileio_cmd, capture_output=True, text=True)
        sysbench_fileio_data = sysbench_fileio_result.stdout.lower()
        
        # Combine sysbench performance data
        log = f"{sysbench_cpu_data} {sysbench_mem_data} {sysbench_fileio_data}"
        
        print("RAW SYSBENCH:", log[:300])
        
        # Log raw performance data
        perf_logger.info(f"Container={CONTAINER_NAME},SysbenchCPU={len(sysbench_cpu_data)},SysbenchMem={len(sysbench_mem_data)},SysbenchIO={len(sysbench_fileio_data)}")

        # 🔍 DEBUG (very important)
        if log.strip() == "" or 'sysbench_unavailable' in log:
            print("[WARNING] Sysbench data unavailable")
            print(f"CPU stderr: {sysbench_cpu_result.stderr}")
            print(f"Memory stderr: {sysbench_mem_result.stderr}")
            print(f"FileIO stderr: {sysbench_fileio_result.stderr}")
            security_logger.warning(f"Sysbench unavailable for {CONTAINER_NAME} - Check if sysbench is installed")

        return log

    except Exception as e:
        print(f"[ERROR] Sysbench monitoring failed: {e}")
        security_logger.error(f"Sysbench monitoring failed for {CONTAINER_NAME}: {e}")
        return ""

# ==============================
# STEP 2: Feature extraction (Enhanced for better detection)
# ==============================

def extract_performance_metrics(log):
    """
    Extract comprehensive sysbench performance metrics for anomaly detection
    """
    
    # Parse CPU performance (events per second)
    cpu_performance = 0
    cpu_latency = 0
    cpu_total_time = 0
    
    for line in log.split('\n'):
        if 'events per second' in line:
            try:
                # Extract number before "events per second"
                parts = line.strip().split()
                for i, part in enumerate(parts):
                    if part.replace('.', '').replace('-', '').isdigit() and i < len(parts) - 1:
                        if 'events' in parts[i + 1]:
                            cpu_performance = float(part)
                            break
            except:
                pass
        if 'avg:' in line and 'ms' in line:
            try:
                # Extract average latency
                avg_part = line.split('avg:')[1].split('ms')[0].strip()
                cpu_latency = float(avg_part)
            except:
                pass
        if 'total time:' in line and 's' in line:
            try:
                # Extract total time
                time_part = line.split('total time:')[1].split('s')[0].strip()
                cpu_total_time = float(time_part)
            except:
                pass
    
    # Parse memory performance (MiB/sec)
    memory_throughput = 0
    memory_total_time = 0
    
    for line in log.split('\n'):
        if 'mib transferred' in line:
            try:
                # Extract MiB/sec from sysbench memory test
                if '(' in line and 'mib/sec' in line:
                    throughput_part = line.split('(')[1].split('mib/sec')[0].strip()
                    memory_throughput = float(throughput_part)
            except:
                pass
        if 'total time:' in line and 's' in line and memory_throughput > 0:
            try:
                # Extract memory test total time
                time_part = line.split('total time:')[1].split('s')[0].strip()
                memory_total_time = float(time_part)
            except:
                pass
    
    # Parse file I/O performance
    reads_per_sec = 0
    writes_per_sec = 0
    read_throughput = 0
    write_throughput = 0
    
    for line in log.split('\n'):
        if 'reads/s:' in line:
            try:
                reads_per_sec = float(line.split('reads/s:')[1].split()[0])
            except:
                pass
        if 'writes/s:' in line:
            try:
                writes_per_sec = float(line.split('writes/s:')[1].split()[0])
            except:
                pass
        if 'read, mib/s:' in line:
            try:
                read_throughput = float(line.split('read, mib/s:')[1].split()[0])
            except:
                pass
        if 'written, mib/s:' in line:
            try:
                write_throughput = float(line.split('written, mib/s:')[1].split()[0])
            except:
                pass
    
    # Performance degradation indicators
    sysbench_available = 0 if 'sysbench_unavailable' in log else 1
    performance_issues = log.count('timeout') + log.count('failed') + log.count('error')
    
    return {
        # CPU Performance metrics
        "cpu_events_per_sec": cpu_performance,
        "cpu_avg_latency_ms": cpu_latency,
        "cpu_total_time_s": cpu_total_time,
        
        # Memory Performance metrics
        "memory_throughput_mib": memory_throughput,
        "memory_total_time_s": memory_total_time,
        
        # File I/O Performance metrics
        "fileio_reads_per_sec": reads_per_sec,
        "fileio_writes_per_sec": writes_per_sec,
        "fileio_read_mib_sec": read_throughput,
        "fileio_write_mib_sec": write_throughput,
        
        # Availability and error metrics
        "sysbench_available": sysbench_available,
        "performance_errors": performance_issues,
        
        # Performance anomaly indicators
        "low_cpu_performance": 1 if cpu_performance > 0 and cpu_performance < 100 else 0,
        "high_cpu_latency": 1 if cpu_latency > 50 else 0,
        "low_memory_throughput": 1 if memory_throughput > 0 and memory_throughput < 100 else 0,
        "low_fileio_performance": 1 if (reads_per_sec > 0 and reads_per_sec < 10) or (writes_per_sec > 0 and writes_per_sec < 10) else 0,
        "performance_degradation": 1 if (
            (cpu_performance > 0 and cpu_performance < 50) or 
            (memory_throughput > 0 and memory_throughput < 50) or
            (reads_per_sec > 0 and reads_per_sec < 5)
        ) else 0
    }

def extract_features(log):
    """
    Extract features from sysbench performance data only
    """
    # Get sysbench performance metrics as features
    features = extract_performance_metrics(log)
    
    return features

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
        perf_logger.info(f"TrainingSample={i+1},TotalProcesses={features.get('total_processes', 0)},TmpFiles={features.get('tmp_files', 0)},NetworkConnections={features.get('network_connections', 0)}")
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
        
        # Log performance metrics (enhanced with sysbench data)
        perf_logger.info(f"TotalProcesses={features.get('total_processes', 0)},PHPProcesses={features.get('php_processes', 0)},TmpFiles={features.get('tmp_files', 0)},WebshellFiles={features.get('webshell_files', 0)},NetworkConnections={features.get('network_connections', 0)},CommandInjection={features.get('command_injection', 0)},CPUPerf={features.get('cpu_events_per_sec', 0)},MemThroughput={features.get('memory_throughput_mib', 0)},CPULatency={features.get('cpu_avg_latency_ms', 0)}")

        # Check for critical behavior patterns that should trigger immediate alerts (enhanced with performance indicators)
        critical_threshold_met = (
            features.get("webshell_files", 0) >= 5 or
            features.get("command_injection", 0) >= 3 or
            features.get("privilege_escalation", 0) >= 2 or
            (features.get("tmp_files", 0) >= 3 and features.get("php_processes", 0) >= 1) or
            features.get("total_processes", 0) >= 20 or
            # Performance-based attack indicators
            features.get("performance_degradation", 0) == 1 or
            features.get("high_cpu_latency", 0) == 1 or
            (features.get("low_cpu_performance", 0) == 1 and features.get("low_memory_throughput", 0) == 1) or
            features.get("performance_errors", 0) >= 3
        )

        # Force anomaly detection if critical thresholds are met
        if critical_threshold_met:
            prediction = -1
            print("[FORCED-ANOMALY] 🚨 Critical behavior thresholds exceeded - forcing anomaly detection!")
            security_logger.critical(f"Critical thresholds exceeded for {CONTAINER_NAME} - WebshellFiles={features.get('webshell_files', 0)}, CommandInjection={features.get('command_injection', 0)}, PrivilegeEscalation={features.get('privilege_escalation', 0)}, PerfDegradation={features.get('performance_degradation', 0)}, CPULatency={features.get('cpu_avg_latency_ms', 0)}ms, CPUPerf={features.get('cpu_events_per_sec', 0)}")

        if prediction == -1:
            print("[ALERT] 🚨 Syscall anomaly detected! Possible attack")
            security_logger.warning(f"Syscall anomaly detected on {CONTAINER_NAME} - ML Prediction: {prediction}")
            
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
                    security_logger.critical(f"CRITICAL CVEs detected on {CONTAINER_NAME}: {len(critical_cves)} vulnerabilities")
                    for cve in critical_cves:
                        print(f"   • {cve['cve_id']}: {cve['description']}")
                        cve_logger.critical(f"CRITICAL CVE detected - {cve['cve_id']}: {cve['description']} (Score: {cve.get('score', 'N/A')})")
                
                if high_cves and len(high_cves) >= 2:
                    print(f"\n⚠️  HIGH RISK ALERT: {len(high_cves)} HIGH severity CVE(s) detected!")
                    security_logger.warning(f"HIGH risk CVEs detected on {CONTAINER_NAME}: {len(high_cves)} vulnerabilities")
                    for cve in high_cves[:3]:  # Show top 3
                        print(f"   • {cve['cve_id']}: {cve['description']}")
                        cve_logger.warning(f"HIGH CVE detected - {cve['cve_id']}: {cve['description']} (Score: {cve.get('score', 'N/A')})")
            else:
                print("No specific CVE patterns identified, but anomalous behavior detected.")
                security_logger.info(f"Anomalous behavior detected on {CONTAINER_NAME} but no specific CVE patterns matched")
            
            print()
        else:
            # Also check for CVE patterns in normal behavior (early warning)
            potential_cves = detect_cve_patterns(log, features)
            if potential_cves:
                high_risk_cves = [cve for cve in potential_cves if cve['risk'] in ['HIGH', 'CRITICAL']]
                if high_risk_cves:
                    print(f"[WARNING] ⚠️  Suspicious patterns detected (not anomalous yet)")
                    security_logger.info(f"Suspicious patterns detected on {CONTAINER_NAME} (not anomalous): {len(high_risk_cves)} CVE patterns")
                    for cve in high_risk_cves[:2]:  # Show top 2
                        print(f"   • {cve['cve_id']} [{cve['risk']}]: {cve['description']}")
                        cve_logger.info(f"Suspicious pattern - {cve['cve_id']} [{cve['risk']}]: {cve['description']}")
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