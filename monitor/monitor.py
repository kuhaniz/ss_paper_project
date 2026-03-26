import subprocess
import time
import pandas as pd
from sklearn.ensemble import IsolationForest

# ==============================
# CONFIG
# ==============================
CONTAINER_NAME = "dvwa"
TRAINING_ROUNDS = 50
DETECTION_INTERVAL = 2  # seconds

# ==============================
# STEP 1: Capture syscalls (Alternative Docker approach)
# ==============================
def capture_syscalls(duration=1):
    """
    Capture container activity using Docker stats and logs instead of sysdig
    """
    try:
        # Method 1: Try to get container stats
        stats_cmd = [
            "docker", "stats", CONTAINER_NAME, 
            "--no-stream", "--format", 
            "table {{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"
        ]
        
        stats_result = subprocess.run(stats_cmd, capture_output=True, text=True)
        stats_log = stats_result.stdout.lower()
        
        # Method 2: Try to get recent logs 
        logs_cmd = [
            "docker", "logs", CONTAINER_NAME, 
            "--tail", "50", "--since", f"{duration}s"
        ]
        
        logs_result = subprocess.run(logs_cmd, capture_output=True, text=True)
        logs_data = logs_result.stdout.lower()
        
        # Method 3: Get process list from inside container
        ps_cmd = [
            "docker", "exec", CONTAINER_NAME,
            "ps", "aux"
        ]
        
        ps_result = subprocess.run(ps_cmd, capture_output=True, text=True)
        ps_data = ps_result.stdout.lower()
        
        # Combine all data for analysis
        log = f"{stats_log} {logs_data} {ps_data}"
        
        print("RAW:", log[:200])

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
# STEP 2: Feature extraction (Updated for Docker data)
# ==============================
def extract_features(log):
    """
    Extract features from Docker stats, logs, and process data
    """
    return {
        # Process-based features
        "apache_processes": log.count("apache"),
        "php_processes": log.count("php"),
        "mysql_processes": log.count("mysql"),
        "sh_processes": log.count("/bin/sh") + log.count("/bin/bash"),
        
        # Log-based features  
        "error_logs": log.count("error") + log.count("warning"),
        "access_logs": log.count("get ") + log.count("post "),
        "login_attempts": log.count("login") + log.count("password"),
        
        # Activity indicators
        "network_activity": log.count("established") + log.count("listen"),
        "file_operations": log.count("open") + log.count("write") + log.count("read"),
        
        # Memory and CPU indicators (from stats)
        "high_cpu": 1 if any(word for word in log.split() if word.endswith("%") and "." in word) else 0,
        "memory_usage": log.count("mib") + log.count("gib"),
        
        # Suspicious patterns
        "command_injection": log.count("system") + log.count("exec") + log.count("eval"),
    }

# ==============================
# STEP 3: Build baseline
# ==============================
def train_model():
    print("[+] Training baseline model (normal behavior)...")
    data = []

    for i in range(TRAINING_ROUNDS):
        log = capture_syscalls(duration=1)
        features = extract_features(log)
        data.append(features)

        print(f"[TRAIN] Sample {i+1}: {features}")
        time.sleep(1)

    df = pd.DataFrame(data)

    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(df)

    print("[+] Model training complete\n")
    return model

# ==============================
# STEP 4: Detection loop
# ==============================
def detect(model):
    print("[+] Starting real-time syscall monitoring...\n")

    while True:
        log = capture_syscalls(duration=1)
        features = extract_features(log)

        df = pd.DataFrame([features])
        prediction = model.predict(df)[0]

        print(f"[DATA] {features}")

        if prediction == -1:
            print("[ALERT] 🚨 Syscall anomaly detected! Possible attack\n")
        else:
            print("[OK] Normal behavior\n")

        time.sleep(DETECTION_INTERVAL)

# ==============================
# MAIN
# ==============================
if __name__ == "__main__":
    model = train_model()
    detect(model)