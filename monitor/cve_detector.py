# Docker CVE Mapping for Anomaly Detection
# This file maps detected anomaly patterns to known Docker CVEs

CVE_PATTERNS = {
    # Container Escape CVEs
    "CVE-2019-5736": {
        "description": "runc container escape via malicious container image",
        "patterns": ["runc", "proc/self/exe", "container_escape"],
        "features": ["privilege_escalation", "suspicious_commands", "file_changes"],
        "risk": "CRITICAL"
    },
    
    "CVE-2022-0847": {
        "description": "Dirty Pipe - kernel privilege escalation",
        "patterns": ["pipe", "splice", "kernel", "/proc/version"],
        "features": ["privilege_escalation", "reconnaissance", "file_changes"],
        "risk": "HIGH"
    },
    
    # Information Disclosure CVEs  
    "CVE-2020-15257": {
        "description": "containerd information disclosure",
        "patterns": ["/etc/passwd", "/etc/shadow", "/proc/", "cat "],
        "features": ["suspicious_commands", "reconnaissance", "file_changes"],
        "risk": "MEDIUM"
    },
    
    "CVE-2021-30465": {
        "description": "runc mount destinations information disclosure", 
        "patterns": ["/proc/mounts", "/etc/hosts", "mount", "filesystem"],
        "features": ["reconnaissance", "file_changes", "suspicious_commands"],
        "risk": "MEDIUM"
    },
    
    # Remote Code Execution CVEs
    "CVE-2020-1472": {
        "description": "Netlogon privilege escalation (Zerologon)",
        "patterns": ["netlogon", "system(", "eval(", "exec("],
        "features": ["command_injection", "privilege_escalation", "network_activity"],
        "risk": "CRITICAL"
    },
    
    "CVE-2019-14271": {
        "description": "Docker cp command allows arbitrary file write",
        "patterns": ["docker cp", "arbitrary_write", "symlink", "/tmp/", "suspicious_file", "exploit", "malicious", "backdoor", ".sh", "chmod +x"],
        "features": ["file_changes", "tmp_files", "suspicious_commands", "webshell_files"],
        "risk": "HIGH"
    },
    
    # Privilege Escalation CVEs
    "CVE-2018-15664": {
        "description": "Docker symlink-exchange attack",
        "patterns": ["symlink", "chroot", "/proc/self/root"],
        "features": ["privilege_escalation", "file_changes", "root_shells"],
        "risk": "HIGH"
    },
    
    "CVE-2021-41089": {
        "description": "Moby/Docker CLI path traversal",
        "patterns": ["../", "path_traversal", "directory_traversal"],
        "features": ["file_changes", "suspicious_commands", "tmp_files"],
        "risk": "MEDIUM"
    },
    
    # Network-based CVEs
    "CVE-2020-13401": {
        "description": "Docker Engine API exposure",
        "patterns": [":2375", ":2376", "docker.sock", "api_exposure"],
        "features": ["network_activity", "network_connections", "high_cpu"],
        "risk": "HIGH"
    },
    
    # Web Application CVEs (for DVWA specifically)
    "CVE-2019-16278": {
        "description": "DVWA SQL injection vulnerability",
        "patterns": ["sql", "injection", "select", "union"],
        "features": ["network_activity", "access_logs", "mysql_processes"],
        "risk": "HIGH"
    },
    
    "CVE-2020-25613": {
        "description": "Web application file upload vulnerability",
        "patterns": ["upload", "webshell", ".php", "shell.php"],
        "features": ["tmp_files", "php_processes", "command_injection"],
        "risk": "HIGH"
    },
    
    # Supply Chain CVEs
    "CVE-2021-44228": {
        "description": "Log4j remote code execution (Log4Shell)",
        "patterns": ["log4j", "jndi", "ldap://", "${"],
        "features": ["command_injection", "network_activity", "access_logs"],
        "risk": "CRITICAL"
    }
}

# Attack to CVE mapping based on our demonstration
ATTACK_CVE_MAPPING = {
    "reconnaissance": ["CVE-2020-15257", "CVE-2021-30465", "CVE-2020-13401"],
    "file_disclosure": ["CVE-2020-15257", "CVE-2021-30465"],
    "tmp_file_creation": ["CVE-2019-14271", "CVE-2021-41089", "CVE-2020-25613"],
    "webshell_creation": ["CVE-2020-25613", "CVE-2019-16278"],
    "process_manipulation": ["CVE-2019-5736", "CVE-2018-15664"],
    "network_reconnaissance": ["CVE-2020-13401", "CVE-2021-30465"],
    "privilege_usage": ["CVE-2019-5736", "CVE-2018-15664", "CVE-2022-0847"]
}

def detect_cve_patterns(log_data, features):
    """
    Analyze log data and extracted features to identify potential CVE matches
    """
    potential_cves = []
    log_lower = log_data.lower()
    
    for cve_id, cve_info in CVE_PATTERNS.items():
        score = 0
        matched_patterns = []
        matched_features = []
        
        # Check for pattern matches in log data
        for pattern in cve_info["patterns"]:
            if pattern.lower() in log_lower:
                score += 2
                matched_patterns.append(pattern)
        
        # Check for feature matches
        for feature in cve_info["features"]:
            if feature in features and features[feature] > 0:
                score += 1
                matched_features.append(f"{feature}({features[feature]})")
        
        # If we have matches, add to potential CVEs
        if score >= 1:  # Lower threshold for better detection
            potential_cves.append({
                "cve_id": cve_id,
                "description": cve_info["description"],
                "risk": cve_info["risk"],
                "score": score,
                "matched_patterns": matched_patterns,
                "matched_features": matched_features
            })
    
    # Sort by score (highest first)
    return sorted(potential_cves, key=lambda x: x["score"], reverse=True)

def format_cve_alert(cves):
    """
    Format CVE detection results for alerting
    """
    if not cves:
        return "No known CVE patterns detected."
    
    alert = "🚨 POTENTIAL CVE MATCHES DETECTED:\n"
    for cve in cves:
        alert += f"\n• {cve['cve_id']} [{cve['risk']}] (Score: {cve['score']})\n"
        alert += f"  Description: {cve['description']}\n"
        if cve['matched_patterns']:
            alert += f"  Patterns: {', '.join(cve['matched_patterns'])}\n"
        if cve['matched_features']:
            alert += f"  Features: {', '.join(cve['matched_features'])}\n"
    
    return alert