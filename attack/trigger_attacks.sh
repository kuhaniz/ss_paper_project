#!/bin/bash
# Manual Attack Trigger Script
# Executes various attacks on the victim container for anomaly detection testing

VICTIM_CONTAINER="case1_exception_handling-victim-1"

echo "🎯 Manual Attack Trigger for Anomaly Detection"
echo "============================================="
echo "Target Container: $VICTIM_CONTAINER"
echo ""

# Check if container is running
if ! docker ps --format '{{.Names}}' | grep -q "^${VICTIM_CONTAINER}$"; then
    echo "❌ Error: Container $VICTIM_CONTAINER is not running"
    echo "   Start it with: cd ../container_cgroup_escape_exploitation/attacks/case1_exception_handling && docker compose up victim"
    exit 1
fi

echo "Available attacks:"
echo "  [1] CPU Exhaustion Attack (High CPU load)"
echo "  [2] Memory Bomb Attack (Memory exhaustion)" 
echo "  [3] Fork Bomb Attack (Process explosion)"
echo "  [4] Disk I/O Attack (File system stress)"
echo "  [5] Network Flood Attack (Network saturation)"
echo "  [6] Combined Performance Attack (All resources)"
echo "  [7] Privilege Escalation Attempt (CVE simulation)"
echo "  [8] Container Escape Simulation (Filesystem stress)"
echo "  [s] Status check (Container health)"
echo "  [q] Quit"
echo ""

read -p "Select attack [1-8/s/q]: " choice

case $choice in
    1)
        echo "🔥 Launching CPU Exhaustion Attack..."
        echo "   This will max out CPU cores for 60 seconds"
        docker exec $VICTIM_CONTAINER bash -c "
            echo 'Starting CPU stress attack...'
            # Stress all CPU cores
            for i in \$(seq 1 \$(nproc)); do
                (while true; do echo > /dev/null; done) &
            done
            sleep 60
            pkill -f 'while true'
            echo 'CPU attack completed'
        " &
        ATTACK_PID=$!
        echo "   Attack running in background (PID: $ATTACK_PID)"
        echo "   Monitor should detect high CPU usage and performance degradation"
        ;;
        
    2)
        echo "💥 Launching Memory Bomb Attack..."
        echo "   This will consume available memory rapidly"
        docker exec $VICTIM_CONTAINER bash -c "
            echo 'Starting memory exhaustion attack...'
            # Allocate memory rapidly
            python3 -c \"
import time
data = []
try:
    for i in range(1000):
        # Allocate 10MB chunks
        chunk = 'x' * (10 * 1024 * 1024)
        data.append(chunk)
        print(f'Allocated {(i+1)*10}MB')
        if i % 10 == 0:
            time.sleep(1)
except MemoryError:
    print('Memory exhausted!')
    time.sleep(30)
except KeyboardInterrupt:
    pass
finally:
    print('Memory attack completed')
            \"
        " &
        ATTACK_PID=$!
        echo "   Attack running in background (PID: $ATTACK_PID)"
        echo "   Monitor should detect memory pressure and allocation anomalies"
        ;;
        
    3)
        echo "⚡ Launching Fork Bomb Attack..."
        echo "   This will create excessive processes (limited for safety)"
        docker exec $VICTIM_CONTAINER bash -c "
            echo 'Starting controlled fork bomb attack...'
            # Safe fork bomb with limits
            for i in \$(seq 1 200); do
                (sleep 30) &
            done
            echo 'Fork bomb processes created'
            sleep 45
            pkill -f 'sleep 30'
            echo 'Fork bomb attack completed'
        " &
        ATTACK_PID=$!
        echo "   Attack running in background (PID: $ATTACK_PID)"
        echo "   Monitor should detect process count spikes and resource contention"
        ;;
        
    4)
        echo "💾 Launching Disk I/O Attack..."
        echo "   This will stress filesystem with intensive I/O"
        docker exec $VICTIM_CONTAINER bash -c "
            echo 'Starting disk I/O stress attack...'
            # Create intensive disk activity
            mkdir -p /tmp/iostress
            cd /tmp/iostress
            
            # Write attack
            for i in \$(seq 1 10); do
                dd if=/dev/zero of=stress_file_\$i bs=1M count=100 2>/dev/null &
            done
            
            # Read attack  
            for i in \$(seq 1 5); do
                (while [ -f stress_file_1 ]; do cat stress_file_* > /dev/null 2>&1; done) &
            done
            
            sleep 45
            pkill -f 'dd if=/dev/zero'
            pkill -f 'cat stress_file'
            rm -rf /tmp/iostress
            echo 'Disk I/O attack completed'
        " &
        ATTACK_PID=$!
        echo "   Attack running in background (PID: $ATTACK_PID)"
        echo "   Monitor should detect high disk I/O and filesystem stress"
        ;;
        
    5)
        echo "🌐 Launching Network Flood Attack..."
        echo "   This will generate network traffic and connection attempts"
        docker exec $VICTIM_CONTAINER bash -c "
            echo 'Starting network flood attack...'
            # Network stress simulation
            for i in \$(seq 1 50); do
                (curl -s http://localhost:80 --connect-timeout 1 --max-time 1 >/dev/null 2>&1 || true) &
                (ping -c 100 127.0.0.1 >/dev/null 2>&1 || true) &
            done
            sleep 30
            pkill -f curl
            pkill -f ping
            echo 'Network flood attack completed'
        " &
        ATTACK_PID=$!
        echo "   Attack running in background (PID: $ATTACK_PID)"
        echo "   Monitor should detect network anomalies and connection spikes"
        ;;
        
    6)
        echo "🔥💥⚡💾 Launching Combined Performance Attack..."
        echo "   This will stress CPU, memory, processes, and disk simultaneously"
        docker exec $VICTIM_CONTAINER bash -c "
            echo 'Starting combined resource attack...'
            
            # CPU stress
            for i in \$(seq 1 2); do
                (while true; do echo > /dev/null; done) &
            done
            
            # Memory pressure
            python3 -c \"
import time
data = []
for i in range(50):
    data.append('x' * (5 * 1024 * 1024))  # 5MB chunks
    time.sleep(0.5)
\" &
            
            # Process explosion
            for i in \$(seq 1 50); do
                (sleep 60) &
            done
            
            # Disk I/O
            mkdir -p /tmp/combined_attack
            dd if=/dev/zero of=/tmp/combined_attack/stress bs=1M count=50 2>/dev/null &
            
            sleep 45
            
            # Cleanup
            pkill -f 'while true'
            pkill -f 'python3'
            pkill -f 'sleep 60' 
            pkill -f 'dd if=/dev/zero'
            rm -rf /tmp/combined_attack
            echo 'Combined attack completed'
        " &
        ATTACK_PID=$!
        echo "   Attack running in background (PID: $ATTACK_PID)"
        echo "   Monitor should detect CRITICAL performance degradation across all metrics"
        ;;
        
    7)
        echo "🔓 Launching Privilege Escalation Simulation..."
        echo "   This simulates CVE exploitation patterns"
        docker exec $VICTIM_CONTAINER bash -c "
            echo 'Starting privilege escalation simulation...'
            
            # Simulate suspicious file access patterns
            touch /tmp/shadow_copy /tmp/passwd_copy 2>/dev/null || true
            cat /etc/passwd > /tmp/passwd_copy 2>/dev/null || true
            
            # Simulate setuid exploitation attempts  
            find / -perm -4000 2>/dev/null | head -5 | while read file; do
                ls -la \"\$file\" 2>/dev/null || true
            done
            
            # Simulate kernel module enumeration
            lsmod 2>/dev/null || true
            cat /proc/version 2>/dev/null || true
            
            # Simulate capability enumeration
            capsh --print 2>/dev/null || true
            
            sleep 20
            rm -f /tmp/shadow_copy /tmp/passwd_copy
            echo 'Privilege escalation simulation completed'
        " &
        ATTACK_PID=$!
        echo "   Attack running in background (PID: $ATTACK_PID)"
        echo "   Monitor should detect CVE-related patterns and security anomalies"
        ;;
        
    8)
        echo "🏃 Launching Container Escape Simulation..."
        echo "   This simulates container breakout attempts"
        docker exec $VICTIM_CONTAINER bash -c "
            echo 'Starting container escape simulation...'
            
            # Simulate cgroup manipulation attempts
            find /sys/fs/cgroup -name '*' 2>/dev/null | head -10 | while read cg; do
                cat \"\$cg\" 2>/dev/null | head -1 || true
            done
            
            # Simulate mount enumeration
            mount | grep -E 'proc|sys|dev' || true
            
            # Simulate namespace exploration  
            ls -la /proc/self/ns/ 2>/dev/null || true
            
            # Intensive filesystem stress (escape attempt simulation)
            mkdir -p /tmp/escape_attempt
            for i in \$(seq 1 20); do
                dd if=/dev/zero of=/tmp/escape_attempt/breakout_\$i bs=1M count=20 2>/dev/null &
            done
            
            sleep 30
            pkill -f 'dd if=/dev/zero'
            rm -rf /tmp/escape_attempt
            echo 'Container escape simulation completed'
        " &
        ATTACK_PID=$!
        echo "   Attack running in background (PID: $ATTACK_PID)"
        echo "   Monitor should detect filesystem manipulation and potential escape attempts"
        ;;
        
    s)
        echo "📊 Container Status Check..."
        echo ""
        echo "Container Info:"
        docker ps --filter name=$VICTIM_CONTAINER --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
        echo ""
        echo "Resource Usage:"
        docker stats $VICTIM_CONTAINER --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"
        echo ""
        echo "Running Processes:"
        docker exec $VICTIM_CONTAINER ps aux | head -10
        echo ""
        echo "Sysbench Available:"
        docker exec $VICTIM_CONTAINER which sysbench 2>/dev/null && echo "✅ Sysbench installed" || echo "❌ Sysbench not found"
        ;;
        
    q)
        echo "👋 Exiting attack interface"
        exit 0
        ;;
        
    *)
        echo "❌ Invalid choice. Please select 1-8, s, or q"
        exit 1
        ;;
esac

if [ ! -z "$ATTACK_PID" ]; then
    echo ""
    echo "📈 Attack Progress:"
    echo "   - Attack PID: $ATTACK_PID"
    echo "   - Monitor logs: tail -f /Users/tanjinwei/Documents/MSSD/TERM_2/Systems_Security/PROJECT/Demo/logs/security_alerts.log"
    echo "   - Performance logs: tail -f /Users/tanjinwei/Documents/MSSD/TERM_2/Systems_Security/PROJECT/Demo/logs/performance_data.log"
    echo "   - CVE detections: tail -f /Users/tanjinwei/Documents/MSSD/TERM_2/Systems_Security/PROJECT/Demo/logs/cve_detections.log"
    echo ""
    echo "💡 Keep your monitor running: cd ../monitor && sudo python3 monitor.py"
    echo "   The monitor should detect anomalies within 1-5 seconds"
fi