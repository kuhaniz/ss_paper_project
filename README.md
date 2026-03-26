```
docker-compose up
python monitor.py

# INSIDE CONTAINER
docker exec -it dvwa sh -c "cat /etc/passwd"
docker exec -it dvwa sh
cat /etc/passwd
ls /root
whoami

```