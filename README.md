# Ping: ICMP ECHO_REQUEST/ECHO_REPLY

Implementation of the ping command from scratch. Given a host, the program resolves the host to an IPv4 address, creates a raw IPv4 socket, sends ICMP echo requests and waits for ICMP echo replies.

Compile the program by running:
```
gcc ping.c -o ping
```

Then start pinging:
```
sudo ./ping google.com
```

Note: root privileges are necessary since we use raw IPv4 sockets in the code (sorry!).

Note bis: some hosts may not accept ICMP traffic from the internet.