#!/bin/sh
FILE="/etc/sysctl.d/sysctl.conf"
cat 2> /dev/null > $FILE <<EOF
#disable all ipv6
net.ipv6.conf.all.disable_ipv6 = 1

# Controls IP packet forwarding
net.ipv4.ip_forward = 0

# Controls IPv4 redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Controls IPv6 redirects
net.ipv6.conf.default.accept_redirects = 0

# Log martians
net.ipv4.conf.all.log_martians = 1

# Ignore
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# IP filter
net.ipv4.conf.all.rp_filter = 1

# Controls source route verification
net.ipv4.conf.default.rp_filter = 1

# Do not accept source routing
net.ipv4.conf.all.accept_source_route = 0

# Controls the System Request debugging functionality of the kernel
kernel.sysrq = 0

# Controls whether core dumps will append the PID to the core filename.
# Useful for debugging multi-threaded applications.
kernel.core_uses_pid = 1

# Controls the use of TCP syncookies
net.ipv4.tcp_syncookies = 1

# Disable netfilter on bridges.
net.bridge.bridge-nf-call-ip6tables = 0
net.bridge.bridge-nf-call-iptables = 0
net.bridge.bridge-nf-call-arptables = 0

# Controls the default maxmimum size of a mesage queue
kernel.msgmnb = 65536

# Controls the maximum size of a message, in bytes
kernel.msgmax = 65536

# Controls the maximum shared segment size, in bytes
kernel.shmmax = 68719476736

# Controls the maximum number of shared memory segments, in pages
kernel.shmall = 4294967296

# controls virtual address space randomization
kernel.randomize_va_space = 2
EOF
chmod 644 $FILE > /dev/null 2>&1
/sbin/sysctl -q --system > /dev/null 2>&1