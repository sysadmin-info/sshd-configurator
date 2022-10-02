#!/bin/bash
echo "This quick installer script requires root privileges."
echo "Checking..."
if [[ $(/usr/bin/id -u) -ne 0 ]]; 
then
    echo "Not running as root"
    exit 0
else
	echo "Installation continues"
fi

SUDO=
if [ "$UID" != "0" ]; then
	if [ -e /usr/bin/sudo -o -e /bin/sudo ]; then
		SUDO=sudo
	else
		echo "*** This quick installer script requires root privileges."
		exit 0
	fi
fi
# Set your timezone
timedatectl set-timezone Europe/Warsaw
# Add group admins
groupadd admins
# Add your_username
useradd your_username
# Set a apassword for your user
echo "your_username:your_password" | chpasswd
# Add a user to a group admins
usermod -a -G admins your_username
# Check is the user in admins group
id your_username
# Create .ssh directory
mkdir -p /home/your_username/.ssh
# Create authorized keys for a user
touch /home/your_username/.ssh/authorized_keys
# Set proper permissions for .ssh directory
chmod 700 /home/your_username/.ssh
# Add RSA key to authorized-keys
echo "ssh-rsa key" >> /home/your_username/.ssh/authorized_keys
# Set proper permissions for authorized keys
chmod 600 /home/your_username/.ssh/authorized_keys
# Change owner recursivelly to your user for .ssh directory
chown -R your_username:your_group /home/your_username/.ssh
# Add group admins to sudoers
sed -i 's/%sudo/%admins/g' /etc/sudoers
# Make a backup of a sshd_config
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
## Replace with sed settings in sshd config
# Deny access for rott via ssh
sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
# Deby password authentication via ssh
sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config
# Deny using empty passwords
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
# Don't read the uer's ~/.rhosts and ~/.shosts files
sed -i 's/#IgnoreRhosts no/IgnoreRhosts yes/g' /etc/ssh/sshd_config
# Enable public key authentication
sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/g' /etc/ssh/sshd_config
# Disable PAM authentication
sed -i 's/UsePAM yes/UsePAM no/g' /etc/ssh/sshd_config
# Enable logging
sed -i 's/#SyslogFacility AUTH/SyslogFacility AUTH/g' /etc/ssh/sshd_config
sed -i 's/#LogLevel INFO/LogLevel VERBOSE/g' /etc/ssh/sshd_config
# Disable host based authentication 
sed -i 's/#HostbasedAuthentication no/HostbasedAuthentication no/g' /etc/ssh/sshd_config
# Enable keys
sed -i 's/#HostKey/HostKey/g' /etc/ssh/sshd_config
# Add algorithms
echo "# Specifies the available KEX (Key Exchange) algorithms." >> /etc/ssh/sshd_config
echo "KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256" >> /etc/ssh/sshd_config
 # Add ciphers
echo "# Specifies the ciphers allowed" >> /etc/ssh/sshd_config
echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" >> /etc/ssh/sshd_config
 # Add MACs
echo "#Specifies the available MAC (message authentication code) algorithms" >> /etc/ssh/sshd_config
echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >> /etc/ssh/sshd_config
# Enable login grace time
sed -i 's/#LoginGraceTime 2m/LoginGraceTime 2m/g' /etc/ssh/sshd_config
# Set how many bad logins can be allowed
sed -i 's/#MaxAuthTries 6/MaxAuthTries 3/g' /etc/ssh/sshd_config
# Set how many paralel ssh sessions can be performed
sed -i 's/#MaxSessions 10/MaxSessions 3/g' /etc/ssh/sshd_config
# Change the interval for the client
sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 300/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 0/g' /etc/ssh/sshd_config
sed -i 's/#UseDNS no/UseDNS yes/g' /etc/ssh/sshd_config
# Diable X11FForwarding
sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
# use a random port above 1024
sed -i 's/#Port [0-9]*/Port 1337/g' /etc/ssh/sshd_config
# Add a port for firewalld service
firewall-cmd --add-port=1337/tcp --permanent --zone=public
# Add a port fir iptables service (uncomment if needed)
#iptables -A input -i eth0 -p tcp dport 1337 -j ACCEPT
# Add a a port for ufw service (uncomment if needed)
#ufw allow 1337
# Check added port in ufw
#ufw show added
# Reload firewalld
firewall-cmd --reload
# Check firewalld rules
firewall-cmd --list-all
# Check the port in sshd config
grep Port /etc/ssh/sshd_config
# Add your username to allowed users in sshd. Only this user will be allowed to login through sshd to the server.
echo "AllowUsers your_username" >> /etc/ssh/sshd_config
# Check is the user added
grep AllowUsers /etc/ssh/sshd_config
# Add IP range to /etc/hosts.allow to allow only login from this subnet to the server through ssh
echo "sshd : 10.10.0.0/255.255.255.0 : ALLOW" >> /etc/hosts.allow
# Deny all to log through ssh except allowed IP range configured above
echo "sshd : All : DENY" >> /etc/hosts.deny
# Reload the daemon for services (needed for sudo)
systemctl daemon-reload
# Restart ssh daemon
systemctl restart sshd.service
