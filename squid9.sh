#!/bin/sh
# Created by https://www.hostingtermurah.net
# Modified by 0123456

# install screenfetch
cd
wget -O /usr/bin/screenfetch "https://raw.githubusercontent.com/nexne/ani/master/screenfetch"
chmod +x /usr/bin/screenfetch
echo "clear" >> .profile
echo "screenfetch" >> .profile

cd
# install fail2ban
apt-get -y install fail2ban
service fail2ban restart

# install squid3
apt-get -y install squid3
cat > /etc/squid3/squid.conf <<-END
acl localhost src 127.0.0.1/32 ::1
acl to_localhost dst 127.0.0.0/8 0.0.0.0/32 ::1
acl SSL_ports port 443
acl Safe_ports port 80
acl Safe_ports port 21
acl Safe_ports port 443
acl Safe_ports port 70
acl Safe_ports port 210
acl Safe_ports port 1025-65535
acl Safe_ports port 280
acl Safe_ports port 488
acl Safe_ports port 591
acl Safe_ports port 777
acl CONNECT method CONNECT
acl SSH dst xxxxxxxxx-xxxxxxxxx/32
http_access allow SSH
http_access allow manager localhost
http_access deny manager
http_access allow localhost
http_access deny all
http_port 8888
http_port 8080
http_port 8000
http_port 80
http_port 3128
coredump_dir /var/spool/squid3
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname private
END
sed -i $MYIP2 /etc/squid3/squid.conf;
service squid3 restart
