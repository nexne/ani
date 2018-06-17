#!/bin/sh
# Created by https://www.hostingtermurah.net
# Modified by 0123456

#Requirement
if [ ! -e /usr/bin/curl ]; then
    apt-get -y update && apt-get -y upgrade
	apt-get -y install curl
fi
# initializing var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(curl -4 icanhazip.com)
if [ $MYIP = "" ]; then
   MYIP=`ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1`;
fi
MYIP2="s/xxxxxxxxx/$MYIP/g";

# go to root
cd

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

#Add DNS Server ipv4
echo "nameserver 8.8.8.8" > /etc/resolv.conf
echo "nameserver 8.8.4.4" >> /etc/resolv.conf
sed -i '$ i\echo "nameserver 8.8.8.8" > /etc/resolv.conf' /etc/rc.local
sed -i '$ i\echo "nameserver 8.8.4.4" >> /etc/resolv.conf' /etc/rc.local

# install wget and curl
apt-get update;apt-get -y install wget curl;

# set time GMT +8
ln -fs /usr/share/zoneinfo/Asia/Kuala_Lumpur /etc/localtime

# set repo
cat > /etc/apt/sources.list <<END2
deb http://security.debian.org/ jessie/updates main contrib non-free
deb-src http://security.debian.org/ jessie/updates main contrib non-free
deb http://http.us.debian.org/debian jessie main contrib non-free
deb http://packages.dotdeb.org jessie all
deb-src http://packages.dotdeb.org jessie all
END2
wget "http://www.dotdeb.org/dotdeb.gpg"
cat dotdeb.gpg | apt-key add -;rm dotdeb.gpg

# remove unused
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove bind9*;
apt-get -y purge sendmail*
apt-get -y remove sendmail*

# update
apt-get update; apt-get -y upgrade;

# install webserver
#apt-get -y install nginx php5-fpm php5-cli

# install essential package
echo "mrtg mrtg/conf_mods boolean true" | debconf-set-selections
apt-get -y install bmon iftop htop nmap axel nano iptables traceroute sysv-rc-conf dnsutils bc nethogs openvpn vnstat less screen psmisc apt-file whois ptunnel ngrep mtr git zsh mrtg snmp snmpd snmp-mibs-downloader unzip unrar rsyslog debsums rkhunter
apt-get -y install build-essential
apt-get -y install libio-pty-perl libauthen-pam-perl apt-show-versions

# disable exim
service exim4 stop
sysv-rc-conf exim4 off

# update apt-file
apt-file update

# setting vnstat
#vnstat -u -i eth0
#service vnstat restart

# install screenfetch
cd
wget -O /usr/bin/screenfetch "https://raw.githubusercontent.com/nexne/ani/master/screenfetch"
chmod +x /usr/bin/screenfetch
echo "clear" >> .profile
echo "screenfetch" >> .profile

# setting port ssh
#sed -i '/Port 22/a Port 68' /etc/ssh/sshd_config
#sed -i '/Port 22/a Port  90' /etc/ssh/sshd_config
sed -i 's/Port 22/Port  22/g' /etc/ssh/sshd_config
service ssh restart

# install dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=443/g' /etc/default/dropbear
#sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 109 -p 110"/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 90 -p 993 -p 995 -p 777 -p 143 -p 109 -p 110 -p 192 -p 427 -p 625 -p 1220 -K 3"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
service dropbear restart
#Upgrade to Dropbear 2018
cd
apt-get install zlib1g-dev
wget https://raw.githubusercontent.com/nexne/ani/master/dropbear-2018.76.tar.bz2
bzip2 -cd dropbear-2018.76.tar.bz2 | tar xvf -
cd dropbear-2018.76
./configure
make && make install
mv /usr/sbin/dropbear /usr/sbin/dropbear.old
ln /usr/local/sbin/dropbear /usr/sbin/dropbear
cd && rm -rf dropbear-2018.76 && rm -rf dropbear-2018.76.tar.bz2
service dropbear restart

# install vnstat gui
#cd /home/vps/public_html/
#wget https://raw.githubusercontent.com/nexne/ani/master/vnstat_php_frontend-1.5.1.tar.gz
#tar xf vnstat_php_frontend-1.5.1.tar.gz
#rm vnstat_php_frontend-1.5.1.tar.gz
#mv vnstat_php_frontend-1.5.1 vnstat
#cd vnstat
#sed -i "s/\$iface_list = array('eth0', 'sixxs');/\$iface_list = array('eth0');/g" config.php
#sed -i "s/\$language = 'nl';/\$language = 'en';/g" config.php
#sed -i 's/Internal/Internet/g' config.php
#sed -i '/SixXS IPv6/d' config.php
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
http_port 1080
http_port 3130
http_port 3000
coredump_dir /var/spool/squid3
refresh_pattern ^ftp: 1440 20% 10080
refresh_pattern ^gopher: 1440 0% 1440
refresh_pattern -i (/cgi-bin/|\?) 0 0% 0
refresh_pattern . 0 20% 4320
visible_hostname daybreakersx
END
sed -i $MYIP2 /etc/squid3/squid.conf;
service squid3 restart

# install stunnel4
apt-get -y install stunnel4
wget -O /etc/stunnel/stunnel.pem "https://raw.githubusercontent.com/nexne/ani/master/updates/stunnel.pem"
wget -O /etc/stunnel/stunnel.conf "https://raw.githubusercontent.com/nexne/ani/master/req/stunnel.conf"
sed -i $MYIP2 /etc/stunnel/stunnel.conf
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
service stunnel4 restart

# install webmin
cd

#install OpenVPN

# install badvpn
wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/nexne/ani/master/badvpn-udpgw"
if [ "$OS" == "x86_64" ]; then
  wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/nexne/ani/master/badvpn-udpgw64"
fi
sed -i '$ i\screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
chmod +x /usr/bin/badvpn-udpgw
screen -AmdS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300

# SSH brute-force protection
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --set 
iptables -A INPUT -p tcp --dport ssh -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j DROP  

# Protection against port scanning
iptables -N port-scanning 
iptables -A port-scanning -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j RETURN 
iptables -A port-scanning -j DROP

# First Level Block Torrent
iptables -A OUTPUT -p tcp --dport 6881:6889 -j DROP
iptables -A OUTPUT -p udp --dport 1024:65534 -j DROP
iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP

# Second Level Block Torrent
iptables -A INPUT -m string --algo bm --string "BitTorrent" -j REJECT
iptables -A INPUT -m string --algo bm --string "BitTorrent protocol" -j REJECT
iptables -A INPUT -m string --algo bm --string "peer_id=" -j REJECT
iptables -A INPUT -m string --algo bm --string ".torrent" -j REJECT
iptables -A INPUT -m string --algo bm --string "announce.php?passkey=" -j REJECT
iptables -A INPUT -m string --algo bm --string "torrent" -j REJECT
iptables -A INPUT -m string --algo bm --string "info_hash" -j REJECT
iptables -A INPUT -m string --algo bm --string "/default.ida?" -j REJECT
iptables -A INPUT -m string --algo bm --string ".exe?/c+dir" -j REJECT
iptables -A INPUT -m string --algo bm --string ".exe?/c_tftp" -j REJECT
iptables -A INPUT -m string --string "peer_id" --algo kmp -j REJECT
iptables -A INPUT -m string --string "BitTorrent" --algo kmp -j REJECT
iptables -A INPUT -m string --string "BitTorrent protocol" --algo kmp -j REJECT
iptables -A INPUT -m string --string "bittorrent-announce" --algo kmp -j REJECT
iptables -A INPUT -m string --string "announce.php?passkey=" --algo kmp -j REJECT
iptables -A INPUT -m string --string "find_node" --algo kmp -j REJECT
iptables -A INPUT -m string --string "info_hash" --algo kmp -j REJECT
iptables -A INPUT -m string --string "get_peers" --algo kmp -j REJECT
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j REJECT
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j REJECT
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j REJECT
iptables -A FORWARD -m string --algo bm --string ".torrent" -j REJECT
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j REJECT
iptables -A FORWARD -m string --algo bm --string "torrent" -j REJECT
iptables -A FORWARD -m string --algo bm --string "info_hash" -j REJECT
iptables -A FORWARD -m string --algo bm --string "/default.ida?" -j REJECT
iptables -A FORWARD -m string --algo bm --string ".exe?/c+dir" -j REJECT
iptables -A FORWARD -m string --algo bm --string ".exe?/c_tftp" -j REJECT
iptables -A FORWARD -m string --string "peer_id" --algo kmp -j REJECT
iptables -A FORWARD -m string --string "BitTorrent" --algo kmp -j REJECT
iptables -A FORWARD -m string --string "BitTorrent protocol" --algo kmp -j REJECT
iptables -A FORWARD -m string --string "bittorrent-announce" --algo kmp -j REJECT
iptables -A FORWARD -m string --string "announce.php?passkey=" --algo kmp -j REJECT
iptables -A FORWARD -m string --string "find_node" --algo kmp -j REJECT
iptables -A FORWARD -m string --string "info_hash" --algo kmp -j REJECT
iptables -A FORWARD -m string --string "get_peers" --algo kmp -j REJECT
iptables -A OUTPUT -m string --algo bm --string "BitTorrent" -j REJECT
iptables -A OUTPUT -m string --algo bm --string "BitTorrent protocol" -j REJECT
iptables -A OUTPUT -m string --algo bm --string "peer_id=" -j REJECT
iptables -A OUTPUT -m string --algo bm --string ".torrent" -j REJECT
iptables -A OUTPUT -m string --algo bm --string "announce.php?passkey=" -j REJECT
iptables -A OUTPUT -m string --algo bm --string "torrent" -j REJECT
iptables -A OUTPUT -m string --algo bm --string "info_hash" -j REJECT
iptables -A OUTPUT -m string --algo bm --string "/default.ida?" -j REJECT
iptables -A OUTPUT -m string --algo bm --string ".exe?/c+dir" -j REJECT
iptables -A OUTPUT -m string --algo bm --string ".exe?/c_tftp" -j REJECT
iptables -A OUTPUT -m string --string "peer_id" --algo kmp -j REJECT
iptables -A OUTPUT -m string --string "BitTorrent" --algo kmp -j REJECT
iptables -A OUTPUT -m string --string "BitTorrent protocol" --algo kmp -j REJECT
iptables -A OUTPUT -m string --string "bittorrent-announce" --algo kmp -j REJECT
iptables -A OUTPUT -m string --string "announce.php?passkey=" --algo kmp -j REJECT
iptables -A OUTPUT -m string --string "find_node" --algo kmp -j REJECT
iptables -A OUTPUT -m string --string "info_hash" --algo kmp -j REJECT
iptables -A OUTPUT -m string --string "get_peers" --algo kmp -j REJECT
iptables -A INPUT -p tcp --dport 25 -j REJECT   
iptables -A FORWARD -p tcp --dport 25 -j REJECT 
iptables -A OUTPUT -p tcp --dport 25 -j REJECT 

# install ddos deflate
cd
apt-get -y install dnsutils dsniff
wget https://github.com/jgmdev/ddos-deflate/archive/master.zip
unzip master.zip
cd ddos-deflate-master
./install.sh
rm -rf /root/master.zip

# setting banner
rm /etc/issue.net
wget -O /etc/issue.net "https://raw.githubusercontent.com/nexne/ani/master/issue.net"
sed -i 's@#Banner@Banner@g' /etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear
service ssh restart
service dropbear restart

# download script
cd
wget https://raw.githubusercontent.com/nexne/ani/master/install-premiumscript.sh -O - -o /dev/null|sh

# finalizing
apt-get -y autoremove
chown -R www-data:www-data /home/vps/public_html
#service nginx start
#service php5-fpm start
#service vnstat restart
service openvpn restart
service snmpd restart
service ssh restart
service dropbear restart
service fail2ban restart
service squid3 restart
#service webmin restart
#service pptpd restart
sysv-rc-conf rc.local on

# download script
cd /usr/bin
wget -O menu "https://raw.githubusercontent.com/nexne/32n64/master/menu.sh"
wget -O usernew "https://raw.githubusercontent.com/nexne/32n64/master/usernew.sh"
wget -O trial "https://raw.githubusercontent.com/nexne/32n64/master/trial.sh"
wget -O hapus "https://raw.githubusercontent.com/nexne/32n64/master/hapus.sh"
wget -O login "https://raw.githubusercontent.com/nexne/32n64/master/user-login.sh"
wget -O dropmon "https://raw.githubusercontent.com/nexne/32n64/master/dropmon.sh"
wget -O user-expired.sh "https://raw.githubusercontent.com/ForNesiaFreak/FNS_Debian7/fornesia.com/freak/user-expired.sh"
#wget -O userlimit.sh "https://raw.githubusercontent.com/suryadewa/fornesiavps/fns/limit.sh"
wget -O member "https://raw.githubusercontent.com/nexne/32n64/master/user-list.sh"
wget -O restart "https://raw.githubusercontent.com/nexne/32n64/master/resvis.sh"
wget -O speedtest "https://raw.githubusercontent.com/ForNesiaFreak/FNS_Debian7/fornesia.com/null/speedtest_cli.py"
wget -O bench-network "https://raw.githubusercontent.com/ForNesiaFreak/FNS_Debian7/fornesia.com/null/bench-network.sh"
wget -O ps-mem "https://raw.githubusercontent.com/ForNesiaFreak/FNS_Debian7/fornesia.com/null/ps_mem.py"
wget -O about "https://raw.githubusercontent.com/nexne/32n64/master/about.sh"
wget -O delete "https://raw.githubusercontent.com/nexne/32n64/master/delete.sh"
wget -O renew "https://raw.githubusercontent.com/nexne/32n64/master/renew.sh"
wget -O kill "https://raw.githubusercontent.com/nexne/32n64/master/kill.sh"
wget -O ban "https://raw.githubusercontent.com/nexne/32n64/master/ban.sh"
wget -O unban "https://raw.githubusercontent.com/nexne/32n64/master/unban.sh"
wget -O log "https://raw.githubusercontent.com/nexne/32n64/master/log.sh"
wget -O rasakan "https://raw.githubusercontent.com/nexne/32n64/master/rasakan.sh"
wget -O log1 "https://raw.githubusercontent.com/nexne/32n64/master/log1.sh"
echo "0 0 * * * root /root/user-expired.sh" > /etc/cron.d/user-expired
#echo "0 0 * * * root /usr/bin/expired" > /etc/cron.d/expired
echo "0 0 * * * root /usr/bin/reboot" > /etc/cron.d/reboot
echo "#* * * * * service dropbear restart" > /etc/cron.d/dropbear
chmod +x menu
chmod +x usernew
chmod +x trial
chmod +x hapus
chmod +x login
chmod +x dropmon
chmod +x user-expired
#chmod +x userlimit.sh
chmod +x member
chmod +x restart
chmod +x speedtest
chmod +x bench-network
chmod +x ps-mem
chmod +x about
chmod +x delete
chmod +x renew
chmod +x user-expired.sh
chmod +x kill
chmod +x ban
chmod +x unban
chmod +x log
chmod +x rasakan
chmod +x log1
cd
echo "0 */12 * * * root /usr/bin/delete" >> /etc/crontab
echo "#* * * * * root service dropbear restart" >> /etc/crontab
echo "#0 */6 * * * root /usr/bin/restart" >> /etc/crontab
#echo "#*/10 * * * * root service squid3 restart" >> /etc/crontab
echo "#* * * * * root /usr/bin/kill" >> /etc/crontab
#echo "#* * * * * root sleep 10; /usr/bin/kill" >> /etc/crontab
echo "#0 */6 * * * root /usr/bin/ban" >> /etc/crontab
echo "#* * * * * root /usr/bin/rasakan 2" >> /etc/crontab
echo "0 3 * * * root /sbin/reboot" > /etc/cron.d/reboot
service cron restart

#!/bin/bash
# OpenVPN road warrior installer for Debian, Ubuntu and CentOS

# This script will work on Debian, Ubuntu, CentOS and probably other distros
# of the same families, although no support is offered for them. It isn't
# bulletproof but it will probably work if you simply want to setup a VPN on
# your Debian/Ubuntu/CentOS box. It has been designed to be as unobtrusive and
# universal as possible.

###############################################################################################################
# START_VARIABLE_SECTION
# This section contains setup and variables
###############################################################################################################

TCP_SERVICE_AND_CONFIG_NAME="openvpn_tcp"
UDP_SERVICE_AND_CONFIG_NAME="openvpn_udp"

if [[ "$USER" != 'root' ]]; then
	echo "Sorry, you need to run this as root"
	exit
fi


if [[ ! -e /dev/net/tun ]]; then
	echo "TUN/TAP is not available"
	exit
fi


if grep -qs "CentOS release 5" "/etc/redhat-release"; then
	echo "CentOS 5 is too old and not supported"
	exit
fi

if [[ -e /etc/debian_version ]]; then
	OS=debian
	RCLOCAL='/etc/rc.local'
elif [[ -e /etc/centos-release || -e /etc/redhat-release ]]; then
	OS=centos
	RCLOCAL='/etc/rc.d/rc.local'
	# Needed for CentOS 7
	chmod +x /etc/rc.d/rc.local
else
	echo "Looks like you aren't running this installer on a Debian, Ubuntu or CentOS system"
	exit
fi

###############################################################################################################
# END_VARIABLE_SECTION
###############################################################################################################


newclient () {
	# This function is used to create udp client .ovpn file
	cp /etc/openvpn/client-common.txt ~/"$1.ovpn"
	echo "<ca>" >> ~/"$1.ovpn"
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/"$1.ovpn"
	echo "</ca>" >> ~/"$1.ovpn"
	echo "<cert>" >> ~/"$1.ovpn"
	cat /etc/openvpn/easy-rsa/pki/issued/"$1.crt" >> ~/"$1.ovpn"
	echo "</cert>" >> ~/"$1.ovpn"
	echo "<key>" >> ~/"$1.ovpn"
	cat /etc/openvpn/easy-rsa/pki/private/"$1.key" >> ~/"$1.ovpn"
	echo "</key>" >> ~/"$1.ovpn"
	if [ "$TLS" = "1" ]; then  #check if TLS is selected to add a TLS static key
		echo "key-direction 1" >> ~/"$1.ovpn"
		echo "<tls-auth>" >> ~/"$1.ovpn"
		cat /etc/openvpn/easy-rsa/pki/private/ta.key >> ~/"$1.ovpn"
		echo "</tls-auth>" >> ~/"$1.ovpn"
	fi
	if [ $TLSNEW = 1 ]; then
		echo "--tls-version-min 1.2" >> ~/"$1.ovpn"
	fi

}


newclienttcp () {
	# This function is used to create tcp client .ovpn file
	cp /etc/openvpn/clienttcp-common.txt ~/"$1tcp.ovpn"
	echo "<ca>" >> ~/"$1tcp.ovpn"
	cat /etc/openvpn/easy-rsa/pki/ca.crt >> ~/"$1tcp.ovpn"
	echo "</ca>" >> ~/"$1tcp.ovpn"
	echo "<cert>" >> ~/"$1tcp.ovpn"
	cat /etc/openvpn/easy-rsa/pki/issued/"$1.crt" >> ~/"$1tcp.ovpn"
	echo "</cert>" >> ~/"$1tcp.ovpn"
	echo "<key>" >> ~/"$1tcp.ovpn"
	cat /etc/openvpn/easy-rsa/pki/private/"$1.key" >> ~/"$1tcp.ovpn"
	echo "</key>" >> ~/"$1tcp.ovpn"
	if [ "$TLS" = "1" ]; then  #check if TLS is selected to add a TLS static key
		echo "key-direction 1" >> ~/"$1tcp.ovpn"
		echo "<tls-auth>" >> ~/"$1tcp.ovpn"
		cat /etc/openvpn/easy-rsa/pki/private/ta.key >> ~/"$1tcp.ovpn"
		echo "</tls-auth>" >> ~/"$1tcp.ovpn"
	fi
	if [ $TLSNEW = 1 ]; then
		echo "--tls-version-min 1.2" >> ~/"$1.ovpn"
	fi
}

function version_gt() { test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" != "$1"; }
	# This function is used to compare installed openvpn and specific version

# Try to get our IP from the system and fallback to the Internet.
# I do this to make the script compatible with NATed servers (lowendspirit.com)
# and to avoid getting an IPv6.
IP=$(ip addr | grep 'inet' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -o -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | head -1)
if [[ "$IP" = "" ]]; then
		IP=$(wget -qO- ipv4.icanhazip.com)
fi


if [ -e /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf -o -e /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf ]; then    #check if udp or tcp config file is present
	while :
	do
	clear
		echo "Looks like OpenVPN is already installed"
		echo ""
		echo "What do you want to do?"
		echo "   1) Add a cert for a new user"
		echo "   2) Revoke existing user cert"
		echo "   3) Remove OpenVPN"
		echo "   4) Exit"
		read -p "Select an option [1-4]: " option
		case $option in
			1)
			echo ""
			echo "Tell me a name for the client cert"
			echo "Please, use one word only, no special characters"
			read -p "Client name: " -e -i client CLIENT
			cd /etc/openvpn/easy-rsa/
			./easyrsa build-client-full "$CLIENT" nopass
			# Generates the custom client.ovpn
			if [[ -e /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf ]]; then
				TLS=0
				TLSNEW=0
				if [ -n "$(cat /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf | grep tls-auth)" ]; then #check if TLS is enabled in server config file so that static TLS key can be added to new client
					TLS=1
				fi
				if [ -n "$(cat /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf | grep "tls-version-min 1.2")" ]; then #check if TLS 1.2 is enabled in server config file so that static TLS key can be added to new client
					TLSNEW=1
				fi
				newclient "$CLIENT"
				echo "UDP client $CLIENT added, certs available at ~/$CLIENT.ovpn"
			fi

			#everything here is the same as above just for the tcp client
			if [[ -e /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf ]]; then
				TLS=0
				TLSNEW=0
				if [ -n "$(cat /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf | grep tls-auth)" ]; then
					TLS=1
				fi
				if [ -n "$(cat /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf | grep "tls-version-min 1.2")" ]; then
					TLSNEW=1
				fi
				newclienttcp "$CLIENT"
				echo "TCP client $CLIENT added, certs available at ~/${CLIENT}tcp.ovpn"
			fi

			echo ""
			exit
			;;
			2)
			# This option could be documented a bit better and maybe even be simplimplified
			# ...but what can I say, I want some sleep too
			NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep -c "^V")
			if [[ "$NUMBEROFCLIENTS" = '0' ]]; then
				echo ""
				echo "You have no existing clients!"
				exit
			fi
			echo ""
			echo "Select the existing client certificate you want to revoke"
			tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
			if [[ "$NUMBEROFCLIENTS" = '1' ]]; then
				read -p "Select one client [1]: " CLIENTNUMBER
			else
				read -p "Select one client [1-$NUMBEROFCLIENTS]: " CLIENTNUMBER
			fi
			CLIENT=$(tail -n +2 /etc/openvpn/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
			cd /etc/openvpn/easy-rsa/
			./easyrsa --batch revoke "$CLIENT"
			./easyrsa gen-crl
			rm -rf "pki/reqs/$CLIENT.req"
			rm -rf "pki/private/$CLIENT.key"
			rm -rf "pki/issued/$CLIENT.crt"
			# And restart

			if pgrep systemd-journal; then
				systemctl restart openvpn
			else
				if [[ "$OS" = 'debian' ]]; then
					/etc/init.d/openvpn restart
				else
					service openvpn restart
				fi
			fi

			echo ""
			echo "Certificate for client \"$CLIENT\" revoked"
			exit
			;;
			###############################################################################################################
			# START_OPENVPN_REMOVAL_SECTION
			# This section contains to remove openvpn as installed by this script
			###############################################################################################################
			3)
			echo ""
			read -p "Do you really want to remove OpenVPN? [y/n]: " -e -i n REMOVE
			if [[ "$REMOVE" = 'y' ]]; then
			if [[ -e /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf ]]; then  #removal of udp firewall rules
				PORT=$(grep '^port ' /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf | cut -d " " -f 2)
				    iptables -L | grep -q REJECT
					sed -i "/iptables -I INPUT -p udp --dport $PORT -j ACCEPT/d" $RCLOCAL
					sed -i "/iptables -I FORWARD -s 10.8.0.0\/24 -j ACCEPT/d" $RCLOCAL
					sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT/d" $RCLOCAL

				sed -i '/iptables -t nat -A POSTROUTING -s 10.8.0.0\/24 -j SNAT --to /d' $RCLOCAL
				fi

				if [[ -e /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf ]]; then #removal of tcp firewall rules
				PORT=$(grep '^port ' /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf | cut -d " " -f 2)

				iptables -L | grep -q REJECT
					sed -i "/iptables -I INPUT -p tcp --dport $PORT -j ACCEPT/d" $RCLOCAL
					sed -i "/iptables -I FORWARD -s 10.9.0.0\/24 -j ACCEPT/d" $RCLOCAL
					sed -i "/iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT/d" $RCLOCAL
					sed -i '/iptables -t nat -A POSTROUTING -s 10.9.0.0\/24 -j SNAT --to /d' $RCLOCAL
				fi
				sed -i '/iptables -t nat -A PREROUTING -p tcp -i tun+ --dport 80 -j REDIRECT --to-port 8080/d' $RCLOCAL #Remove HAVP proxy
				iptables -t nat -D PREROUTING -i tun+ -p tcp --dport 80 -j REDIRECT --to-port 8080
				apt-get remove --purge -y openvpn openvpn-blacklist unbound clamav clamav-daemon privoxy havp

				rm -rf /etc/openvpn
				rm -rf /usr/share/doc/openvpn*
				if pgrep systemd-journal; then
					sudo systemctl disable $UDP_SERVICE_AND_CONFIG_NAME.service
					sudo systemctl disable $TCP_SERVICE_AND_CONFIG_NAME.service
				fi
				rm -rf /etc/systemd/system/$UDP_SERVICE_AND_CONFIG_NAME.service
				rm -rf /etc/systemd/system/$TCP_SERVICE_AND_CONFIG_NAME.service
				echo ""
				echo "OpenVPN removed!"

			fi
			exit
			;;
			###############################################################################################################
			# END_OPENVPN_REMOVAL_SECTION
			###############################################################################################################
			4) exit;;
		esac
	done
else
	clear
	echo 'Welcome to this quick OpenVPN "road warrior" installer'
	echo ""
	# OpenVPN setup and first user creation
	echo "I need to ask you a few questions before starting the setup"
	echo "You can leave the default options and just press enter if you are ok with them"
	echo ""
	echo "First I need to know the IPv4 address of the network interface you want OpenVPN"
	echo "listening to."
	read -p "IP address: " -e -i $IP IP
	echo ""
	while :
	do
	while :
	do
	clear
	read -p "Do you want to run a UDP server [y/n]: " -e -i y UDP
        case $UDP in
	       y)   UDP=1
	    break ;;
	       n)   UDP=0
	     break ;;
        esac
	 done

	 while :
	do
	clear
	echo "***************************************************"
	echo "*                   !!!!!NB!!!!!                  *"
	echo "*                                                 *"
	echo "* Here be dragons!!! If you're using this to get  *"
	echo "* past firewalls then go ahead and choose *y*,    *"
	echo "* but please read and understand                  *"
	echo "*                                                 *"
	echo "* http://sites.inka.de/bigred/devel/tcp-tcp.html  *"
	echo "* http://tinyurl.com/34qzu5z                      *"
	echo "***************************************************"
	echo ""
	read -p "Do you want to run a TCP server [y/n]: " -e -i n TCP
        case $TCP in
	       y)   TCP=1
	    break ;;
	       n)   TCP=0
	     break ;;
        esac
	 done
	 if [ "$UDP" = 1 -o "$TCP" = 1 ]; then
	  break
	  fi
	 done
	 if [ "$UDP" = 1 ]; then
	clear
	read -p "What UDP port do you want to run OpenVPN on?: " -e -i 1194 PORT
	 fi
	 if [ "$TCP" = 1 ]; then
	clear
	read -p "What TCP port do you want to run OpenVPN on?: " -e -i 443 PORTTCP
	 fi
       while :
	do
	clear
	echo "What size do you want your key to be? :"
	echo "     1) 2048bits"
	echo "     2) 4096bits"
	echo ""
	read -p "Key Size [1-2]: " -e -i 1 KEYSIZE
	case $KEYSIZE in
		1)
			KEYSIZE=2048
			break
		;;
		2)
			KEYSIZE=4096
			break
		;;
	esac
	done

	 while :
	do
	clear
	echo "What size do you want your SHA digest to be? :"
	echo "     1) 256bits"
	echo "     2) 512bits"
	echo ""
	read -p "Digest Size [1-2]: " -e -i 1 DIGEST
	case $DIGEST in
		1)
			DIGEST=SHA256
			break
		;;
        2)
			DIGEST=SHA512
			break
		;;
	esac
	done
	AES=0
        grep -q aes /proc/cpuinfo #Check for AES-NI availability
        if [[ "$?" -eq 0 ]]; then
         AES=1
        fi

	while :
	do
	clear
	 if [[ "$AES" -eq 1 ]]; then
         echo "Your CPU supports AES-NI instruction set."
         echo "It enables faster AES encryption/decryption."
         echo "Choosing AES will decrease CPU usage."
         fi
	 echo "Which cipher do you want to use? :"
	 echo "     1) AES-256-CBC"
	 echo "     2) AES-128-CBC"
	 echo "     3) BF-CBC"
	 echo "     4) CAMELLIA-256-CBC"
	 echo "     5) CAMELLIA-128-CBC"
	 echo ""
	read -p "Cipher [1-5]: " -e -i 1 CIPHER
	 case $CIPHER in
	    1) CIPHER=AES-256-CBC
		 break ;;
		2) CIPHER=AES-128-CBC
         break ;;
        3) CIPHER=BF-CBC
         break ;;
        4) CIPHER=CAMELLIA-256-CBC
         break ;;
        5) CIPHER=CAMELLIA-128-CBC
         break ;;
        esac
	done
    while :
    do
    clear
    read -p "Do you want to use additional TLS authentication [y/n]: " -e -i y TLS
     case $TLS in
      y) TLS=1
      break ;;
      n) TLS=0
      break ;;
      esac
      done

      while :
    do
    clear
    echo "Do you want to enable internal networking for the VPN(iptables only)?"
	echo "This can allow VPN clients to communicate between them"
	read -p "Allow internal networking [y/n]: " -e -i y INTERNALNETWORK
     case $INTERNALNETWORK in
      y) INTERNALNETWORK=1
      break ;;
      n) INTERNALNETWORK=0
      break ;;
      esac
      done
     while :
     do
      clear
         echo "Do you want to create self hosted DNS resolver ?"
         echo "This resolver will be only accessible through VPN to prevent"
         echo "your server to be used for DNS amplification attack"
           read -p "Create DNS resolver [y/n]: " -e -i n DNSRESOLVER
           case $DNSRESOLVER in
            y) DNSRESOLVER=1
              break;;
            n) DNSRESOLVER=0
              break;;
            esac
     done

     while :
     do
       clear
        echo "Do you want to setup Privoxy+ClamAV+HAVP?"
        echo "Privoxy will be used to block ads."
        echo "ClamAV+HAVP will be used to scan all of your web traffic for viruses."
        echo "This will only work with unencrypted traffic."
        echo "You should have at least 1GB RAM for this option."
        read -p "[y/n]: " -e -i n ANTIVIR
        case $ANTIVIR in
        y) ANTIVIR=1
           break;;
        n) ANTIVIR=0
           break;;
        esac
      done

	clear
	if [ "$DNSRESOLVER" = 0 ]; then    #If user wants to use his own DNS resolver this selection is skipped
	echo "What DNS do you want to use with the VPN?"
	echo "   1) Current system resolvers"
	echo "   2) OpenDNS"
	echo "   3) Verisign"
	echo "   4) NTT"
	echo "   5) Hurricane Electric"
	echo "   6) Google"
	echo ""
	read -p "DNS [1-6]: " -e -i 1 DNS
    fi

	clear
	echo "Tell me your name for the client cert"
	echo "Please, use one word only, no special characters"
	read -p "Client name: " -e -i client CLIENT
	echo ""
	
		if [[ "$OS" = 'debian' ]]; then
		apt-get update -qq
		apt-get install openvpn iptables openssl -y -qq

		if [ "$DNSRESOLVER" = 1 ]; then
        DNS=7
        #Installation of "Unbound" caching DNS resolver
           sudo apt-get install unbound  -y -qq
        if [ "$TCP" -eq 1 ]; then
        echo "interface: 10.9.0.1" >> /etc/unbound/unbound.conf
        fi
        if [ "$UDP" -eq 1 ]; then
        echo "interface: 10.8.0.1" >> /etc/unbound/unbound.conf
        fi
        echo "access-control: 0.0.0.0/0 allow" >> /etc/unbound/unbound.conf
        fi
 if [ "$ANTIVIR" = 1 ]; then
             apt-get install clamav clamav-daemon  -qq -y
 service clamav-freshclam stop
 freshclam
 service clamav-freshclam start
 sed -i "s/AllowSupplementaryGroups false/AllowSupplementaryGroups true/" /etc/clamav/clamd.conf
 service clamav-daemon restart
 apt-get install havp -y
sed -i '/ENABLECLAMLIB true/c\ENABLECLAMLIB false'  /etc/havp/havp.config
sed -i '/ENABLECLAMD false/c\ENABLECLAMD true'  /etc/havp/havp.config
sed -i '/RANGE false/c\RANGE true'  /etc/havp/havp.config
sed -i '/SCANIMAGES true/c\ENABLECLAMD false'  /etc/havp/havp.config
sed -i 's/\# SKIPMIME/SKIPMIME/'  /etc/havp/havp.config
sed -i '/\LOG_OKS true/c\LOG_OKS false'  /etc/havp/havp.config
 gpasswd -a clamav havp
 service clamav-daemon restart
 service havp restart
 apt-get install privoxy -y -qq
sed -i '/listen-address  localhost:8118/c\listen-address  127.0.0.1:8118' /etc/privoxy/config
HOST=$(hostname -f)
sed -i "/hostname hostname.example.org/c\hostname "$HOST""  /etc/privoxy/config
 service privoxy restart
sed -i '/PARENTPROXY localhost/c\PARENTPROXY 127.0.0.1'  /etc/havp/havp.config
sed -i '/PARENTPORT 3128/c\PARENTPORT 8118'  /etc/havp/havp.config
sed -i '/TRANSPARENT false/c\TRANSPARENT true'  /etc/havp/havp.config
sed -i "3 a\iptables -t nat -A PREROUTING -p tcp -i tun+ --dport 80 -j REDIRECT --to-port 8080" $RCLOCAL  #Add this firewall rule to startup(redirect traffic on port 80 to privoxy)
 service havp restart
iptables -t nat -A PREROUTING -i tun+ -p tcp --dport 80 -j REDIRECT --to-port 8080
 fi
	else
		echo "Only Debian-based distros supported currently"
	fi
	ovpnversion=$(openvpn --status-version | grep -o "([0-9].*)" | sed 's/[^0-9.]//g')
	if version_gt $ovpnversion "2.3.3"; then
		while :
    do
			clear
			echo "Your OpenVPN version is $ovpnversion and it supports"
			echo "newer and more secure TLS 1.2 protocol for its control channel."
			echo "Do you want to force usage of TLS 1.2 ?"
			echo "NOTE: Your client also must use version 2.3.3 or newer"
			read -p "Force TLS 1.2 [y/n]: " -e -i n TLSNEW
			case $TLSNEW in
			 y) TLSNEW=1
			 break ;;
			 n) TLSNEW=0
			 break ;;
			 esac
			 done
	fi
        echo "Okay, that was all I needed. We are ready to setup your OpenVPN server now"
	read -n1 -r -p "Press any key to continue..."
	# An old version of easy-rsa was available by default in some openvpn packages
	if [[ -d /etc/openvpn/easy-rsa/ ]]; then
		rm -rf /etc/openvpn/easy-rsa/
	fi
	# Get easy-rsa
	wget --no-check-certificate -O ~/EasyRSA-3.0.1.tgz https://github.com/OpenVPN/easy-rsa/releases/download/3.0.1/EasyRSA-3.0.1.tgz
	tar xzf ~/EasyRSA-3.0.1.tgz -C ~/
	mv ~/EasyRSA-3.0.1/ /etc/openvpn/
	mv /etc/openvpn/EasyRSA-3.0.1/ /etc/openvpn/easy-rsa/
	chown -R root:root /etc/openvpn/easy-rsa/
	rm -rf ~/EasyRSA-3.0.1.tgz
	cd /etc/openvpn/easy-rsa/
	# Create the PKI, set up the CA, the DH params and the server + client certificates
	./easyrsa init-pki
	cp vars.example vars

	sed -i 's/#set_var EASYRSA_KEY_SIZE	2048/set_var EASYRSA_KEY_SIZE   '$KEYSIZE'/' vars #change key size to desired size
	./easyrsa --batch build-ca nopass
	./easyrsa gen-dh
	./easyrsa build-server-full server nopass
	./easyrsa build-client-full "$CLIENT" nopass
	./easyrsa gen-crl

	openvpn --genkey --secret /etc/openvpn/easy-rsa/pki/private/ta.key    #generate TLS key for additional security


	# Move the stuff we need
	cp pki/ca.crt pki/private/ca.key pki/dh.pem pki/issued/server.crt pki/private/server.key /etc/openvpn
	if [ "$UDP" = 1 ]; then
	# Generate udp.conf
		echo "port $PORT
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
push \"register-dns\"
topology subnet
server 10.8.0.0 255.255.255.0
cipher $CIPHER
auth $DIGEST
ifconfig-pool-persist ipp.txt" > /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
		echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
		if [ $TLS = 1 ]; then
			echo "--tls-auth /etc/openvpn/easy-rsa/pki/private/ta.key 0" >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf #TLS key information added to config file
		fi
		if [ $TLSNEW = 1 ]; then
			echo "--tls-version-min 1.2" >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
		fi
	# DNS
		case $DNS in
			1)
			# Obtain the resolvers from resolv.conf and use them for OpenVPN
			grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
				echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
			done
			;;
			2)
			echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
			echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
			;;
			3)
			echo 'push "dhcp-option DNS 64.6.64.6"' >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
			echo 'push "dhcp-option DNS 64.6.65.6"' >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
			;;
			4)
			echo 'push "dhcp-option DNS 129.250.35.250"' >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
			echo 'push "dhcp-option DNS 129.250.35.251"' >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
			;;
			5)
			echo 'push "dhcp-option DNS 74.82.42.42"' >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
			;;
			6)
			echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
			echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
			;;
			7)
			echo 'push "dhcp-option DNS 10.8.0.1"' >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
		esac
		echo "keepalive 10 120
comp-lzo
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify /etc/openvpn/easy-rsa/pki/crl.pem" >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
		if [ "$INTERNALNETWORK" = 1 ]; then
			echo "client-to-client" >> /etc/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.conf
		fi
	fi

	if [ "$TCP" = 1 ]; then
		echo "port $PORTTCP
proto tcp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
push \"register-dns\"
topology subnet
server 10.9.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
cipher $CIPHER
auth $DIGEST
sndbuf 0
rcvbuf 0" > /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
		echo 'push "redirect-gateway def1 bypass-dhcp"' >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf

		if [ $TLS = 1 ]; then
			echo "--tls-auth /etc/openvpn/easy-rsa/pki/private/ta.key 0" >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf #TLS key information added to config file
		fi
		if [ $TLSNEW = 1 ]; then
			echo "--tls-version-min 1.2" >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
		fi
	# DNS
		case $DNS in
			1)
			# Obtain the resolvers from resolv.conf and use them for OpenVPN
			grep -v '#' /etc/resolv.conf | grep 'nameserver' | grep -E -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | while read line; do
				echo "push \"dhcp-option DNS $line\"" >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
			done
			;;
			2)
			echo 'push "dhcp-option DNS 208.67.222.222"' >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
			echo 'push "dhcp-option DNS 208.67.220.220"' >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
			;;
			3)
			echo 'push "dhcp-option DNS 64.6.64.6"' >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
			echo 'push "dhcp-option DNS 64.6.65.6"' >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
			;;
			4)
			echo 'push "dhcp-option DNS 129.250.35.250"' >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
			echo 'push "dhcp-option DNS 129.250.35.251"' >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
			;;
			5)
			echo 'push "dhcp-option DNS 74.82.42.42"' >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
			;;
			6)
			echo 'push "dhcp-option DNS 8.8.8.8"' >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
			echo 'push "dhcp-option DNS 8.8.4.4"' >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
			;;
			7)
			echo 'push "dhcp-option DNS 10.9.0.1"' >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
		esac
		echo "keepalive 10 120
comp-lzo
persist-key
persist-tun
status openvpn-status.log
verb 3
crl-verify /etc/openvpn/easy-rsa/pki/crl.pem" >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
		if [ "$INTERNALNETWORK" = 1 ]; then
			echo "client-to-client" >> /etc/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.conf
		fi
	fi

	# Enable net.ipv4.ip_forward for the system
	sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf
	sed -i " 5 a\echo 1 > /proc/sys/net/ipv4/ip_forward" $RCLOCAL    # Added for servers that don't read from sysctl at startup

	# Avoid an unneeded reboot
	echo 1 > /proc/sys/net/ipv4/ip_forward
	# Set NAT for the VPN subnet
	   if [ "$INTERNALNETWORK" = 1 ]; then
	    if [ "$UDP" = 1 ]; then
	iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP
		sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.0/24 -j SNAT --to $IP" $RCLOCAL
	    fi
		if [ "$TCP" = 1 ]; then
			iptables -t nat -A POSTROUTING -s 10.9.0.0/24 ! -d 10.9.0.0/24 -j SNAT --to $IP
			sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.9.0.0/24 ! -d 10.9.0.0/24 -j SNAT --to $IP" $RCLOCAL
	    fi
	   else
	   if [ "$UDP" = 1 ]; then
	iptables -t nat -A POSTROUTING -s 10.8.0.0/24 ! -d 10.8.0.1 -j SNAT --to $IP
	sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -j SNAT --to $IP" $RCLOCAL
	    fi
		if [ "$TCP" = 1 ]; then
			iptables -t nat -A POSTROUTING -s 10.9.0.0/24  ! -d 10.9.0.1 -j SNAT --to $IP #This line and the next one are added for tcp server instance
			sed -i "1 a\iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -j SNAT --to $IP" $RCLOCAL
		fi
	   fi

	if iptables -L | grep -q REJECT; then
		# If iptables has at least one REJECT rule, we asume this is needed.
		# Not the best approach but I can't think of other and this shouldn't
		# cause problems.
		if [ "$UDP" = 1 ]; then
		iptables -I INPUT -p udp --dport $PORT -j ACCEPT
		iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT
		iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
		sed -i "1 a\iptables -I INPUT -p udp --dport $PORT -j ACCEPT" $RCLOCAL
		sed -i "1 a\iptables -I FORWARD -s 10.8.0.0/24 -j ACCEPT" $RCLOCAL
		sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
		fi
		if [ "$TCP" = 1 ]; then
			iptables -I INPUT -p udp --dport $PORTTCP -j ACCEPT #This line and next 5 lines have been added for tcp support
			iptables -I FORWARD -s 10.9.0.0/24 -j ACCEPT
			iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
			sed -i "1 a\iptables -I INPUT -p tcp --dport $PORTTCP -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -s 10.9.0.0/24 -j ACCEPT" $RCLOCAL
			sed -i "1 a\iptables -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" $RCLOCAL
		fi
	fi
	###############################################################################################################
	# START_SERVICE_SECTION
	# Install and start service for both UDP and TCP
	###############################################################################################################
	if [ "$UDP" = 1 ]; then
		echo "[Unit]
#Created by openvpn-install-advanced (https://github.com/pl48415/openvpn-install-advanced)
Description=OpenVPN Robust And Highly Flexible Tunneling Application On <server>
After=syslog.target network.target

[Service]
Type=forking
PIDFile=/var/run/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.pid
ExecStart=/usr/sbin/openvpn --daemon --writepid /var/run/openvpn/$UDP_SERVICE_AND_CONFIG_NAME.pid --cd /etc/openvpn/ --config $UDP_SERVICE_AND_CONFIG_NAME.conf

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/$UDP_SERVICE_AND_CONFIG_NAME.service
		if pgrep systemd-journal; then
			sudo systemctl enable $UDP_SERVICE_AND_CONFIG_NAME.service
		fi
	fi

	if [ "$TCP" = 1 ]; then
		echo "[Unit]
#Created by openvpn-install-advanced (https://github.com/pl48415/openvpn-install-advanced)
Description=OpenVPN Robust And Highly Flexible Tunneling Application On <server>
After=syslog.target network.target

[Service]
Type=forking
PIDFile=/var/run/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.pid
ExecStart=/usr/sbin/openvpn --daemon --writepid /var/run/openvpn/$TCP_SERVICE_AND_CONFIG_NAME.pid --cd /etc/openvpn/ --config $TCP_SERVICE_AND_CONFIG_NAME.conf

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/$TCP_SERVICE_AND_CONFIG_NAME.service
		if pgrep systemd-journal; then
			sudo systemctl enable $TCP_SERVICE_AND_CONFIG_NAME.service
		fi
	fi

	if pgrep systemd-journal; then
		sudo systemctl start openvpn.service
	else
		if [[ "$OS" = 'debian' ]]; then
			/etc/init.d/openvpn start
		else
			service openvpn start
		fi
	fi

	###############################################################################################################
	# END_SERVICE_SECTION
	###############################################################################################################

	# Try to detect a NATed connection and ask about it to potential LowEndSpirit or Scaleway users
	EXTERNALIP=$(wget -qO- ipv4.icanhazip.com)
	if [[ "$IP" != "$EXTERNALIP" ]]; then
		echo ""
		echo "Looks like your server is behind a NAT!"
		echo ""
		echo "If your server is NATed (LowEndSpirit or Scaleway), I need to know the external IP"
		echo "If that's not the case, just ignore this and leave the next field blank"
		read -p "External IP: " -e USEREXTERNALIP
		if [[ "$USEREXTERNALIP" != "" ]]; then
			IP=$USEREXTERNALIP
		fi
	fi
	# client-common.txt is created so we have a template to add further UDP users later
	if [ "$UDP" = 1 ]; then
	echo "client
dev tun
cipher $CIPHER
auth $DIGEST
proto udp
remote $IP $PORT
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
comp-lzo
verb 3" > /etc/openvpn/client-common.txt
newclient "$CLIENT"
  fi
    if [ "$TCP" = 1 ]; then
	echo "client
	cipher $CIPHER
auth $DIGEST
dev tun
proto tcp
remote $IP $PORTTCP
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
comp-lzo
verb 3
sndbuf 0
rcvbuf 0
" > /etc/openvpn/clienttcp-common.txt  # clienttcp-common.txt is created so we have a template to add further TCP users later
newclienttcp "$CLIENT"
	fi
	# Generates the custom client.ovpn



	echo ""
	echo "Finished!"
	echo ""
	if [ "$UDP" = 1 ]; then
	echo "Your UDP client config is available at ~/$CLIENT.ovpn"
	fi
	if [ "$TCP" = 1 ]; then
	echo "Your TCP client config is available at ~/${CLIENT}tcp.ovpn"
	fi
	echo "If you want to add more clients, you simply need to run this script another time!"
fi
if [ "$DNSRESOLVER" = 1 ]; then
sudo service unbound restart
fi

#clearing history
history -c

# info
clear
echo " "
echo "Installation has been completed!!"
echo " "
echo "--------------------------- Configuration Setup Server -------------------------"
echo "                         Copyright HostingTermurah.net                          "
echo "                        https://www.hostingtermurah.net                         "
echo "               Created By Steven Indarto(fb.com/stevenindarto2)                 "
echo "                                Modified by 0123456                             "
echo "--------------------------------------------------------------------------------"
echo ""  | tee -a log-install.txt
echo "Server Information"  | tee -a log-install.txt
echo "   - Timezone    : Asia/Manila (GMT +8)"  | tee -a log-install.txt
echo "   - Fail2Ban    : [ON]"  | tee -a log-install.txt
echo "   - Dflate      : [ON]"  | tee -a log-install.txt
echo "   - IPtables    : [ON]"  | tee -a log-install.txt
echo "   - Auto-Reboot : [OFF]"  | tee -a log-install.txt
echo "   - IPv6        : [OFF]"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Application & Port Information"  | tee -a log-install.txt
echo "   - OpenVPN     : TCP 1194 "  | tee -a log-install.txt
echo "   - OpenSSH     : 22, 143"  | tee -a log-install.txt
echo "   - Stunnel4    : 442"  | tee -a log-install.txt
echo "   - Dropbear    : 109, 110, 443"  | tee -a log-install.txt
echo "   - Squid Proxy : 80, 3128, 8000, 8080, 8888 (limit to IP Server)"  | tee -a log-install.txt
echo "   - Badvpn      : 7300"  | tee -a log-install.txt
echo "   - Nginx       : 85"  | tee -a log-install.txt
echo "   - PPTP VPN    : 1732"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Server Tools"  | tee -a log-install.txt
echo "   - htop"  | tee -a log-install.txt
echo "   - iftop"  | tee -a log-install.txt
echo "   - mtr"  | tee -a log-install.txt
echo "   - nethogs"  | tee -a log-install.txt
echo "   - screenfetch"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Premium Script Information"  | tee -a log-install.txt
echo "   To display list of commands: menu"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   Explanation of scripts and VPS setup" | tee -a log-install.txt
echo "   follow this link: http://bit.ly/penjelasansetup"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Important Information"  | tee -a log-install.txt
echo "   - Download Config OpenVPN : http://$MYIP:85/client.ovpn"  | tee -a log-install.txt
echo "     Mirror (*.tar.gz)       : http://$MYIP:85/openvpn.tar.gz"  | tee -a log-install.txt
echo "   - Webmin                  : http://$MYIP:10000/"  | tee -a log-install.txt
echo "   - Vnstat                  : http://$MYIP:85/vnstat/"  | tee -a log-install.txt
echo "   - MRTG                    : http://$MYIP:85/mrtg/"  | tee -a log-install.txt
echo "   - Installation Log        : cat /root/log-install.txt"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "----------- Script Created By Steven Indarto(fb.com/stevenindarto2) ------------"
echo "------------------------------ Modified by 0123456 -----------------------------"
