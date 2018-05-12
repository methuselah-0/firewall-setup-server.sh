#!/bin/bash

# Copyright © 2017 David Larsson <david.larsson@selfhosted.xyz>
#
# This file is part of Nextcloud-Suite.sh.
# 
# Nextcloud-Suite.sh is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
# 
# Nextcloud-Suite.sh is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied warranty
# of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with Nextcloud-Suite.sh.  If not, see
# <http://www.gnu.org/licenses/>.

# This software is based on another script, but most of it is different.
# Credits to Guilhem Moulin who wrote https://git.fripost.org/fripost-ansible/tree/roles/common/files/usr/local/sbin/update-firewall.sh

################################################################################
#
# Example usage (must be run from it's source directory):
# in case of running local nameserver: echo "nameserver 46.227.67.134" >> /etc/resolv.conf first
# or the ovpn connection might not be restorable.
# iptables --flush && ./firewall-setup-server sslh ipset && systemctl restart openvpn-client@ovpn.service
#
# Running with sslh option will assume local ssh source port 22 and
# ssl source port 4443.
################################################################################

localif="eth0"
pubif="tun0"
pwd="$(pwd)"
Whitelist=(192.168.0.0/16 94.23.0.0/16 163.172.0.0/16 163.172.0.0/16) #lemonldap-ng website, some nameserver, etc.
server_local_ip=192.168.1.4
service_local_ip=192.168.1.5
VPN_ports=(1196 1197)
#Services=('25' '53' '80' '443' '554' '1935' '3478' '4190' '5349' '5350' '8443' '9001' '9418' '9980') # removed some email-related ports: 993, 995, 587, 465
declare -A Services
Services[25]="smtp - postfix"
Services[53]="dns - bind9"
Services[80]="nginx - http"
Services[443]="nginx - https"
#Services[1935]="rtmp"
Services[3478]="webrtc - turnserver"
Services[4190]="imap - dovecot"
Services[5349]="webrtc - turnserver"
Services[5350]="webrtc - turnserver"
Services[8443]="postfix"
Services[9001]="etherpad-lite - node"
Services[9418]="git-daemon"
Services[9418]="git-daemon"
Services[9980]="libreoffice online - loolwsd"
# User connections: tcp ports for dns, browsing, email, XMR-mining at xmr.suprnova.cc:5221, bss_conn.c:246, and udp ports for ftp and DNS.
User_Connections[21]="ftp"
User_Connections[22]="ssh"
User_Connections[25]="smtp"
User_Connections[53]="dns"
User_Connections[80]="http"
User_Connections[123]="ntp - network time protocol"
User_Connections[246]="bss_conn.c - XMR-mining"
User_Connections[443]="https"
User_Connections[2222]="ssh-altport"
User_Connections[5221]="xmr.suprnova.cc - XMR-mining"
User_Connections[2701]="razor - spamassasin stuff"
# see bottom of this script for main function

# Log everything by creating and using logchains. 
sys_Setup_Log_Chains(){
    iptables -N LOG_ACCEPT
    iptables -A LOG_ACCEPT -m limit --limit 15/m --limit-burst 30 -j NFLOG --nflog-group 0 --nflog-prefix "ACCEPT "
    # -j LOG --log-prefix "iptables: ACCEPT " --log-level 4
    iptables -A LOG_ACCEPT -j ACCEPT

    iptables -N LOG_DROP
    iptables -A LOG_DROP -m limit --limit 15/m --limit-burst 30 -j NFLOG --nflog-group 0 --nflog-prefix "DROP "
    # -j LOG --log-prefix "iptables: DROP " --log-level 4
    iptables -A LOG_DROP -j DROP
    # If there are 15 connection requests per minute (or more), your server will allow 15 new connections every minute. If there are less than 15 requests in a minute, the bucket will fill up (actually it starts out full). This means that if there are only a few requests in one minute, the server will accept more than 15 new requests in the next minute. To keep this from getting out of control, there is a cap on how many tokens the bucket can hold. 30 in this case. When the bucket is full, your server will accept the next incoming 30 connections, even when they hit your server at the same time. As this is more than 15, we call this a burst, where the number of accept connections spikes up to more than the 15 we want ON AVAERAGE. - https://unix.stackexchange.com/questions/266343/iptables-rule-explanation
}

# Allow everything auto-identified as a related connection:
sys_Allow_Related_Established(){
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j LOG_ACCEPT 
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j LOG_ACCEPT 
    iptables -P INPUT DROP
}

sys_Allow_Localhost(){
    # localhost connections are always allowed (failure to allow this will
    # break many programs which rely on localhost)
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
}
# Only use this if not using ulogd.
# create /etc/rsyslog.d/iptables.conf with
#: <<EOF
#cat <<EOT > /etc/rsyslog.d/iptables.conf
#:msg, startswith, "iptables: " -/var/log/iptables.log
#& stop
#:msg, regex, "^\[ *[0-9]*\.[0-9]*\] iptables: " -/var/log/iptables.log
#& stop
#EOT
#EOF


# Enable outputs on OpenVPN interface for establishing VPN. Check your
# /etc/openvpn/client.conf for protocol and port numbers.
sys_Allow_To_VPN(){
    for port in "$@"
    do
	iptables -A OUTPUT -p udp --dport "${port}" -j LOG_ACCEPT -m comment --comment "OVPN"
	iptables -A OUTPUT -p tcp --dport "${port}" -j LOG_ACCEPT -m comment --comment "OVPN"
    done
}

sys_Allow_Multicast_DNS(){
    	# Allow local udp port 5353 for multicast DNS on local network port (avahi-daemon)
	iptables -A INPUT -p udp --in-interface "${1}" --dport 5353 -j LOG_ACCEPT -m comment --comment "multicast-dns"
	# Allow local outgoing multicast DNS connections
	iptables -A OUTPUT -p udp --out-interface "${1}" -d 224.0.0.251 --dport 5353 -j LOG_ACCEPT -m comment --comment "multicast-dns"
}

sys_Reject_RFC1918(){
# Reject packets from RFC1918 class networks (i.e., spoofed)
RFC1918=('0.0.0.0/8' '10.0.0.0/8' '127.0.0.0/8' '169.254.0.0/16' '172.16.0.0/12' '192.168.0.0/16' '224.0.0.0/4' '239.255.255.0/24' '240.0.0.0/5' '255.255.255.255')
for cidr in "${RFC1918[@]}" ; do
    iptables -A INPUT -s "$cidr" -i "${1}" -j LOG_DROP -m comment --comment "RFC1918 class network - spoofed address"
    iptables -A INPUT -d "$cidr" -i "${1}" -j LOG_DROP -m comment --comment "RFC1918 class network - spoofed address"
done
}

sys_Drop_Invalid_Packets(){
# Drop invalid packets immediately
iptables -A INPUT   -m conntrack --ctstate INVALID -j LOG_DROP -m comment --comment "INVALID packet type"
iptables -A FORWARD -m conntrack --ctstate INVALID -j LOG_DROP -m comment --comment "INVALID packet type"
iptables -A OUTPUT  -m conntrack --ctstate INVALID -j LOG_DROP -m comment --comment "INVALID packet type"
# Drop bogus TCP packets
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,FIN SYN,FIN -j LOG_DROP -m comment --comment "Bogus tcp packet type"
iptables -A INPUT -p tcp -m tcp --tcp-flags SYN,RST SYN,RST -j LOG_DROP -m comment --comment "Bogus tcp packet type"
}

# Additional ssh port
sys_Allow_Extra_SSH_Port(){
    iptables -A INPUT -p tcp --dport "${1}" -j LOG_ACCEPT
}

sys_Block_Portscanners(){
    # see cat /proc/net/xt_recent/portscan for added ip's.    
    # These rules add scanners to the portscan list, and logs the attempt. 
    portscan_ranges=('1:21' '23:24' '26:52' '54:66' '68:79' '81:442' '444:464' '466:553' '555:586' '588:992' '994:1934' '1936:3477' '3479:4189' '4191:5348' '5351:8442' '8444:9000' '9002:9417' '9419:59999' '61001:65535')    
    
    for range in "${portscan_ranges[@]}" ; do
	iptables -A INPUT   -p tcp -m tcp --dport "${range}" -m recent --name portscan --set -j LOG_DROP -m comment --comment "Portscan" 
	#iptables -A FORWARD -p tcp -m tcp --dport 139 -m recent --name portscan --set -j LOG --log-prefix "Portscan:"
	iptables -A FORWARD -p tcp -m tcp --dport "${range}" -m recent --name portscan --set -j LOG_DROP -m comment --comment "Portscan"
    done # any packet listed in recent is blocked directly (that is block on 2nd, not 1st scan). See for example --seconds and --hitcount options for alternative ways.

	# Anyone who tried to portscan us is locked out for an entire day.
	iptables -A INPUT   -m recent --name portscan --rcheck --seconds 86400 -j LOG_DROP -m comment --comment "Portscan: locking out for a day."
	iptables -A FORWARD -m recent --name portscan --rcheck --seconds 86400 -j LOG_DROP -m comment --comment "Portscan: locking out for a day." # "drop this packet if the source IP has been put on the list portscan within the last 86400 seconds".
	
	# Once the day has passed, remove them from the portscan list
	iptables -A INPUT   -m recent --name portscan --remove -m comment --comment "Portscan: remove a locked-out address after a day." 
	iptables -A FORWARD -m recent --name portscan --remove -m comment --comment "Portscan: remove a locked-out address after a day." # "remove this IP address from the list portscan". Please not that this rule is only evaluated if the previous rule did not match. This rule exists to keep the list portscan short. Longer lists take longer to search.

    # Examplanations (from: https://we.riseup.net/debian/iptables-recent-module-and-hit-limits )
    #—name xyz give a name to the particular ‘class’ you are defining
    #—rsource in the list you keep, use the remote (source) address
    #—rcheck see if the address is in the list
    #—update like rcheck, but update the timestamp for tracking hits
    #—seconds the number of seconds to track the address
    #—hitcount the number of hits withing the time defined be —seconds at which point the rule gets activated.	
}

sys_Allow_User_Connections(){
    for port in "${!User_Connections[@]}"
    do
	iptables -A OUTPUT -p udp --dport "$port" -m conntrack --ctstate NEW,ESTABLISHED -j LOG_ACCEPT -m comment --comment "${User_Connections[$port]}"
	iptables -A OUTPUT -p tcp --dport "$port" -m conntrack --ctstate NEW,ESTABLISHED -j LOG_ACCEPT -m comment --comment "${User_Connections[$port]}"
#	printf '%s\n' "key  : $i"
#	printf '%s\n' "value: ${array[$i]}"
    done
}

# Optional setups
sys_do_ipsetSetup(){
cat <<EOF > /lib/systemd/system/ipset.service
[Unit]
Description=Loading IP Sets
Before=network-pre.target iptables.service ip6tables.service ufw.service
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/sbin/ipset -f /etc/ipset.conf restore
ExecReload=/sbin/ipset -f /etc/ipset.conf restore
ExecStop=/sbin/ipset destroy

[Install]
WantedBy=multi-user.target
EOF
echo "running ./my-ipset-update.sh. May take some time."
./my-ipset-update.sh

whitelist(){
    for someList in $(ipset list -n)
    do
	for someSet in "${Whitelist[@]}"
	do ipset del "$someList" "$someSet" 2>/dev/null
	done
    done
}
whitelist

ipset save > /etc/ipset.conf
systemctl daemon-reload
systemctl enable ipset
echo "finished ipsetSetup"
}

sys_do_sslhSetup(){
    #SSLH SETUP
    # not used
#    localsship=192.168.1.5
    echo "Assuming you have sslh installed and setup; with local ssh source port 22 and ssl source port 4443."
    iptables -t mangle -N SSLH
    # This host receives incoming connections on it's public IP that's on tun0 (VPN).
    #iptables -t mangle -I OUTPUT --protocol tcp --out-interface $pubif --sport 22 --jump ACCEPT
    iptables -t mangle -I OUTPUT --protocol tcp --out-interface $pubif --sport 4443 --jump SSLH
    #iptables -t mangle -I OUTPUT --protocol tcp --sport 4443 --jump SSLH
#    iptables -t mangle -I SSLH  --protocol tcp -d $localsship --sport 22 --jump ACCEPT
#    iptables -t mangle -I SSLH  --protocol tcp -s $localsship --jump ACCEPT
    iptables -t mangle -A SSLH --jump MARK --set-mark 0x1
    iptables -t mangle -A SSLH --jump ACCEPT
    # avoid duplicate fwmark
    if ! ip rule show | grep "fwmark 0x1 lookup 100" -q ; then ip rule add fwmark 0x1 lookup 100 ; fi
    ip route add local 0.0.0.0/0 dev lo table 100
    echo "finished sslhSetup"
}

sys_Allow_Safe_ICMP(){
# Allow three types of ICMP packets to be received (so people can
# check our presence), but restrict the flow to avoid ping flood
# attacks. See iptables -p icmp --help for available icmp types.
for y in 'echo-reply' 'destination-unreachable' 'echo-request' ; do
    iptables -A INPUT -p icmp -m icmp --icmp-type $y -m limit --limit 1/second -j LOG_ACCEPT -m comment --comment "smurf-attack-protection"
    iptables -A OUTPUT -p icmp -m icmp --icmp-type $y -m limit --limit 1/second -j LOG_ACCEPT -m comment --comment "smurf-attack-protection"
done
}

# Not needed anymore because of default drop policy.
#for n in 'address-mask-request' 'timestamp-request' ; do
#  iptables -A INPUT  -p icmp -m icmp --icmp-type $n -j LOG_DROP
#done

# Protect against SYN floods by rate limiting the number of new
# connections from any host to 60 per second.  This does *not* do rate
# limiting overall, because then someone could easily shut us down by
# saturating the limit.
sys_Synflood_Protect(){
    # see cat /proc/net/xt_recent/synflood for added ip's.
    iptables -A INPUT -m conntrack --ctstate NEW -p tcp -m tcp --syn -m recent --name synflood --set
    iptables -A INPUT -m conntrack --ctstate NEW -p tcp -m tcp --syn -m recent --name synflood --update --seconds 1 --hitcount 90 -j LOG_DROP -m comment --comment "synflood-protection"
}

sys_Protect_SSH(){
    # Defend against brute-force attempts on ssh-port. -I flag to place at
    # top of chain.
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set -m comment --comment "Limit SSH IN" # add ip to recent list with --set.
    iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 -j LOG_DROP -m comment --comment "Limit SSH IN"
}

sys_Allow_SSH(){
# Secondly, to make sure you don't lock yourself out from your server
# you should add two allow ssh rules to iptables first thing:
iptables -A INPUT -p tcp -s "${1}" -d "${2}" -m tcp --dport 22 -j LOG_ACCEPT -m comment --comment "allow SSH IN"
}

sys_Allow_Mosh(){
# These udp-ports are for Mosh which is an ssh wrapper software for
# better responsiveness and roaming.
    iptables -A INPUT -p udp -m udp --dport "$1" -j LOG_ACCEPT -m comment --comment "Mosh UDP IN"
    iptables -A OUTPUT -p udp -m udp --sport "$1" -j LOG_ACCEPT -m comment --comment "Mosh UDP OUT"
    #iptables -A INPUT -p tcp -m tcp --dport 60000:61000 -j LOG_ACCEPT -m comment --comment "Mosh TCP IN"
    #iptables -A OUTPUT -p tcp -m tcp --sport 60000:61000 -j LOG_ACCEPT -m comment --comment "Mosh TCP OUT"
}

# Allow requests to our services.
# Allow the following hosted services on top of SSH:
# 
# 53=bind9 dns.
# 80/443=nginx http,https
# 88=kerberos
# 389/636=ldap
# 587/465/25=postfix submission,smtps,smtp
# 143/993/110/995/4190=dovecot imap,imaps,pop3,pop3s,managesieve.
# 7825=smbd/samba but this is not in use at the moment.
# 8443,3478,5349=coturn STUN/TURN server. 8443 is tls.
# 9001=etherpad-lite
# 9980=LibreOffice Online websocket daemon.
# 9418=git with git-daemon
# 1935=rtmp ports for video streaming, 554=RSTP for streaming.
sys_Allow_Services(){
    local -n _Services="${1}"
    for port in "${!_Services[@]}"
    do
	iptables -A INPUT -p udp --dport "${port}" -m conntrack --ctstate NEW,ESTABLISHED -j LOG_ACCEPT -m comment --comment "${_Services[$port]}"
	iptables -A INPUT -p tcp --dport "${port}" -m conntrack --ctstate NEW,ESTABLISHED -j LOG_ACCEPT -m comment --comment "${_Services[$port]}"
	
	#iptables -A INPUT -p tcp -s $server_local_ip --in-interface ${localif} --dport 389 -j LOG_ACCEPT -m comment --comment "ldap"

	# Specifically allow outgoing established connections from our services. (This should be taken care of automatically by above statement)
	iptables -A OUTPUT -p udp --match multiport --sports "${port}" -m conntrack --ctstate ESTABLISHED -j LOG_ACCEPT -m comment --comment "${_Services[$port]}"
	iptables -A OUTPUT -p tcp --match multiport --sports "${port}" -m conntrack --ctstate ESTABLISHED -j LOG_ACCEPT -m comment --comment "${_Services[$port]}"
	# Allow opening new connections on these same services from server.
	iptables -A OUTPUT -p udp --match multiport --dports "${port}" -m conntrack --ctstate NEW,ESTABLISHED -j LOG_ACCEPT -m comment --comment "${_Services[$port]}"
	iptables -A OUTPUT -p tcp --match multiport --dports "${port}" -m conntrack --ctstate NEW,ESTABLISHED -j LOG_ACCEPT -m comment --comment "${_Services[$port]}"
    done
}
	# iptables -A OUTPUT -p udp --match multiport --sports 80,443,587,465,25,143,993,110,995,4190,8443,3478,5349,9980,9418 -m conntrack --ctstate ESTABLISHED -j LOG_ACCEPT -m comment --comment "service-connection-reply"
	# iptables -A OUTPUT -p tcp --match multiport --sports 80,443,587,465,25,143,993,110,995,4190,8443,3478,5349,9980,9418 -m conntrack --ctstate ESTABLISHED -j LOG_ACCEPT -m comment --comment "service-connection-reply"
	# # Allow opening new connections on these same services from server.
	# iptables -A OUTPUT -p udp --match multiport --dports 80,443,587,465,25,143,993,110,995,4190,8443,3478,5349,9980,9418 -m conntrack --ctstate NEW,ESTABLISHED -j LOG_ACCEPT -m comment --comment "service-connection-reply"
	# iptables -A OUTPUT -p tcp --match multiport --dports 80,443,587,465,25,143,993,110,995,4190,8443,3478,5349,9980,9418 -m conntrack --ctstate NEW,ESTABLISHED -j LOG_ACCEPT -m comment --comment "service-connection-reply"	

# No need to use for-loop as below anymore since iptables have multiport option (although max 15 entries).
#for SERVICE in '53' '80' '443' '587' '465' '25' '143' '993' '110' '995' '4190' '8443' '3478' ; do
#    iptables -A INPUT -p tcp -m tcp -d $OURIP --dport $SERVICE -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#    iptables -A OUTPUT -p tcp -m tcp -s $OURIP --sport $SERVICE -m conntrack --ctstate ESTABLISHED -j ACCEPT
#    iptables -A OUTPUT -s $OURIP -p udp -m udp --dport $SERVICE -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#    iptables -A INPUT -d $OURIP -p udp -m udp --sport $SERVICE -m conntrack --ctstate ESTABLISHED -j ACCEPT    
#done 
#for SERVICE in '53' '80' '443' '587' '465' '25' '143' '993' '110' '995' '4190' '8443' '3478' ; do
#    iptables -A OUTPUT -s $OURIP -p tcp -m tcp --dport $SERVICE -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#    iptables -A INPUT -d $OURIP -p tcp -m tcp --sport $SERVICE -m conntrack --ctstate ESTABLISHED -j ACCEPT
#    iptables -A OUTPUT -s $OURIP -p udp -m udp --dport $SERVICE -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
#    iptables -A INPUT -d $OURIP -p udp -m udp --sport $SERVICE -m conntrack --ctstate ESTABLISHED -j ACCEPT    
#done 

# Log and drop all packages which are not specifically allowed.
sys_Default_Drop_Log(){
iptables -A INPUT -s 0.0.0.0/0 -d 0.0.0.0/0 -j LOG_DROP
iptables -A OUTPUT -s 0.0.0.0/0 -d 0.0.0.0/0 -j LOG_DROP
iptables -A FORWARD -s 0.0.0.0/0 -d 0.0.0.0/0 -j LOG_DROP
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP 
}

sys_Save_Config(){
    # Save configuration across network restarts and reboots.
    /sbin/iptables-save > /etc/iptables.up.rules
    if [[ "${1}" == "sslh" ]] || [[ "${2}" == "sslh" ]] ; then
cat <<EOT > /etc/network/if-pre-up.d/iptables
#!/bin/bash
/sbin/iptables-restore < /etc/iptables.up.rules
# for sslh
# avoid duplicate fwmark
if ! ip rule show | grep "fwmark 0x1 lookup 100" -q ; then ip rule add fwmark 0x1 lookup 100 ; fi
if ip route add local 0.0.0.0/0 dev lo table 100 ; then echo "ip route add local 0.0.0.0/0 dev lo table 100 was issued" ; fi
EOT
    else
cat <<EOT > /etc/network/if-pre-up.d/iptables
#!/bin/bash
/sbin/iptables-restore < /etc/iptables.up.rules

EOT
    fi   
chmod u+x /etc/network/if-pre-up.d/iptables
}

main(){
    iptables -P OUTPUT ACCEPT
    iptables --flush    
    sys_Setup_Log_Chains
    sys_Allow_Related_Established
    sys_Allow_Localhost
    sys_Allow_To_VPN "${VPN_ports[@]}"
    sys_Allow_User_Connections "User_Connections"
    sys_Reject_RFC1918 "$pubif"    
    cd "$pwd" || exit 1
    case "${1}" in
	"sslh") sys_do_sslhSetup ;;
	"ipset") sys_do_ipsetSetup ;;
	*) echo "No arguments given. Ok. Continuing."
    esac
    case "${2}" in
	"sslh") sys_do_sslhSetup ;;
	"ipset") sys_do_ipsetSetup ;;
	*) echo "No second argument given. Ok. Continuing."    
    esac
    sys_Drop_Invalid_Packets
#    sys_Allow_Extra_SSH_Port "1234"
    sys_Block_Portscanners
    sys_Synflood_Protect
    sys_Allow_Safe_ICMP        
    sys_Protect_SSH
    sys_Allow_SSH "${service_local_ip}" "${server_local_ip}"
    sys_Allow_Mosh "60000:61000"
    sys_Allow_Multicast_DNS "${localif}"
    sys_Allow_Services "${Services[@]}"
    sys_Default_Drop_Log
    sys_Save_Config "$@"
}
main "$@"
