#!/bin/bash

#fix my-ipset-update.sh issues:
#1. 31 chars too long
#2. don't use both list _1d and _30d etc. - use a large include list.
#fix ssh issue
#fix flashrom to boot cryptomount -a and configfile (crypto0)/boot/grub/grub.cfg

# -------------------------------------------------------- #
# ipset-update.sh (C) 2012-2015 Matt Parnell http://www.mattparnell.com
# Licensed under the GNU-GPLv2+
# -------------------------------------------------------- #

# -------------------------------------------------------- #
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
# -------------------------------------------------------- #

# -------------------------------------------------------- #
#
# This script downloads, parses and installs selected ipset blocklists
# from:
#
# -  https://www.iblocklist.com/lists.php
# -  https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=$ip&port=$port
# -  http://www.ipdeny.com/ipblocks/data/countries/$country.zone
# -  My additions:
# -  https://www.abuseipdb.com/
# -  https://github.com/firehol/blocklist-ipsets
#
# -------------------------------------------------------- #
# ENABLE DEFAULT OPTIONS HERE
# -------------------------------------------------------- #
# enable bluetack lists?
ENABLE_BLUETACK=1

# enable country blocks?
ENABLE_COUNTRY=0

# enable tor blocks?
ENABLE_TORBLOCK=0

# enable abuseipdb?
ENABLE_ABUSEIPDB=0

# enable firehol lists?
ENABLE_FIREHOL=1

# enable ssh-timeout block?
ENABLE_SSH_BLOCK=1
# -------------------------------------------------------- #
# SPECIFY OPTIONS HERE
# -------------------------------------------------------- #

# place to keep our cached blocklists, note - full directory will be
# removed and recreated during updates.
LISTDIR="/var/cache/blocklists"
FIREHOLDIR="/var/cache" # this will create /var/cache/blocklist-ipsets from the firehol github repo
# create cache directory for our lists if it isn't there
[ ! -d "${LISTDIR}" ] && mkdir "${LISTDIR}"

# countries to block, must be lcase
COUNTRIES=(af ae ir iq tr cn sa sy ru ua hk id kz kw ly)

# bluetack lists to use - they now obfuscate these so get the BLUETACK
# part from https://www.iblocklist.com/lists.php
#BLUETACKALIAS=(DShield Bogon Hijacked DROP ForumSpam WebExploit Ads Proxies BadSpiders CruzIT Zeus Palevo Malicious Malcode Adservers level1) # level2 level3)
BLUETACKALIAS=(DShield Hijacked DROP ForumSpam WebExploit Ads Proxies BadSpiders CruzIT Zeus Palevo Malicious Malcode Adservers) # level1 level2 level3)
#BLUETACK=(xpbqleszmajjesnzddhv lujdnbasfaaixitgmxpp usrcshglbiilevmyfhse zbdlwrqkabxbcppvrnos
BLUETACK=(xpbqleszmajjesnzddhv usrcshglbiilevmyfhse zbdlwrqkabxbcppvrnos ficutxiwawokxlcyoeye ghlzqtqxnzctvvajwwag dgxtneitpuvgqqcpfulq xoebmbyexwuiogmbyprb mcvxsnihddgutbjfbghy czvaehmjpsnwwttrdoyl ynkdjqsjyfmilsgbogqf erqajhwrxiuvjxqrrwfj npkuuhuxcsllnhoamkvm pbqcylkejciyhmwttify zhogegszwduurnvsyhdf) # ydxerpxkpcfqjaybcssw gyisgnzbhppbvsphucsw) uwnukjqktoggdknzrhgh) 
# ports to block tor users from
PORTS=(80 443 6667 22 21)

# See https://github.com/firehol/blocklist-ipsets for sets. There's
# some overlap with bluetack lists - make sure not to duplicate. For
# Don't use the openbl list, idk where the ip's for that list are.
exclude_patterns=('ransomware' 'hphosts' 'bambenek' 'cleanmx' 'coinbl' 'cta_cryptowal')

# -------------------------------------------------------- #
# Script-code below
# -------------------------------------------------------- #
shopt -s extglob
removeOldLists()
{
    rm -r $LISTDIR && mkdir $LISTDIR
    # remove old countries list
    #[ -f $LISTDIR/countries.txt ] && rm $LISTDIR/countries.txt
    # remove the old tor node list
    #[ -f $LISTDIR/tor.txt ] && rm $LISTDIR/tor.txt
    #rm $LISTDIR/*.txt
}
removeOldLists

#cache a copy of the iptables rules
IPTABLES=$(iptables-save)

importList(){
    local list="$1"    
    if [ -f "${LISTDIR}/${list}.txt" ] || [ -f "${LISTDIR}/${list}.gz" ]
    then
	echo "Importing $list blocks..."
	if (( ${#list} > 27 ))
	then
	    local list="${list[0]: -27}"
	fi	
	ipset create -exist "${list}" hash:net maxelem 4294967295
	ipset create -exist "${list}-TMP" hash:net maxelem 4294967295
	ipset flush "${list}-TMP" &> /dev/null
	#the second param determines if we need to use zcat or not
	if [ $2 = 1 ]
	then
	    zcat "${LISTDIR}/${1}.gz" | grep  -v \# | grep -v ^$ | grep -v 127\.0\.0 | pg2ipset - - "${list}-TMP" | ipset restore
	else
	    awk '!x[$0]++' "${LISTDIR}/${1}".txt | grep  -v \# | grep -v ^$ |  grep -v 127\.0\.0 | sed -e "s/^/add\ \-exist\ $list\-TMP\ /" | ipset restore
	fi
	
	ipset swap "{$list}" "${list}-TMP" &> /dev/null
	ipset destroy "${list}-TMP" &> /dev/null
	
	# only create if the iptables rules don't already exist
	if ! echo "${IPTABLES}" | grep -q "\-A\ INPUT\ \-m\ set\ \-\-match\-set\ $list\ src\ \-\j\ LOG_DROP"
	then
	    #iptables -A INPUT -m set --match-set $list src -j ULOG --ulog-prefix "Blocked input $list"
	    #iptables -A FORWARD -m set --match-set $list src -j ULOG --ulog-prefix "Blocked fwd $list"
	    #iptables -A FORWARD -m set --match-set $list dst -j ULOG --ulog-prefix "Blocked fwd $list"
	    #iptables -A OUTPUT -m set --match-set $list dst -j ULOG --ulog-prefix "Blocked out $list"
	    
	    #iptables -A INPUT -m set --match-set $list src -j DROP
	    #iptables -A FORWARD -m set --match-set $list src -j DROP
	    #iptables -A FORWARD -m set --match-set $list dst -j REJECT
	    #iptables -A OUTPUT -m set --match-set $list dst -j REJECT

	    #My change:
	    iptables -A INPUT -m set --match-set "${list}" src -j LOG_DROP
	    iptables -A OUTPUT -m set --match-set "${list}" dst -j LOG_DROP
	    # enable these if you do forwarding
	    #iptables -A FORWARD -m set --match-set $list src -j LOG_DROP
	    #iptables -A FORWARD -m set --match-set $list dst -j LOG_DROP	    
	fi
    else
	echo "List $1.txt does not exist."
    fi
}

if [ "${ENABLE_BLUETACK}" = 1 ]
then
  # get, parse, and import the bluetack lists
  # they are special in that they are gz compressed and require
  # pg2ipset to be inserted
  i=0
  for list in ${BLUETACK[@]}
  do  
      if [ eval $(wget --quiet -O /tmp/${BLUETACKALIAS[i]}.gz http://list.iblocklist.com/?list=$list&fileformat=p2p&archiveformat=gz) ]
      then
	  mv /tmp/${BLUETACKALIAS[i]}.gz $LISTDIR/${BLUETACKALIAS[i]}.gz
      else
	  echo "Using cached list for ${BLUETACKALIAS[i]}."
      fi
      
      echo "Importing bluetack list ${BLUETACKALIAS[i]}..."
      
      importList ${BLUETACKALIAS[i]} 1
      
      i=$((i+1))
  done
fi

if [ $ENABLE_COUNTRY = 1 ]
then
  # get the country lists and cat them into a single file
    for country in ${COUNTRIES[@]}
    do
	if [ eval $(wget --quiet -O /tmp/${country}.txt http://www.ipdeny.com/ipblocks/data/countries/$country.zone) ]
	then
	  cat /tmp/${country}.txt >> ${LISTDIR}/countries.txt
	  rm /tmp/${country}.txt
	fi
    done
    
    importList "countries" 0
fi


if [ $ENABLE_TORBLOCK = 1 ]; then
  # get the tor lists and cat them into a single file
    for ip in $(ip -4 -o addr | awk '!/^[0-9]*: ?lo|link\/ether/ {gsub("/", " "); print $4}')
    do
      for port in "${PORTS[@]}"
      do
	  if [ eval $(wget --quiet -O "/tmp/${port}.txt" https://check.torproject.org/cgi-bin/TorBulkExitList.py?ip=$ip&port=$port) ]
	  then
		cat "/tmp/${port}.txt" >> "${LISTDIR}/tor.txt"
		rm "/tmp/${port}.txt"
	  fi
      done
  done 
  
  importList "tor" 0
fi

# add any custom import lists below
# ex: importTextList "custom"

if [ "${ENABLE_FIREHOL}" = 1 ]; then
    if [[ -d "${FIREHOLDIR}" ]] ; then
	cd "${FIREHOLDIR}"
	git pull https://github.com/firehol/blocklist-ipsets
	cd "${FIREHOLDIR}/blocklist-ipsets"
    else
	git clone https://github.com/firehol/blocklist-ipsets $FIREHOLDIR
	cd "${FIREHOLDIR}/blocklist-ipsets"
    fi
    for list in $(ls "${FIREHOLDIR}/blocklist-ipsets" | grep .ipset); do
#    for list in $($FIREHOL_BLISTS); do
	# importList function wants .txt extensions in $LIST directory.
	#	if [[ $list = *.ipset ]]  ; then
	for exclude_pattern in "${exclude_patterns[@]}" ; do
	    if grep "$exclude_pattern" <<<"$list"
	    then
		continue 2
	    fi
	done
	    grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/*[0-9]*" "${FIREHOLDIR}/blocklist-ipsets/${list}" > "${LISTDIR}/${list%%.ipset}.txt"
	# elif [[ $list = *.netset ]]  ; then	    
	    #     grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/*[0-9]*" $FIREHOLDIR/blocklist-ipsets/${list} > $LISTDIR/${list}.txt
	# fi
	importList "${list%%.ipset}" 0
    done;
    cd -
fi

# Downloads ip-lists pages from the abuseipdb website and parses the
# html file for the addresses and saves them into a file with the name
# of the first argument the script is invoked with.

f_do_AbuseIPDB(){ 
    for i in {1..100} ; do
	# avoid getting caught by potential syn-flood firewall-filter.
	sleep 1 && wget --quiet https://www.abuseipdb.com/sitemap?page=$i

	# Break loop when we get to a page without ip-addresses.
	# This string is only on non-empty pages.
	if ! ( grep -q "<div class=\"col-md-2\">" "sitemap?page=$i" ) ; then
	    rm "sitemap?page=$i"
	    echo "Reached last page with ip-addresses at abuseipdb.com"
	    break
	fi

	# Append ip-addresses to a line-separated file.
	grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" "sitemap?page=$i" | cut -c 45-59 | sed 's/\".*//g' >>"$1"
	# clean up
	rm "sitemap?page=$i"
    done
}
if [ "${ENABLE_ABUSEIPDB}" = 1 ]; then
    echo "Downloading and parsing ip sets from https://www.abuseipdb.com/"
    f_do_AbuseIPDB "$LISTDIR/abuseipdb.txt"
    importList "abuseipdb" 0
fi
if [ "${ENABLE_SSH_BLOCK}" = 1 ]; then
    ipset create fwknop_allow hash:ip,port timeout 30
    iptables -A INPUT -m set --match-set fwknop_allow src,dst -j LOG_ACCEPT
fi
