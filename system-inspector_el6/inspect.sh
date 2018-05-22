#!/bin/bash
###############################################################################
# System Inspector
#
# This script was written by Zach LeBlanc
# Last update was 22 May 2018
#
# Author: Zach LeBlanc (zleblanc@mitre.org)
# Contributor: Drew Bonasera (dbonasera@mitre.org)
# Contributor: Frank Caviggia (fcaviggia@mitre.org)
# Copyright: The MITRE Corporation, 2018
# License: MIT
# Description: Evaluates the security settings of a Linux (RHEL/CentOS)
#              System.
###############################################################################
###############################################################################
# (C) 2018 The MITRE Corporation. All Rights Reserved. This software is provided 
# as-is and MITRE disclaims all liability and all guarantees and warranties, 
# express or implied, including warranties of merchantability, non-infringement, 
# and fitness for a particular purpose. For open source code incorporated, such 
# open source software is distributed on an as-is basis under the respective 
# license terms thereof. MITRE disclaims any liability in relation to this 
# open source software. This notice shall be marked on any reproduction of 
# these data, in whole or in part. For further information, please contact 
# The MITRE Corporation, Contracts Office, 
# 7515 Colshire Drive, McLean, VA 22102-7539, (703) 983-6000.
###############################################################################

# Determine the Path
function realpath() {
    local r=$1; local t=$(readlink $r)
    while [ $t ]; do
        r=$(cd $(dirname $r) && cd $(dirname $t) && pwd -P)/$(basename $t)
        t=$(readlink $r)
    done
    echo $r
}
# Determine Execution Directory
BASE_DIR=$(dirname $(realpath $0))
# Working Directory for results
WORK_DIR=$(pwd)

trap ctrl_c INT
ctrl_c() {
	echo "** Trapped CTRL-C **"
	cd $WORK_DIR
	rm -rf results
	rm -f results.tar.gz
	killall -9 inspect.sh
	exit 1
}
if [ "$(id -u)" != "0" ]; then
	echo "Please run as root!"
	exit 1
fi
MAIL=$(echo $MAIL | awk -F / '{print $5}')
if [ ! $MAIL = "root" ]; then
	echo "Run as root, not SUDOER!"
	exit 1
fi 
GETENFORCE=$(getenforce)
if [ $GETENFORCE = "Disabled" ]; then
	echo "STOP DISABLING SELINUX!"
	exit 1
fi
if [ $GETENFORCE = "Enforcing" ]; then
	echo "Please set SELinux to Permissive."
	exit 1
fi
if [ -a "/etc/redhat-release" ]; then
	VERSION="$(grep -oP "(?<=release )[^ ]+" /etc/redhat-release)"
	if [[ ! $VERSION = "6."[0-9] ]]; then
		echo "This script will not work with $( cat /etc/redhat-release)" | sed 's/release //g' | sed 's/ (Maipo)//g'
		exit 1
	fi
fi
MODE=0
echo "Please select a mode: "
echo "[1] Online"
echo "[2] Offline"
echo
echo -n "Selection: "
read MODE
if [ ! -d $WORK_DIR/results ]; then
	mkdir $WORK_DIR/results
fi
cd $WORK_DIR/results
mkdir {elfs,scap,network,users,selinux,pirvsec,repochk}
(
echo "Starting Main Processes."
########## BEGIN CHKCONFIG ##########
chkconfig --list > chkconfig-list.txt

########## BEGIN NETWORK CHECKS ##########
cd network
if [ -x /usr/sbin/ifconfig ]; then
	ifconfig > network_information.txt
elif [ -x /usr/sbin/ip ]; then
	ip addr > network_information.txt
fi
cat /etc/hosts > etc-hosts
cat /etc/resolv.conf > etc-resolv.conf
cat /etc/sysctl.conf > etc-sysctl.conf
cat /etc/sysconfig/network > etc-sysconfig-network
if [ -x /usr/sbin/iptables ]; then
	iptables -L -n -v > iptables-output.txt
	cat /etc/sysconfig/iptables-config > etc-sysconfig-iptables
fi
if [ -x /usr/sbin/ip6tables ]; then
	ip6tables -L -n -v > ip6tables-output.txt
	cat /etc/sysconfig/ip6tables-config > etc-sysconfig-ip6tables
fi
if [ -x /usr/bin/netstat ]; then
	netstat -a > netstat-a.txt
	netstat -lnZ > netstat-lnZ.txt
fi
ps auxZ | grep sshd > psauxZ-sshd.txt 
cd $WORK_DIR/results

########## BEGIN USER CHECKS ##########
cd users
cat /etc/passwd > etc-passwd
cat /etc/shadow > etc-shadow
cat /etc/group > etc-group
cat /etc/shells > etc-shells
BIN=($(cat /etc/passwd | awk -F: '{print $NF}'))
USR=($(cat /etc/passwd | awk -F: '{print $1}'))
SIZE=${#BIN[@]}
VAL=/bin/bash
echo 'User'' | ''Groups' > users-groups.txt
for (( c=0; c<SIZE; c++)); do
	if [ ${BIN[$c]} == $VAL ]; then
		groups "${USR[$c]}" >> users-groups.txt
	fi
done
cd $WORK_DIR/results

########## BEGIN SELINUX CHECKS ##########
cd $WORK_DIR/results/selinux/
echo '############### sestatus ###############' > selinux-info
sestatus >> selinux-info
echo >> selinux-info
if [ -x /usr/sbin/semanage ]; then
	echo '############### semanage login -l (SELinux Login/Users Map) ###############' >> selinux-info
	semanage login -l >> selinux-info
	echo '############### semanage user -l (SELinux Users) ###############' >> selinux-info
	semanage user -l >> selinux-info
fi
if [ -x /usr/bin/seinfo ]; then
	echo '############### seinfo -r (SELinux Roles) ###############' >> selinux-info
	seinfo -r >> selinux-info
fi
cd $WORK_DIR/results

########## BEGIN MISC CHECKS ##########

echo "Running Kernel: $(uname -mrs)" > kernel-info.txt
echo "Kernel FIPS Mode: $(cat /proc/sys/crypto/fips_enabled)" >> kernel-info.txt
echo "Blacklisted/Disabled Kernel Modules:" >> kernel-info.txt
echo "---------------------------------------------------" >> kernel-info.txt
grep -E 'blacklist|/bin/true|/bin/false' /etc/modprobe.d/* >> kernel-info.txt
echo >> kernel-info.txt
echo "---------------------------------------------------" >> kernel-info.txt
echo "Kernel Modules:" >> kernel-info.txt
echo "---------------------------------------------------" >> kernel-info.txt
lsmod &>> kernel-info.txt
echo >> kernel-info.txt
echo "---------------------------------------------------" >> kernel-info.txt
echo "Kernel Module Configuration (Detailed):" >> kernel-info.txt
echo "---------------------------------------------------" >> kernel-info.txt
modprobe -c &>> kernel-info.txt
echo >> kernel-info.txt
echo "---------------------------------------------------" >> kernel-info.txt
echo "Kernel Options:" >> kernel-info.txt
echo "---------------------------------------------------" >> kernel-info.txt
sysctl -a &>> kernel-info.txt
echo >> kernel-info.txt
echo "---------------------------------------------------" >> kernel-info.txt

echo "Hardware Information" > hardware-info.txt
echo >> hardware-info.txt
echo "CPU Information:" >> hardware-info.txt
echo "---------------------------------------------------" >> hardware-info.txt
cat /proc/cpuinfo >> hardware-info.txt
echo >> hardware-info.txt
echo "---------------------------------------------------" >> hardware-info.txt
echo "Storage Information:" >> hardware-info.txt
echo "---------------------------------------------------" >> hardware-info.txt
lsblk >> hardware-info.txt
echo >> hardware-info.txt
echo "---------------------------------------------------" >> hardware-info.txt
if [ -x /sbin/lspci ]; then
echo "PCI Information:" >> hardware-info.txt
echo "---------------------------------------------------" >> hardware-info.txt
lspci -v >> hardware-info.txt
echo >> hardware-info.txt
echo "---------------------------------------------------" >> hardware-info.txt
fi
if [ -x /sbin/lsusb ]; then
echo "USB Information:" >> hardware-info.txt
echo "---------------------------------------------------" >> hardware-info.txt
lsusb -v >> hardware-info.txt
echo >> hardware-info.txt
echo "---------------------------------------------------" >> hardware-info.txt
fi

mapfile -t ARRAY < <(find / -name "*sshd_config*" >/dev/null 2>&1)
LENGTH=${#ARRAY[@]}
for ((i=0; i<LENGTH; i++)); do
        if [[ ! ${ARRAY[$i]} = *\.* ]]; then
                if grep -q "\<Port\>" ${ARRAY[$i]} && grep -q "\<ListenAddress\>" ${ARRAY[$i]}; then
                        cat ${ARRAY[$i]} > sshd_config[$i]
                fi
        fi
done
cd $WORK_DIR/results

######### BEGIN REPOCHK ##########
yum -v repolist &> repository-info.txt
cd $WORK_DIR
if [ $MODE -eq 1 ]; then
        $BASE_DIR/../repochk/getrpms.sh
        $BASE_DIR/../repochk/update_repo.sh >/dev/null 2>&1
        $BASE_DIR/../repochk/repochk.py > $WORK_DIR/results/repochk/repochk-results
        mv rpmlist.txt $WORK_DIR/results/repochk/
        rm -f repocache.txt
        echo "Finished Main Processes."
elif [ $MODE -eq 2 ]; then
        if [ -f $BASE_DIR/../repochk/repocache.txt ]; then
                $BASE_DIR/../repochk/getrpms.sh
                cp $BASE_DIR/../repochk/repocache.txt .
                $BASE_DIR/../repochk/repochk.py > $WORK_DIR/results/repochk/repochk-results
                mv rpmlist.txt $WORK_DIR/results/repochk/
                rm -f repocache.txt
                echo "Finished Main Processes."
        else
                echo "Repo Cache file (repocache.txt) does not exist. Skipping repochk."
        fi
fi
cd $WORK_DIR/results
) &

(
########## BEGIN OSCAP CHECK ##########
echo "Starting OpenSCAP Process."
cd $WORK_DIR/results/scap
oscap >/dev/null 2>&1 oval eval --results oscap-results.xml /usr/share/xml/scap/ssg/content/ssg-rhel6-ds.xml &
SCAP_SCAN_PID=$!
while kill -0 $SCAP_SCAN_PID >/dev/null 2>&1; do
        echo "OpenSCAP configuration scan process is still active..."
        sleep 15
done
oscap >/dev/null 2>&1 oval generate report oscap-results.xml > $(hostname)-scap-scan-report-$(date +%Y%m%d).html &
SCAP_RESULTS_PID=$!
while kill -0 $SCAP_RESULTS_PID >/dev/null 2>&1; do
        echo "OpenSCAP configuration scan process is still active..."
        sleep 15
done

if [ $MODE -eq 1 ]; then
    wget http://www.redhat.com/security/data/oval/com.redhat.rhsa-all.xml >/dev/null 2>&1
    if [ $? -gt 1 ]; then
        echo "Error Downloading Red Hat Security Advisory (RHSA) data from Red Hat!"
    fi
    wget http://www.redhat.com/security/data/metrics/com.redhat.rhsa-all.xccdf.xml >/dev/null 2>&1
    if [ $? -gt 1 ]; then
        echo "Error Downloading XCCDF data from Red Hat!"
    fi
fi
if [[ -e com.redhat.rhsa-all.xml && -e com.redhat.rhsa-all.xccdf.xml ]]; then
        oscap xccdf eval --results $(hostname)-scap-vulnerability-report-$(date +%Y%m%d).xml --report $(hostname)-scap-vulnerability-report-$(date +%Y%m%d).html com.redhat.rhsa-all.xccdf.xml >/dev/null 2>&1 &
	SCAP_VULN_PID=$!
        while kill -0 $SCAP_VULN_PID >/dev/null 2>&1; do
                echo "OpenSCAP vulnerability check process is still active..."
                sleep 30
        done
else
        echo "Red Hat Vulnerability Content Missing - please run in Online mode!"
fi
echo "Finished OpenSCAP Process."
) &

(
########## BEGIN PRIVESC CHECK ##########
if [ -d $BASE_DIR/../unix-privesc-check-1_x ]; then
	echo "Starting Privilege Checks."
	cd $BASE_DIR/../unix-privesc-check-1_x
	chmod 755 unix-privesc-check
	./unix-privesc-check detailed > $WORK_DIR/results/privesc/privesc-check
	echo "Finished Privilege Checks."
else
	echo "PRIVESC Check does not exist."
fi
) &

(
######### BEGIN AIDE CHECKS ##########
echo "Starting AIDE Process."
if [ -f /etc/aide.conf ] && [ -f /var/lib/aide/aide.db.gz ]; then
        mkdir -p cd $WORK_DIR/results/AIDE
        cd $WORK_DIR/results/AIDE
        echo 'Performing AIDE Check.'
        cat /etc/aide.conf > etc-aide.conf
        aide --check > aide-check &
        AIDE_PID=$!
        while kill -0 $AIDE_PID >/dev/null 2>&1; do
                echo "AIDE check process is still active..."
                sleep 15
        done
        cd $WORK_DIR/results
else
        echo 'AIDE is not installed or configured!' > aide-check
fi
echo "Finished AIDE Process."
) &

(
########## BEGIN FIND ROGUE ELFS ##########
cd $WORK_DIR/results/elfs
echo "Starting Rogue ELFs Process."
$BASE_DIR/../FindRogueElfs/FindRogueElfs.sh &
ELFS_PID=$!
while kill -0 $ELFS_PID >/dev/null 2>&1; do
	echo "Find Rogue ELFs process is still active..."
        sleep 15
done
echo "Finished Rogue ELFs Process."
) &

wait
cd $WORK_DIR
warning() {
cat << EOF 
*********************************************
*     WARNING WARNING WARNING WARNING       *
*********************************************
*					    *
*  Remove the files from the system that    *
*  this script has created! They contain    *
*  highly sensitive information and should  *
*   and should not be left on the system.   *
*					    *
*********************************************
EOF
} 
echo "Everything is done."
tar -zcf results.tar.gz results/
rm -rf $WORK_DIR/results
echo
warning
echo
