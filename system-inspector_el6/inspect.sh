#!/bin/bash
#Created by Zachary LeBlanc
HOME=$(pwd)
trap ctrl_c INT
ctrl_c() {
	echo "** Trapped CTRL-C **"
	cd $HOME
	rm -rf results/
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
if [ ! -d results/ ]; then
	mkdir results/
fi
cd results/
mkdir elfs/
mkdir scap/
mkdir scap/oscap/
mkdir network/
mkdir users/
mkdir selinux/
mkdir privesc/
mkdir repochk/
(
echo "Starting Main Processes."
########## BEGIN CHKCONFIG ##########
chkconfig --list > chkconfig-list.txt

########## BEGIN NETWORK CHECKS ##########
cd network/
ifconfig > ifconfig.txt
cat /etc/hosts > etc-hosts
cat /etc/resolv.conf > etc-resolv.conf
cat /etc/sysctl.conf > etc-sysctl.conf
cat /etc/sysconfig/network > etc-sysconfig-network
iptables -L -n -v > iptables-output.txt
cat /etc/sysconfig/iptables > etc-sysconfig-iptables
netstat -a > netstat-a.txt
netstat -lnZ > netstat-lnZ.txt
ps auxZ | grep sshd > psauxZ-sshd.txt 
cd $HOME/results/

########## BEGIN USER CHECKS ##########
cd users/
cp /etc/passwd ./etc-passwd
cp /etc/shadow ./etc-shadow
cp /etc/group ./etc-group
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
cd $HOME/results/

########## BEGIN SELINUX CHECKS ##########
cd selinux/
echo '############### sestatus ###############' > selinux-info.txt
sestatus >> selinux-info.txt
echo >> selinux-info.txt
echo '############### semanage login -l ###############' >> selinux-info.txt
#semanage login -l >> selinux-info.txt
echo '############### semanage user -l ###############' >> selinux-info.txt
#semanage user -l >> selinux-info.txt
echo '############### SELINUX USERS ###############' >> selinux-info.txt
#seinfo -r >> selinux-info.txt
cd $HOME/results/

########## BEGIN MISC CHECKS ##########
echo "Running Kernel: $(uname -mrs)" > kernel-info.txt
echo "Blacklisted/Disabled Kernel Modules:" >> kernel-info.txt
echo "---------------------------------------------------" >> kernel-info.txt
grep -E 'blacklist|/bin/true|/bin/false' /etc/modprobe.d/* >> kernel-info.txt
echo >> kernel-info.txt
echo "---------------------------------------------------" >> kernel-info.txt
echo "Kernel Modules:" >> kernel-info.txt
echo "---------------------------------------------------" >> kernel-info.txt
lsmod >> kernel-info.txt
echo >> kernel-info.txt
echo "---------------------------------------------------" >> kernel-info.txt
echo "Kernel Module Configuration (Detailed):" >> kernel-info.txt
echo "---------------------------------------------------" >> kernel-info.txt
modprobe -c >> kernel-info.txt
echo >> kernel-info.txt
echo "---------------------------------------------------" >> kernel-info.txt
echo "Kernel Options:" >> kernel-info.txt
echo "---------------------------------------------------" >> kernel-info.txt
sysctl -a  >> kernel-info.txt
echo >> kernel-info.txt
echo "---------------------------------------------------" >> kernel-info.txt
mapfile -t ARRAY < <(find / -name "*sshd_config*" >/dev/null 2>&1)
LENGTH=${#ARRAY[@]}
for ((i=0; i<LENGTH; i++)); do
        if [[ ! ${ARRAY[$i]} = *\.* ]]; then
                if grep -q "\<Port\>" ${ARRAY[$i]} && grep -q "\<ListenAddress\>" ${ARRAY[$i]}; then
                        cat ${ARRAY[$i]} > sshd_config[$i]
                fi
        fi
done
cd $HOME/results/

########## BEGIN REPOCHK ##########
if [ "$MODE" == 1 ]; then
	cd $HOME/../repochk/
	yum -v repolist > repository-info.txt
	./getrpms.sh
	./update_repo.sh
	./repochk.py > $HOME/results/repochk/repochk-results
	rm -f repocache.txt
	mv rpmlist.txt $HOME/results/repochk/
	echo "Finished Main Processes."
elif [ "$MODE" == 2 ]; then
	if [ -f $HOME/../repochk/repocache.txt ]; then
		cd $HOME/../repochk/
		./getrpms.sh
		./repochk.py > $HOME/results/repochk/repochk-results
		rm -f repocache.txt
		mv rpmlist.txt $HOME/results/repochk/
		echo "Finished Main Processes."
	else
		echo "Repo Cache file (repocache.txt) does not exist. Skipping repochk."
	fi
fi
) &

(
########## BEGIN OSCAP CHECK ##########
echo "Starting OpenSCAP Process."
cd scap/oscap/
oscap >/dev/null 2>&1 oval eval --results oscap-results.xml /usr/share/xml/scap/ssg/content/ssg-rhel6-ds.xml
oscap >/dev/null 2>&1 oval generate report oscap-results.xml > oscap-results.html
echo "Finished OpenSCAP Process."
) &

(
########## BEGIN PRIVESC CHECK ##########
if [ -d $HOME/../unix-privesc-check-1_x ]; then
	echo "Starting Privilege Checks."
	cd $HOME/../unix-privesc-check-1_x/
	chmod 755 unix-privesc-check
	./unix-privesc-check detailed > $HOME/results/privesc/privesc-check
	echo "Finished Privilege Checks."
else
	echo "PRIVESC Check does not exist."
fi
) &

(
######### BEGIN AIDE CHECKS ##########
echo "Starting AIDE Process."
if [ -f /etc/aide.conf ] && [ -f /var/lib/aide/aide.db.gz ]; then
	CHK=1
	while ps aux | grep "aide --check" | grep -v grep >/dev/null 2>&1; do
		if [ "$CHK" == 1 ]; then
			echo "Waiting for existing AIDE CHECK to finish..."
			$((CHK++))
		fi
	done
	mkdir -p AIDE/
	cd AIDE/
	echo 'Performing AIDE Check.'
	cat /etc/aide.conf > etc-aide.conf
	aide --check > aide-check
	cd $HOME/results/
else
	echo 'AIDE is not installed or configured!' > aide-check
fi
echo "Finished AIDE Process."
) &

(
########## BEGIN FIND ROGUE ELFS ##########
cd elfs/
echo "Starting Rogue Elfs Process."
$HOME/../FindRogueElfs/FindRogueElfs.sh >/dev/null 2>&1

echo "Finished Rogue Elfs Process."
) &

wait
cd $HOME
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
rm -rf results/
echo
warning
echo
