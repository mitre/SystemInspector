#!/bin/bash
#Created by Zachary LeBlanc
HOME=$(pwd)
trap ctrl_c INT
ctrl_c() {
	echo "** Trapped CTRL-C **"
	cd $HOME
	rm -rf results/ rm -f results.tar.gz
	killall inspect.sh
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
if [ $GETENFORCE = "Enforcing" ]; then
	echo "Please set SELinux to Permissive."
	exit 1
elif [ $GETENFORCE = "Disabled" ]; then
	echo "STOP DISABLING SELINUX!"
	exit 1
fi
if [ -a "/etc/redhat-release" ]; then
	VERSION="$(grep -oP "(?<=release )[^ ]+" /etc/redhat-release)"
	if [[ ! $VERSION = "7."[0-9] ]]; then
		echo "This script will not work with $(cat /etc/redhat-release)" | sed 's/release //g' | sed 's/ (Maipo)//g'
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
	mkdir $HOME/results/
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

########## BEGIN SYSTEMCTL ##########
systemctl list-unit-files > systemctl-unit-files

########## BEGIN NETWORK CHECKS ##########
cd network/
ifconfig > ifconfig
cat /etc/hosts > etc-hosts
cat /etc/resolv.conf > etc-resolv.conf
cat /etc/sysctl.conf > etc-sysctl.conf
cat /etc/sysconfig/network > etc-sysconfig-network
iptables -L -n -v > iptables-output
if [ -f /etc/sysconfig/iptables ]; then
	cat /etc/sysconfig/iptables > etc-sysconfig-iptables
else
	echo "No IPTABLES file was found. The system may be using FIREWALLD instead. Please check with system administrator." > etc-sysconfig-iptables
fi
netstat -a > netstat-a
netstat -lnZ > netstat-lnZ
ps auxZ > psauxZ
cd $HOME/results/

########## BEGIN USER CHECKS ##########
cd users/
cat /etc/passwd > etc-passwd
cat /etc/shadow > etc-shadow
cat /etc/group > etc-group
BIN=($(cat /etc/passwd | awk -F: '{print $NF}'))
USR=($(cat /etc/passwd | awk -F: '{print $1}'))
SIZE=${#BIN[@]}
VAL=/bin/bash
echo 'User'' | ''Groups' > users-groups
for (( c=0; c<SIZE; c++)); do
	if [ ${BIN[$c]} == $VAL ]; then
		groups "${USR[$c]}" >> users-groups
	fi
done
cd $HOME/results/

########## BEGIN SELINUX CHECKS ##########
cd selinux/
echo '############### sestatus ###############' > selinux-info
sestatus >> selinux-info
echo >> selinux-info
echo '############### semanage login -l (SELinux Login/Users Map) ###############' >> selinux-info
semanage login -l >> selinux-info
echo '############### semanage user -l (SELinux Users) ###############' >> selinux-info
semanage user -l >> selinux-info
echo '############### seinfo -r (SELinux Roles) ###############' >> selinux-info
seinfo -r >> selinux-info
cd $HOME/results/

########## BEGIN MISC CHECKS ##########
sysctl kernel.randomize_va_space > kernel-info
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

######### BEGIN REPOCHK ##########
if [ "$MODE" == 1 ]; then
	cd $HOME/../repochk/
	./getrpms.sh
	./update_repo.sh
	./repochk.py > $HOME/results/repochk/repochk-results
	rm -f repocache.txt
	mv rpmlist.txt $HOME/results/repochk/
	echo "Finished Main Processes."
elif [ "$MODE" == 2 ]; then
	if [ -f $HOME/../repochk/rpmlist.txt ]; then
		cd $HOME/../repochk/
		./getrpms.sh
		./repochk.py > $HOME/results/repochk/repochk-results
		rm -f repocache.txt
		mv rpmlist.txt $HOME/results/repochk/
		echo "Finished Main Processes."
	else
		echo "RPM list file (rpmlist.txt) does not exist. Skipping repochk."
	fi
fi
) &

(
########## BEGIN OSCAP CHECK ##########
echo "Starting OpenSCAP Process."
cd scap/oscap/
oscap >/dev/null 2>&1 oval eval --results oscap-results.xml /usr/share/xml/scap/ssg/content/ssg-rhel7-ds.xml
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
	echo "Unix Privesc Check does not exist."
fi
) &

(
######### BEGIN AIDE CHECKS ##########
echo "Starting AIDE Process."
if [ -f /etc/aide.conf ] && [ -f /var/lib/aide/aide.db.gz ]; then
	CHK=1
	while ps aux | grep "aide --check" | grep -v grep >/dev/null 2>&1; do
		if [ $CHK -eq 1 ]; then
			echo "Waiting for existing AIDE CHECK to finish..."
			$(CHK++)
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
tar -zcf results.tar.gz results/
rm -rf results/
echo "Everything is done."
echo
warning
