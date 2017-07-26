## System Inspector for Enterprise Linux ##

System Inspector for Enterprise Linux is designed to pull some of the most of the security-relevant files and 
information from a Linux system; current versions supported are Red Hat Enterprise Linux 6 and 7 and 
CentOS 6 and 7. Items such as iptables may differ between the output of the running configuration  and the 
saved configuration in /etc/sysconfig/iptables, so System Inspector pulls both in order for the user to 
evaluate such conditions.

If you would like to use System Inspector to its full potential, please download the Unix Privilege Escalation
Check zip file from the following link and save the `unix-privesc-check-1_x` folder into the root of 
the `system-inspector-el[x]` folder. Note that there will probably be a `unix-privesc-check-1_x` folder within a folder of the same name, move the second folder: https://github.com/pentestmonkey/unix-privesc-check/tree/1_x

## Requirements ## 
1. Internet Connection for REPOCHK
2. Run as root
3. Set SELinux to Permissive
4. OpenSCAP and OpenSCAP Scanner installed locally

## How to Operate ##
First the user needs to run the following to clone the repo correctly: `git clone --recursive https://github.com/mitre/SystemInspector.git`

In the root directory of system-inspector-el[x], run the `inspect.sh` shell script; during scan, it is normal
to see a permission denial for /run/user/[x]/gvfs. Once the scan is complete, everything will be deposited 
into the `results/` folder under the root directory of system-inspector-el6. 
