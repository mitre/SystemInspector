## SystemInspector for Enterprise Linux ##

System Inspector for Enterprise Linux is designed to pull some of the most of the security-relevant files and 
information from a Linux system; current versions supported are Red Hat Enterprise Linux 6 and 7 and 
CentOS 6 and 7. Items such as iptables may differ between the output of the running configuration  and the 
saved configuration in /etc/sysconfig/iptables, so System Inspector pulls both in order for the user to 
evaluate such conditions.

If you would like to use System Inspector to its full potential, please download the Unix Privilege Escalation
Check zip file from the following link and save the `unix-privesc-check-1_x` folder into the root of 
the `system-inspector-el[x]` folder. Note that there will probably be a `unix-privesc-check-1_x` folder within a folder of the same name, move the second folder to the `SystemInspector` directory: https://github.com/pentestmonkey/unix-privesc-check/tree/1_x

## Requirements ## 
1. Run as root
2. Set SELinux to Permissive
3. OpenSCAP installation (openscap-scanner and scap-security-guide)
4. python2.x (if running repochk)

## How to Operate ##
If the system is able to connect to the Internet, the user needs to run the following to clone the repo correctly, which will clone SystemInspector, repochk, and FindRogueElfs: `git clone --recursive https://github.com/mitre/SystemInspector.git`

If the system is not able to connect to the Internet, the user needs to download the .zip file from GitHub, extract the contents, and manually bring the files to the system (i.e. via CD/DVD, USB, etc.). If the user plans to run repochk, the `update_repo.sh` script needs to be run on a system with Internet access. The output of that script should then be placed in the `repochk` directory on the system to be inspected. If the system does not have Python >= 2.x, repochk will not work. 

In the root directory of system-inspector-el[x], run the `inspect.sh` shell script. The user will be prompted to run the tool in either offline or online mode.

Once the scan is complete, everything will be dumped into a `results/` folder and then into a gzipped tarball; the `results/` folder will be deleted for ease of use. 

***DO NOT FORGET TO REMOVE THE FILES FROM THE SYSTEM WHEN FINISHED.*** 
