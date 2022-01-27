## Hunt for PwnKit CVE with Sentinel

### Details on the CVE-2021-4034

All details about this vulnerability can be found here: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
This is not a *new* vulnerability, CVE registation dates back from late 2021 and the actual bug is 12 years old! A patch is available for most standard distributions. <br />
On 26th of January, Qualys researchers disclosed how it could lead to local Privilege Escalation, from any user to root. This is exploiting a vulnerability in *pkexec* command, from polkit, a SUID-root program allowing to run any program as another user, or root if no user is specificied (see [manual pages](https://linux.die.net/man/1/pkexec)).
The problem is that polkit is installed by default on every major Linux distribution.

### Is there an exploit available and how hard is it to exploit?

The exploit exists and can easily be found on the Internet. The idea here is to keep responsible disclosure in mind and not put any source. You can however consider any script kiddy out there will be able to (1) find it, (2) execute it as long as they have regular user access to a vulnerable OS.

### Is there a fix available?

Yes a patch already exists for this CVE for most standard OS'es but not all of them. Patching is the best and recommended solution. Pkexec >= 0.120 is considered patched.
However a temporary mitigation exists, which at time of writing, seems to work: changing the permissions on the vulnerable binary, *pkexec*.<br />
Indeed, by default the pkexec binary has the *SETUID* bit set, which allows this privilege escalation to happen. SETUID bit allows to execute a program with the owner's privileges.
In most distributions, SETUID (4755) bit is set on pkexec (or even the setuid + SETGID bits: 6755).<br />
If you change the permissions using for instance chmod 0755 (chmod a+rwx,g-w,o-w,ug-s,-t), it would set permissions so that, (U)ser / owner can read, can write and can execute. (G)roup can read, can't write and can execute. (O)thers can read, can't write and can execute, and SETUID bit is not set anymore on the binary. 
This means pkexec will probably not work at all anymore, so it might have adverse impact if it used by *legitimate* operators, however this is rarely used as such. And ok, there are priorities to be made here right?

### How to threat hunt for this using Sentinel?

**Note:** most modern EDR and vulnerability scanning solutions (Qualys, TVM on MDE...) should be able to at least detect your system as being vulnerable. 

If you send audit logs to Sentinel, using syslog, the default connector for Linux logs in Sentinel, you can simply look for execution of the *pkexec* command by a non-root user (successful or not, in any case it is good to know) or in most cases, look for other IoCs such as *'GCONV_PATH'* and/or *'The value for SHELL variable'* which will output as result of executing the exploit. <br />
Details of successfull or unsucessfull attempts will depends on syslog configuration and target os (there are subtle differences between for instance Ubuntu syslog facilities and CentOS). Most of the time, you can leverage beyond other logs, find interesting details in *auth.log*, *authpriv.log* or *secure.log* (for CentOS). 
Example (here a failed attempt) on Ubuntu auth.log:

```
*./auth.log:Jan 26 20:08:30 XXXX-Server polkitd(authority=local): Registered Authentication Agent for unix-process:4885:58817 (system bus name :1.31 [pkexec ls], object
 path /org/freedesktop/PolicyKit1/AuthenticationAgent, locale en_US.UTF-8)
./auth.log:Jan 26 20:08:36 XXXX-Server pkexec[4981]: tux: Error executing command as another user: Not authorized [USER=root] [TTY=/dev/pts/0] [CWD=/home/azureuser] [C
OMMAND=/usr/bin/ls]*
```

Now, here is an example of a successful straightforward exploit on CentOS. Again, this is pretty easy. There are several exploits out there, some only working on specific releases.

<img src=images/success_exploit.png />

After successful exploit (or unsuccessful) in CentOS, *secure* log file (=auth/authpriv syslog facility on CentOS) is populated as such:

![image](https://user-images.githubusercontent.com/18376283/151335767-9b86699d-f3db-44f9-9330-cb31b3cd604f.png)

Note, in your Sentinel configuration for Syslog, make sure you collect all needed facilities depending on your syslog config and OS, example:

![image](https://user-images.githubusercontent.com/18376283/151343185-72be60e0-b546-4e8d-9318-ede2b4c789ef.png)


The query I used for Sentinel is a very straightforward/basic one. This is certainly not bullet-proof and will probably not detect all exploits out there, as well as bringing some false-positives but this is a good start.
I suggest to use it as hunting query in Sentinel, adapt it to your needs or own investigations.
Microsoft MSTIC team or other security researchers will probably release more complete IoCs and detection rules in coming days.
The query is filtering on the either on *auth* and *authpriv* facilies in syslog, with brute-force kind of parsing and looking for IoCs explained here above. The first query was validated on CentOS or equivalent systems where both auth and authpriv are included as part of *secure* file in /var/log/, and assuming only a basic default syslog configuration:

```
Syslog
| where Facility == "authpriv" or Facility == "auth"
| where SyslogMessage contains "the SHELL variable " or SyslogMessage contains "GCONV_PATH"
```

The second query is parsing a bit more and working for Ubuntu or Debian-based systems for instance, where user, auth and authpriv facilities are both more verbose:

```
Syslog
  | parse SyslogMessage with "type=" EventType " audit(" * "): " EventData
  | project TimeGenerated, EventType, Computer, EventData 
  | parse EventData with * "syscall=" syscall " syscall_r=" * " success=" success " exit=" exit " a0" * " ppid=" ppid " pid=" pid " audit_user=" audit_user " auid=" auid " user=" user " uid=" uid " group=" group " gid=" gid "effective_user=" effective_user " euid=" euid " set_user=" set_user " suid=" suid " filesystem_user=" filesystem_user " fsuid=" fsuid " effective_group=" effective_group " egid=" egid " set_group=" set_group " sgid=" sgid " filesystem_group=" filesystem_group " fsgid=" fsgid " tty=" tty " ses=" ses " comm=\"" comm "\" exe=\"" exe "\"" * "cwd=\"" cwd "\"" * "name=\"" name "\"" * "cmdline=\"" cmdline "\" containerid=" containerid
  // Find pkexec usage or exploit IoCs
  // You can potientially remove some false positives by limiting to non-root users:
  //| where uid != 0 and gid != 0
  | where cmdline contains "pkexec" or cmdline contains ("PKEXEC") or comm in ("pkexec","PKEXEC") or EventData contains "The value for SHELL variable" or comm contains "GCONV_PATH"
  | project TimeGenerated, Computer, audit_user, user, cmdline, comm, EventData
  | extend AccountCustomEntity = user, HostCustomEntity = Computer, timestamp = TimeGenerated
  | sort by TimeGenerated desc
```

In summary, for syslog:
- auth.log on Ubuntu and/or Debian will contain all authentication/authorization related events: as pkexec is actually executing commands as another user, most events will be logged here.
- secure.log on RedHat or CentOS based systems, as they use this log file instead of /var/log/auth.log. 

### Wait...if he gained root, the attacker can simply delete the auth.log file, journal file and all the other log files?

Indeed! this is why you should make sure that *auditd* is properly configured in all your Linux hosts. Root is supposed to be trusted, this can lead to some security operations headaches with privilege escalations. 
Anyway, deleting logs on its own is something you should already detect on Sentinel or with your EDR solution, as this already means something bad is going on. <br />
You could still look for bash history or similar files, but these will probably also be cleared by a clever attacker. 
You could also detect all changes to files in latest 120 minutes, using find command for instance, including logs deletion. 
But an attacker can also bypass this, quite easily by messing up with timestamping. 
Conclusion being, always send your log to an external system, and make sure auditd is properly configured.

You can also have other mitigations in place such as leveraging SELinux.
<br />
<br />
If none of the above helps in your case, and logging is not set properly in your environment, then the only alternative to detect such log deletion is more advanced forensics commands and tools, but this is not the idea to cover this here.

### A note on CVE-2022-0185: Kubescape vulnerability

Recently another critical vulnerability was disclosed, in Kubernetes environments. This vulnerability exploits a capability (basically giving more privileges to a container than what they normally should have), CAP_SYS_ADMIN, to gain node access on a Kubernetes cluster. It also allows to exploit a container in a different namespace. 
Most container runtime protection tools would detect and alert on the usage of this capability and this should be part of your best-practices to drop all capabilities in your container environments and leverage *seccomp* profiles.<br />
However, the above CVE, pwnkit, combined with this kubescape vulnerability allows to completely compromise a full Kubernetes cluster, so be vigilent. 

Defender for containers for instance would spot such runtime security issue. By the way, it would also spot deletion of command history file on your host.
All alerts which can be raised by Defender for containers can be found [here](https://docs.microsoft.com/en-us/azure/defender-for-cloud/alerts-reference#alerts-k8scluster). Full details on the product, [here](https://docs.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction?tabs=defender-for-container-arch-aks). <br />
Similarly in your CI/CD pipeline you should use DockerBench, Clair, Trivy or other similar tools to detect bad practices in container images or Kubernetes yaml deployment files. 



