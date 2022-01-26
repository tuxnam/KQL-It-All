## Hunt for PwnKit CVE with Sentinel

### Details on the CVE-2021-4034

All details about this vulnerability can be found here: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
This is not a *new* vulnerability, CVE registation dates back from late 2021 and the actual bug is 12 years old! A patch is available for most standard distributions. <br />
On 26th of January, Qualys researchers disclosed how it could lead to local Privilege Escalation, from any user to root, exploiting a vulnerability in *pkexec* command, from polkit, a SUID-root program allowing to run any program as another user, or root if no user is specificied (see [manual pages](https://linux.die.net/man/1/pkexec)).
The problem is that polkit is installed by default on every major Linux distribution.

### Is there an exploit availabe and how hard is it to exploit?

The exploit exists and can easily be found on the Internet. The idea here is to keep responsible disclosure in mind and not put any source. You can however consider any script kiddy out there will be able to (1) find it, (2) execute it as long as they have regular user access to a vulnerable OS.

### Is there a fix available?**

Yes a patch already exists for this CVE for most standard OS'es but not all of them. Patching is the best and recommended solution.
However a temporary mitigation exists, which at time of writing, seems to work: changing the permissions on the vulnerable binary, *pkexec*.<br />
Indeed, by default the exec has the SETUID bit set, which allows this privilege escalation to happen. Indeed SETUID allows to basically execute a program with the owner's privileges.  
The SETUID (4755) bit is set (or even the setuid + SETGID bits: 6755). If you change the permissions using for instance chmod 0755 (chmod a+rwx,g-w,o-w,ug-s,-t), it would set permissions so that, (U)ser / owner can read, can write and can execute. (G)roup can read, can't write and can execute. (O)thers can read, can't write and can execute, and SETUID bit is not set anymore on the binary. 
This means pkexec will probably not work at all anymore, so it might have adverse impact if it used by *legitimate* operators, however this is rarely used as such. And ok, there are priorities to be made here right?

### How to threat hunt for this using Sentinel?

**Note:** most modern EDR and vulnerability scanning solutions should be able to at least detect your system as being vulnerable. 

If you send audit logs to Sentinel, using syslog, the default connecotr for Linux logs in Sentinel, you can simply look for execution of the *pkexec* command by a non-root user (successful or not, in any case it is good to know). 
Details of successfull or unsucessfull *pkexec* commands will be located in *auth.log*, example:

```
*./auth.log:Jan 26 20:08:30 XXXX-Server polkitd(authority=local): Registered Authentication Agent for unix-process:4885:58817 (system bus name :1.31 [pkexec ls], object
 path /org/freedesktop/PolicyKit1/AuthenticationAgent, locale en_US.UTF-8)
./auth.log:Jan 26 20:08:36 XXXX-Server pkexec[4981]: tux: Error executing command as another user: Not authorized [USER=root] [TTY=/dev/pts/0] [CWD=/home/azureuser] [C
OMMAND=/usr/bin/ls]*
```

This is very straightforward query. This is not bullet-proof and will probably not detect all exploits out there, as well as bringing some false-positives but this is a good start:

```
Syslog
  | parse SyslogMessage with "type=" EventType " audit(" * "): " EventData
  | project TimeGenerated, EventType, Computer, EventData 
  | parse EventData with * "syscall=" syscall " syscall_r=" * " success=" success " exit=" exit " a0" * " ppid=" ppid " pid=" pid " audit_user=" audit_user " auid=" auid " user=" user " uid=" uid " group=" group " gid=" gid "effective_user=" effective_user " euid=" euid " set_user=" set_user " suid=" suid " filesystem_user=" filesystem_user " fsuid=" fsuid " effective_group=" effective_group " egid=" egid " set_group=" set_group " sgid=" sgid " filesystem_group=" filesystem_group " fsgid=" fsgid " tty=" tty " ses=" ses " comm=\"" comm "\" exe=\"" exe "\"" * "cwd=\"" cwd "\"" * "name=\"" name "\"" * "cmdline=\"" cmdline "\" containerid=" containerid
  // Find pkexec usage or exploit IoCs
  //| where uid != 0 and gid != 0
  | where cmdline contains "pkexec" or cmdline contains ("PKEXEC") or comm in ("pkexec","PKEXEC") or EventData contains "The value for SHELL variable" or comm contains "GCONV_PATH"
  // Find command lines featuring known crypto currency miner names
  | project TimeGenerated, Computer, audit_user, user, cmdline, comm, EventData
  | extend AccountCustomEntity = user, HostCustomEntity = Computer, timestamp = TimeGenerated
  | sort by TimeGenerated desc
```

### Wait...if he gained root, the attacker can simply delete the auth.log file, journal file and all the other log files?

Indeed! this is why you should make sure that auditd is properly set in all your Linux hosts. Root is supposed to be trusted, this can lead to some security operations headaches with privilege escalations. Anyway, deleting logs on its own is something you should already detect on Sentinel or with your EDR solution, as this already means something bad is going on. <br />
You could still look for bash history or similar files, but these will probably also be cleared by a cleever attacker. 
You could also detect all changes to files in latest 120 minutes, using find command for instance, including logs deletion. But an attacker can also bypass this, quite easily. Conclusion being, always send your log to an external system, and make sure auditd is properly configured.
You also have other mitigations in place such as leveraging SELinux.
<br />
<br />
If auditd is not set properly in your environment, then the only alternative to detect such log deletion is more advanced forensics commands and tools, but this is not the idea to cover this here.

### A note on CVE-2022-0185: Kubescape vulnerability

Recently another critical vulnerability was disclosed, in Kubernetes environments. This vulnerability basically exploits a capability (basically giving more privileges to a container than what they normally should have), CAP_SYS_ADMIN, to gain node access on a Kubernetes cluster. It also allows to exploit a container in a different namespace. 
Most container runtime protection tools would detect and alert on the usage of this capability and this should be part of your best-practices to drop all capabilities in your container environments. <br />
However, the above CVE, pwnkit, combined with this kubescape vulnerability allows to completely compromise a full Kubernetes cluster, so be vigilent. 

Defender for containers for instance would spot such runtime security issue. By the way, it would also spot deletion of command history file on your host.
All alerts which can be raised by Defender for containers can be found (here)[https://docs.microsoft.com/en-us/azure/defender-for-cloud/alerts-reference#alerts-k8scluster]. Full details on the product, (here)[https://docs.microsoft.com/en-us/azure/defender-for-cloud/defender-for-containers-introduction?tabs=defender-for-container-arch-aks]. <br />
Similarly in your CI/CD pipeline you should use DockerBench, Claire, Trivy or other similar tools to detect bad practices in container images or Kubernetes yaml deployment files. 



