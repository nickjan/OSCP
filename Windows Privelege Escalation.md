# Windows Privilege Escalation: From Recon to Exploitation

This guide provides a step-by-step walkthrough of Windows privilege escalation, starting from initial reconnaissance to exploitation. It is designed to take you from beginner to advanced levels, with practical examples and explanations.

---

## Table of Contents

1. [Introduction](#introduction)
2. [Reconnaissance](#reconnaissance)
   - [Gather Basic Information](#gather-basic-information)
   - [Check Group Memberships](#check-group-memberships)
   - [Enumerate Users and Groups](#enumerate-users-and-groups)
   - [Check Operating System and Version](#check-operating-system-and-version)
   - [Network Information](#network-information)
   - [Installed Applications](#installed-applications)
   - [Running Processes](#running-processes)
   - [Scheduled Tasks](#scheduled-tasks)
   - [Check for Services](#check-for-services)
   - [Look for Sensitive Information](#look-for-sensitive-information)
3. [Common Vulnerabilities](#common-vulnerabilities)
   - [Misconfigured Services](#misconfigured-services)
   - [Weak Permissions](#weak-permissions)
   - [Unquoted Service Paths](#unquoted-service-paths)
   - [DLL Hijacking](#dll-hijacking)
4. [Exploitation Techniques](#exploitation-techniques)
   - [Token Impersonation](#token-impersonation)
   - [Service Exploitation](#service-exploitation)
   - [Registry Exploitation](#registry-exploitation)
   - [Pass the Hash](#pass-the-hash)
5. [Advanced Techniques](#advanced-techniques)
   - [Application-Based Vulnerabilities](#application-based-vulnerabilities)
   - [Windows Kernel Vulnerabilities](#windows-kernel-vulnerabilities)
   - [Abusing Windows Privileges](#abusing-windows-privileges)
   - [Named Pipes](#named-pipes)
   - [Access Control Mechanisms](#access-control-mechanisms)
6. [Tools of the Trade](#tools-of-the-trade)
   - [Metasploit](#metasploit)
   - [PowerSploit](#powersploit)
   - [Windows Exploit Suggester](#windows-exploit-suggester)
   - [Mimikatz](#mimikatz)
7. [Defense and Mitigation](#defense-and-mitigation)
   - [Best Practices](#best-practices)
   - [Monitoring and Logging](#monitoring-and-logging)
8. [Practice and Resources](#practice-and-resources)
   - [Vulnerable Machines](#vulnerable-machines)
   - [Further Reading](#further-reading)

---

## Introduction

Privilege escalation is the process of gaining higher levels of access on a system than what was originally granted. This is a critical skill in penetration testing, red teaming, and ethical hacking. On Windows systems, privilege escalation often involves exploiting misconfigurations, vulnerabilities, or weak permissions to gain administrative or SYSTEM-level access.

---

## Reconnaissance

The first step in privilege escalation is gathering information about the target system. This phase is called reconnaissance.

### Gather Basic Information

- **Command**: `whoami`
  - **Purpose**: Identify the current user and domain.
  - **Lookout**: Note the username and domain for context on group memberships and privileges.
  - **Example Output**:
    ```plaintext
    win-user
    ```

- **Command**: `hostname`
  - **Purpose**: Find the hostname of the machine.
  - **Lookout**: The hostname can indicate the machine's role (e.g., server, workstation).
  - **Example Output**:
    ```plaintext
    WIN-ABCD1234
    ```

### Check Group Memberships

- **Command**: `whoami /groups`
  - **Purpose**: List all groups the current user belongs to.
  - **Lookout**: Look for special privileges like `SeImpersonatePrivilege`.
  - **Example Output**:
    ```plaintext
    GROUP INFORMATION
    -----------------
    Everyone                               Well-known group
    BUILTIN\Users                          Alias
    ```

### Enumerate Users and Groups

- **Command**: `net user`
  - **Purpose**: List all user accounts on the system.
  - **Lookout**: Identify accounts with administrative privileges or known service accounts.
  - **Example Output**:
    ```plaintext
    User accounts for \\WIN-ABCD1234
    ---------------------------------
    Administrator            Guest                    win-user
    ```

- **Command**: `net localgroup`
  - **Purpose**: List all local groups.
  - **Lookout**: Check for groups like `Administrators`, `Backup Operators`, or custom groups with elevated privileges.
  - **Example Output**:
    ```plaintext
    Aliases for \\WIN-ABCD1234
    --------------------------
    *Administrators
    *Backup Operators
    *Users
    ```

### Check Operating System and Version

- **Command**: `systeminfo`
  - **Purpose**: Gather detailed information about the OS, including version and installed patches.
  - **Lookout**: Identify unpatched vulnerabilities.
  - **Example Output**:
    ```plaintext
    OS Name:                   Microsoft Windows 10 Pro
    OS Version:                10.0.19041 N/A Build 19041
    Hotfix(s):                 5 Hotfix(s) Installed.
    ```

### Network Information

- **Command**: `ipconfig /all`
  - **Purpose**: Display all network interfaces and their configurations.
  - **Lookout**: Look for unusual configurations or connections.
  - **Example Output**:
    ```plaintext
    Ethernet adapter Ethernet:
       Connection-specific DNS Suffix  . : localdomain
       IPv4 Address. . . . . . . . . . . : 192.168.1.100
       Subnet Mask . . . . . . . . . . . : 255.255.255.0
       Default Gateway . . . . . . . . . : 192.168.1.1
    ```

### Installed Applications

- **Command**: `wmic product get name,version`  
  OR  
  ```powershell
  Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
  Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

- **Purpose**: List installed applications and their versions.
- **Lookout**: Identify applications with known vulnerabilities.

---

## Running Processes

- **Command**: `tasklist`
  - **Purpose**: List all running processes.
  - **Lookout**: Look for processes running with elevated privileges or suspicious processes.
  - **Example Output**:
    ```plaintext
    Image Name                     PID Session Name        Session#    Mem Usage
    ========================= ======== ================ =========== ============
    System Idle Process              0 Services                   0          8 K
    System                           4 Services                   0        132 K
    ```

---

## Scheduled Tasks

- **Command**: `schtasks /query /fo LIST /v`
  - **Purpose**: List all scheduled tasks.
  - **Lookout**: Identify tasks that run with elevated privileges or execute commands as a different user.
  - **Example Output**:
    ```plaintext
    TaskName: \ExampleTask
    Next Run Time: 01/01/2025 12:00:00
    Status: Ready
    ```

---

## Check for Services

- **Command**: `sc query`
  - **Purpose**: List all services and their statuses.
  - **Lookout**: Look for services running as `LocalSystem` or `LocalService`.
  - **Example Output**:
    ```plaintext
    SERVICE_NAME: ExampleService
    DISPLAY_NAME: Example Service
    STATE       : RUNNING
    ```

---

## Look for Sensitive Information

- **Command**: `dir /s /b C:\*password*`
  - **Purpose**: Search for files containing sensitive information.
  - **Lookout**: Identify configuration files or documents containing passwords or credentials.
  - **Example Output**:
    ```plaintext
    C:\Program Files\ExampleApp\config\password.txt
    ```

---

## Common Vulnerabilities

### Misconfigured Services

- **Description**: Services running with excessive privileges or weak permissions can be exploited to execute arbitrary code.
- **Exploitation**:
  1. Identify the service using `sc query`.
  2. Replace the service binary with a malicious one.
  3. Restart the service to execute the payload.

### Weak Permissions

- **Description**: Files or directories with weak permissions can be modified by non-privileged users.
- **Exploitation**:
  1. Use `icacls` to check permissions.
  2. Replace the binary with a malicious one.
  3. Execute the binary to gain elevated privileges.

### Unquoted Service Paths

- **Description**: Services with unquoted paths can be exploited if a malicious executable is placed in a directory that is searched before the legitimate one.
- **Exploitation**:
  1. Identify unquoted service paths using `wmic service get name,pathname`.
  2. Place a malicious executable in the vulnerable directory.
  3. Restart the service to execute the payload.

### DLL Hijacking

- **Description**: Exploiting the way Windows searches for DLLs to load malicious code.
- **Exploitation**:
  1. Identify a vulnerable application using tools like `Process Monitor`.
  2. Place a malicious DLL in the target directory.
  3. Execute the application to load the malicious DLL.

---

## Exploitation Techniques

### Token Impersonation

- **Description**: Impersonating a token of a higher-privileged user to execute commands with their privileges.
- **Tool**: `incognito` in Metasploit.
- **Steps**:
  1. Use Metasploit to gain a shell on the target.
  2. Load the `incognito` module.
  3. List available tokens using `list_tokens -u`.
  4. Impersonate a token using `impersonate_token <token>`.

### Service Exploitation

- **Description**: Exploiting misconfigured services to gain higher privileges.
- **Steps**:
  1. Identify a vulnerable service using `sc query`.
  2. Modify the service binary path using `sc config <service> binPath= "<malicious path>"`.
  3. Restart the service using `sc start <service>`.

### Registry Exploitation

- **Description**: Exploiting weak registry permissions to execute code.
- **Steps**:
  1. Identify a vulnerable service using `reg query`.
  2. Modify the `ImagePath` to point to a malicious executable.
  3. Restart the service to execute the payload.

### Pass the Hash

- **Description**: Using a captured hash to authenticate as a user without needing the plaintext password.
- **Tool**: `Mimikatz`.
- **Steps**:
  1. Dump hashes using `Mimikatz` or `lsadump::sam`.
  2. Use the hash to authenticate using tools like `pth-winexe`.

---

## Advanced Techniques

### Application-Based Vulnerabilities

- Exploit vulnerabilities in applications running with administrative permissions.
- Example: Outdated or vulnerable software.

## Windows Kernel Vulnerabilities

- **Description**: Exploit kernel vulnerabilities to escalate privileges.
- **Caution**: Kernel exploits can crash systems.

---

## Abusing Windows Privileges

- **Description**: Exploit privileges like `SeImpersonatePrivilege`, `SeBackupPrivilege`, and `SeDebugPrivilege`.

---

## Named Pipes

- **Description**: Use named pipes for inter-process communication to impersonate privileged accounts.

---

## Access Control Mechanisms

- **Description**: Understand Security Identifiers (SIDs), access tokens, and User Account Control (UAC).

---

## Tools of the Trade

### Metasploit

- **Description**: A comprehensive framework for developing and executing exploit code.
- **Use Case**: Exploiting known vulnerabilities and post-exploitation activities.

### PowerSploit

- **Description**: A collection of PowerShell scripts for penetration testing.
- **Use Case**: Privilege escalation, reconnaissance, and persistence.

### Windows Exploit Suggester

- **Description**: A tool to suggest potential exploits based on system information.
- **Use Case**: Identifying potential vulnerabilities on a target system.

### Mimikatz

- **Description**: A tool to extract plaintext passwords, hashes, and Kerberos tickets from memory.
- **Use Case**: Pass the hash attacks and credential dumping.

---

## Defense and Mitigation

### Best Practices

- **Principle of Least Privilege**: Ensure users and services run with the minimum necessary privileges.
- **Regular Patching**: Keep systems and software up to date with the latest security patches.
- **Strong Password Policies**: Enforce complex passwords and regular changes.

### Monitoring and Logging

- **Enable Auditing**: Monitor and log access to sensitive files and directories.
- **SIEM Solutions**: Use Security Information and Event Management (SIEM) tools to detect suspicious activities.

---

## Practice and Resources

### Vulnerable Machines

- **VulnHub**: Offers a variety of vulnerable virtual machines for practice.
- **Hack The Box**: An online platform with vulnerable machines and challenges.

### Further Reading

- **Books**: 
  - "Windows Internals" by Mark Russinovich.
  - "The Art of Exploitation" by Jon Erickson.
- **Online Courses**: 
  - Offensive Security's PEN-300.
  - SANS SEC560.
