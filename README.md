# NTDSPasswordChecker

Check if Active Directory passwords are reused and/or pwned using NTDS.dit file.

## Quick start guide

### Extracting NTDS.dit file

This script uses an offline copy of the NTDS.dit file, which means that you'll have to extract it from a domain controller using `ntdsutils.exe` with a domain admin account:

```plaintext
C:\> ntdsutils.exe
ntdsutil: activate instance ntds
ntdsutil: IFM
IFM: create full C:\temp\ntds
```

The "C:\temp" folder will now contains the following folders and files:

```plaintext
📁 ntds
  📁 Active Directory
    📄 ntds.dit
    📄 ntds.jfm
  📁 registry
    📄 SECURITY
    📄 SYSTEM
```

Please treat this NTDS folder with all the seriousness that it needs, since it contains a copy of your Active Directory environment (including passwords).

### Install DSInternals module

The script needs the [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) PowerShell module, which you can install this way:

```powershell
Install-Module DSInternals
```

### Run the script

You must run the script as administrator:

```powershell
.\script.ps1 -NTDSPath 'C:\temp\ntds'
```

## Output

### Results

DisplayName | SamAccountName | Prefix | Pwned | Duplicate | SamePwdAs
----------- | -------------- | ------ | ----- | --------- | ---------
Production Line 4 | pline4 | B862A | False | True | Production Line 5, Production Line 6
Production Line 5 | pline5 | B862A | False | True | Production Line 4, Production Line 6
Production Line 6 | pline6 | B862A | False | True | Production Line 4, Production Line 5
John Smith | jsmith | F56A0 | True | False |
Jane Doe | jdoe | 1A98E | False | True | Jane Doe (ADMIN)
Jane Doe (ADMIN) | jdoe_admin | 1A98E | False | True | Jane Doe

Here's how to read the results:

Results | Description
------- | -----------
Pwned=True | 🚩 Bad news! The hash is known and can be reversed
Pwned=False | ✔️ Good news! The hash isn't known and can't be reversed
Duplicate=True | 🚩 Bad news! Someone else is using the same password
Duplicate=False | ✔️ Good news! This user uses a password that is unique

## Legitimate questions

### How can the script knows when a password is reused on another account?

Pretty simple: the same string will always generate the same hash. For example, the NTLM hash for *p@ssw0rd* will always be *DE26CCE0356891A4A020E7C4957AFC72*. Knowing this, the script simply checks whether the hash appears more than once in the domain.

### Is it possible to audit password length with this script?

Nope we can't (and that's a good thing)! The hash of a 1-character password will be the same length as the hash of a 128-characters password.

### How does the script check if the password isn't safe then?

This script uses an [API from Have I Been Pwned?](https://haveibeenpwned.com/API#PwnedPasswords) to check if the NTLM hash as been exposed in previous data breaches. There is hundreds of millions of hashes available. If a NTML hash is found in this list, it means that the password isn't secure anymore.

### What do you means by "not secure anymore"?

It means that the NTML hash is known and if anyone get the hash, it will be able to retreive the clear-text password using a website like [hashes.com](https://hashes.com/en/decrypt/hash) for example.

### Wait, are you sending my NTML hash to some random website?

Sort of, but it isn't as bad as you think. The script send only the first five characters of the hash (which is about 15% of the total length) and then receive the list of all exposed hash that starts with those five characters.

For example, if I want to test the hash *DE26CCE0356891A4A020E7C4957AFC72*, I will send *DE26C* to the API and then receive a list of +800 hash to check.

### Is it possible to do this offline?

I haven't started working on this, but I don't think it can be done offline only using PowerShell. You can download the PwnedPasswords database using [PwnedPasswordsDownloader \| GitHub](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader) but I'm pretty sure PowerShell won't be able to parse a +1B row text file.

## Useful work

This script would probably doesn't exist without [PassTester by Elymaro \| GitHub](https://github.com/Elymaro/PassTester) so go check it out. 👍
