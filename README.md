# NTDSPasswordChecker

Check if Active Directory passwords are reused or pwned within your domain using NTDS.dit file.

## How does it works?

### Extracting NTDS.dit file

This script uses an offline copy of the NTDS.dit file, which means that you'll have to extract it from a Domain Controller using `ntdsutils.exe`:

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

Please treat the "NTDS" folder with all the seriousness that it needs, since it contains a copy of your Active Directory environment (with all user passwords).

### Run the script

The script needs the [DSInternals](https://github.com/MichaelGrafnetter/DSInternals) PowerShell module, which you can install this way:

```powershell
Install-Module DSInternals
```

Then you can simply execute the script like this:

```powershell
.\script.ps1 -NTDSPath 'C:\temp\ntds'
```

### Results

DisplayName | SamAccountName | Prefix | Pwned | Duplicate | SamePwdAs
----------- | -------------- | ------ | ----- | --------- | ---------
Production Line 4 | pline4 | B862A | False | True | CN=Production Line 5,OU=Generic accounts,DC=domain,DC=com<br>CN=Production Line 6,OU=Generic accounts,DC=domain,DC=com
Production Line 5 | pline5 | B862A | False | True | CN=Production Line 4,OU=Generic accounts,DC=domain,DC=com<br>CN=Production Line 6,OU=Generic accounts,DC=domain,DC=com
Production Line 6 | pline6 | B862A | False | True | CN=Production Line 4,OU=Generic accounts,DC=domain,DC=com<br>CN=Production Line 5,OU=Generic accounts,DC=domain,DC=com
John Smith | jsmith | F56A0 | True | False |
Jane Doe | jdoe | 1A98E | False | True | CN=Jane Doe (ADMIN),OU=Administrators,DC=domain,DC=com
Jane Doe (ADMIN) | jdoe_admin | 1A98E | False | True | CN=Jane Doe,OU=Employees,DC=domain,DC=com

Here's how to read the results:

Results | Description
------- | -----------
Pwned=True | 🚩 Bad news! The hash has been found in data breaches and is vulnerable.
Pwned=False | ✔️ Good news! The hash has been found in known data breaches.
Duplicate=True | 🚩 Bad news! Someone else in this domain is using the same password.
Duplicate=False | ✔️ Good news! This user uses a password that is unique in the domain.

## Legitimate questions

### How can the script knows when a password is reused on another account?

Pretty simple: the same string will always generate the same hash. For example, the NTLM hash for *p@ssw0rd* will always be *DE26CCE0356891A4A020E7C4957AFC72*. Knowing this, the script simply checks whether the hash appears more than once in the domain.

### Is it possible to audit password length with this script?

Nope we can't (and that's a good thing)! The hash of a 1-character password will be the same length as the hash of a 128-characters password.

### How does the script check if the password isn't safe then?

This script uses an [API from Have I Been Pwned?](https://haveibeenpwned.com/API#PwnedPasswords) to check if the NTLM hash as been exposed in previous data breaches. There is hundreds of millions of hashes available. If a NTML hash is found in this list, it means that the password isn't secure anymore.

### What do you means by "not secure anymore"?

It means that the NTML hash is known and if anyone get the hash, it will be able to retreive the clear-text password using a website like [hashes.com](https://hashes.com/en/decrypt/hash) for example.

### Wait, are you sending NTML hash to some random website?

Sort of, but it isn't as bad as you think it is. The script send only the first five characters of the hash (which is about 15% of the total length) and then receive the list of all exposed hash that starts with those five characters.

For example, if I want to test the hash *DE26CCE0356891A4A020E7C4957AFC72*, I will send *DE26C* to the API and then receive a list of +800 hash to check.

### Is it possible to do this offline?

I haven't started working on this, but I don't think it can be done offline only using PowerShell. You can download the PwnedPasswords database using [PwnedPasswordsDownloader \| GitHub](https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader) but I'm pretty sure PowerShell won't be able to parse a +1B row text file.

## Useful work

This script would probably doesn't exist without [PassTester by Elymaro \| GitHub](https://github.com/Elymaro/PassTester) so go check it out. 👍
