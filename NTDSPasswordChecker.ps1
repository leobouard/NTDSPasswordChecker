#Requires -RunAsAdministrator
#Requires -Version 5.1
#Requires -Modules @{ModuleName='DSInternals';ModuleVersion='4.14'}

[CmdletBinding(DefaultParameterSetName = 'All')]
param(
    [Parameter(Mandatory)]
    [System.IO.DirectoryInfo]$NTDSPath,

    [string]$SearchBase,

    [Parameter(ParameterSetName = 'All')]
    [switch]$All,

    [Parameter(ParameterSetName = 'Select')]
    [Parameter(ParameterSetName = 'Pwned')]
    [switch]$Pwned,

    [Parameter(ParameterSetName = 'Pwned')]
    [switch]$FindPlainTextPwd,

    [Parameter(ParameterSetName = 'Select')]
    [switch]$PwdResetAbuse,

    [Parameter(ParameterSetName = 'Select')]
    [switch]$Duplicate,

    [System.IO.DirectoryInfo]$LogPath = "$PSScriptRoot\logs",

    [System.IO.DirectoryInfo]$OutputPath = "$PSScriptRoot\output"
)

# Create logs & output folders if needed
'LogPath', 'OutputPath' | ForEach-Object {
    if (!(Test-Path -Path (Get-Variable $_ -ValueOnly).FullName -PathType Container)) {
        $null = New-Item -Path (Get-Variable $_ -ValueOnly).FullName -ItemType Directory
    }
}

# Start transcript
Start-Transcript -Path "$LogPath\NTDSPasswordChecker_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').log"

# Import module
Import-Module "$PSScriptRoot\NTDSPasswordChecker.psm1"

# Extracting NTDS base
Write-Host "Extracting all accounts from NTDS base at path '$NTDSPath'"
$bootkey = Get-BootKey -SystemHiveFilePath "$NTDSPath\registry\SYSTEM"
$addbaccounts = Get-ADDBAccount -All -BootKey $bootkey -DatabasePath "$NTDSPath\Active Directory\ntds.dit"

# Create a simple PSObject
$users = Format-ADDBAccount -ADDBAccounts $addbaccounts -SearchBase $SearchBase
$userCount = ($users | Measure-Object).Count
Write-Host "Users count: $userCount"

# Duplicate passwords
if ($All.IsPresent -or $Duplicate.IsPresent) {

    # Add new properties
    $users | Add-Member -MemberType NoteProperty -Name 'Duplicate' -Value $false
    $users | Add-Member -MemberType NoteProperty -Name 'DuplicateCount' -Value 0
    $users | Add-Member -MemberType NoteProperty -Name 'SamePwdAs' -Value @()

    # Find unique and non-unique hash
    $nonUniqueNTHash = Find-NonUniqueNTHash -NTHash $users.NTHash

    # Update properties
    $users | Where-Object { $_.NTHash -in $nonUniqueNTHash } | ForEach-Object {
        Write-Progress -Activity 'Update information about non-unique hash' -Status "Processing: $($_.SamAccountName)"
        $nthash = $_.NTHash
        $dn = $_.DistinguishedName
        $samePwdAs = $users.GetEnumerator().Where({ $_.NTHash -eq $nthash -and $_.DistinguishedName -ne $dn })
        $_.Duplicate = $true
        $_.DuplicateCount = ($samePwdAs | Measure-Object).Count
        $_.SamePwdAs += $samePwdAs | Select-Object DisplayName, SamAccountName, DistinguishedName
    }

    # Show results
    $duplicateCount = ($users | Where-Object { $_.Duplicate -eq $true } | Measure-Object).Count
    Write-Host "$duplicateCount accounts are using a non-unique password [$([Math]::Round(($duplicateCount/$userCount*100),2))%]"

    # Display the most common hash
    $groupByNTHash = $users | Where-Object { $_.Duplicate -eq $true } | Group-Object Prefix | Sort-Object Count -Descending
    Write-Host "List of the most common hash:"
    $groupByNTHash | Select-Object -First 10 -Property Count, Name, @{N = 'DisplayName'; E = { $_.Group.DisplayName } } | Format-Table -AutoSize
    
    # Display if administrators uses a non-unique password
    $adminWithNonUniqueNTHash = $users | Where-Object { $_.Duplicate -eq $true -and $_.IsAdministrator -eq $true }
    Write-Host "List of administrators with a non-unique password:"
    $adminWithNonUniqueNTHash | Select-Object DisplayName, Prefix, @{N = 'SamePasswordAs'; E = { $_.SamePwdAs.DisplayName } } | Format-Table -AutoSize

    # Export results to CSV
}

# Password reset abuse
if ($All.IsPresent -or $PwdResetAbuse.IsPresent) {

    # Add new properties
    $users | Add-Member -MemberType NoteProperty -Name 'PwdResetAbuse' -Value 0
    $users | Add-Member -MemberType NoteProperty -Name 'PrefixHistory' -Value $null

    # Update properties
    $users | Where-Object { ($_.NTHashHistory | Measure-Object).Count -ne ($_.NTHashHistory | Sort-Object -Unique | Measure-Object).Count } | ForEach-Object {
        $ntHashHistoryCount = ($_.NTHashHistory | Measure-Object).Count
        $ntHashHistoryUniqueCount = ($_.NTHashHistory | Sort-Object -Unique | Measure-Object).Count
        $_.PwdResetAbuse = [math]::Round(($ntHashHistoryCount - $ntHashHistoryUniqueCount) / $ntHashHistoryCount, 2)
        $_.PrefixHistory = $_.NTHashHistory | ForEach-Object { $_.SubString(0, 5) }
    }
    
    # Display accounts with the most PwdResetAbuse
    Write-Host "List of the users with the most password reset abuse:"
    $users | Sort-Object PwdResetAbuse -Descending | Select-Object -First 10 | Format-Table DisplayName, PrefixHistory, PwdResetAbuse -AutoSize

    # Display administrators with PwdResetAbuse
    Write-Host "List of the administrators with password reset abuse:"
    $users | Where-Object { $_.IsAdministrator -eq $true -and $_.PwdResetAbuse -gt 0 } | Sort-Object PwdResetAbuse -Descending | Format-Table DisplayName, PrefixHistory, PwdResetAbuse -AutoSize

    # Export results to CSV
}

# Pwned passwords
if ($All.IsPresent -or $Pwned.IsPresent) {

    # Add new properties
    $users | Add-Member -MemberType NoteProperty -Name 'Pwned' -Value $false
    $users | Add-Member -MemberType NoteProperty -Name 'Exposure' -Value 0
    
    # Prepare progress bar
    $prefixes = $users.Prefix | Sort-Object -Unique
    $i = 1
    $total = ($prefixes | Measure-Object).Count
    Write-Host "$total NTLM hash prefix to check"

    # Process
    $prefixes | ForEach-Object {
        $prefix = $_
        # Update progress bar
        Write-Progress -Activity "Search hash on HaveIBeenPwned API" -Status "Prefix: $prefix" -PercentComplete ($i / $total * 100)
        $i++
    
        # Get pwned passwords
        $pwnedPasswords = Get-PwnedNTHashList -Prefix $Prefix
        
        # Check if users are concerned by a pwned password
        $users.GetEnumerator().Where({ $_.Prefix -eq $prefix -and $_.NTHash -in $pwnedPasswords.NTHash }) | ForEach-Object {
            $nthash = $_.NTHash
            $_.Pwned = $true
            $_.Exposure = ($pwnedPasswords | Where-Object { $_.NTHash -eq $nthash }).Exposure
        }
    }

    # Show results
    $pwnedCount = ($users | Where-Object { $_.Pwned -eq $true } | Measure-Object).Count
    Write-Host "$pwnedCount accounts are using a unsecure password [$([Math]::Round(($pwnedCount/$total*100),2))%]"
    Write-Host "List of accounts with pwned password:"
    $users | Where-Object { $_.Pwned -eq $true } | Select-Object DisplayName, Prefix, DistinguishedName | Sort-Object Prefix | Format-Table -AutoSize

    # Export results to CSV
}

# Plain text passwords
if ($Pwned.IsPresent -and $FindPlainTextPwd.IsPresent) {

    # Add new property
    $users | Add-Member -MemberType NoteProperty -Name 'PlainTextPwd' -Value ''

    # Get plain text password from API
    $plainTextPwd = Convert-NTHashToPlainTextPassword -NTHash ($users | Where-Object {$_.Pwned -eq $true}).NTHash

    # Add plain text password
    $plainTextPwd | Where-Object {$_.password} | ForEach-Object {
        $item = $_
        $users | Where-Object {$_.NTHash -eq $item.hash} | ForEach-Object {
            $_.PlainTextPwd = $item.password
        }
    }

    # Export results to CSV

}

Stop-Transcript