#Requires -RunAsAdministrator
#Requires -Version 5.1
#Requires -Modules @{ModuleName='DSInternals';ModuleVersion='4.14'}

[CmdletBinding(DefaultParameterSetName = 'Pwned')]
param(
    [Parameter(Mandatory)]
    [System.IO.DirectoryInfo]$NTDSPath,

    [string]$SearchBase,

    [Parameter(ParameterSetName = 'Pwned')]
    [switch]$SkipPwned,

    [Parameter(ParameterSetName = 'Duplicate')]
    [switch]$SkipDuplicate,

    [System.IO.DirectoryInfo]$LogPath = "$PSScriptRoot\logs",

    [System.IO.DirectoryInfo]$OutputPath = "$PSScriptRoot\output"
)

# Create logs & output folders if needed
'LogPath','OutputPath' | ForEach-Object {
    if (!(Test-Path -Path (Get-Variable $_ -ValueOnly).FullName -PathType Container)) {
        $null = New-Item -Path (Get-Variable $_ -ValueOnly).FullName -ItemType Directory
    }
}

# Start transcript
Start-Transcript -Path "$LogPath\NTDSPasswordChecker_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').log"

# Extracting NTDS base
Write-Host "Extracting all accounts from NTDS base at path '$NTDSPath'"
$bootkey = Get-BootKey -SystemHiveFilePath "$NTDSPath\registry\SYSTEM"
$addbaccounts = Get-ADDBAccount -All -BootKey $bootkey -DatabasePath "$NTDSPath\Active Directory\ntds.dit"

# Reducing results to a searchbase
if ($SearchBase) {
    Write-Host "Reducing results to the searchbase '$SearchBase'"
    $addbaccounts = $addbaccounts | Where-Object { $_.DistinguishedName -like "*$SearchBase" }
}

# Create a simple PSObject
$users = $addbaccounts | Where-Object { $_.NTHash -and $_.SamAccountType -eq 'user' -and $_.Enabled -eq $true } | Sort-Object NTHash | ForEach-Object {
    $nthash = ($_.NTHash | ConvertTo-Hex -UpperCase) -join ''
    [PSCustomObject]@{
        DisplayName       = $_.DisplayName
        SamAccountName    = $_.SamAccountName
        NTHash            = $nthash
        Prefix            = $nthash.Substring(0, 5)
        IsAdministrator   = $_.AdminCount
        DistinguishedName = $_.DistinguishedName
    }
}
$userCount = ($users | Measure-Object).Count
Write-Host "Users count: $userCount"

# Search for duplicate passwords
if (!$SkipDuplicate.IsPresent) {
    # Add new properties
    $users | Add-Member -MemberType NoteProperty -Name 'Duplicate' -Value $false
    $users | Add-Member -MemberType NoteProperty -Name 'SamePwdAs' -Value @()

    # Find unique and non-unique hash
    Write-Host "Searching for hash that appears more than once in the current searchbase"
    $uniqueNTHash = $users.NTHash | Sort-Object -Unique
    Write-Host "$(($uniqueNTHash | Measure-Object).Count) unique hash found!"
    $nonUniqueNTHash = (Compare-Object -ReferenceObject $uniqueNTHash -DifferenceObject $users.NTHash).InputObject
    Write-Host "$(($nonUniqueNTHash | Measure-Object).Count) non-unique hash found!"

    if ($nonUniqueNTHash -gt 0) {
        # Update the new properties
        $users | Where-Object { $_.NTHash -in $nonUniqueNTHash } | ForEach-Object {
            Write-Progress -Activity 'Update information about non-unique hash' -Status "Processing: $($_.SamAccountName)"
            $nthash = $_.NTHash
            $dn = $_.DistinguishedName
            $samePwdAs = $users.GetEnumerator().Where({ $_.NTHash -eq $nthash -and $_.DistinguishedName -ne $dn })
            $_.Duplicate = $true
            $_.SamePwdAs += $samePwdAs | Select-Object DisplayName, SamAccountName, DistinguishedName
        }

        # Show results
        $duplicateCount = ($users | Where-Object { $_.Duplicate -eq $true } | Measure-Object).Count
        Write-Host "$duplicateCount accounts are using a non-unique password [$([Math]::Round(($duplicateCount/$userCount*100),2))%]"

        # Display the most common hash
        $groupByNTHash = $users | Where-Object { $_.Duplicate -eq $true } | Group-Object Prefix | Sort-Object Count -Descending
        if ($groupByNTHash) {
            Write-Host "List of the most common hash:"
            $groupByNTHash | Select-Object -First 10 -Property Count, Name, @{N = 'DisplayName'; E = { $_.Group.DisplayName } } | Format-Table -AutoSize
        }
        
        # Display if administrators uses a non-unique password
        $adminWithNonUniqueNTHash = $users | Where-Object { $_.Duplicate -eq $true -and $_.IsAdministrator -eq $true }
        if ($adminWithNonUniqueNTHash) {
            Write-Host "List of administrators with a non-unique password:"
            $adminWithNonUniqueNTHash | Select-Object DisplayName, Prefix, @{N = 'SamePasswordAs'; E = { $_.SamePwdAs.DisplayName } } | Format-Table -AutoSize
        }
    }
    else {
        Write-Host "Good news! All password are unique" -ForegroundColor Green
    }
}

# Search for pwned passwords
if (!$SkipPwned.IsPresent) {
    # Add new property
    $users | Add-Member -MemberType NoteProperty -Name 'Pwned' -Value $false
    
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
        $pwnedPasswords = Invoke-RestMethod -Method GET -Uri "https://api.pwnedpasswords.com/range/$prefix`?mode=ntlm"
        $pwnedPasswords = $pwnedPasswords -split "`n" | ForEach-Object { $prefix + ($_ -split ':')[0] }
        
        # Check if users are concerned by a pwned password
        $users.GetEnumerator().Where({ $_.Prefix -eq $prefix -and $_.NTHash -in $pwnedPasswords }) | ForEach-Object { $_.Pwned = $true }
    }

    # Show results
    $pwnedCount = ($users | Where-Object { $_.Pwned -eq $true } | Measure-Object).Count
    if ($pwnedCount -gt 0) {
        Write-Host "$pwnedCount accounts are using a unsecure password [$([Math]::Round(($pwnedCount/$total*100),2))%]"
        Write-Host "List of accounts with pwned password:"
        $users | Where-Object {$_.Pwned -eq $true} | Select-Object DisplayName, Prefix, DistinguishedName | Sort-Object Prefix | Format-Table -AutoSize
    }
    else {
        Write-Host "Good news! None of the password are pwned" -ForegroundColor Green
    }
}

# Export CSV
$users | Select-Object *,@{N='SamePasswordAs';E={$_.SamePwdAs.DisplayName -join ', '}} -ExcludeProperty SamePwdAs,NTHash |
    Export-Csv -Path "$OutputPath\NTDSPasswordChecker_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').csv" -Delimiter ';' -Encoding UTF8 -NoTypeInformation

Stop-Transcripts