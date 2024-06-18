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

    [Parameter(ParameterSetName = 'PwdResetAbuse')]
    [switch]$SkipPwdResetAbuse,

    [System.IO.DirectoryInfo]$LogPath = $PSScriptRoot,

    [System.IO.DirectoryInfo]$OutputPath = $PSScriptRoot
)

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
    $nthashHistory = if ($_.NTHashHistory) { $_.NTHashHistory | ForEach-Object { ($_ | ConvertTo-Hex -UpperCase) -join '' } } else { $null }
    [PSCustomObject]@{
        DisplayName       = $_.DisplayName
        SamAccountName    = $_.SamAccountName
        NTHash            = $nthash
        NTHashHistory     = $nthashHistory
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

        # Display the proportion
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

# Search for password reset abuse
if (!$SkipPwdResetAbuse.IsPresent) {
    $users | Add-Member -MemberType NoteProperty -Name 'PwdResetAbuse' -Value 0
    $users | Where-Object { ($_.NTHashHistory | Measure-Object).Count -ne ($_.NTHashHistory | Sort-Object -Unique | Measure-Object).Count } | ForEach-Object {
        $ntHashHistoryCount = ($_.NTHashHistory | Measure-Object).Count
        $ntHashHistoryUniqueCount = ($_.NTHashHistory | Sort-Object -Unique | Measure-Object).Count
        $_.PwdResetAbuse = $ntHashHistoryCount - $ntHashHistoryUniqueCount
    }

    # Display accounts with the most PwdResetAbuse
    Write-Host "List of the users with the most password reset abuse:"
    $users | Sort-Object PwdResetAbuse -Descending | Select-Object -First 5 | Format-Table DisplayName,
    @{Name = 'HistoryPrefix'; Expression = { $_.NTHashHistory | Sort-Object | ForEach-Object { $_.SubString(0, 5) } } }, PwdResetAbuse -AutoSize
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
}

# Export CSV
$users | Select-Object *, @{N = 'SamePasswordAs'; E = { $_.SamePwdAs.DisplayName -join ', ' } } -ExcludeProperty SamePwdAs, NTHash |
Export-Csv -Path "$logPath\NTDSPasswordChecker_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').csv" -Delimiter ';' -Encoding UTF8 -NoTypeInformation

Stop-Transcript