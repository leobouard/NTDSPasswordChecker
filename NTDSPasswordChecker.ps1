#Requires -Version 5.1
#Requires -Modules @{ModuleName='DSInternals';ModuleVersion='4.14'}

param(
    [Parameter(Mandatory)][System.IO.DirectoryInfo]$NTDSPath,
    [string]$SearchBase,
    [switch]$SkipPwned,
    [switch]$SkipDuplicates
)

# Extracting NTDS base
$bootkey = Get-BootKey -SystemHiveFilePath "$NTDSPath\registry\SYSTEM"
$addbaccounts = Get-ADDBAccount -All -BootKey $bootkey -DatabasePath "$NTDSPath\Active Directory\ntds.dit"

# Reducing results to a searchbase
if ($SearchBase) { $addbaccounts = $addbaccounts | Where-Object { $_.DistinguishedName -like "*$SearchBase" } }

# Create a simple PSObject
$users = $addbaccounts | Where-Object { $_.NTHash -and $_.SamAccountType -eq 'user' -and $_.Enabled -eq $true } | Sort-Object NTHash | ForEach-Object {
    $nthash = (($_.NTHash | ConvertTo-Hex) -join '').ToUpper()
    [PSCustomObject]@{
        DisplayName       = $_.DisplayName
        SamAccountName    = $_.SamAccountName
        DistinguishedName = $_.DistinguishedName
        NTHash            = $nthash
        Prefix            = $nthash.Substring(0, 5)
        Pwned             = $false
        Duplicate         = $false
        SamePwdAs         = @()
    }
}

# Search for duplicate passwords
if (!$SkipDuplicates.IsPresent) {
    $uniqueNTHash = $users.NTHash | Sort-Object -Unique
    $nonUniqueNTHash = (Compare-Object -ReferenceObject $uniqueNTHash -DifferenceObject $users.NTHash).InputObject
    $users | Where-Object { $_.NTHash -in $nonUniqueNTHash } | ForEach-Object {
        $nthash = $_.NTHash
        $dn = $_.DistinguishedName
        $_.Duplicate = $true
        $_.SamePwdAs += ($users | Where-Object { $_.NTHash -eq $nthash -and $_.DistinguishedName -ne $dn }).DistinguishedName
    }
}

# Search for pwned passwords
if (!$SkipPwned.IsPresent) {

    # Prepare progress bar
    $prefixes = $users.Prefix | Sort-Object -Unique
    $i = 1
    $total = ($prefixes | Measure-Object).Count

    # Process
    $prefixes | ForEach-Object {
        $prefix = $_

        # Update progress bar
        $progressBar = @{
            Activity        = "Checking NTHash with prefix: $prefix"
            PercentComplete = ($i / $total) * 100
        }
        Write-Progress  @progressBar
        $i++
        
        # Get pwned passwords
        $pwnedPasswords = Invoke-RestMethod -Method GET -Uri "https://api.pwnedpasswords.com/range/$prefix`?mode=ntlm"
        $pwnedPasswords = $pwnedPasswords -split "`n" | ForEach-Object { $prefix + ($_ -split ':')[0] }
        
        # Check if users are concerned by a pwned password
        $users | Where-Object { $_.NTHash -in $pwnedPasswords } | ForEach-Object { $_.Pwned = $true }
    }
}

# Display results
$report = $users | Where-Object { $_.Pwned -eq $true -or $_.Duplicate -eq $true }
$properties = 'DisplayName', 'SamAccountName', 'Prefix'
if (!$SkipPwned.IsPresent) { $properties += 'Pwned' }
if (!$SkipDuplicates.IsPresent) { $properties += 'Duplicate', 'SamePwdAs' }
$report | Select-Object $properties | Format-Table -AutoSize
