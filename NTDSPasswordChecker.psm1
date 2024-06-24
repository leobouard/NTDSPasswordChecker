function Format-ADDBAccount {
    param(
        [System.Object[]]$ADDBAccounts,
        [string]$SearchBase
    )

    if ($SearchBase) {
        Write-Host "Reducing results to the searchbase '$SearchBase'"
        $addbaccounts = $addbaccounts | Where-Object { $_.DistinguishedName -like "*$SearchBase" }
    }

    $addbaccounts | Where-Object { $_.NTHash -and $_.SamAccountType -eq 'user' -and $_.Enabled -eq $true } | Sort-Object NTHash | ForEach-Object {
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
}

function Find-NonUniqueNTHash {
    param([string[]]$NTHash)

    Write-Host "Searching for hash that appears more than once in the current searchbase"
    $uniqueNTHash = $NTHash | Sort-Object -Unique
    Write-Host "$(($uniqueNTHash | Measure-Object).Count) unique hash found!"
    $nonUniqueNTHash = (Compare-Object -ReferenceObject $uniqueNTHash -DifferenceObject $NTHash).InputObject | Sort-Object -Unique
    Write-Host "$(($nonUniqueNTHash | Measure-Object).Count) non-unique hash found!"

    $nonUniqueNTHash
}

function New-NTHashPrefix {
    param(
        [int]$Decimal = (Get-Random -Minimum 0 -Maximum 1048576),
        [ValidateRange(5, 8)][int]$PrefixLength = 5
    )

    $hex = ([System.BitConverter]::GetBytes($Decimal) | ConvertTo-Hex -UpperCase) -join ''
    $hex.Substring(0, $PrefixLength)
}

function Convert-NTHashToPlainTextPassword {
    param(
        [string[]]$NTHash,
        [ValidateRange(16, 32)][int]$PrefixLength = 16
    )

    $skip = 0
    $count = ($NTHash | Measure-Object).Count

    do {
        $body = [PSCustomObject]@{
            hashes = $NTHash | Select-Object -First 500 -Skip $skip | ForEach-Object {
                $_.Substring(0, $PrefixLength)
            }
        } | ConvertTo-Json
        $uri = 'https://ntlm.pw/api/lookup?hashtype=nt'
        (Invoke-RestMethod -Method POST -Uri $uri -Body $body -ContentType 'application/json').results
        $skip = $skip + 500
    } until ($skip -ge $count)
}

function Get-PwnedNTHashList {
    param([string]$Prefix)

    $pwnedPasswords = Invoke-RestMethod -Method GET -Uri "https://api.pwnedpasswords.com/range/$Prefix`?mode=ntlm"
    $pwnedPasswords -split "`n" | ForEach-Object {
        [PSCustomObject]@{
            NTHash   = [string]($Prefix + ($_ -split ':')[0])
            Exposure = [int](($_ -split ':')[-1])
        }
    }
}

function Start-Cooldown {
    param(
        [int]$Minutes = 15,
        [string]$Activity = 'Waiting for https://ntlm.pw/ quota to cooldown'
    )

    $total = $Minutes*60
    1..$total | ForEach-Object {
        Write-Progress -Activity $Activity -PercentComplete ($_/$total*100) -SecondsRemaining ($total-$_)
        Start-Sleep -Seconds 1
    }
}