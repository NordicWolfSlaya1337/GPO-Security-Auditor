#Requires -Version 5.0
#Requires -Modules GroupPolicy

Import-Module GroupPolicy -ErrorAction Stop

# Resolve paths and domain info
$scriptDir   = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$domain      = (Get-ADDomain).DNSRoot
$date        = Get-Date -Format 'dd-MM-yyyy'
$zipName     = "${domain}_GPOs_${date}.zip"
$zipPath     = Join-Path $scriptDir $zipName
$tempDir     = Join-Path $env:TEMP "GPOExport_$([guid]::NewGuid().ToString('N'))"

New-Item -Path $tempDir -ItemType Directory -Force | Out-Null

try {
    $allGPOs   = Get-GPO -All
    $csvRows   = [System.Collections.ArrayList]::new()

    foreach ($gpo in $allGPOs) {
        $displayName = $gpo.DisplayName
        Write-Host "Processing: $displayName"

        # Sanitize display name for filename
        $safeName = $displayName -replace '[\\/:*?"<>|]', '_'
        $xmlPath  = Join-Path $tempDir "$safeName.xml"

        # Export XML report
        Get-GPOReport -Guid $gpo.Id -ReportType XML -Path $xmlPath

        # Parse XML to extract OU links
        [xml]$xmlContent = [System.IO.File]::ReadAllText($xmlPath)
        $ns = New-Object System.Xml.XmlNamespaceManager($xmlContent.NameTable)
        $ns.AddNamespace('gpo', 'http://www.microsoft.com/GroupPolicy/Settings')

        $links = $xmlContent.SelectNodes('//gpo:LinksTo', $ns)

        if ($links -and $links.Count -gt 0) {
            foreach ($link in $links) {
                $ouPath      = $link.SOMPath
                $linkEnabled = $link.Enabled
                [void]$csvRows.Add([PSCustomObject]@{
                    GPOName     = $displayName
                    GPOStatus   = $gpo.GpoStatus.ToString()
                    LinkedOU    = $ouPath
                    LinkEnabled = $linkEnabled
                })
            }
        }
        else {
            # GPO with no links — still include in CSV
            [void]$csvRows.Add([PSCustomObject]@{
                GPOName     = $displayName
                GPOStatus   = $gpo.GpoStatus.ToString()
                LinkedOU    = ''
                LinkEnabled = ''
            })
        }
    }

    # Export CSV
    $csvPath = Join-Path $tempDir "GPO_OU_Links.csv"
    $csvRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

    # Remove existing zip if present
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

    # Create zip
    Compress-Archive -Path (Join-Path $tempDir '*') -DestinationPath $zipPath -Force

    Write-Host "`nExport complete: $zipPath"
    Write-Host "Total GPOs exported: $($allGPOs.Count)"
}
finally {
    # Cleanup temp folder
    if (Test-Path $tempDir) {
        Remove-Item $tempDir -Recurse -Force
    }
}

# SIG # Begin signature block
# MIIcKAYJKoZIhvcNAQcCoIIcGTCCHBUCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCCIHebaEKRa8cJI
# 7B6eLDAW1Nei+ELb0EwU/5/yO+h2BKCCFmQwggMmMIICDqADAgECAhBhzDPyrAdk
# nEOhrApmDYjrMA0GCSqGSIb3DQEBCwUAMCoxKDAmBgNVBAMMH05vcmRpY1dvbGZT
# bGF5YSBha2EgQmVuamkgRW5kZXIwIBcNMjYwMjAyMTQzNzE1WhgPMzAyNTAyMDIx
# NDQ3MTZaMCoxKDAmBgNVBAMMH05vcmRpY1dvbGZTbGF5YSBha2EgQmVuamkgRW5k
# ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDKywZ4B1Trle+EcWK4
# 8Q2j3YJIUU+Q3kJIBjbKMvtBwPPIWVEeENmnfWRQ4ZEpTor8hhSqpv8gRi6yGZNw
# 5KR25KrolQiQ8LAnt6ufmKtrf7jo2dkXKtLFJynOQ7w+wjkiPbn6OA2tvTnAGVcM
# ARlQs6TWh5uw/VbghCaQglBPMWp/woGjayUTJSkLoHCVx3VZtn9xPN6NbIYbtsOT
# A6CcgdLhuGI9yDGfmiPs8O/iYvxRft3X07KcXjLGx+a2NMDiSQ1/jooilA7w9hVQ
# cK6+9lhQEqKOFami4Np6eL5GwDWoybCP5eCALE3cYxW59xQR5esQmi+1h8Smg5W2
# OxLZAgMBAAGjRjBEMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcD
# AzAdBgNVHQ4EFgQU2rtOzGKp98OOnKe40OuR1KrrnFIwDQYJKoZIhvcNAQELBQAD
# ggEBAHbhHmrDsWFNQBp4k5OZ6ctgESr29B9SDb/ijGyxEqh873ItdsCg/nszC3vO
# 8aqsdEm0fi5UW2g/Gj33YNObEpl5QMHUf/PTXTns5e7QxHyQwWGKTKkaaptbMjcn
# AcnNWaZLe+fhpDIloXw8DCAwyMAilGNkToVZFfdKzEI/Z7W5I69yerP533MCUyYn
# 1yasZXGl2KwGfBRDjjt/h8ZAHTA6L4OeCz8x88YOOoFDehzHuLpHodDYxGDvc8L9
# dB8TB8X6/142Lh8H0j4f+SnSF/Gi74PTAdoUtGef8eQz0kZ0blhstGml9cbJGxkH
# ugd/AOpa10gd/9sRMPE9+3Fm+nwwggWNMIIEdaADAgECAhAOmxiO+dAt5+/bUOII
# QBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdp
# Q2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xJDAiBgNVBAMTG0Rp
# Z2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEwMDAwMDBaFw0zMTEx
# MDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMx
# GTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRy
# dXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/m
# kHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprNrnsbhA3EMB/zG6Q4
# FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVyr2iTcMKyunWZanMy
# lNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4IWGbNOsFxl7sWxq8
# 68nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13jrclPXuU15zHL2pNe
# 3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4QkXCrVYJBMtfbBHMq
# bpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQnvKFPObURWBf3JFxG
# j2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu5tTvkpI6nj3cAORF
# JYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/8tWMcCxBYKqxYxhE
# lRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQpJYls5Q5SUUd0vias
# tkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFfxCBRa2+xq4aLT8LW
# RV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGjggE6MIIBNjAPBgNV
# HRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/57qYrhwPTzAfBgNV
# HSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8BAf8EBAMCAYYweQYI
# KwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j
# b20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6oDigNoY0aHR0cDov
# L2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDAR
# BgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEBAHCgv0NcVec4X6Cj
# dBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0aFPQTSnovLbc47/T/
# gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNEm0Mh65ZyoUi0mcud
# T6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZqaVSwuKFWjuyk1T3o
# sdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCsWKAOQGPFmCLBsln1
# VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9FcrBjDTZ9ztwGpn1eq
# XijiuZQwgga0MIIEnKADAgECAhANx6xXBf8hmS5AQyIMOkmGMA0GCSqGSIb3DQEB
# CwUAMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNV
# BAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMTGERpZ2lDZXJ0IFRydXN0ZWQg
# Um9vdCBHNDAeFw0yNTA1MDcwMDAwMDBaFw0zODAxMTQyMzU5NTlaMGkxCzAJBgNV
# BAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGlnaUNl
# cnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAyNSBD
# QTEwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC0eDHTCphBcr48RsAc
# rHXbo0ZodLRRF51NrY0NlLWZloMsVO1DahGPNRcybEKq+RuwOnPhof6pvF4uGjwj
# qNjfEvUi6wuim5bap+0lgloM2zX4kftn5B1IpYzTqpyFQ/4Bt0mAxAHeHYNnQxqX
# mRinvuNgxVBdJkf77S2uPoCj7GH8BLuxBG5AvftBdsOECS1UkxBvMgEdgkFiDNYi
# OTx4OtiFcMSkqTtF2hfQz3zQSku2Ws3IfDReb6e3mmdglTcaarps0wjUjsZvkgFk
# riK9tUKJm/s80FiocSk1VYLZlDwFt+cVFBURJg6zMUjZa/zbCclF83bRVFLeGkuA
# hHiGPMvSGmhgaTzVyhYn4p0+8y9oHRaQT/aofEnS5xLrfxnGpTXiUOeSLsJygoLP
# p66bkDX1ZlAeSpQl92QOMeRxykvq6gbylsXQskBBBnGy3tW/AMOMCZIVNSaz7BX8
# VtYGqLt9MmeOreGPRdtBx3yGOP+rx3rKWDEJlIqLXvJWnY0v5ydPpOjL6s36czwz
# sucuoKs7Yk/ehb//Wx+5kMqIMRvUBDx6z1ev+7psNOdgJMoiwOrUG2ZdSoQbU2rM
# kpLiQ6bGRinZbI4OLu9BMIFm1UUl9VnePs6BaaeEWvjJSjNm2qA+sdFUeEY0qVjP
# KOWug/G6X5uAiynM7Bu2ayBjUwIDAQABo4IBXTCCAVkwEgYDVR0TAQH/BAgwBgEB
# /wIBADAdBgNVHQ4EFgQU729TSunkBnx6yuKQVvYv1Ensy04wHwYDVR0jBBgwFoAU
# 7NfjgtJxXWRM3y5nP+e6mK4cD08wDgYDVR0PAQH/BAQDAgGGMBMGA1UdJQQMMAoG
# CCsGAQUFBwMIMHcGCCsGAQUFBwEBBGswaTAkBggrBgEFBQcwAYYYaHR0cDovL29j
# c3AuZGlnaWNlcnQuY29tMEEGCCsGAQUFBzAChjVodHRwOi8vY2FjZXJ0cy5kaWdp
# Y2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9vdEc0LmNydDBDBgNVHR8EPDA6MDig
# NqA0hjJodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkUm9v
# dEc0LmNybDAgBgNVHSAEGTAXMAgGBmeBDAEEAjALBglghkgBhv1sBwEwDQYJKoZI
# hvcNAQELBQADggIBABfO+xaAHP4HPRF2cTC9vgvItTSmf83Qh8WIGjB/T8ObXAZz
# 8OjuhUxjaaFdleMM0lBryPTQM2qEJPe36zwbSI/mS83afsl3YTj+IQhQE7jU/kXj
# jytJgnn0hvrV6hqWGd3rLAUt6vJy9lMDPjTLxLgXf9r5nWMQwr8Myb9rEVKChHyf
# pzee5kH0F8HABBgr0UdqirZ7bowe9Vj2AIMD8liyrukZ2iA/wdG2th9y1IsA0QF8
# dTXqvcnTmpfeQh35k5zOCPmSNq1UH410ANVko43+Cdmu4y81hjajV/gxdEkMx1NK
# U4uHQcKfZxAvBAKqMVuqte69M9J6A47OvgRaPs+2ykgcGV00TYr2Lr3ty9qIijan
# rUR3anzEwlvzZiiyfTPjLbnFRsjsYg39OlV8cipDoq7+qNNjqFzeGxcytL5TTLL4
# ZaoBdqbhOhZ3ZRDUphPvSRmMThi0vw9vODRzW6AxnJll38F0cuJG7uEBYTptMSbh
# dhGQDpOXgpIUsWTjd6xpR6oaQf/DJbg3s6KCLPAlZ66RzIg9sC+NJpud/v4+7RWs
# WCiKi9EOLLHfMR2ZyJ/+xhCx9yHbxtl5TPau1j/1MIDpMPx0LckTetiSuEtQvLsN
# z3Qbp7wGWqbIiOWCnb5WqxL3/BAPvIXKUjPSxyZsq8WhbaM2tszWkPZPubdcMIIG
# 7TCCBNWgAwIBAgIQCoDvGEuN8QWC0cR2p5V0aDANBgkqhkiG9w0BAQsFADBpMQsw
# CQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERp
# Z2lDZXJ0IFRydXN0ZWQgRzQgVGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIw
# MjUgQ0ExMB4XDTI1MDYwNDAwMDAwMFoXDTM2MDkwMzIzNTk1OVowYzELMAkGA1UE
# BhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2Vy
# dCBTSEEyNTYgUlNBNDA5NiBUaW1lc3RhbXAgUmVzcG9uZGVyIDIwMjUgMTCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANBGrC0Sxp7Q6q5gVrMrV7pvUf+G
# cAoB38o3zBlCMGMyqJnfFNZx+wvA69HFTBdwbHwBSOeLpvPnZ8ZN+vo8dE2/pPvO
# x/Vj8TchTySA2R4QKpVD7dvNZh6wW2R6kSu9RJt/4QhguSssp3qome7MrxVyfQO9
# sMx6ZAWjFDYOzDi8SOhPUWlLnh00Cll8pjrUcCV3K3E0zz09ldQ//nBZZREr4h/G
# I6Dxb2UoyrN0ijtUDVHRXdmncOOMA3CoB/iUSROUINDT98oksouTMYFOnHoRh6+8
# 6Ltc5zjPKHW5KqCvpSduSwhwUmotuQhcg9tw2YD3w6ySSSu+3qU8DD+nigNJFmt6
# LAHvH3KSuNLoZLc1Hf2JNMVL4Q1OpbybpMe46YceNA0LfNsnqcnpJeItK/DhKbPx
# TTuGoX7wJNdoRORVbPR1VVnDuSeHVZlc4seAO+6d2sC26/PQPdP51ho1zBp+xUIZ
# kpSFA8vWdoUoHLWnqWU3dCCyFG1roSrgHjSHlq8xymLnjCbSLZ49kPmk8iyyizND
# IXj//cOgrY7rlRyTlaCCfw7aSUROwnu7zER6EaJ+AliL7ojTdS5PWPsWeupWs7Np
# ChUk555K096V1hE0yZIXe+giAwW00aHzrDchIc2bQhpp0IoKRR7YufAkprxMiXAJ
# Q1XCmnCfgPf8+3mnAgMBAAGjggGVMIIBkTAMBgNVHRMBAf8EAjAAMB0GA1UdDgQW
# BBTkO/zyMe39/dfzkXFjGVBDz2GM6DAfBgNVHSMEGDAWgBTvb1NK6eQGfHrK4pBW
# 9i/USezLTjAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgw
# gZUGCCsGAQUFBwEBBIGIMIGFMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdp
# Y2VydC5jb20wXQYIKwYBBQUHMAKGUWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNv
# bS9EaWdpQ2VydFRydXN0ZWRHNFRpbWVTdGFtcGluZ1JTQTQwOTZTSEEyNTYyMDI1
# Q0ExLmNydDBfBgNVHR8EWDBWMFSgUqBQhk5odHRwOi8vY3JsMy5kaWdpY2VydC5j
# b20vRGlnaUNlcnRUcnVzdGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAy
# NUNBMS5jcmwwIAYDVR0gBBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqG
# SIb3DQEBCwUAA4ICAQBlKq3xHCcEua5gQezRCESeY0ByIfjk9iJP2zWLpQq1b4UR
# GnwWBdEZD9gBq9fNaNmFj6Eh8/YmRDfxT7C0k8FUFqNh+tshgb4O6Lgjg8K8elC4
# +oWCqnU/ML9lFfim8/9yJmZSe2F8AQ/UdKFOtj7YMTmqPO9mzskgiC3QYIUP2S3H
# QvHG1FDu+WUqW4daIqToXFE/JQ/EABgfZXLWU0ziTN6R3ygQBHMUBaB5bdrPbF6M
# RYs03h4obEMnxYOX8VBRKe1uNnzQVTeLni2nHkX/QqvXnNb+YkDFkxUGtMTaiLR9
# wjxUxu2hECZpqyU1d0IbX6Wq8/gVutDojBIFeRlqAcuEVT0cKsb+zJNEsuEB7O7/
# cuvTQasnM9AWcIQfVjnzrvwiCZ85EE8LUkqRhoS3Y50OHgaY7T/lwd6UArb+BOVA
# kg2oOvol/DJgddJ35XTxfUlQ+8Hggt8l2Yv7roancJIFcbojBcxlRcGG0LIhp6Gv
# ReQGgMgYxQbV1S3CrWqZzBt1R9xJgKf47CdxVRd/ndUlQ05oxYy2zRWVFjF7mcr4
# C34Mj3ocCVccAvlKV9jEnstrniLvUxxVZE/rptb7IRE2lskKPIJgbaP5t2nGj/UL
# Li49xTcBZU8atufk+EMF/cWuiC7POGT75qaL6vdCvHlshtjdNXOCIUjsarfNZzGC
# BRowggUWAgEBMD4wKjEoMCYGA1UEAwwfTm9yZGljV29sZlNsYXlhIGFrYSBCZW5q
# aSBFbmRlcgIQYcwz8qwHZJxDoawKZg2I6zANBglghkgBZQMEAgEFAKCBhDAYBgor
# BgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJAzEMBgorBgEEAYI3AgEE
# MBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMC8GCSqGSIb3DQEJBDEiBCAF
# aQCa9mZE2g1SY7tkKo7oT3Pd4eJLHeJyGSdUYr6OMjANBgkqhkiG9w0BAQEFAASC
# AQBc8ZnbIHhbPKKiqHr7q1zrIwVT4IoVhJgfxJg/ajiWkK97dtpZwLFvIw5MvOYS
# NhgqB4453eDUxuwWHakTlMkpKksvp3H3CmcEtBVvgA1PNj6t+54hme6QpM1Ne9HW
# CsSNpzjKMo5OkrriEIon83DPBwL1A4DRZhhpeGMGCCw5WwTIkHJbVhSrYgHH98vo
# QDkv0IGYDBuTQsFNvcIGqKURHlNsjYbllRLkXrg4XRv0Fst3Q8KkuyStvuRny5YW
# PpG/i7HWUHuuchBLOD8qKnr3HJeuudLNUb70VqBKudKclkPkImK+6X7u9WPruVv7
# RfoZAGBjUvEuL9YtkEa8VdNZoYIDJjCCAyIGCSqGSIb3DQEJBjGCAxMwggMPAgEB
# MH0waTELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYD
# VQQDEzhEaWdpQ2VydCBUcnVzdGVkIEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNI
# QTI1NiAyMDI1IENBMQIQCoDvGEuN8QWC0cR2p5V0aDANBglghkgBZQMEAgEFAKBp
# MBgGCSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI2MDMx
# OTA5NTkwOVowLwYJKoZIhvcNAQkEMSIEIAVbU+6OkzxB2SKq9FiLNO0YyvLuDHRo
# F2QmvtPaftQOMA0GCSqGSIb3DQEBAQUABIICAJoNeciWh5wKo9orBHFV5ompRsPH
# vVKbDs65LhKdbe1rE+XB4gPYcCGMTb5oNPk30Zlqs3kogg8qCh3Y51Vuc+0zaZAb
# yPF+9mneEM2IHIFEau3c8oTv+eFtYcTZO2+ibCMDjeSPKsRhVdPUKCFrHCaPibh4
# GxBG58PFqwNeQuLZ/STLUxRfCCeZ1KRo7mBZDQjfykyl5ajPYkPQkYEP5PP/T1kD
# HeNFxxWObyjdxyyhRx7K+izWYuDg2dY1V4/q/NN6RtfV+eEvMPuDwOY0gSMkUttT
# PD+Wj1Rs6AAlv66nveGho1a9lHIGntaGMy6YtG4amrqWXb07dC9x7vifaU+TNKw4
# iCO27vefrhWvlfEnrlDgihHVuA1bow+YN5pMSmbMTNqz/Jq7kkTHbBaQXRewq8Kc
# +6rE0IO3+Xe0n0cKxWeZ8QSKXtPQLAg3NVkNrK/Fq4XV5hpOuSVerpVKLQppdpYZ
# YldDqCks29iiJdq2yM0COU9s3nzhGuocLygp7RqAYRpFF5Oj7KdUwnMHPIpdLrX7
# HZjFf/JIltafezsxpzFU5Kq7D1mfqZa5UL2/IEgzVbTgxSztUyJiSAvadfGEm40o
# 8KcWuliGiHCncrhJvhyVOS/KklC9E4nN8O6ds5GwG+dnlFRyQkHL1ORBKs4rCbka
# KOqkYNHEoz6hSqdM
# SIG # End signature block
