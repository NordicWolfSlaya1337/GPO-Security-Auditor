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
        [xml]$xmlContent = Get-Content -Path $xmlPath -Encoding UTF8
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
