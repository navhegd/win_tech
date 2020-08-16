#requires -Version 2

Param(
    [Parameter(HelpMessage = 'Enter a directory or file path')]     
    [ValidateScript({if ($_ -match '\\'){Test-Path $_}else{$True}})]
    [string]$path
)

$global:arr = @()
Get-ChildItem -Path $path -Recurse | ForEach-Object -Process {
    $path = $_.fullname.Replace("[", "`[").Replace("]", "`]")
    $acl = Get-Acl -LiteralPath $path
    $sid = $acl.access | Where-Object -FilterScript {
        $_.identityreference -match 'S-1-.*' -and !($_.isinherited)
    }
    if($sid)
    {
        $sid| ForEach-Object -Process {
            $co = [pscustomobject]@{
                Path       = $path
                RemovedSID = $_.identityreference
            }
            $co|Format-List
            $arr += $co
            $null = $acl.removeaccessrule($_)
        }
         Set-Acl -LiteralPath $path -AclObject $acl
    }
}
'- Report'
$arr|Format-Table -AutoSize

"`nPaths are stored in the $arr variable"