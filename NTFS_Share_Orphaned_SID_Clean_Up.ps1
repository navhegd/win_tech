#######################################################################
################### Variables #########################################
#######################################################################
$RootPath = "\\FOLDER\TO\SCAN"
$OldSID = "S-1-5-*" ## SIDS 
$ReportLocation = "\\LOCATION\FORLOG\"
$EmailFrom = "FolderRevocationReport@Domain.TLD"
$EmailTo = "SysAdmin@Domain.TLD"
$SMTPServer = "EMAIL.SMTP.RELAY"
#######################################################################
### Note: This script will recursively scan a folder and remove all ### 
### orphaned SID folder NTFS access left by AD account deletions ######
#######################################################################

$Date = Get-Date -format o
$Date = $Date -replace('/','--')
$Date = $Date -replace(':','-')
$FileName = -join("$Date","___RevokeSIDsFolderPermsLog.csv")
$TermLog = -join("$ReportLocation","$Filename") 
$blk = ".",".",".","."
[System.Collections.ArrayList]$EmailLog = $blk
$br="<br>"
$EmailLog.add("$br")
$EmailLog.add("$br")

Write-Progress -activity "Pre-load subfolders..."
Write-Host "Pre-Load subfolders..."
$SubFolders = Get-ChildItem -Path $RootPath -recurse -ev err -ea SilentlyContinue| ? {$_.psIscontainer -eq $true}

$ms = ''
$OldSIDACLAccess=''
$OldSIDACL=''
$AccessRule = ''
$i = 1
$j = 0

$RootFolder = Get-Item $RootPath
Write-Progress -activity "Startling trawl of: $RootFolder"
Write-Host "Startling trawl of: $RootFolder"
$OldSIDACLAccess = ($RootFolder | Get-Acl).Access | Where {$_.IdentityReference -like $OldSID} | Add-Member -MemberType NoteProperty -Name "Path" -Value $($RootFolder.fullname).ToString() -PassThru
if ($OldSIDACLAccess.IdentityReference -like $OldSID)
{
    $OldSIDACLAccess
    ForEach ($OldSIDs in $OldSIDACLAccess)
    {
        $OldSIDACL = Get-Acl $OldSIDs.Path
        $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule `
        ($OldSIDs.IdentityReference, $OldSIDs.FileSystemRights, $OldSIDs.InheritanceFlags, $OldSIDs.PropagationFlags, $OldSIDs.AccessControlType) 
        $OldSIDACL.RemoveAccessRuleAll($AccessRule)
        Set-Acl -Path $OldSIDs.Path -AclObject $OldSIDACL
        $Wiper = $OldSIDs.IdentityReference
        $MS = -join("Wiped: ","$Wiper"," from RootFolder:","$RootFolder")
        $MS | out-file $TermLog -Append 
        $EmailLog.add("$MS")  
        $EmailLog.add("$br")
        Write-Progress -activity "Wiped $Wiper from RootFolder: $RootFolder"
        Write-Host "Wiped $Wiper from RootFolder: $RootFolder"
    }
   
}

    if ($SubFolders -eq $null) {break}
        foreach ($SubFolder in $SubFolders)
        {
        $i++  
        $OldSIDACLAccess=''
        $OldSIDACL=''
        $AccessRule = ''
        $OldSIDACLAccess = ($SubFolder | Get-Acl).Access | Where {$_.IdentityReference -like $OldSID -and $_.IsInherited -eq $false } | Add-Member -MemberType NoteProperty -Name "Path" -Value $($SubFolder.fullname).ToString() -PassThru
        Write-Progress -activity "Checking: $Subfolder... " -status "Cleared: $i of $($SubFolders.Count) folders... Located: $j instances." -percentComplete (($i / $SubFolders.Count)  * 100)
            if ($OldSIDACLAccess.IdentityReference -like $OldSID)
            {
            $j++
             ForEach ($OldSIDs in $OldSIDACLAccess)
                {
                $OldSIDACL = Get-Acl $OldSIDs.Path
                $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule `
                ($OldSIDs.IdentityReference, $OldSIDs.FileSystemRights, $OldSIDs.InheritanceFlags, $OldSIDs.PropagationFlags, $OldSIDs.AccessControlType) 
  
                $OldSIDACL.RemoveAccessRuleAll($AccessRule)
                Set-Acl -Path $OldSIDs.Path -AclObject $OldSIDACL
                $Wiper = $OldSIDs.IdentityReference
                $Pathy = $OldSIDs.Path
                $MS = -join("Wiped: ","$Wiper"," from SubFolder:","$Pathy")
                $MS | out-file $TermLog -Append 
                $EmailLog.add("$MS")  
                $EmailLog.add("$br")
                Write-Progress -activity "Wiped $Wiper from SubFolder: $Pathy"
                Write-Host "Wiped $Wiper from SubFolder: $Pathy"
                }
            }
        } 
Send-MailMessage -from $EmailFrom -to $EmailTo -subject "Orphaned SIDs Revocation Log" -body "The following actions have been taken and logged.<br> Log: '$TermLog'  <font color='blue'><b><br> $EmailLog </b></font>" –BodyasHtml -SMTPServer $SMTPServer