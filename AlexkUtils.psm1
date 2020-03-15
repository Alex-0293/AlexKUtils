﻿<#
 .Synopsis
  Generate new AES key file.

  .Description
  Generate new AES key file with key file path.

 .Parameter AESKeyFilePath
  Full path to file for generating new AES key file into.


 .Example
   Get-NewAESKey "d:\key1.aes"
#>
function Get-NewAESKey {
    [CmdletBinding()]
    param
    (
        [Parameter( Mandatory )]
        [string] $AESKeyFilePath
    )

    $AESKey = New-Object Byte[] 32
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($AESKey)
    $AESKey | out-file $AESKeyFilePath
}    
<#
 .Synopsis
  Get settings from file.

 .Description
  Load settings from file to hash table.

 .Parameter RootPath
  Full path to folder where the files are.

 
 .Example
   Get-SettingsFromFile  "d:\powershell"
#>
Function Get-SettingsFromFile {
    [CmdletBinding()]
    param
    (
        [Parameter( Mandatory )]
        [string] $RootPath
    )
    
    $Org = get-content ($RootPath + "\org.txt") -Encoding UTF8
    $ParamsFilePath = $RootPath + "\params-" + $ORG + ".xml"
    $Params = Import-Clixml $ParamsFilePath
    ReplaceVars $Params
    return $Params
}
Function ReplaceVars  {
    [CmdletBinding()]
    param
    (
        [Parameter( Mandatory )]
        $PSO
    )
    
    $NotePropertys = $PSO | get-member -type NoteProperty

    foreach ($item in $NotePropertys) {
        $Param = "%" + $Item.name + "%"
        $Value = $pso."$($item.name)"
        Foreach ($item1 in $NotePropertys) {
            if (($pso."$($item1.name)".gettype()).name -eq "String") {
                $pso."$($item1.name)" = ($pso."$($item1.name)").replace($Param, $Value)
            }
        }
    }

}
Function Get-VarFromFile {
    param
    (
        [string] $AESKeyFilePath,
        [string] $VarFilePath
    )
    
    if (!(test-path $AESKeyFilePath)) {
        write-host "AESKeyFilePath not exist" -ForegroundColor Red
        $AESKeyFilePathExist = $false 
    }
    else { $AESKeyFilePathExist = $true }
    if (!(test-path $VarFilePath)) {
        write-host "VarFilePath not exist" -ForegroundColor Red
        $VarFilePathExist = $false 
    } 
    else { $VarFilePathExist = $true }
     
    if ($VarFilePathExist -and $AESKeyFilePathExist) {
        $Var = Get-Content $VarFilePath | ConvertTo-SecureString -Key (get-content $AESKeyFilePath) 
        $Var = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Var)
        $Var = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($Var)
        return $Var
    }
    Else { return $null }   
}
Function Set-VarToFile {
    param
    (
        [string] $Var,
        [string] $AESKeyFilePath,
        [string] $VarFilePath
    )
    
    
    ConvertTo-SecureString $Var -AsPlainText | ConvertFrom-SecureString -Key (get-content $AESKeyFilePath) | Set-Content $VarFilePath
}
Function Add-ToLog {
    Param
    (
        [string] $Message,
        [string] $logFilePath,
        [string] $Mode = "Append"
    )

    $Date = Get-Date
    $Text = ($Date.ToString() + " " + $Message)
    switch ($Mode) {
        "Append" { Out-File -FilePath $logFilePath -Encoding utf8 -Append -Force -InputObject $Text }
        "Replace" { Out-File -FilePath $logFilePath -Encoding utf8 -Force -InputObject $Text }
        Default { }
    
    }

    # $Params = @{
    #     Token   = "1092680109:AAEoegeqtIBhKkQkyx_w4uRRu3eXr1cPEFc"
    #     ChatID  = "-283904757"
    #     Message = $Text
    #     Proxy   = ""
    # }
    # Send-TelegramMessage @Params
}
function Disconnect-VPN {
    Param
    (
        [string] $VPNConnectionName,
        [string] $logFilePath
    )    
    
    Add-ToLog "Try to disconnect VPN - $VPNConnectionName" $logFilePath
    $Res = & rasdial $VPNConnectionName /disconnect
    if ($Res -like "*success*") {
        Add-ToLog ($Res -like "*success*") $logFilePath
        return $true
    }
    else {
        Add-ToLog  $Res $logFilePath
        return $false
    }
}
Function Connect-VPN {
    Param
    (
        [string] $VPNConnectionName,
        [string] $logFilePath,
        [string] $Login,
        [string] $Pass
    )   
    Add-ToLog "Try to connect VPN - $VPNConnectionName under $Login" $logFilePath
    $Res = & rasdial $VPNConnectionName  $Login $Pass
    if (($Res -like "*success*") -or ($Res -like "*успешно*")) {
        Add-ToLog $Res $logFilePath
        #Add-ToLog $true $logFilePath
        return $true
    }
    else {
        Add-ToLog $Res $logFilePath
        #Add-ToLog $false $logFilePath
        return $false
    }
}
Function RebootSwitches {
    Param
    (
        [System.Array]$SwitchesIP,
        [string] $logFilePath,
        [string] $PLinkPath, 
        [string] $SshConString,
        [string] $SshCommand,
        [string] $Login = "",
        [string] $Pass = "",
        [string] $CertFilePath = ""
    ) 
    Foreach ($Item in $SwitchesIP) {
        $Ip = $Item.SwitchIp
        $Command = $SshCommand.Clone()
        $Command = $Command.Replace("%ip%", $Ip)

        if (("" -eq $Login) -and ("" -eq $Pass) -and ("" -ne $CertFilePath) -and ("" -ne $SshConString) -and ("" -ne $SshCommand)) {
            $Arguments = " -ssh -i """ + $CertFilePath + """ " + $SshConString + " -no-antispoof """ + $Command + """ -batch"
            #Add-ToLog "$Arguments" $logFilePath 
            Start-Process $PLinkPath -ArgumentList $Arguments -WindowStyle Hidden #-RedirectStandardOutput "C:\DATA\PROJECTS\RebootUnpingableClientSwitch\ssh-out.log" #
            Add-ToLog "Start switch reboot $Ip" $logFilePath 
        }
        elseif (("" -ne $Login) -and ("" -eq $CertFilePath) -and ("" -ne $SshConString) -and ("" -ne $SshCommand)) {
            $Arguments = " -ssh -l """ + $Login + """ -pw """ + $Pass + """ " + $SshConString + " -no-antispoof """ + $Command + """ -batch"
            Start-Process $PLinkPath -ArgumentList $Arguments -WindowStyle Hidden   #-RedirectStandardOutput "C:\DATA\PROJECTS\RebootUnpingableClientSwitch\ssh-out.log" #
            Add-ToLog "Start switch reboot $Ip" $logFilePath  
        } 
        switch ($Item.RebootOrder) {
            2 { Start-Sleep 10 }
            3 { Start-Sleep 10 }
            
        }
    }
}
<#
 .Synopsis
  Test hardware rebooting.

 .Description
  Test whether or not, hardware rebooting right now.

 .Parameter HardwareRebootStartTime
  Start time interval for rebooting.

 .Parameter HardwareRebootEndTime
  End time interval for rebooting.
 
  .Example
   IsHardwareRebooting "08:45" "9:00"
#>
Function IsHardwareRebooting {
    Param
    (
        [string] $HardwareRebootStartTime,
        [string] $HardwareRebootEndTime
    ) 
    $CHour = [int](Get-date -Format "%H")
    $CMin = [int](Get-date -Format "%m")
    $StartHour = [int]($HardwareRebootStartTime -split ":")[0]
    $StartMin = [int]($HardwareRebootStartTime -split ":")[1]
    $EndHour = [int]($HardwareRebootEndTime -split ":")[0]
    $EndMin = [int]($HardwareRebootEndTime -split ":")[1]
    if ($CHour -ge $StartHour -and $CHour -le $EndHour) {
        if ($CMin -ge $StartMin -and $CMin -le $EndMin) {
            return $True
        }
        else {
            return $false 
        }
    }
    else {
        return $false
    }
}
Function Get-EventList {
    param (
        [string] $LogFilePath,
        [string] $Event,
        [int32] $Interval = 0
    )
    $Res = @()
    $Log = Get-Content $LogFilePath -Encoding UTF8
    if ($interval -ne 0) {
        $FirstDate = (get-date).AddSeconds((-1 * $interval))
    }
    foreach ($Item in $log) {
        if ($event -ne "") {
            if ($item -like "*$event*") {
                if ($interval -eq 0) {
                    $Res += $item 
                }
                Else {
                    $ItemDate = get-date (($item -split " ")[0].Trim() + " " + ($item -split " ")[1].Trim())
                    if ($ItemDate -ge $FirstDate) {
                        $Res += $item
                    }
                }
            }
        }
        else {
            if ($interval -eq 0) {
                $Res += $item
            }
            Else {
                try {
                    $ItemDate = Get-Date (($item -split " ")[0].Trim() + " " + ($item -split " ")[1].Trim())
                    if ($ItemDate -ge $FirstDate) {
                        $Res += $item
                    }
                }
                Catch {}
            }
            
        }
    }
   
    return $Res
}
Function Send-Email {
    param (
        [string] $SmtpServer,
        [string] $Subject,
        [string] $Body,
        [bool]   $HtmlBody,
        [string] $User,
        [string] $Pass,
        [string] $From,
        [string] $To,
        [int16]  $Port                = 25,
        [bool]   $SSL                 = $True,
        [string] $Attachment          = "",
        [string] $AttachmentContentId = "",
        [int16]  $Cntr                = 100
    )
    
    $emailMessage              = New-Object System.Net.Mail.MailMessage
    $emailMessage.From         = $From
    $emailMessage.Subject      = $Subject
    $emailMessage.IsBodyHtml   = $HtmlBody
    $emailMessage.Body         = $Body
    $emailMessage.BodyEncoding = [System.Text.Encoding]::UTF8
    $emailMessage.To.add($To)
    
    if ("" -ne $Attachment) {
        $Attachment = new-object Net.Mail.Attachment($Attachment)
        $Attachment.ContentId = $AttachmentContentId
        $emailMessage.Attachments.Add( $Attachment )
    }
      

    $smtp = New-Object net.mail.smtpclient($SmtpServer, $Port)
    if ($SSL){
        try {
            if ([Net.ServicePointManager]::SecurityProtocol -notcontains 'Tls12') {
                [Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12
            }
        }
        Catch {}
        [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        #[System.Net.ServicePointManager]::CertificatePolicy = 
        $smtp.EnableSSL = $SSL
    }
    if ($user -ne "") {
        $smtp.Credentials = New-Object System.Net.NetworkCredential($user, $pass)
    }
    try {
        $smtp.Send($emailMessage)  
    }
    catch {
        "Send-Email exeption $($_.Exception)"        
        if ($Cntr -gt 0) {
            start-sleep -Seconds 300
            $Cntr = $Cntr - 1
            Send-Email $SmtpServer $Subject $Body $HtmlBody $User $Pass $To $Attachment $AttachmentContentId $Cntr           
        }  

    }
}
Function StartPSScript {
    param (
        [string] $ScriptPath,
        [string] $PSCommand = "",
        [string] $Username = "",
        [string] $Pwd = "",
        [string] $logFilePath,
        [string] $OutputFilePath = "",
        [bool]   $Elevated = $false        
    )
    $PowerShellPrgPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    if ($PSCommand -eq "") {
        $Arguments = "-WindowStyle Hidden -NonInteractive -Executionpolicy unrestricted  -file ""$ScriptPath""" 
    }
    else {
        $Arguments = "-NoNewWindow -WindowStyle Hidden -NonInteractive -Executionpolicy unrestricted -Command  ""& {$PSCommand}"""
    }
     
    switch ($Elevated) {
        $True { $Arguments += " -Verb runas" }
        Default { }
    }
    switch ($Username) {
        "" { }
        Default {
            $SecurePassword = ConvertTo-SecureString -String $Pwd -AsPlainText -Force
            $Credential = New-Object System.Management.Automation.PSCredential( $Username, $SecurePassword)
        }
    }
    switch ($OutputFilePath) {
        "" { }
        Default { $Arguments += " -RedirectStandardOutput ""$OutputFilePath""" }
    }
    if ($PSCommand -eq "") {
        $PossibleToStart = $True
        if ($Elevated -eq $true -and ("" -ne $Username -or "" -ne $OutputFilePath )) {
            $PossibleToStart = $false
            write-host ("Cannt run script with elevated and (credentials or outputredirect)!")
        }

        if ($PossibleToStart -eq $true) {
            Add-ToLog "Start script  $ScriptPath" $logFilePath 
            if ($username -ne "") {
                Start-Process $PowerShellPrgPath -ArgumentList $Arguments -Credential $Credential
            }  
            Else {
                Start-Process $PowerShellPrgPath -ArgumentList $Arguments
            }     
        }
    }
    else {
        if ($username -ne "") {
            Start-Process $PowerShellPrgPath -ArgumentList $Arguments -Credential $Credential
        }  
        Else {
            Start-Process $PowerShellPrgPath -ArgumentList $Arguments
        } 
    }
}
Function RebootSwitchesInInterval {
    param (
        [array] $SwitchIp,
        [string] $PlinkPath,
        [string] $CertFilePath,
        [string] $SshConString,
        [string] $SshCommand,
        [string] $EventLogPath,
        [int16]  $MinIntervalBetweenReboots
    )
    foreach ($switch in $SwitchIp) {
        $Event = "Start switch reboot $($switch.switchip)"
        $EventList = Get-EventList $EventLogPath $Event
        
        
        if (@($EventList).count -gt 0 -and $MinIntervalBetweenReboots -ne 0) {
            if (@($EventList).count -gt 1) {
                $lastDate = get-date (($EventList[($EventList.count - 1)] -split " ")[0].Trim() + " " + (($EventList[($EventList.count - 1)]) -split " ")[1].Trim())
            }
            Else {
                $lastDate = get-date (($EventList -split " ")[0].Trim() + " " + ($EventList -split " ")[1].Trim())
            }
            $TimeInterval = [int]((get-date) - $lastDate).TotalSeconds
            #write-host "time interval between host reboot $TimeInterval"
            if ($timeInterval -gt $MinIntervalBetweenReboots) {
                #Add-ToLog $Event $EventLogPath 
                ShowNotification "RebootSwitchesInInterval" "Try to reboot switch $($Switch.switchip)!" "Info" "C:\DATA\PROJECTS\ConnectVPN\VPN.log" 10
                RebootSwitches $Switch $EventLogPath $PlinkPath $SshConString $SshCommand $Null $Null $CertFilePath
            }
        }
        Else {
            #Add-ToLog $Event $EventLogPath
            RebootSwitches $Switch $EventLogPath $PlinkPath $SshConString $SshCommand $Null $Null $CertFilePath
            ShowNotification "RebootSwitchesInInterval" "Try to reboot switch $($Switch.switchip)!" "Info" "C:\DATA\PROJECTS\ConnectVPN\VPN.log" 10
        } 
    }
}
Function RestartLocalHostInInterval {
    param (
        [string] $EventLogPath,
        [int16]  $MinIntervalBetweenReboots
    )
    $Event = "Restart localhost"
    $EventList = Get-EventList $EventLogPath $Event
     
    if (@($EventList).count -gt 0 -and $MinIntervalBetweenReboots -ne 0) {
        if (@($EventList).count -gt 1) {
            $lastDate = get-date (($EventList[($EventList.count - 1)] -split " ")[0].Trim() + " " + (($EventList[($EventList.count - 1)]) -split " ")[1].Trim())
        }
        Else {
            $lastDate = get-date (($EventList -split " ")[0].Trim() + " " + ($EventList -split " ")[1].Trim())
        }
        $TimeInterval = [int]((get-date) - $lastDate).TotalSeconds
        #write-host "time interval between host reboot $TimeInterval"
        if ($timeInterval -gt $MinIntervalBetweenReboots) {
            Add-ToLog "Restart localhost in $MinIntervalBetweenReboots time interval" $EventLogPath
            Restart-Computer localhost -Force 
        }
    }
    Else {
        Add-ToLog "Restart localhost in $MinIntervalBetweenReboots time interval" $EventLogPath
        Restart-Computer localhost -Force 
    } 
}
Function ShowNotification { 
    param (
        [string] $MsgTitle,
        [string] $MsgText,
        [string] $Status,
        [string] $FilePath,
        [int16]  $Timeout = 5
    )    

    #Load the required assemblies
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    #Create the notification object
    $notification = New-Object System.Windows.Forms.NotifyIcon 
    #Define various parts of the notification
    $notification.Icon = [System.Drawing.SystemIcons]::$Status
    $notification.BalloonTipTitle = $MsgTitle
    #$notification.BalloonTipIcon = $Status
    $notification.BalloonTipText = $MsgText

    #Make balloon tip visible when called
    $notification.Visible = $True
    $notification.ShowBalloonTip(1)

    Register-ObjectEvent $notification BalloonTipClicked -SourceIdentifier event_BalloonTipClicked
    Register-ObjectEvent $notification BalloonTipClosed -SourceIdentifier event_BalloonTipClosed

    $retEvent = Wait-Event event_BalloonTip* -TimeOut $Timeout

    # Script resumes here.
    $retSourceIdentifier = $retEvent.SourceIdentifier
  
    If ($retSourceIdentifier -eq "event_BalloonTipClicked") {
        Start-Process "C:\Windows\System32\notepad.exe" -ArgumentList "C:\DATA\PROJECTS\ConnectVPN\VPN.log" -WindowStyle Normal -Verb Open
    }

    $notification.Dispose()

    # Tidy up, This is needed if returning to parent shell.
    Unregister-Event -SourceIdentifier event_BalloonTip*
    Get-Event event_BalloonTip* | Remove-Event

    # register-objectevent $notification BalloonTipClicked BalloonClicked_event -Action {
    #     Start-Process "C:\Windows\System32\notepad.exe" -ArgumentList "C:\DATA\PROJECTS\ConnectVPN\VPN.log" -WindowStyle Normal -Verb Open
    #     #Get rid of the icon after action is taken
    #     write-host "BalloonClicked_event"
    #     $notification.Dispose()
    # }  | Out-Null
    # register-objectevent $notification BalloonTipClosed BalloonClosed_event -Action { write-host "BalloonClosed_event" ; $notification.Dispose() } | Out-Null
    
    
    # #get-event | Format-List -Property *
    # Wait-Event "BalloonClosed_event" -timeout $Timeout
}
# Фабрика логгеров "для бедных", совместимая с PowerShell v3
function Get-Logger {
    [CmdletBinding()]
    param (
        [Parameter( Mandatory = $true )]
        [string] $LogPath,
        [string] $TimeFormat = 'yyyy-MM-dd HH:mm:ss'
    )

    $LogsDir = [System.IO.Path]::GetDirectoryName( $LogPath )
    New-Item $LogsDir -ItemType Directory -Force | Out-Null
    #New-Item $LogPath -ItemType File -Force | Out-Null

    $Logger = [PSCustomObject]@{
        LogPath    = $LogPath
        TimeFormat = $TimeFormat
    }

    Add-Member -InputObject $Logger -MemberType ScriptMethod AddErrorRecord -Value {
        param(
            [Parameter( Mandatory = $true )]
            [string]$String      
        )
        "$( Get-Date -Format 'yyyy-MM-dd HH:mm:ss' ) [Error] $String" | Out-File $this.LogPath -Append -Encoding utf8
    }
    return $Logger
}
Function RestartServiceInInterval {
    param (
        [string] $EventLogPath,
        [int16]  $MinIntervalBetweenRestarts,
        [string] $ServiceName
    )
    $Event     = "Restart service $ServiceName"
    $EventList = Get-EventList $EventLogPath $Event
     
    if (@($EventList).count -gt 0 -and $MinIntervalBetweenRestarts -ne 0) {
        if (@($EventList).count -gt 1) {
            $lastDate = get-date (($EventList[($EventList.count - 1)] -split " ")[0].Trim() + " " + (($EventList[($EventList.count - 1)]) -split " ")[1].Trim())
        }
        Else {
            $lastDate = get-date (($EventList -split " ")[0].Trim() + " " + ($EventList -split " ")[1].Trim())
        }
        $TimeInterval = [int]((get-date) - $lastDate).TotalSeconds
        #write-host "time interval between host reboot $TimeInterval"
        if ($timeInterval -gt $MinIntervalBetweenRestarts) {
            Add-ToLog "Restart service $ServiceName in $MinIntervalBetweenRestarts time interval" $EventLogPath
            Restart-Service $ServiceName -Force  
        }
    }
    Else {
        Add-ToLog "Restart service $ServiceName in $MinIntervalBetweenRestarts time interval" $EventLogPath
        Restart-Service $ServiceName -Force  
    } 
}
Function Set-TelegramMessage {
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0 )]
        [string]$Token,
        [Parameter( Mandatory = $true, Position = 1 )]
        [string]$ChatID,
        [Parameter( Mandatory = $true, Position = 2 )]
        [string]$Message,
        [Parameter( Mandatory = $false, Position = 3 )]
        [string]$ProxyURL,
        [Parameter( Mandatory = $false, Position = 4 )]
        [string]$ProxyUser,
        [Parameter( Mandatory = $false, Position = 5 )]
        [string]$ProxyPass
    ) 

    try {
        if ([Net.ServicePointManager]::SecurityProtocol -notcontains 'Tls12') {
            [Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12
        }
    }
    Catch {}
    [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $URI = "https://api.telegram.org/bot" + $Token + "/sendMessage?chat_id=" + $ChatID + "&text=" + $Message
     
    if ($Proxy -ne "") {    
        $secPasswd = ConvertTo-SecureString $ProxyPass -AsPlainText -Force
        $myCreds = New-Object System.Management.Automation.PSCredential -ArgumentList $ProxyUser, $secPasswd
        [system.net.webrequest]::defaultwebproxy = New-Object system.net.webproxy($ProxyURL)
        [system.net.webrequest]::defaultwebproxy.credentials = $myCreds
        [system.net.webrequest]::defaultwebproxy.BypassProxyOnLocal = $true

        
        $Response = Invoke-RestMethod -Uri $URI
    }
    else {
        $Response = Invoke-RestMethod -Uri $URI
    }

    return $Response
}
function InitLogging {
    [CmdletBinding()]
    Param(
        [string]$MyScriptRoot,
        [string]$StrictVer,
        [bool]$Dbg = $false
    )
    Set-StrictMode -Version $StrictVer #Latest

    # Error trap
    trap {
        [string]$line = $_.InvocationInfo.ScriptLineNumber
        [string]$Script = $_.InvocationInfo.ScriptName
        [string]$Message = "$_ [script] $Script [line] $line"
        $Logger.AddErrorRecord( $Message )
        exit 1
    }
    if (Test-Path "$MyScriptRoot\debug.txt") {
        $TranscriptPath = "$MyScriptRoot\Transcript.log"
        Start-Transcript -Path $TranscriptPath -Append -Force
    }
    else {
        if (! $Dbg){
            $ErrorActionPreference = 'Stop'
        }
    }

    $ErrorFileName = "Errors.log"
    $Logger = Get-Logger "$MyScriptRoot\$ErrorFileName"
}
function InitVars {
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory )]
        [string]$MyScriptRoot
    )
    try {
        . ("$MyScriptRoot\Vars.ps1")
    }
    catch {
        Write-Host "Error while loading variables from file $MyScriptRoot\Vars.ps1" 
    }

}
Function Get-HTMLTable {
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0 )]
        [string]$String        
    )
    $Lines = $String -split "`n"
    foreach ($item in $Lines) {
        if ($item -ne "") {
            $SplitedRow = Get-SplitedRow $item
            $HTML += Get-Row $SplitedRow
        }
    }
    Return $HTML
}
function Get-Row {
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory=$true, Position = 0 )]
        [array]$SplitedRow,
        [Parameter( Mandatory=$false, Position = 1 )]
        [string]$ColSpan = 0
    )    
    $row = ""
    if ($SplitedRow -ne "") {
        $rows = ""
        $row = @"
            <tr>
                %row%
            </tr>

"@
        $ColCount = 1
        foreach ($col in $SplitedRow) {
            if ($ColCount -ne 3) {
                if ($rows -eq "") {
                    $cols = @($col.Split("]"))
                    if ($cols.count -eq 1) {
                        $rows += (Get-Col $cols[0] $ColSpan)
                    }
                    Else {
                        $rows += (Get-Col $cols[1] $ColSpan)
                    }
                }
                Else {
                    $cols = @($col.Split("]"))
                    if ($cols.count -eq 1) {
                        $rows += "`n            " + (Get-Col $cols[0] $ColSpan)
                    }
                    Else {
                        $rows += "`n            " + (Get-Col $cols[1] $ColSpan)
                    }
                }
            }
            $ColCount += 1
        }
        $row = $row.Replace("%row%", $rows)
    }
    return $row
}

Function Get-Col  {
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0 )]
        [string]$String,
        [Parameter( Mandatory = $false, Position = 1 )]
        [string]$ColSpan = 0
    )  
    $String = $String.Trim()
    $col = " <td%ColSpan%>%String%</td>"
    if ($ColSpan -gt 0) {
        $col = $col.Replace("%ColSpan%", " colspan=`"$ColSpan`"")
    }
    Else {
        $col = $col.Replace("%ColSpan%", "")
    }
    $col = $col.Replace("%String%", $String)
    return $col 
}
Function Get-ContentFromHTMLTemlate {
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0 )]
        [string]$HTMLData,
        [Parameter( Mandatory = $true, Position = 1 )]
        [array]$ColNames,
        [Parameter( Mandatory = $true, Position = 2 )]
        [string]$HTMLTemplateFile,
        [Parameter( Mandatory = $false, Position = 3 )]
        [string]$HTMLFile
    )
    $th = @"
            <th>
                %col%
            </th>

"@
    $Header=""
    foreach ($Col in $ColNames){
        $Header += $th.Replace("%col%", $Col)
    }
    
    $HTMLTemplate = Get-Content $HTMLTemplateFile
    $HTMLTemplate = $HTMLTemplate.Replace( "%data%", $HTMLData)
    $HTMLTemplate = $HTMLTemplate.Replace( "%colnames%", $Header)
    if ($HTMLFile -ne "") { 
        $HTMLTemplate | Out-File $HTMLFile -Encoding utf8 -Force
    }
    return $HTMLTemplate
}

Export-ModuleMember -Function Get-NewAESKey, Get-SettingsFromFile, Get-VarFromFile, Disconnect-VPN, Connect-VPN, Add-ToLog, IsHardwareRebooting, RebootSwitches, RebootSwitchesInInterval, Get-EventList, Send-Email, StartPSScript, RestartLocalHostInInterval, ShowNotification, Get-Logger, RestartServiceInInterval, Set-TelegramMessage, InitLogging, InitVars, Get-HTMLTable, Get-Row, Get-Col, Get-ContentFromHTMLTemlate