<#
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
Function Get-VarFromFile  {
    [CmdletBinding()]
    param
    (   
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateNotNullOrEmpty()]
        [string]$AESKeyFilePath,
        [Parameter(Mandatory=$true, Position=1)]
        [ValidateNotNullOrEmpty()]
        [string]$VarFilePath
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
            try {
                $Var = Get-Content $VarFilePath | ConvertTo-SecureString -Key (get-content $AESKeyFilePath) 
                $Var = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Var)
                $Var = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($Var)
                return $Var
            }
            Catch {
                write-host "Error, check your key"
                return $Null 
            }
            

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
    $CHour     = [int](Get-date -Format "%H")
    $CMin      = [int](Get-date -Format "%m")
    $StartHour = [int]($HardwareRebootStartTime -split ":")[0]
    $StartMin  = [int]($HardwareRebootStartTime -split ":")[1]
    $EndHour   = [int]($HardwareRebootEndTime -split ":")[0]
    $EndMin    = [int]($HardwareRebootEndTime -split ":")[1]
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
        [int16]  $Cntr                = 100,
        [int16]  $PauseBetweenTryes   = 30
    )
    
    $emailMessage                 = New-Object System.Net.Mail.MailMessage
    $emailMessage.From            = $From
    $emailMessage.Subject         = $Subject
    $emailMessage.SubjectEncoding = [System.Text.Encoding]::UTF8
    $emailMessage.IsBodyHtml      = $HtmlBody
    $emailMessage.Body            = $Body
    $emailMessage.BodyEncoding    = [System.Text.Encoding]::UTF8
    $emailMessage.To.add($To)
    
    if ("" -ne $Attachment) {
        $Attach = new-object Net.Mail.Attachment($Attachment)
        $Attach.ContentId = $AttachmentContentId
        $emailMessage.Attachments.Add($Attach)
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
        #Get-ErrorReporting $_  
        write-host "Send-Email exeption $($_.Exception)"        
        if ($Cntr -gt 0) {
            
            $Cntr = $Cntr - 1
            Write-host ""
            Write-host "$(get-date) Try $Cntr"
            Start-Sleep -Seconds $PauseBetweenTryes
            
            $params = @{
                SmtpServer          = $SmtpServer
                Subject             = $Subject
                Body                = $Body
                HtmlBody            = $HtmlBody
                User                = $User
                Pass                = $Pass
                From                = $From
                To                  = $To
                Port                = $Port
                SSL                 = $SSL
                Attachment          = $Attachment
                AttachmentContentId = $AttachmentContentId
                Cntr                = $Cntr
                PauseBetweenTryes   = $PauseBetweenTryes  
            }

            Send-Email @params     
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
        [string]$StrictVer
    )
    Set-StrictMode -Version $StrictVer #Latest
    
    $ErrorFileName = "Errors.log"
    $Global:Logger = Get-Logger "$MyScriptRoot\$ErrorFileName"
    Write-Debug $Global:Logger
    if (Test-Path "$MyScriptRoot\debug.txt") {
        $TranscriptPath = "$MyScriptRoot\Transcript.log"
        Start-Transcript -Path $TranscriptPath -Append -Force
    }
    else {
            $ErrorActionPreference = 'Stop'
    }    
}
function Get-Vars {
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0 )]
        [string]$VarFile
    )
    try {
        . ("$VarFile")
    }
    catch {
        Write-Host "Error while loading variables from file $VarFile" 
    }

}
Function Get-HTMLTable {
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0 )]
        [array]$Array        
    )
    [string]$HTML = ""
    if ($Array.count -gt 0) {        
        foreach ($item in $Array) {
            if ($item -ne "") {
                $HTML += (Get-Row $item) + "`n"
            }
        }
    }
    Return $HTML    
}
function Get-Row {
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory=$true, Position = 0 )]
        [array]$Line,
        [Parameter( Mandatory=$false, Position = 1 )]
        [string]$ColSpan = 0
    )    
    $row = ""
    if ($Line.count -gt 0) {
        $rows = ""
        $row = @"
            <tr>
                %row%
            </tr>
"@
        if ((Get-RowFillness $Line) -gt 1){
            foreach ($col in ($Line[0].PSObject.Properties.Name )) {
                $rows += (Get-Col $Line.$col $ColSpan) + "`n"
            }
            $row = $row.Replace("%row%", $rows)
        }
        Else{
            $ColCount  = $Line[0].PSObject.Properties.Name.count
            $Col       = $Line[0].PSObject.Properties.Name[0]
            $ColSpan   = $ColCount
            $bold      = $true
            $rows     += (Get-Col $Line.$col $ColSpan $bold) + "`n"
            $row       = $Row.Replace("%row%", $rows)
        }
    }
    return $row
}

Function Get-Col  {
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $false, Position = 0 )]
        [string]$String,
        [Parameter( Mandatory = $false, Position = 1 )]
        [string]$ColSpan = 0,
        [Parameter( Mandatory = $false, Position = 2 )]
        [bool]$Bold = $false
    )  
    $String = $String.Trim()
    if ($Bold) {
        $col = " <td%ColSpan%><b>%String%</b></td>"
    } 
    else {
        $col = " <td%ColSpan%>%String%</td>"
    }
 
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
    $cd = "<col id=`"col%num%`" />"
    $th = @"
            <th>
                %col%
            </th>

"@
    $Header   = ""
    $ColId    = ""
    $ColCount = 1
    foreach ($Col in $ColNames){
        $Header   += $th.Replace("%col%", $Col.Name)
        $ColId    += $cd.Replace("%num%", $ColCount)
        $ColCount += 1
    }
    
    $HTMLTemplate = (Get-Content $HTMLTemplateFile) -join "`n" 
    $HTMLTemplate = $HTMLTemplate.Replace( "%data%", $HTMLData)
    $HTMLTemplate = $HTMLTemplate.Replace( "%colnames%", $Header)
    $HTMLTemplate = $HTMLTemplate.Replace( "%colid%", $ColId)
    if ($HTMLFile -ne "") { 
        $HTMLTemplate | Out-File $HTMLFile -Encoding utf8 -Force
    }
    return $HTMLTemplate
}

function Get-ErrorReporting {
 [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0 )]
        $Trap       
    )
    [string]$Trap1 = $Trap
    $Trap1 = ($Trap1.replace("[","")).replace("]","")
    [string]$line   = $Trap.InvocationInfo.ScriptLineNumber
    [string]$Script = $Trap.InvocationInfo.ScriptName
    if ($Script -ne $Trap.exception.errorrecord.InvocationInfo.ScriptName) {
        [string]$Module = (($Trap.ScriptStackTrace).split(",")[1]).split("`n")[0].replace(" line ", "").Trim()
        [string]$Function    = (($Trap.ScriptStackTrace).split(",")[0]).replace("at ","")
        [string]$ToScreen    = "$Trap `n    Script:   `"$($Script):$($line)`"`n    Module:   `"$Module`"`n    Function: `"$Function`""
        [string]$Message     = "$Trap1 [script] $($Script):$($line) ; $Module ; $Function"
    }
    else { 
        [string]$Message = "$Trap1 [script] $($Script):$($line)" 
        $ToScreen = "$Trap `n   $($Script):$($line)"
    }
    $Message = $Message.Replace("`n", "") 
    $Global:Logger.AddErrorRecord( $Message )
    Write-Host "SCRIPT EXIT DUE TO ERROR!!!" -ForegroundColor Red
    Write-Host "==========================================================================" -ForegroundColor Red
    Write-Host $ToScreen -ForegroundColor Blue
}
function Get-RowFillness {
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $false, Position = 0 )]
        [array]$Line
    )  
    $FillCounter = 0
    foreach ($col in ($Line[0].PSObject.Properties.Name )) {
        if ($Line.$col -ne "") {
            $FillCounter += 1
        }
    }
    return $FillCounter
}
function Get-CopyByBITS {
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0 )]
        [string]$Source,
        [Parameter( Mandatory = $true, Position = 1 )]
        [string]$Destination,
        [Parameter( Mandatory = $false, Position = 2 )]
        [bool]$Replace = $false,
        [Parameter( Mandatory = $false, Position = 3)]
        [bool]$ShowStatus = $false
    )  
    
    Import-Module BitsTransfer
    $GlobalTransfered = 0
    $GlobalStartTime = Get-Date
    $GlobalSize = (Get-ChildItem -Recurse $Source | Measure-Object -Property Length -Sum).sum
    $ScreenBuffer = ""
    $BitsJobs = @()
    if (Test-Path $Source) {
        if (!(Test-Path $Destination)) {
            New-Item -Path $Destination -ItemType Directory | Out-Null
            $ScreenBuffer += "Created directory '$Destination'`n"
        }
        $Files = Get-ChildItem  -Path "$Source" -Recurse
        foreach ($item in $Files) {
            $DestItem = $item.fullname.replace($Source, $Destination)
            if ($item.PSIsContainer) {
                try {
                    if (!(Test-Path $DestItem)) {
                        New-Item -Path $DestItem -ItemType Directory | Out-Null
                        $ScreenBuffer += "Created directory '$Destination'`n" 
                    } 
                }   
                catch {
                    $ScreenBuffer += "Error: $_.exeption `n"
                    Write-Host  $ScreenBuffer   
                }            
            }
            Else {
                $FileExist = Test-Path $DestItem
                if (!($FileExist) -or $Replace) {
                    $FileSize = [math]:: Round(($item.Length / 1Mb), 2)
                    if ($FileExist) {
                        $ScreenBuffer += "  - replacing file '$($DestItem) ($FileSize MB.)'`n"
                    }
                    Else {
                        $ScreenBuffer += "  - copy file '$($DestItem) ($FileSize MB.)'`n"     
                    }
                    try {
                        $BitsJobs += Start-BitsTransfer -Source $item.fullname -Destination $DestItem -Asynchronous -Priority Low -DisplayName $DestItem -ErrorAction SilentlyContinue  
                    }
                    Catch {
                        $ScreenBuffer += "      Error: $_.exeption `n"
                    }
                    Clear-Host
                    Write-Host  $ScreenBuffer 
                }
                Else {
                    $ScreenBuffer += "File $DestItem already exist and replace is $replace!"
                }
            }
        }
    }
    else {
        Write-Host "$Source doesn't exist!"
    }
    if ($ShowStatus) {
        #$BitsJobs = @(Get-BitsTransfer)
        $CounTransferingAndConnecting = @($BitsJobs | Where-Object { $_.JobState -eq "Transferring" -or $_.JobState -eq "Connecting" }).count
        Write-Host "$(Get-BitsTransfer | Out-String)"
        while ( $BitsJobs.count -gt 0 -and $CounTransferingAndConnecting -gt 0) {                         
            $FileArray = @()              
            foreach ($BitsJob in $BitsJobs) {
                $Status = $BitsJob.JobState
                $File = $BitsJob.FileList[$BitsJob.FilesTransferred]
                if ($null -ne $File) {
                    $CurentFile = $File.localName
                    $RemoteFile = $File.remoteName
                    $Size = [math]:: Round(($File.BytesTotal / 1MB), 2)
                }
                else {
                    $CurentFile = $BitsJob.FileList.localName
                    $RemoteFile = $BitsJob.FileList.remoteName                                        
                    $Size = [math]:: Round(($BitsJob.FileList.BytesTotal / 1MB), 2)
                }
                $FileCompletion = 0
                switch ($Status) {
                    { $_ -eq "Transferring" -or $_ -eq "Connecting" } {                                      
                        $CurrentTransfered = 0            
                        foreach ($Item in $BitsJob.FileList) {
                            $CurrentTransfered += $Item.BytesTransferred
                        }

                        $OverallCompletion = [math]:: Round(($GlobalTransfered + $CurrentTransfered) / $GlobalSize * 100, 2)
                        try {
                            $FileCompletion = [math]:: Round($File.BytesTransferred / $File.BytesTotal * 100, 2)
                        }
                        catch {
                            $FileCompletion = 100
                        }
                        $SecondsRun = [math]:: Round(((Get-Date) - $GlobalStartTime).TotalSeconds, 0)
                        if ($OverallCompletion -ne 0) {
                            $SecondsTotal = [math]:: Round($SecondsRun / $OverallCompletion * 100, 0)
                        }
                        else { $SecondsTotal = 0 }
                        $SecondsRemaining = $SecondsTotal - $SecondsRun
                        $AproxCompliteTime = ($GlobalStartTime).AddSeconds($SecondsTotal)
                        try {
                            $MBSec = [math]:: Round(($GlobalTransfered + $CurrentTransfered) / 1Mb / $SecondsRun, 2)
                        }
                        catch {
                            $MBSec = ""
                        } 
                    }
                    "Transferred" {                                                
                        $FileCompletion = 100                                                
                    }
                    "Queued" {                                                
                        $Size = [math]:: Round(((Get-Item $RemoteFile).Length / 1Mb), 2)                                               
                    }

                    Default { }
                }
                                  
                $PSO = [PSCustomObject]@{
                    JobState       = $Status
                    FileCompletion = $FileCompletion
                    Size           = $Size
                    RemoteFile     = $RemoteFile
                    CurentFile     = $CurentFile
                } 
                $FileArray += $PSO
            }
            $CommonData = [PSCustomObject]@{
                ScreenBuffer      = $ScreenBuffer
                OverallCompletion = $OverallCompletion
                AproxCompliteTime = $AproxCompliteTime
                SecondsRun        = $SecondsRun
                SecondsRemaining  = $SecondsRemaining
                MBSec             = $MBSec
            }                                 
                        
            Set-CopyStatus $CommonData $FileArray
                                                                        
            Start-Sleep 1
                        
            $CounTransferingAndConnecting = @($BitsJobs | Where-Object { $_.JobState -eq "Transferring" -or $_.JobState -eq "Connecting" }).count
        }
        $CommonData = [PSCustomObject]@{
            ScreenBuffer      = $ScreenBuffer
            OverallCompletion = 100
            AproxCompliteTime = Get-Date
            SecondsRun        = $SecondsRun
            SecondsRemaining  = 0
            MBSec             = $MBSec
        }  
                
        $GlobalTransfered += $CurrentTransfered 
        Set-CopyStatus $CommonData $null 
    }      
    $Uncompleted = @()
    foreach ($job in $BitsJobs) {
        if ($job.jobstate -eq "Transferred") {
            try { Complete-BitsTransfer -BitsJob $job }
            catch { Remove-BitsTransfer -BitsJob $job }
        }
        Else 
        { $Uncompleted += $job }
    }
    if ($uncompleted.count -gt 0) {
        Write-Host "Uncompleted job:"
        $Uncompleted | Select-Object  ErrorDescription, TransferType, JobState, OwnerAccount, RetryInterval, ErrorCondition, DisplayName  | Format-Table -AutoSize
    }
    Get-BitsTransfer | Format-Table -AutoSize
    Write-Host "Completed!"
}
Function Set-CopyStatus ($CommonData, $Array) {
    Clear-Host
    Write-Host $CommonData.ScreenBuffer
    Write-Host "================================================================================================================================================================" -ForegroundColor Green
    Write-Host "Overall: " -NoNewline -ForegroundColor Blue ; Write-Host "$($CommonData.OverallCompletion) % " -NoNewline -ForegroundColor Yellow; Write-Host "till: " -NoNewline -ForegroundColor Blue ; Write-Host "$($CommonData.AproxCompliteTime)" -ForegroundColor Yellow
    Write-Host "Run: " -NoNewline -ForegroundColor Blue ; Write-Host "$($CommonData.SecondsRun) sec. " -NoNewline -ForegroundColor Yellow; Write-Host "remain: " -NoNewline -ForegroundColor Blue ; Write-Host "$($CommonData.SecondsRemaining) sec." -ForegroundColor Yellow -NoNewline ; Write-Host " speed: " -ForegroundColor Blue -NoNewline ; Write-Host "$($CommonData.MBSec) MB/sec" -ForegroundColor Yellow
    foreach ($Pso in $Array) {     
        if ($Pso.JobState -ne "Transferred") {
            Write-Host "----------------------------------------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor Green
            Write-Host "    Current: " -NoNewline -ForegroundColor Blue ; Write-Host "$($PSO.FileCompletion) %" -ForegroundColor Yellow 
            Write-Host "    $($Pso.JobState) ($($PSO.Size) MB.) " -NoNewline -ForegroundColor Blue ; Write-Host "$($PSO.RemoteFile)" -ForegroundColor Yellow -NoNewline; Write-Host " -> " -ForegroundColor Blue -NoNewline; Write-Host "$($PSO.CurentFile)" -ForegroundColor Red
        }
    }                                                              
    Write-Host "================================================================================================================================================================"  -ForegroundColor Green    
}
Function Get-OpenDialog{
[CmdletBinding()]
    Param(        
        [Parameter( Mandatory = $true, Position = 0)]
        [string]$Type,
        [Parameter( Mandatory = $false, Position = 1 )]
        [string]$InitPath = "",
        [Parameter( Mandatory = $false, Position = 2 )]
        [string]$Description = "",
        [Parameter( Mandatory = $false, Position = 3 )]
        [string]$FileFilter = "",
        [Parameter( Mandatory = $false, Position = 4 )]
        [bool]$FileMultiSelect = $false
    )  
    
    Add-Type -AssemblyName System.Windows.Forms
    if ($InitPath -eq "") {$InitPath = Get-Location}
    switch ($type.tolower()) {
        "file" { 
            $File                  = New-Object Windows.Forms.OpenFileDialog
            $File.InitialDirectory = $InitPath
            $File.Filter           = $FileFilter
            $File.ShowHelp         = $true
            $File.Multiselect      = $FileMultiSelect
            $File.ShowDialog() | Out-Null
            if ($File.Multiselect) { return $File.FileNames } else { return $File.FileName }  
        }
        "folder" {  
            $Folder = New-Object Windows.Forms.FolderBrowserDialog
            $Folder.SelectedPath = $InitPath
            $Folder.ShowDialog() | Out-Null
            return $Folder.SelectedPath 
        }
        Default {}
    }
}
function Import-ModuleRemotely {
    [CmdletBinding()]    
    Param (
        [Parameter( Mandatory = $true, Position = 0)]
        [string] $moduleName,
        [Parameter( Mandatory = $true, Position = 1)]
        [System.Management.Automation.Runspaces.PSSession] $session
    )

    Import-Module $moduleName

    $Script = @"
    if (get-module $moduleName)
    {
        remove-module $moduleName;
    }

    New-Module -Name $moduleName { $($(Get-Module $moduleName).Definition) } | Import-Module
"@

    Invoke-Command -Session $Session -ScriptBlock {
        Param($Script)
        . ([ScriptBlock]::Create($Script))
        Get-Module 
    } -ArgumentList $Script
}

Export-ModuleMember -Function Get-NewAESKey, Get-SettingsFromFile, Get-VarFromFile, Disconnect-VPN, Connect-VPN, Add-ToLog, IsHardwareRebooting, RebootSwitches, RebootSwitchesInInterval, Get-EventList, Send-Email, StartPSScript, RestartLocalHostInInterval, ShowNotification, Get-Logger, RestartServiceInInterval, Set-TelegramMessage, InitLogging, Get-Vars, Get-HTMLTable, Get-Row, Get-Col, Get-ContentFromHTMLTemlate, Get-ErrorReporting, Get-CopyByBITS, Get-OpenDialog, Import-ModuleRemotely