<#
    .SYNOPSIS
        AlexK utility module.
    .DESCRIPTION
        This module contains utility functions.
        Use inside AlexkFramework.
    .NOTES
        AUTHOR  Alexk
        CREATED 25.04.19
        MOD     26.10.20
        VER     4
#>


[bool] $Global:modSuppressOutput   = $false
[int]  $Global:modPSSessionCounter = 0

#region AES
function Get-NewAESKey {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        This function create a new AES key and save it to file
    .EXAMPLE
        Get-NewAESKey -AESKeyFilePath $AESKeyFilePath
#>
    [OutputType([Byte[]])]
    [CmdletBinding()]
    param
    (
        [Parameter( Mandatory=$false, Position = 0,HelpMessage = "Full path, where we make AES key file."  )]
        [string] $AESKeyFilePath,
        [Parameter(Mandatory = $false, Position = 1, HelpMessage = "Return object." )]
        [switch] $PassThru
    )

    $AESKey = New-Object Byte[] 32
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($AESKey)
    if ( $AESKeyFilePath ) {
        $AESKey | out-file $AESKeyFilePath
    }

    if ( $PassThru ){
        Return $AESKey
    }
}
Function Get-VarFromAESFile  {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        Function to read variable from file encrypted with AES key.
    .EXAMPLE
        Get-VarFromAESFile -AESKeyFilePath $AESKeyFilePath -VarFilePath $VarFilePath
#>
    [OutputType([SecureString])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Path to AES key file." )]
        [ValidateNotNullOrEmpty()]
        [string]$AESKeyFilePath,
        [Parameter(Mandatory=$true, Position=1, HelpMessage = "Encrypted file path." )]
        [ValidateNotNullOrEmpty()]
        [string]$VarFilePath
    )

    if (!(test-path $AESKeyFilePath)) {
        write-host "AESKeyFilePath [$AESKeyFilePath] not exist" -ForegroundColor Red
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
                $Res = Get-Content $VarFilePath | ConvertTo-SecureString -Key (get-content $AESKeyFilePath)
            }
            Catch {
                write-host "Error [$($_.exception)], check your key!" - -ForegroundColor red
                $Res = $Null
            }


        }
    Else {
        $Res = $null
    }

    return $Res
}
Function Set-VarToAESFile {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        Function to write variable to file with encryption with AES key file
    .EXAMPLE
        Set-VarToAESFile -Var $Var -AESKeyFilePath $AESKeyFilePath -VarFilePath $VarFilePath
#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Value." )]
        [ValidateNotNullOrEmpty()]
        [string] $Var,
        [Parameter(Mandatory = $true, Position = 1, HelpMessage = "Path to AES key file." )]
        [ValidateNotNullOrEmpty()]
        [string] $AESKeyFilePath,
        [Parameter(Mandatory = $true, Position = 2, HelpMessage = "Path to encrypted file." )]
        [ValidateNotNullOrEmpty()]
        [string] $VarFilePath,
        [Parameter(Mandatory = $false, Position = 3, HelpMessage = "Return object." )]
        [switch] $PassThru
    )

    $AESData = ConvertTo-SecureString -String $Var -AsPlainText | ConvertFrom-SecureString -Key (get-content $AESKeyFilePath) 
    $AESData | Set-Content -path $VarFilePath

    if ( $PassThru ){
        Return $AESData
    }
}
Function Get-VarToString {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   09.04.20
        VER    1
    .DESCRIPTION
        Function to make string from secure string.
    .EXAMPLE
        Get-VarToString -Var $Var
#>
    [OutputType([string])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Secure string." )]
        [ValidateNotNullOrEmpty()]
        $Var
    )

    $Var = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Var)
    $Res = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($Var)
    if(!$res){
        Write-Host "Get-VarToString return $Null! Var type is $($Var.gettype())." -ForegroundColor red
    }
    return $Res
}
#endregion
#region VPN
Function Connect-VPN {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        Function to establish VPN connection
    .EXAMPLE
        Connect-VPN -VPNConnectionName $VPNConnectionName -logFilePath $logFilePath -Login $Login -Password $Password
#>
    [OutputType([string])]
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Name of VPN connection." )]
        [ValidateNotNullOrEmpty()]
        [string] $VPNConnectionName,
        [Parameter(Mandatory = $true, Position = 1, HelpMessage = "Log file path." )]
        [ValidateNotNullOrEmpty()]
        [string] $logFilePath,
        [Parameter(Mandatory = $true, Position = 2, HelpMessage = "VPN Login." )]
        [ValidateNotNullOrEmpty()]
        [SecureString] $Login,
        [Parameter(Mandatory = $true, Position = 3, HelpMessage = "VPN Password." )]
        [ValidateNotNullOrEmpty()]
        [SecureString] $Password
    )

    $ConnectionState = [PSCustomObject]@{
        Success = "Success"
        Fail    = "Fail"
        Hang    = "Hang"
    }

    [string] $LoginText = Get-VarToString -var $Login
    [string] $PassText  = Get-VarToString -var $Password
    Add-ToLog -Message "Try to connect VPN - $VPNConnectionName under $LoginText" -logFilePath $logFilePath

    $StartConnection = Get-Date
    $Res = (& rasdial.exe $VPNConnectionName $LoginText $PassText ) -join " "
    if (($Res -like "*success*") -or ($Res -like "*успешно*")) {
        $TimeRun = ((Get-Date) - $StartConnection).TotalMilliseconds
        if ($TimeRun -le 100) {
            Add-ToLog -Message $Res -logFilePath $logFilePath
            return $ConnectionState.Hang
        }
        Else {
            Add-ToLog -Message $Res -logFilePath $logFilePath
            return $ConnectionState.Success
        }

    }
    else {
        Add-ToLog -Message $Res -logFilePath $logFilePath
        #Add-ToLog $false $logFilePath
        return $ConnectionState.Fail
    }
}
function Disconnect-VPN {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        Function to break VPN connection
    .EXAMPLE
        Disconnect-VPN -VPNConnectionName $VPNConnectionName -logFilePath $logFilePath
#>
    [OutputType([bool])]
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Name of VPN connection." )]
        [ValidateNotNullOrEmpty()]
        [string] $VPNConnectionName,
        [Parameter(Mandatory = $true, Position = 1, HelpMessage = "Log file path." )]
        [ValidateNotNullOrEmpty()]
        [string] $logFilePath
    )

    Add-ToLog "Try to disconnect VPN - $VPNConnectionName" $logFilePath
    $Res = (& rasdial $VPNConnectionName /disconnect)  -join " "
    if ($Res -like "*success*") {
        Add-ToLog ($Res -like "*success*") $logFilePath
        return $true
    }
    else {
        Add-ToLog  $Res $logFilePath
        return $false
    }
}

#endregion
#region Restart
Function Restart-LocalHostInInterval {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        Function to restart computer in time interval based on last restart.
    .EXAMPLE
        Restart-LocalHostInInterval -LogFilePath $LogFilePath [-MinIntervalBetweenReboots $MinIntervalBetweenReboots]
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Log file path." )]
        [ValidateNotNullOrEmpty()]
        [string] $LogFilePath,
        [Parameter(Mandatory = $false, Position = 1, HelpMessage = "Minimal interval between localhost reboots." )]
        [int16]  $MinIntervalBetweenReboots,
        [Parameter(Mandatory = $false, Position = 2, HelpMessage = "Return object." )]
        [switch] $PassThru
    )
    $ThisEvent = "Restart localhost"
    $EventList = Get-EventList -LogFilePath $LogFilePath -Event $ThisEvent

    $res = $false

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
            Add-ToLog "Restart localhost in $MinIntervalBetweenReboots time interval" $LogFilePath
            $res = $true
        }
    }
    Else {
        Add-ToLog "Restart localhost in $MinIntervalBetweenReboots time interval" $LogFilePath
        $res = $true
    }

    If ( $PassThru ){
        return $res
    }
    Else {
        If ( $res ){
            Restart-Computer localhost -Force
        }
    }
}
Function Restart-Switches {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        Function to reboot device
    .EXAMPLE
        Parameter set: "Login"
            Restart-Switches -SwitchesIP $SwitchesIP -logFilePath $logFilePath -PLinkPath $PLinkPath -SshConString $SshConString -SshCommand $SshCommand [-Login $Login] [-Password $Password]
        Parameter set: "Cert"
            Restart-Switches -SwitchesIP $SwitchesIP -logFilePath $logFilePath -PLinkPath $PLinkPath -SshConString $SshConString -SshCommand $SshCommand [-CertFilePath $CertFilePath]
#>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Array with device IPs." )]
        [ValidateNotNullOrEmpty()]
        [Array]$SwitchesIP,
        [Parameter(Mandatory = $true, Position = 1, HelpMessage = "Log file path." )]
        [ValidateNotNullOrEmpty()]
        [string] $logFilePath,
        [Parameter(Mandatory = $true, Position = 2, HelpMessage = "Plink.exe path." )]
        [ValidateNotNullOrEmpty()]
        [string] $PLinkPath,
        [Parameter(Mandatory = $true, Position = 3, HelpMessage = "SSH connection string." )]
        [ValidateNotNullOrEmpty()]
        [string] $SshConString,
        [Parameter(Mandatory = $true, Position = 4, HelpMessage = "SSH command." )]
        [ValidateNotNullOrEmpty()]
        [string] $SshCommand,
        [Parameter(Mandatory = $false, Position = 5, HelpMessage = "SSH Login.", ParameterSetName = "Login" )]
        [string] $Login,
        [Parameter(Mandatory = $false, Position = 6, HelpMessage = "SSH Password.", ParameterSetName = "Login" )]
        [securestring] $Password,
        [Parameter(Mandatory = $false, Position = 7, HelpMessage = "SSH certificate path.", ParameterSetName = "Cert" )]
        [string] $CertFilePath
    )
    Foreach ($Item in $SwitchesIP) {
        $Ip = $Item.SwitchIp
        $Command = $SshCommand.Clone()
        $Command = $Command.Replace("%ip%", $Ip)

        if (!$Login -and $CertFilePath -and $SshConString -and $SshCommand) {
            $Arguments = " -ssh -i """ + $CertFilePath + """ " + $SshConString + " -no-antispoof """ + $Command + """ -batch"
            #Add-ToLog "$Arguments" $logFilePath
            Start-Process $PLinkPath -ArgumentList $Arguments -WindowStyle Hidden #-RedirectStandardOutput "C:\DATA\PROJECTS\RebootUnpingableClientSwitch\ssh-out.log" #
            Add-ToLog "Start switch reboot $Ip" $logFilePath
        }

        elseif ($Login -and !$CertFilePath -and $SshConString -and $SshCommand) {
            $Arguments = " -ssh -l """ + $Login + """ -pw """ + $Password + """ " + $SshConString + " -no-antispoof """ + $Command + """ -batch"
            Start-Process $PLinkPath -ArgumentList $Arguments -WindowStyle Hidden   #-RedirectStandardOutput "C:\DATA\PROJECTS\RebootUnpingableClientSwitch\ssh-out.log" #
            Add-ToLog "Start switch reboot $Ip" $logFilePath
        }

        switch ($Item.RebootOrder) {
            2 { Start-Sleep 10 }
            3 { Start-Sleep 10 }
        }
    }
}
Function Restart-SwitchInInterval {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        Function to restart devices in time interval.
    .EXAMPLE
        Parameter set: "Login"
            Restart-SwitchInInterval -SwitchesIP $SwitchesIP -logFilePath $logFilePath -PLinkPath $PLinkPath -SshConString $SshConString -SshCommand $SshCommand [-Login $Login] [-Password $Password] [-MinIntervalBetweenReboots $MinIntervalBetweenReboots]
        Parameter set: "Cert"
            Restart-SwitchInInterval -SwitchesIP $SwitchesIP -logFilePath $logFilePath -PLinkPath $PLinkPath -SshConString $SshConString -SshCommand $SshCommand [-CertFilePath $CertFilePath] [-MinIntervalBetweenReboots $MinIntervalBetweenReboots]
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Array with device IPs." )]
        [ValidateNotNullOrEmpty()]
        [Array]$SwitchesIP,
        [Parameter(Mandatory = $true, Position = 1, HelpMessage = "Log file path." )]
        [ValidateNotNullOrEmpty()]
        [string] $logFilePath,
        [Parameter(Mandatory = $true, Position = 2, HelpMessage = "Plink.exe path." )]
        [ValidateNotNullOrEmpty()]
        [string] $PLinkPath,
        [Parameter(Mandatory = $true, Position = 3, HelpMessage = "SSH connection string." )]
        [ValidateNotNullOrEmpty()]
        [string] $SshConString,
        [Parameter(Mandatory = $true, Position = 4, HelpMessage = "SSH command." )]
        [ValidateNotNullOrEmpty()]
        [string] $SshCommand,
        [Parameter(Mandatory = $false, Position = 5, HelpMessage = "SSH Login.", ParameterSetName = "Login" )]
        [string] $Login,
        [Parameter(Mandatory = $false, Position = 6, HelpMessage = "SSH Password.", ParameterSetName = "Login" )]
        [securestring] $Password,
        [Parameter(Mandatory = $false, Position = 7, HelpMessage = "SSH certificate path.", ParameterSetName = "Cert" )]
        [string] $CertFilePath,
        [Parameter(Mandatory = $false, Position = 8, HelpMessage = "Minimal interval between restarts." )]
        [int16]  $MinIntervalBetweenReboots
    )
    foreach ($switch in $SwitchesIP) {
        $ThisEvent = "Start switch reboot $($switch.SwitchIp)"
        $EventList = Get-EventList -LogFilePath $logFilePath -Event $ThisEvent


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
                Show-Notification -MsgTitle "RebootSwitchesInInterval" -MsgText "Try to reboot switch $($Switch.SwitchIp)!" -Status "Info" -FilePath $logFilePath -Timeout 10
                Restart-Switches -SwitchesIP $Switch -logFilePath $logFilePath -PLinkPath $PlinkPath -SshConString $SshConString -SshCommand $SshCommand -CertFilePath $CertFilePath
            }
        }
        Else {
            #Add-ToLog $Event $EventLogPath
            Restart-Switches -SwitchesIP $Switch -logFilePath $logFilePath -PLinkPath $PlinkPath -SshConString $SshConString -SshCommand $SshCommand -CertFilePath $CertFilePath
            Show-Notification -MsgTitle  "RebootSwitchesInInterval" -MsgText "Try to reboot switch $($Switch.SwitchIp)!" -Status "Info" -FilePath $logFilePath -Timeout 10
        }
    }

}
Function Restart-ServiceInInterval {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        Function to create logger object.
    .EXAMPLE
        Restart-ServiceInInterval -EventLogPath $EventLogPath -ServiceName $ServiceName [-MinIntervalBetweenRestarts $MinIntervalBetweenRestarts=0]
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Log file path." )]
        [ValidateNotNullOrEmpty()]
        [string] $EventLogPath,
        [Parameter(Mandatory = $true, Position = 1, HelpMessage = "Name of service to restart." )]
        [ValidateNotNullOrEmpty()]
        [string] $ServiceName,
        [Parameter(Mandatory = $false, Position = 2, HelpMessage = "Minimal interval between service restart." )]
        [int16]  $MinIntervalBetweenRestarts = 0
    )
    $ThisEvent     = "Restart service $ServiceName"
    $EventList = Get-EventList -LogFilePath $EventLogPath -Event $ThisEvent

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
#endregion
#region Credentials
function Test-Credentials {
<#
    .SYNOPSIS
        AUTHOR Open source
        DATE   16.04.20
        VER    1
    .DESCRIPTION
        Test user credentials.
    .EXAMPLE
        Test-Credentials -Credentials $Credentials
#>

    [CmdletBinding()]
    [OutputType([Bool])]

    Param (
        [Parameter( Mandatory = $true,  ValueFromPipeLine = $true,  ValueFromPipelineByPropertyName = $true )]
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credentials
    )

    process {
        $Domain   = $null
        $Root     = $null
        $Username = $null
        $Password = $null


        # Checking module
        Try {
            # Split username and password
            $Username = $credentials.username
            $Password = $credentials.GetNetworkCredential().password

            # Get Domain
            $Root = "LDAP://" + ([ADSI]'').distinguishedName
            $Domain = New-Object System.DirectoryServices.DirectoryEntry($Root, $UserName, $Password)
        }
        Catch {
            $_.Exception.Message
            Continue
        }

        If (!$Domain) {
            Write-Warning "Domain not found."
            $res = $false
        }
        Else {
            $res = $true
        }

        return $res
    }
}
function Test-ElevatedRights {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
    .EXAMPLE
        Test-ElevatedRights
#>
    [CmdletBinding()]
    [OutputType([Bool])]
    Param (
        [Parameter( Mandatory = $false,  ValueFromPipeLine = $true,  ValueFromPipelineByPropertyName = $true )]
        [ValidateNotNull()]
        [Security.Principal.WindowsIdentity]
        $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    )
    
    $Principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $Identity
    $Res       = $principal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )

    return $Res
}
#endregion
#region Logging
Function Add-ToLog {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        Function to write message into a log file
    .EXAMPLE
        Add-ToLog -Message $Message -logFilePath $logFilePath [-Mode $Mode="append"] [-Display $Display] [-Status $Status] [-Format $Format] [-Level $Level]
#>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Message to log." )]
        [ValidateNotNullOrEmpty()]
        [string] $Message,
        [Parameter(Mandatory = $true, Position = 1, HelpMessage = "Path to log file." )]
        [ValidateNotNullOrEmpty()]
        [string] $logFilePath,
        [Parameter(Mandatory = $false, Position = 2, HelpMessage = "Saving to file mode." )]
        [ValidateSet("append", "replace")]
        [string] $Mode = "append",
        [Parameter(Mandatory = $false, Position = 3, HelpMessage = "Display on the screen." )]
        [switch] $Display,
        [Parameter(Mandatory = $false, Position = 4, HelpMessage = "Message status." )]
        [ValidateSet("Info", "Warning", "Error", "Group1", "Group2", "Group3")]
        [string] $Status,
        [Parameter(Mandatory = $false, Position = 5, HelpMessage = "Date format string." )]
        [string] $Format,
        [Parameter(Mandatory = $false, Position =6, HelpMessage = "Level in string hierarchy." )]
        [int16] $Level
    )
    if ( -not $Global:modSuppressOutput ) {
        if (-not $Level) {
            if($Global:gsParentLevel){
                [int16] $Level = [int16] $Global:gsParentLevel + 1
            }
        }

        if($Global:gsScriptLocalHost -ne "$($Env:COMPUTERNAME)"){
            $Remote  = $true
            $Message = "Remote [$($Env:COMPUTERNAME)]. $Message"
            $Hash = @{
                Message     = $Message
                logFilePath = $logFilePath
                Mode        = $Mode
                Display     = $false
                Status      = $Status
                Format      = $Format
                Level       = $Level
            }
            [array] $Global:gsLogBuffer += $Hash
        }

        if($Format) {
            $Date = Get-Date -Format $Format
        }
        Else {
            if ($Global:gsGlobalDateTimeFormat){
                $Date = Get-Date -Format $Global:gsGlobalDateTimeFormat
            }
            Else {
                $Date = Get-Date
            }
        }

        [string]$LevelText = ""
        if ($Level){
            [string]$LevelSign       = " "
            [int16] $LevelMultiplier = 4
            for ($i = 0; $i -lt ($Level*$LevelMultiplier); $i++) {
                $LevelText += $LevelSign
            }
        }

        $Text = ($Date.ToString()  + " $LevelText" + $Message)
        # Write-host "Text = $Text"
        # Write-Host "Add-ToLog ParentLevel = $ParentLevel"
        # Write-Host "Add-ToLog Level = $Level"
        # Write-Host "Padding = $($LevelMultiplier)"
        if ( -not $remote){
            # Because many process can write simultaneously.
            if ( -not $Global:gsScriptOperationTry) {
                $Global:gsScriptOperationTry = 10
            }
            for ($i = 1; $i -le $Global:gsScriptOperationTry; $i++) {
                try {
                    switch ($Mode.ToLower()) {
                    "append" {
                        Out-File -FilePath $logFilePath -Encoding utf8 -Append -Force -InputObject $Text
                    }
                    "replace" {
                        Out-File -FilePath $logFilePath -Encoding utf8 -Force -InputObject $Text
                    }
                        Default { }
                    }
                    break
                }
                Catch {
                    if ($Global:gsPauseBetweenRetries){
                        Start-Sleep -Milliseconds $Global:gsPauseBetweenRetries
                    }
                    Else {
                        Start-Sleep -Milliseconds 500
                    }
                }
            }
        }
        If ($Display){
            if ($logFilePath -ne $Global:gsScriptLogFilePath){
                $TextLen = $text.Length
                if ($TextLen -le $Global:gsLogFileNamePosition){
                    $text = $text.PadRight($Global:gsLogFileNamePosition, " ")
                    $NewText = "$text[$(split-path -path $logFilePath -Leaf)]"
                }
                Else {
                    $NewText = "$text[$(split-path -path $logFilePath -Leaf)]"
                }
            }
            Else {
                $NewText = $text
            }
            if($status){
                switch ( $Status.ToLower() ) {
                    "info" {
                        Write-Host $NewText  -ForegroundColor Green
                    }
                    "warning" {
                        Write-Host $NewText  -ForegroundColor Yellow
                    }
                    "error" {
                        Write-Host $NewText  -ForegroundColor Red
                    }
                    "group1" {
                        Write-Host $NewText  -ForegroundColor Blue
                    }
                    "group2" {
                        Write-Host $NewText  -ForegroundColor Cyan
                    }
                    "group3" {
                        Write-Host $NewText  -ForegroundColor Magenta
                    }
                    Default {}
                }
        }
        Else{
                Write-Host $NewText
        }

        }
    }
}
Function Send-Alert {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   05.08.20
        VER    1
    .DESCRIPTION
        Send alert by custom transport.
    .EXAMPLE
        Send-Alert -AlertParameters $AlertParameters -AlertMessage $AlertMessage [-AlertSubject $AlertSubject]
#>
    [CmdletBinding()]
    Param (
        [Parameter( Mandatory = $True, Position = 1, HelpMessage = "Alert parameters.")]
        $AlertParameters,
        [Parameter( Mandatory = $True, Position = 2, HelpMessage = "Alert message.")]
        [string] $AlertMessage,
        [Parameter( Mandatory = $false, Position = 3, HelpMessage = "Alert subject.")]
        [string] $AlertSubject
    )
    switch ([string]$AlertParameters.name.ToLower()) {
        "telegram" {
            $Data = $AlertParameters.data
            New-TelegramMessage @Data -Message $AlertMessage
        }
        "email" {
            $Data = $AlertParameters.data
            Send-Email @Data -SSL -Subject $AlertSubject -Body $AlertMessage

        }
        Default {}
    }
}
Function Set-State {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   05.08.20
        VER    1
    .DESCRIPTION
        Save object state to file
    .EXAMPLE
        Set-State -StateObject $StateObject -StateFilePath $StateFilePath [-AlertType $AlertType] [-AlertOnChange $AlertOnChange] [-SaveOnChange $SaveOnChange]
#>
    [CmdletBinding()]
    Param (
        [Parameter( Mandatory = $true, Position = 1, HelpMessage = "State object." )]
        [PSCustomObject] $StateObject,
        [Parameter( Mandatory = $true, Position = 2, HelpMessage = "State file path." )]
        [String] $StateFilePath,
        [Parameter( Mandatory = $false, Position = 3, HelpMessage = "Send alert to." )]
        [string] $AlertType,
        [Parameter( Mandatory = $false, Position = 4, HelpMessage = "Alert only on global state change." )]
        [switch] $AlertOnChange,
        [Parameter( Mandatory = $false, Position = 5, HelpMessage = "Save only on global state change." )]
        [switch] $SaveOnChange
    )

    if (Test-Path $StateFilePath) {
        if ( $StateFilePath.ToLower().contains("csv") ) {
            $States = Import-Csv -Path $StateFilePath
        }
        ElseIf ( $StateFilePath.ToLower().contains("xml") ) {
            $States = Import-Clixml -Path $StateFilePath
        }
    }
    Else {
        $States = @()
    }

    $LastState = $States | Select-Object -Last 1
    $StateChanged = $LastState.State -ne $StateObject.State
    $StateObject.date = Get-Date
    $AlertMessage = @"
$($StateObject.Application)@$($StateObject.Host)[$(Get-Date $StateObject.date -Format HH:mm)]
$($StateObject.Action)
$($StateObject.State)
Global state: $($StateObject.GlobalState)
"@
    if ( $AlertOnChange ) {
        if ($StateChanged) {
            switch ($AlertType.ToLower()) {
                "telegram" {
                    if ($Global:TelegramParameters) {
                        Send-Alert -AlertParameters $Global:TelegramParameters -AlertMessage $AlertMessage
                        Add-ToLog -Message "Sent telegram message." -logFilePath $Global:gsScriptLogFilePath -Display -Status "Info"
                    }
                    Else {
                        Add-ToLog -Message "Telegram parameters not set! Plugin not available" -logFilePath $Global:gsScriptLogFilePath -Display -Status "Error"
                    }
                }
                Default {}
            }
        }
    }
    Else {
        switch ($AlertType.ToLower()) {
            "telegram" {
                if ($Global:TelegramParameters) {
                    Send-Alert -AlertParameters $Global:TelegramParameters -AlertMessage $AlertMessage
                }
                Else {
                    Add-ToLog -Message "Telegram parameters not set! Plugin not available" -logFilePath $Global:gsScriptLogFilePath -Display -Status "Error"
                }
            }
            Default {}
        }
    }

    if ( $SaveOnChange ) {
        if ($StateChanged) {
            [array] $States += $StateObject
            if ( $StateFilePath.ToLower().contains("csv") ) {
                $States | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $StateFilePath -Force
            }
            ElseIf ( $StateFilePath.ToLower().contains("xml") ) {
                $States | Export-Clixml -Path $StateFilePath -Force
            }
        }
    }
    Else {
        [array] $States += $StateObject
        if ( $StateFilePath.ToLower().contains("csv") ) {
            $States | ConvertTo-Csv -NoTypeInformation | Out-File -FilePath $StateFilePath -Force
        }
        ElseIf ( $StateFilePath.ToLower().contains("xml") ) {
            $States | Export-Clixml -Path $StateFilePath -Force
        }
    }
}
Function Send-Email {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        Function to send email message
    .EXAMPLE
        Parameter set: "Auth"
            Send-Email -SmtpServer $SmtpServer -From $From -To $To [-Subject $Subject] [-Body $Body] [-HtmlBody $HtmlBody] [-User $User] [-Password $Password] [-Port $Port=25] [-SSL $SSL] [-Attachment $Attachment] [-AttachmentContentId $AttachmentContentId] [-TTL $TTL=(New-TimeSpan -days 1)] [-PauseBetweenTries $PauseBetweenTries=30]
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "SMTP server FQDN." )]
        [ValidateNotNullOrEmpty()]
        [string] $SmtpServer,
        [Parameter(Mandatory = $true, Position = 1, HelpMessage = "From address." )]
        [ValidateNotNullOrEmpty()]
        [string] $From,
        [Parameter(Mandatory = $true, Position = 2, HelpMessage = "To address." )]
        [ValidateNotNullOrEmpty()]
        [string] $To,
        [Parameter(Mandatory = $false, Position = 3, HelpMessage = "Email subject." )]
        [string] $Subject,
        [Parameter(Mandatory = $false, Position = 4, HelpMessage = "Email body." )]
        [string] $Body,
        [Parameter(Mandatory = $false, Position = 5, HelpMessage = "Email body type." )]
        [switch]   $HtmlBody,
        [Parameter(Mandatory = $false, Position = 6, HelpMessage = "User name.", ParameterSetName = "Auth" )]
        [securestring] $User,
        [Parameter(Mandatory = $false, Position = 7, HelpMessage = "User password.", ParameterSetName = "Auth" )]
        [securestring] $Password,
        [Parameter(Mandatory = $false, Position = 8, HelpMessage = "SMTP port." )]
        [Int32]  $Port                = 25,
        [Parameter(Mandatory = $false, Position = 9, HelpMessage = "Use SSL." )]
        [switch]   $SSL,
        [Parameter(Mandatory = $false, Position = 10, HelpMessage = "Email attachment." )]
        [string] $Attachment,
        [Parameter(Mandatory = $false, Position = 11, HelpMessage = "Email attachment content id." )]
        [string] $AttachmentContentId,
        [Parameter(Mandatory = $false, Position = 12, HelpMessage = "Retry time if error." )]
        [TimeSpan]  $TTL     = (New-TimeSpan -days 1),
        [Parameter(Mandatory = $false, Position = 13, HelpMessage = "Pause between retries in seconds." )]
        [int16]  $PauseBetweenTries   = 30
    )

    $emailMessage                 = New-Object System.Net.Mail.MailMessage
    $emailMessage.From            = $From
    $emailMessage.Subject         = $Subject
    $emailMessage.SubjectEncoding = [System.Text.Encoding]::UTF8
    $emailMessage.IsBodyHtml      = $HtmlBody
    $emailMessage.Body            = $Body
    $emailMessage.BodyEncoding    = [System.Text.Encoding]::UTF8
    $emailMessage.To.add($To)

    if ($Attachment) {
        $Attach = new-object Net.Mail.Attachment($Attachment)
        $Attach.ContentId = $AttachmentContentId
        $emailMessage.Attachments.Add($Attach)
    }


    $smtp = New-Object net.mail.SMTPClient($SmtpServer, $Port)
    if ($SSL){
        try {
            if ([Net.ServicePointManager]::SecurityProtocol -notcontains 'Tls12') {
                [Net.ServicePointManager]::SecurityProtocol +=  [Net.SecurityProtocolType]::Tls12
            }
            [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        }
        Catch {
            Write-Error $_
        }
        $smtp.EnableSSL = $SSL
    }
    if ($user) {
        $Credentials  = New-Object System.Net.NetworkCredential((Get-VarToString $user), (Get-VarToString $Password))
        $smtp.Credentials = $Credentials
    }

    # $ScriptBlock = {
    #     param(
    #         [string]                        $Attachments,
    #         [string]                        $Bcc,
    #         [string]                        $Body,
    #         [switch]                        $BodyAsHtml,
    #         [Encoding]                      $Encoding,
    #         [string]                        $Cc,
    #         [DeliveryNotificationOptions]   $DeliveryNotificationOption,
    #         [string]                        $From,
    #         [string]                        $SmtpServer,
    #         [MailPriority]                  $Priority,
    #         [string]                        $ReplyTo,
    #         [string]                        $Subject,
    #         [string]                        $To,
    #         [PSCredential]                  $Credential,
    #         [switch]                        $UseSsl,
    #         [int32]                         $Port,
    #         [TimeSpan]                      $TTL,
    #         [int16]                         $PauseBetweenTries,
    #         [string]                        $logFilePath
    #     )

    #     $Success  = $null
    #     $Start    = get-date
    #     $Interval = New-TimeSpan -Start (Get-Date)

    #     while ((-not $Success) -and ($Interval -lt $TTL)) {

    #         try {
    #             $MailParams = @{}
    #             $MailParams += @{Attachments = $Attachments}
    #             Send-MailMessage

    #             $Success = $true
    #         }
    #         catch {
    #             Add-ToLog -Message $_ -logFilePath $logFilePath -Status "Error"
    #             Start-Sleep -Seconds $PauseBetweenTries
    #         }
    #         $Interval = New-TimeSpan -Start $Start
    #     }
    # }

    # $EmailLogFilePath = "$($Global:ProjectRoot)\$($Global:gsLOGSFolder)\Email.log"
    #Start-Job -ScriptBlock $ScriptBlock -ArgumentList $SMTP, $emailMessage, $TTL, $PauseBetweenTries, $EmailLogFilePath

    $Success  = $False
    $Start    = get-date
    $Interval = New-TimeSpan -Start $Start

    while ((-not $Success) -and ($Interval -lt $TTL)) {
        try {
            $smtp.Send($emailMessage)
            $Success = $true
        }
        catch {
            Add-ToLog -Message $_ -logFilePath $EmailLogFilePath -Status "Error"
            Start-Sleep -Seconds $PauseBetweenTries
        }
        $Interval = New-TimeSpan -Start $Start
    }
}
Function New-TelegramMessage {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        Function to send telegram message.
    .EXAMPLE
        Parameter set: "Proxy"
            New-TelegramMessage -Token $Token -ChatID $ChatID -Message $Message [-ProxyURL $ProxyURL] [-Credentials $Credentials] [-TTL $TTL=(New-TimeSpan -Days 1)] [-PauseBetweenTries $PauseBetweenTries=30]
#>
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Telegram token." )]
        [ValidateNotNullOrEmpty()]
        [securestring]$Token,
        [Parameter( Mandatory = $true, Position = 1, HelpMessage = "Telegram chat id." )]
        [ValidateNotNullOrEmpty()]
        [securestring]$ChatID,
        [Parameter( Mandatory = $true, Position = 2, HelpMessage = "Message." )]
        [ValidateNotNullOrEmpty()]
        [string]$Message,
        [Parameter( Mandatory = $false, Position = 3, HelpMessage = "Proxy URL." , ParameterSetName = "Proxy")]
        [string]$ProxyURL,
        [Parameter( Mandatory = $false, Position = 4, HelpMessage = "Proxy credentials." , ParameterSetName = "Proxy")]
        [System.Management.Automation.PSCredential] $Credentials,
        [Parameter( Mandatory = $false, Position = 5, HelpMessage = "Message time to live in seconds. Use in case of errors." )]
        [TimeSpan]$TTL = (New-TimeSpan -Days 1),
        [Parameter(Mandatory  = $false, Position = 6, HelpMessage = "Pause between retries in seconds." )]
        [int16]  $PauseBetweenTries   = 30


    )

    try {
        if ([Net.ServicePointManager]::SecurityProtocol -notcontains 'Tls12') {
            [Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12
        }
        [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    }
    Catch {
        Add-ToLog -Message "Error while enabling TLS mode [Tls12]!" -Status "Error" -Display -logFilePath $Global:gsScriptLogFilePath
    }

    $URI  = "https://api.telegram.org/bot" + (Get-VarToString $Token) + "/sendMessage?chat_id=" + (Get-VarToString $ChatID) + "&text=" + $Message

    if ($ProxyURL) {
        [system.net.webrequest]::defaultwebproxy                    = New-Object system.net.webproxy($ProxyURL)
        [system.net.webrequest]::defaultwebproxy.credentials        = $Credentials
        [system.net.webrequest]::defaultwebproxy.BypassProxyOnLocal = $true
    }

    #function Send-Telegram {
    $ScriptBlock = {
        param(
            [string]    $URI,
            [TimeSpan]  $TTL,
            [int16]     $PauseBetweenTries,
            [string]    $logFilePath,
            [string]    $Message
        )
        Import-Module -name AlexkUtils

        $WebRequestSuccess = $null
        $Start             = Get-Date
        $Interval          = New-TimeSpan -Start $Start

        while ((-not $WebRequestSuccess) -and ($Interval -lt $TTL)) {

            try {
                $Response = Invoke-RestMethod -Uri $URI
                switch ($Response.ok) {
                   $true {
                        $WebRequestSuccess = $True
                    }
                    Default {
                        Start-Sleep -Seconds $PauseBetweenTries
                    }
                }
                Add-ToLog -Message $Message -logFilePath $logFilePath -Status "Info"
            }
            catch {
                Add-ToLog -Message "$Message [$_]" -logFilePath $logFilePath -Status "Error"
                Start-Sleep -Seconds $PauseBetweenTries
            }
            $Interval          = New-TimeSpan -Start $Start
        }
    }

    $TelegramLogFilePath = "$($Global:ProjectRoot)\$($Global:gsLOGSFolder)\Telegram.log"
    Start-Job -ScriptBlock $ScriptBlock -ArgumentList $URI, $TTL, $PauseBetweenTries, $TelegramLogFilePath, $Message
    #Send-Telegram $URI $TTL $PauseBetweenTries $TelegramLogFilePath $Message
}
#endregion
#region HTML
Function Get-HTMLTable {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        Create html table code.
    .EXAMPLE
        Get-HTMLTable -Array $Array
#>
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Array with table data." )]
        [ValidateNotNullOrEmpty()]
        [array]$Array
    )
    [string]$HTML = ""
    if ($Array.count -gt 0) {
        foreach ($item in $Array) {
            if ($item -ne "") {
                $HTML += (Get-HTMLRow $item) + "`n"
            }
        }
    }
    Return $HTML
}
function Get-HTMLRow {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        Create html table row code.
    .EXAMPLE
        Get-HTMLRow -Line $Line [-ColSpan $ColSpan=0]
#>
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Array with row data." )]
        [ValidateNotNullOrEmpty()]
        [array]$Line,
        [Parameter( Mandatory = $false, Position = 1, HelpMessage = "HTML column span data." )]
        [int16]$ColSpan = 0
    )
    function Get-HTMLRowFullness {
    <#
        .SYNOPSIS
            AUTHOR Alexk
            DATE   25.10.20
            VER    1
        .DESCRIPTION
            Return number of not empty columns.
        .EXAMPLE
            Get-HTMLRowFullness -Line $Line
    #>
        [CmdletBinding()]
        Param(
            [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Array of columns." )]
            [ValidateNotNullOrEmpty()]
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

    $row = ""
    if ($Line.count -gt 0) {
        $rows = ""
        $row = @"
            <tr>
                %row%
            </tr>
"@
        if (( Get-HTMLRowFullness $Line) -gt 1){
            foreach ($col in ($Line[0].PSObject.Properties.Name )) {
                $rows += (Get-HTMLCol $Line.$col $ColSpan) + "`n"
            }
            $row = $row.Replace("%row%", $rows)
        }
        Else{
            $ColCount  = $Line[0].PSObject.Properties.Name.count
            $Col       = $Line[0].PSObject.Properties.Name[0]
            $ColSpan   = $ColCount
            $bold      = $true
            $rows     += (Get-HTMLCol -Column $Line.$col -ColSpan $ColSpan -Bold $bold) + "`n"
            $row       = $Row.Replace("%row%", $rows)
        }
    }
    return $row
}
Function Get-HTMLCol  {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        Create html table row code.
    .EXAMPLE
        Get-HTMLCol -Column $Column [-ColSpan $ColSpan=0] [-Bold $Bold=$false]
#>
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Column text." )]
        [ValidateNotNullOrEmpty()]
        [string]$Column,
        [Parameter( Mandatory = $false, Position = 1, HelpMessage = "HTML column span data."  )]
        [Int16]$ColSpan = 0,
        [Parameter( Mandatory = $false, Position = 2, HelpMessage = "Bold font."  )]
        [bool]$Bold = $false
    )
    $Column = $Column.Trim()
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
    $col = $col.Replace("%String%", $Column)
    return $col
}
Function Get-ContentFromHTMLTemplate {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        Create html file from template.
    .EXAMPLE
        Get-ContentFromHTMLTemplate -HTMLData $HTMLData -ColNames $ColNames -HTMLTemplateFile $HTMLTemplateFile [-HTMLFile $HTMLFile]
#>
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "HTML code." )]
        [ValidateNotNullOrEmpty()]
        [string]$HTMLData,
        [Parameter( Mandatory = $true, Position = 1, HelpMessage = "Column names." )]
        [array]$ColNames,
        [Parameter( Mandatory = $true, Position = 2, HelpMessage = "Path to HTML template file." )]
        [string]$HTMLTemplateFile,
        [Parameter( Mandatory = $false, Position = 3, HelpMessage = "Path to new HTML file." )]
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
    if ($HTMLFile) {
        $HTMLTemplate | Out-File $HTMLFile -Encoding utf8 -Force
    }
    return $HTMLTemplate
}
#endregion
#region Array
function Get-UniqueArrayMembers {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   10.04.20
        VER    1
    .DESCRIPTION
        Return row with unique elements in column.
    .EXAMPLE
        Get-UniqueArrayMembers -Array $Array -ColumnName $ColumnName
#>
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Data array." )]
        [ValidateNotNullOrEmpty()]
        [array] $Array,
        [Parameter( Mandatory = $true, Position = 1, HelpMessage = "Array column name." )]
        [string] $ColumnName
    )
    [array]$ColumnData = @()
    [array]$Res = @()
    foreach ($item in $array) {
        if ($ColumnData -notcontains $item.$ColumnName -and ($item.$ColumnName)) {
            $ColumnData += $item.$ColumnName
            $Res += $item
        }
    }
    return $Res
}
Function Get-DifferenceBetweenArrays {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   14.04.20
        VER    1
    .DESCRIPTION
        First and second arrays should be the same structure.
        Return array with objects absent in first array.
    .EXAMPLE
        Get-DifferenceBetweenArrays -FirstArray $FirstArray -SecondArray $SecondArray
#>
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "First array." )]
        [ValidateNotNullOrEmpty()]
        [Array] $FirstArray,
        [Parameter( Mandatory = $true, Position = 1, HelpMessage = "Second array." )]
        [ValidateNotNullOrEmpty()]
        [Array] $SecondArray
    )
    [Array] $Res = @()
    [Array] $Columns = $FirstArray | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
    [Array] $NoteProperties1 = $FirstArray | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
    [Array] $NoteProperties2 = $SecondArray | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name
    [Array] $NoteProperties1WithType = @()
    [Array] $NoteProperties2WithType = @()
    [string] $NoteProperties2WithTypeText = ""
    [string] $NoteProperties1WithTypeText = ""
    [int]   $FirstArrayCount = $FirstArray.Count
    [int]   $SecondArrayCount = $SecondArray.Count
    if ($FirstArrayCount) {
        foreach ($note in $NoteProperties1) {
            $PSO = [PSCustomObject]@{
                Name = $note
                Type = $FirstArray[0].$note.GetType()
            }
            $NoteProperties1WithType += $PSO
            $NoteProperties1WithTypeText += "$note($($PSO.type)),"
        }
    }
    if ($SecondArrayCount) {
        foreach ($note in $NoteProperties2) {
            $PSO = [PSCustomObject]@{
                Name = $note
                Type = $SecondArray[0].$note.GetType()
            }
            $NoteProperties2WithType += $PSO
            $NoteProperties2WithTypeText += "$note($($PSO.type)),"
        }
    }

    $NoteProperties1WithTypeText = $NoteProperties1WithTypeText.Remove($NoteProperties1WithTypeText.ToCharArray().count - 1)
    $NoteProperties2WithTypeText = $NoteProperties2WithTypeText.Remove($NoteProperties2WithTypeText.ToCharArray().count - 1)

    if ($NoteProperties1WithTypeText -eq $NoteProperties2WithTypeText) {
        foreach ($Item in $SecondArray ) {
            $NotExist = $True
            foreach ($Item1 in $FirstArray) {
                #Write-Host $Item
                #Write-Host $Item1
                #Write-host ""
                $ColumnEqual = $True
                foreach ($Column in  $Columns) {
                    if ([string]$Item.$Column -ne [string]$item1.$Column) {
                        #write-host $Item.$Column
                        #Write-Host $Item1.$Column
                        $ColumnEqual = $False
                    }
                }
                if ($ColumnEqual) {
                    $NotExist = $False
                    break
                }

            }
            If ($NotExist) {
                $Res += $item
            }
        }
        Return $res
    }
    Else {
        Write-Host "Arrays does not have equal structure! [$NoteProperties1WithTypeText] != [$NoteProperties2WithTypeText]" -ForegroundColor red
        Return $res
    }

}
Function Join-Array {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   23.06.20
        VER    1
    .DESCRIPTION
        Function to union two array by key argument.
    .EXAMPLE
        Join-Array -PrimaryPSO $PrimaryPSO -SecondaryPSO $SecondaryPSO -Key $Key [-MergeColumns $MergeColumns]
#>
    [CmdletBinding()]
    [OutputType([array])]
    param(
        [Parameter(Mandatory = $true, Position = 1, HelpMessage = "Base PSO.")]
        [PSCustomObject] $PrimaryPSO,
        [Parameter(Mandatory = $true, Position = 2, HelpMessage = "PSO with data to merge.")]
        [PSCustomObject] $SecondaryPSO,
        [Parameter(Mandatory = $true, Position = 3, HelpMessage = "Merge keys of primary and secondary arrays.")]
        [Array] $Key,
        [Parameter(Mandatory = $false, Position = 4, HelpMessage = "Merge columns.")]
        [array] $MergeColumns
    )
    [array] $Output = @()
    $PrimaryPSOColumns   = ($PrimaryPSO   | Get-Member -type NoteProperty).name
    $SecondaryPSOColumns = ($SecondaryPSO | Get-Member -type NoteProperty).name
    foreach ( $PrimaryItem in $PrimaryPSO ) {
        foreach ( $SecondaryItem in $SecondaryPSO ) {
            if ( $PrimaryItem.($Key[0]) -eq $SecondaryItem.($Key[1]) ) {
                if ( $MergeColumn ) {
                    foreach ( $MergeColumn in $MergeColumns ) {
                        $PrimaryItem | Add-Member -MemberType NoteProperty -Name $MergeColumn -Value $SecondaryItem.$MergeColumn
                    }
                    $Output += $PrimaryItem
                }
                Else {
                    foreach ( $Column in $SecondaryPSOColumns ) {
                        if ( ($Column -ne $Key[1]) ) {
                            if ( $PrimaryPSOColumns -NotContains $Column ) {
                                $PrimaryItem | Add-Member -MemberType NoteProperty -Name $Column -Value $SecondaryItem.$Column
                            }
                            Else {
                                [int] $Counter = 1
                                do {
                                    $NewColumn = "$Column$Counter"
                                    $Counter ++
                                } until ($PrimaryPSOColumns -NotContains $NewColumn)
                                $PrimaryItem | Add-Member -MemberType NoteProperty -Name $NewColumn -Value $SecondaryItem.$Column
                            }
                        }
                    }
                    $Output += $PrimaryItem
                }
            }
        }
    }

    return $Output
}
#endregion
#region Invoke
Function Start-PSScript {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        Function to start powershell script or command.
    .EXAMPLE
        Parameter set: "Script"
            Start-PSScript -ScriptPath $ScriptPath -logFilePath $logFilePath [-Arguments $Arguments] [-Credentials $Credentials] [-WorkDir $WorkDir] [-Evaluate $Evaluate] [-DebugRun $DebugRun] [-Wait $Wait] [-Program $Program="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"]
        Parameter set: "ScriptBlock"
            Start-PSScript -ScriptBlock $ScriptBlock -logFilePath $logFilePath [-Arguments $Arguments] [-Credentials $Credentials] [-WorkDir $WorkDir] [-Evaluate $Evaluate] [-DebugRun $DebugRun] [-Wait $Wait] [-Program $Program="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"]
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Script path." , ParameterSetName = "Script" )]
        [ValidateNotNullOrEmpty()]
        [string] $ScriptPath,
        [Parameter(Mandatory = $true, Position = 1, HelpMessage = "Script block to execute." , ParameterSetName = "ScriptBlock" )]
        [scriptblock] $ScriptBlock,
        [Parameter(Mandatory = $false, Position = 2, HelpMessage = "Arguments." )]
        [string] $Arguments,
        [Parameter(Mandatory = $false, Position = 3, HelpMessage = "Credentials." )]
        [System.Management.Automation.PSCredential]  $Credentials,
        [Parameter(Mandatory = $true, Position = 4, HelpMessage = "Log file path." )]
        [ValidateNotNullOrEmpty()]
        [string] $logFilePath,
        [Parameter(Mandatory = $false, Position = 5, HelpMessage = "Working directory." )]
        [string] $WorkDir,
        [Parameter(Mandatory = $false, Position = 6, HelpMessage = "Use elevated rights." )]
        [switch]   $Evaluate,
        [Parameter(Mandatory = $false, Position = 7, HelpMessage = "Debug run." )]
        [switch]   $DebugRun,
        [Parameter(Mandatory = $false, Position = 8, HelpMessage = "Wait for result." )]
        [switch]   $Wait,
        [Parameter(Mandatory = $false, Position = 9, HelpMessage = "Program path to execute." )]
        [string]   $Program = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    )
<#
    1	-EncodedCommand <Base64EncodedCommand>	Accepts a base-64-encoded string version of a command. This is useful when you need to submit Powershell commands with complex quotation marks or curly braces
    2	-ExecutionPolicy <ExecutionPolicy> 	This parameter sets the default execution policy for the current session. The execution policy is saved in the $env:PSExecutionPolicyPreference. This does not modify the execution policy set in the registry.
    3	-File <FilePath> [<Parameters>]	Specifies a script to run. It accepts the scripts parameters.
    4	-InputFormat {Text | XML}	Describes the format of data sent to PowerShell. Valid values are “Text” (text strings) or “XML”
    5	-Mta	Starts PowerShell using a multi-threaded apartment. Multi-threaded apartment (MTA) is the default for PowerShell 2.0. The default in PowerShell 3.0 is single-threaded apartment (STA)
    6	-Sta	Starts Windows PowerShell using a single-threaded apartment
    7	-NoExit	If specified, PowerShell will not exit after execution
    8	-NoLogo	Hides the Copyright information that normally displays when PowerShell starts.
    9	-NonInteractive 	Executes without presenting an interactive prompt to the user
    10	-NoProfile	Starts without loading the Windows PowerShell profile
    11	-OutputFormat	Sets the formatting of the output from Windows PowerShell. Valid values are “Text” or “XML”
    12	-PSConsoleFile <FilePath>	Loads the Windows PowerShell console file specified in <FilePath>
    13	-Version <Windows PowerShell Version> 	Starts Windows PowerShell with the specified version. Valid values are 2.0 and 3.0.
    14	-WindowStyle <Window Style> 	Sets the window style for the session. Valid values are Normal, Minimized, Maximized and Hidden.
    15	-Command 	Executes the command specified. The value of Command can be “-“, a string. or a script block. Script blocks must be enclosed in braces ({})
    16	-Help, -?, /? 	Displays help for PowerShell.exe. You can use PowerShell.exe -Help, PowerShell.exe -? or PowerShell.exe /?
#>
    if ($ScriptPath){
        $Message               = "Starting powershell script [$ScriptPath]"
    }
    if ($ScriptBlock){
        $Message               = "Starting powershell scriptblock"
    }
    if ($DebugRun){
        $PowershellArguments += " -NoExit"
    }
    Else {
        $PowershellArguments += " -NonInteractive -NoLogo"
    }
    if ($ScriptBlock) {
        $PowershellArguments += " -ExecutionPolicy Bypass –NoProfile -Command $ScriptBlock"
    }
    else {
        $PowershellArguments += " -ExecutionPolicy Bypass –NoProfile -file `"$ScriptPath`""
    }
    if($Arguments){
        $PowershellArguments += " $Arguments"
    }

    if ($Evaluate -and (($Credentials))) {
        # if($Credentials){
        #     if ($DebugRun){
        #         [string]$NestedScriptBlock = {
        #             $ScriptBlock = {%ScriptBlock%}
        #             $Res = Start-PSScript -ScriptBlock $ScriptBlock -logFilePath "%LogFilePath%" -DebugRun -Evaluate
        #             $Res
        #         }
        #         $OutputXMLPath     = "$ProjectRoot\$($Global:gsDATAFolder)\ScriptBlockOutput.xml"
        #         [string]$End = {
        #             if($Res){
        #                 $Res | Export-Clixml -path "%OutputXMLPath%" -Encoding utf8 -Force
        #             }
        #         }
        #         $ScriptBlockNew    = [string]$ScriptBlock + $End
        #         $NestedScriptBlock = $NestedScriptBlock.Replace("%ScriptBlock%", $ScriptBlockNew)
        #         $NestedScriptBlock = $NestedScriptBlock.Replace("%LogFilePath%", $logFilePath)
        #         $NestedScriptBlock = $NestedScriptBlock.Replace("%OutputXMLPath%", $OutputXMLPath)
        #         $NestedScriptBlock = $NestedScriptBlock.Replace("%DATAFolder%", $Global:gsDATAFolder)
        #         write-host $NestedScriptBlock
        #         [scriptblock]$NestedScriptBlock = [scriptblock]::Create($NestedScriptBlock)
        #         Start-PSScript -ScriptBlock $NestedScriptBlock -logFilePath $logFilePath -Credentials $Credentials -DebugRun
        #     }
        #     Else{
        #         [string]$NestedScriptBlock = {
        #             $ScriptBlock = { %ScriptBlock% }
        #             Start-PSScript -ScriptBlock $ScriptBlock -logFilePath "%LogFilePath%" -Evaluate
        #         }
        #         $OutputXMLPath = "$ProjectRoot\$($Global:gsDATAFolder)\ScriptBlockOutput.xml"
        #         [string]$End = {
        #             if ($Res) {
        #                 $Res | Export-Clixml -path "%OutputXMLPath%" -Encoding utf8 -Force
        #             }
        #         }
        #         $ScriptBlockNew = [string]$ScriptBlock + $End
        #         $NestedScriptBlock = $NestedScriptBlock.Replace("%ScriptBlock%", $ScriptBlockNew)
        #         $NestedScriptBlock = $NestedScriptBlock.Replace("%LogFilePath%", $logFilePath)
        #         $NestedScriptBlock = $NestedScriptBlock.Replace("%OutputXMLPath%", $OutputXMLPath)
        #         $NestedScriptBlock = $NestedScriptBlock.Replace("%DATAFolder%", $Global:gsDATAFolder)
        #         [scriptblock]$NestedScriptBlock = [scriptblock]::Create($NestedScriptBlock)

        #         Start-PSScript -ScriptBlock $NestedScriptBlock -logFilePath $logFilePath -Credentials $Credentials
        #     }
        # }
    }
    Else  {
        Add-ToLog -Message "$Message." -logFilePath $logFilePath -Display -Status "Info"

        $Params = @{
            Program        = $Program
            Arguments      = $PowershellArguments
            Credentials    = $Credentials
            LogFilePath    = $logFilePath
            WorkDir        = $WorkDir
        }
        If ($Wait){
            $Params += @{ Evaluate = $true }
        }
        If ($DebugRun){
            $Params += @{ DebugRun = $true }
        }
        If ($Wait){
            $Params += @{ Wait = $true }
        }

        $Res = Start-Program @Params
    }
    Return $Res
}
function Import-ModuleRemotely {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        Import powershell module to the remote session.
    .EXAMPLE
        Import-ModuleRemotely -Modules $Modules -Session $Session
#>
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Local powershell module name." )]
        [ValidateNotNullOrEmpty()]
        [string[]] $Modules,
        [Parameter( Mandatory = $true, Position = 1, HelpMessage = "Powershell session." )]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.RunSpaces.PSSession] $Session
    )

    $ModuleList = @()
    $LastmodSuppressOutput = $Global:modSuppressOutput
    foreach ($Module in $Modules){

        $Res = Import-Module $Module -PassThru
        if ( !$Res )
        {
            Write-Warning "Local module does not exist [$Module]";
            return;
        }
        Else {
            $ModuleList += $Res
        }
    }
    $Global:modSuppressOutput = $LastmodSuppressOutput

    $ScriptBlock = {
        $Modules           = $using:ModuleList
        #[string]   $Definition        = $using:Module.Definition
        ##### Init remote variables
        [string]   $Global:gsScriptLocalHost     = $using:gsScriptLocalHost
        [array]    $Global:gsLogBuffer           = @()
        [string]   $Global:gsScriptLogFilePath   = $using:gsScriptLogFilePath
        [string]   $Global:gsParentLevel         = $using:gsParentLevel
        [string]   $Global:gsLogFileNamePosition = $using:gsLogFileNamePosition
        $Global:gsRunningCredentials             = [System.Security.Principal.WindowsIdentity]::GetCurrent()

        foreach ($Module in $Modules){
            $ScriptBlock     = {
                $ModuleName = $Module.name
                if (Get-Module $ModuleName)
                {
                    Remove-Module $ModuleName -Force
                }

                $Definition = $Module.Definition
                $SB = [ScriptBlock]::Create($Definition)
                $Res = New-Module -Name $ModuleName -ScriptBlock $SB | Import-Module -Force -PassThru

                if ( $Res ) {
                    [bool]     $Global:modSuppressOutput     = $using:LastmodSuppressOutput
                    #Write-Host "Imported module [$Res] in remote session."
                    #Write-Host "$(Get-Module $ModuleName | Select-Object -ExpandProperty ExportedCommands | Out-String)"
                }
            }
            . ([ScriptBlock]::Create($ScriptBlock))
        }

    }

    invoke-command -session $Session -scriptblock $ScriptBlock;
}
function Invoke-PSScriptBlock {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   08.04.20
        VER    1
    .DESCRIPTION
        Function to automate remote PS session or execute scripts locally
    .EXAMPLE
        Parameter set: "Remote"
            Invoke-PSScriptBlock -ScriptBlock $ScriptBlock [-Computer $Computer] [-Credentials $Credentials] [-ImportLocalModule $ImportLocalModule] [-TestComputer $TestComputer] [-ExportedParameters $ExportedParameters] [-SessionOptions $SessionOptions] [-NewSession $NewSession]
#>
    [CmdletBinding()]
    Param (
        [Parameter( Mandatory = $True, Position = 0, HelpMessage = "Script block." )]
        [ValidateNotNullOrEmpty()]
        [scriptblock] $ScriptBlock,
        [Parameter( Mandatory = $False, Position = 1, ParameterSetName = "Remote", HelpMessage = "Remote computer name." )]
        [string] $Computer,
        [Parameter( Mandatory = $False, Position = 2, ParameterSetName = "Remote", HelpMessage = "Remote credentials." )]
        [System.Management.Automation.PSCredential]  $Credentials,
        [Parameter( Mandatory = $False, Position = 3, ParameterSetName = "Remote", HelpMessage = "Local modules to import to remote session." )]
        [string[]]  $ImportLocalModule,
        [Parameter( Mandatory = $False, Position = 4, ParameterSetName = "Remote", HelpMessage = "Test-connection before session." )]
        [Switch]  $TestComputer,
        [Parameter( Mandatory = $False, Position = 5, ParameterSetName = "Remote", HelpMessage = "Array of exported parameters." )]
        $ExportedParameters,
        [Parameter( Mandatory = $False, Position = 6, ParameterSetName = "Remote", HelpMessage = "PS session options." )]
        $SessionOptions,
        [Parameter( Mandatory = $False, Position = 6, ParameterSetName = "Remote", HelpMessage = "Run new session with host and credentials if already exist." )]
        [switch] $NewSession
    )

    $Res = $null


    try {
        $StartParams = @{}
        if ( $Computer ) {
            if ( $TestComputer ) {
                $Connection = Test-Connection -ComputerName $Computer -count 2 -Delay 1 -Quiet
                if ( !$Connection ){
                    Write-host  "Unable to ping $Computer!" -ForegroundColor red
                }
            }
            Else {
                $Connection = $true
            }

            if ( $Connection ) {
                $StartParams += @{ Computer = $Computer }
                if ( $SessionOptions ) {
                    $StartParams += @{ SessionOption = $SessionOptions }
                }

                if ( $Credentials ) {
                    $StartParams += @{ Credential = $Credentials }
                }

                If ( $NewSession ) {
                    $Global:modSessionParams = $StartParams
                    $Global:modSession       = New-PSSession @StartParams
                    $Global:modPSSessionCounter ++
                    Write-verbose "Create new session $($Global:modSession.id)."
                }
                Else {
                    if ( $Global:modSession ) {
                        $Diff = $False
                        foreach ( $Item in $Global:modSessionParams.Keys ){
                            if ( $Global:modSessionParams.$Item -ne $StartParams.$Item ) {
                                $Diff = $True
                            }
                        }
                        foreach ( $Item in $StartParams.Keys ){
                            if ( $Global:modSessionParams.$Item -ne $StartParams.$Item ) {
                                $Diff = $True
                            }
                        }
                        if ( $Diff ){
                            $Global:modSessionParams = $StartParams
                            $Global:modSession       = New-PSSession @StartParams
                            $Global:modPSSessionCounter ++
                            Write-verbose "Create new session $($Global:modSession.id)."
                        }
                        Else {
                            Write-verbose "Reuse session $($Global:modSession.id)."
                        }
                    }
                    Else {
                        $Global:modSessionParams = $StartParams
                        $Global:modSession       = New-PSSession @StartParams
                        $Global:modPSSessionCounter ++
                        Write-verbose "Create new session $($Global:modSession.id)."
                    }
                }

                if ( $Global:modSession ){
                    if ( $ImportLocalModule ){
                        Import-ModuleRemotely -Modules $ImportLocalModule -Session $Global:modSession
                    }
                }
                Else {
                    Add-ToLog -Message "[Error] $_" -logFilePath $Global:gsScriptLogFilePath -Display -Status "Error"
                }
            }
        }
        Else {
            $Global:modSession = $Null
        }
    }
    Catch {
        if ( $Global:modSession ){
            Remove-PSSession $Global:modSession
            $Global:modPSSessionCounter --
            Write-verbose "Remove session $($Global:modSession.id)."
        }
        Get-ErrorReporting $_
        # Write-Host "Invoke-PSScriptBlock: Unable to establish remote session to $Computer" -ForegroundColor Red
        # Write-Host "$_" -ForegroundColor Red
        $Global:modSession = $Null
        exit
    }

    if ( $Global:modSession ) {
        if ( $ExportedParameters ){
            Set-Variable -Name "GlobalExportedParameters" -Value $ExportedParameters -Scope "Global" #-Visibility Private
            $GlobalExportedParameters.Remove("Computer")    | Out-Null
            $GlobalExportedParameters.Remove("Credentials") | Out-Null

            $NewStrings = '
                $Params = $Using:GlobalExportedParameters
            '
            $ScriptBlockWithExportedParams = $ScriptBlock.ToString()
            $FirstString = ($ScriptBlockWithExportedParams -split "`n")[1]
            $ScriptBlockWithExportedParams = $ScriptBlockWithExportedParams.Replace("Using:", "Params.")
            $ScriptBlockWithExportedParams = $ScriptBlockWithExportedParams.Replace("using:", "Params.")
            $ScriptBlockWithExportedParams = $ScriptBlockWithExportedParams.Replace("USING:", "Params.")

            if ( $FirstString -notlike "*param*(*)*" ) {
                $ScriptBlockWithExportedParams = $NewStrings + $ScriptBlockWithExportedParams
            }

            $ScriptBlockWithExportedParams = [scriptblock]::Create($ScriptBlockWithExportedParams)

            if ( $FirstString -notlike "*param*(*)*" ) {
                $Res = Invoke-Command -Session $Global:modSession -ScriptBlock $ScriptBlockWithExportedParams
            }
            Else {
                $ArgsArray = @()
                foreach ( $Item in $GlobalExportedParameters.keys ) {
                    $ArgsArray += ,$GlobalExportedParameters.$Item
                }

                $Res = Invoke-Command -Session $Global:modSession -ScriptBlock $ScriptBlockWithExportedParams -ArgumentList $ArgsArray
            }
            Remove-Variable -Name "GlobalExportedParameters"  -Scope "Global" -Force | Out-Null
        }
        Else {
            $Res = Invoke-Command -Session $Session -ScriptBlock $ScriptBlock
        }
        if ( $NewSession ){
            Remove-PSSession $Session
            $Global:modPSSessionCounter --
            Write-verbose "Remove session $($Global:modSession.id)."
        }
    }
    Else {
        $LocalScriptBlock = [scriptblock]::Create($ScriptBlock.ToString().Replace("Using:", ""))
        $Res = Invoke-Command -ScriptBlock $LocalScriptBlock
    }

    return $Res
}
Function Start-Program {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   10.05.20
        VER    1
    .DESCRIPTION
        Function to start os executable file.
    .EXAMPLE
        Start-Program -LogFilePath $LogFilePath [-Program $Program] [-Arguments $Arguments] [-Credentials $Credentials] [-WorkDir $WorkDir] [-Evaluate $Evaluate] [-DebugRun $DebugRun] [-Wait $Wait]
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false, Position = 0, HelpMessage = "Program path to execute." )]
        [ValidateNotNullOrEmpty()]
        [string]    $Program,
        [Parameter(Mandatory = $false, Position = 1, HelpMessage = "Arguments." )]
        [string] $Arguments,
        [Parameter(Mandatory = $false, Position = 2, HelpMessage = "Credentials." )]
        [System.Management.Automation.PSCredential]  $Credentials,
        [Parameter(Mandatory = $true, Position = 3, HelpMessage = "Log file path." )]
        [ValidateNotNullOrEmpty()]
        [string]    $LogFilePath,
        [Parameter(Mandatory = $false, Position = 4, HelpMessage = "Working directory." )]
        [string]    $WorkDir,
        [Parameter(Mandatory = $false, Position = 5, HelpMessage = "Use elevated rights." )]
        [switch]    $Evaluate,
        [Parameter(Mandatory = $false, Position = 6, HelpMessage = "Debug run." )]
        [switch]    $DebugRun,
        [Parameter(Mandatory = $false, Position = 7, HelpMessage = "Wait for result." )]
        [switch]    $Wait
    )

    $ProcessInfo                        = New-Object -TypeName System.Diagnostics.ProcessStartInfo
    $ProcessInfo.FileName               = $Program
    $ProcessInfo.UseShellExecute        = $false
    $ProcessInfo.RedirectStandardError  = $true
    #$ProcessInfo.RedirectStandardOutput = $true
    $ProcessInfo.CreateNoWindow         = $true

    $Message               = "User [$($RunningCredentials.Name)]. Starting program [$Program]"

    if($Credentials){
        if ($RunningCredentials.name -ne $Credentials.UserName) {
            if(!(Test-Credentials $Credentials)){
                Write-Host "Supplied credentials [$($credentials.username)] error!" -ForegroundColor red
            }

            $Message               += " as [$($Credentials.UserName)]"

            [array]    $UserArray = $Credentials.UserName.Split("\")
            $ProcessInfo.UserName = $UserArray[1]
            $ProcessInfo.Domain   = $UserArray[0]
            $ProcessInfo.Password = $Credentials.Password
        }
        Else {
            $Message               += " as [Current user]"
        }
    }
    if ($DebugRun){
       $Message                += ", with debug"
    }
    if ($Evaluate) {
        $Message               += ", with evaluate"
        $ProcessInfo.Verb = "RunAs"
    }
    if ($WorkDir) {
        $Message               += ", use work directory [$WorkDir]"
        $ProcessInfo.WorkingDirectory = "$WorkDir"
    }
    if ($Arguments){
        $Message               += ", use arguments [$Arguments]"
        $ProcessInfo.Arguments = "$Arguments"
    }

    if ($Evaluate -and (($Credentials) -or ($OutputFilePath) )) {
        Write-host "In the future. Code in progress."
    }
    Else  {
        Add-ToLog -Message "$Message." -logFilePath $logFilePath -Display -Status "Info"
        if ($Wait){
            $Process           = New-Object System.Diagnostics.Process
            $Process.StartInfo = $ProcessInfo
            $Process.Start() | Out-Null
            $Process.WaitForExit()
        }
        Else {
            $Process           = New-Object System.Diagnostics.Process
            $Process.StartInfo = $ProcessInfo
            $Process.Start() | Out-Null
        }
    }
    Return $Process
}
Function Start-Module {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   05.08.20
        VER    1
    .DESCRIPTION
        Install if not installed and start module.
    .EXAMPLE
        Start-Module -Module $Module [-Force $Force] [-InstallScope $InstallScope]
#>
    [CmdletBinding()]
    Param (
        [Parameter( Mandatory = $True, Position = 1, HelpMessage = "Module name.")]
        [string] $Module,
        [Parameter( Mandatory = $False, Position = 2, HelpMessage = "Force reload module.")]
        [switch] $Force,
        [Parameter( Mandatory = $False, Position = 3, HelpMessage = "Install scope.")]
        [string] $InstallScope
    )

    if ($Force) {
        $Res = Import-Module $Module -Force -PassThru
    }
    Else {
        $Res = Import-Module $Module -PassThru
    }

    if ( -not $Res ) {
        if ($InstallScope) {
            Install-Module -Name $Module -Scope $InstallScope
        }
        Else {
            Install-Module -Name $Module
        }

        if ($Force) {
            $Res = Import-Module $Module -Force -PassThru
        }
        Else {
            $Res = Import-Module $Module -PassThru
        }

        if (-not $res) {
            Add-ToLog "Module [$Module] could not be loaded!" -Display -Status "error" -logFilePath $Global:gsScriptLogFilePath
            exit 1
        }
    }
}
Function Invoke-CommandWithDebug {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   05.05.20
        VER    1
    .DESCRIPTION
        Function to invoke command or script with debug info.
    .EXAMPLE
        Parameter set: "Script"
            Invoke-CommandWithDebug -ScriptPath $ScriptPath [-Arguments $Arguments]
        Parameter set: "ScriptBlock"
            Invoke-CommandWithDebug -ScriptBlock $ScriptBlock [-Arguments $Arguments]
#>
    [CmdletBinding()]
    param
    (
        [Parameter( Mandatory = $true,  Position = 0, HelpMessage = "PS script path.", ParameterSetName = "Script" )]
        [ValidateNotNullOrEmpty()]
        [string] $ScriptPath,
        [Parameter( Mandatory = $true,  Position = 1, HelpMessage = "Scriptblock.", ParameterSetName = "ScriptBlock"  )]
        [ValidateNotNullOrEmpty()]
        [scriptblock] $ScriptBlock,
        [Parameter( Mandatory = $false, Position = 2, HelpMessage = "Arguments." )]
        [string] $Arguments
    )
    $EventArray = @()

    $StartTime = Get-Date
    if ($ScriptPath){
        $Res = Start-PSScript -ScriptPath $ScriptPath -Arguments $Arguments -logFilePath $Global:gsScriptLogFilePath  -Wait
    }
    ElseIf ($ScriptBlock) {
        $Res = Start-PSScript -ScriptBlock $ScriptBlock -Arguments $Arguments -logFilePath $Global:gsScriptLogFilePath  -wait
    }
    $EndTime   = Get-Date

    if (Test-ElevatedRights) {
        $Logs = Get-WinEvent -ListLog *

        Foreach ($Log in $Logs) {
            #$Log.LogName
            $Filter = @{
                LogName   = $Log.LogName
                StartTime = $StartTime
                EndTime   = $EndTime
            }
            $EventArray += Get-WinEvent -FilterHashTable $Filter -ErrorAction SilentlyContinue
        }
    }
    Else {
        Add-ToLog -Message "Need admin rights! Invoke-CommandWithDebug Aborted." -logFilePath $Global:gsScriptLogFilePath -Display -Status "Error" -Level ($Global:gsParentLevel + 1)
    }

    Return $EventArray
}
#endregion
#region Utils
Function Convert-SpecialCharacters {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   29.09.20
        VER    1
    .DESCRIPTION
        Replace special characters in string.
    .EXAMPLE
        Convert-SpecialCharacters -String $String [-Mode $Mode="wildcard"]
#>
    [OutputType([String])]
    [CmdletBinding()]
    Param (
        [Parameter( Mandatory = $True, Position = 0, HelpMessage = "String.")]
        [string] $String,
        [Parameter( Mandatory = $False, Position = 1, HelpMessage = "Special characters list.")]
        [string] $Mode = "wildcard"
    )

    switch ( $Mode.ToLower() ) {
        "wildcard" {
            [array] $SpecialCharacters = "[","]", "*", "?", "\", "/",'"'
        }
        Default {}
    }

    $StringArray = $String.ToCharArray()
    [string] $Res = ""
    foreach ( $Char in $StringArray ){
        if ( $Char -in $SpecialCharacters ) {
            $Res += "``$Char"
        }
        Else {
            $Res += $Char
        }
    }
    return [string]$res
}
function Convert-StringToDigitArray {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   06.10.20
        VER    1
    .DESCRIPTION
        Convert string to array of digit.
    .EXAMPLE
        Convert-StringToDigitArray -UserInput $UserInput
#>
    [OutputType([Int[]])]
    [CmdletBinding()]
    param(
        [Parameter( Mandatory = $True, Position = 0, HelpMessage = "String input data.")]
        [string] $UserInput
    )

    $SelectedArray = ($UserInput -split ",").trim()
    $SelectedIntervals = $SelectedArray | Where-Object { $_ -like "*-*" }
    [int[]]$SelectedArray = $SelectedArray | Where-Object { $_ -NotLike "*-*" }
    foreach ( $item in $SelectedIntervals ) {
        [int[]]$Array = $item -split "-"
        if ( $Array.count -eq 2 ) {
            if ( $Array[0] -le $Array[1] ) {
                $Begin = $Array[0]
                $End = $Array[1]
            }
            Else {
                $Begin = $Array[1]
                $End = $Array[0]
            }
            foreach ( $Element in ($begin..$end) ) {
                if ( -not ($Element -in $SelectedArray) -and ($Element -gt 0) ) {
                    $SelectedArray += $Element
                }
            }
        }

    }

    return $SelectedArray
}
function Invoke-TrailerIncrease {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
    .EXAMPLE
        Invoke-TrailerIncrease -String $String
#>

    [OutputType([string])]
    [CmdletBinding()]
    param(
        [Parameter( Mandatory = $True, Position = 0, HelpMessage = "String input data.")]
        [string] $String
    )

    [Int32] $LastDigits  = ([regex]::Matches( $String, "[0-9]+$" )).value
    if ( $LastDigits ) {
        [string] $LastDigits1 = $LastDigits + 1
        $NewString   = [regex]::Replace( $String, $LastDigits, $LastDigits1 )
    }
    Else {
        $NewString = "$($String)1"
    }

    return $NewString
}
Function Format-TimeSpan {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   21.06.20
        VER    1
    .DESCRIPTION
        Function to set time span presentation.
    .EXAMPLE
        Format-TimeSpan -TimeSpan $TimeSpan [-Format $Format="Auto"] [-Round $Round=0]
#>
    [CmdletBinding()]
    param
    (
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Time span." )]
        [ValidateNotNullOrEmpty()]
        [TimeSpan] $TimeSpan,
        [Parameter( Mandatory = $False, Position = 1, HelpMessage = "Time span format.")]
        [ValidateSet("Auto", "Ticks", "TotalDays", "TotalHours", "TotalMinutes", "TotalSeconds", "TotalMilliseconds")]
        [string] $Format = "Auto",
        [Parameter( Mandatory = $false, Position = 2, HelpMessage = "Number of digits after dot." )]
        [ValidateNotNullOrEmpty()]
        [Int16] $Round = 0
    )
    $Res = $Null
    switch ($Format) {
        "Auto" {
            if ($TimeSpan.TotalDays -ge 1 ) {
                $Res = "$([math]::round($TimeSpan.TotalDays,$Round)) days"
            }
            ElseIf ( $TimeSpan.TotalHours -ge 1 ) {
                $Res = "$([math]::round($TimeSpan.TotalHours,$Round)) hours"
            }
            ElseIf ( $TimeSpan.TotalMinutes -ge 1 ) {
                $Res = "$([math]::round($TimeSpan.TotalMinutes,$Round)) minutes"
            }
            ElseIf ( $TimeSpan.TotalSeconds -ge 1 ) {
                $Res = "$([math]::round($TimeSpan.TotalSeconds,$Round)) seconds"
            }
            ElseIf ( $TimeSpan.TotalMilliseconds -ge 1 ) {
                $Res = "$([math]::round($TimeSpan.TotalMilliseconds,$Round)) milliseconds"
            }
            ElseIf ( $TimeSpan.Ticks -ge 1 ) {
                $Res = "$([math]::round($TimeSpan.Ticks,$Round)) ticks"
            }
        }
        "TotalDays" {
            $Res = "$([math]::round($TimeSpan.TotalDays,$Round)) days"
        }
        "TotalHours" {
            $Res = "$([math]::round($TimeSpan.TotalHours,$Round)) hours"
        }
        "TotalMinutes" {
            $Res = "$([math]::round($TimeSpan.TotalMinutes,$Round)) minutes"
        }
        "TotalSeconds" {
            $Res = "$([math]::round($TimeSpan.TotalSeconds,$Round)) seconds"
        }
        "TotalMilliseconds" {
            $Res = "$([math]::round($TimeSpan.TotalMilliseconds,$Round)) milliseconds"
        }
        "Ticks" {
            $Res = "$($TimeSpan.ticks) ticks"
        }
        Default {}
    }
    return $res
}
Function Start-ParallelPortPing {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   23.06.20
        VER    1
    .DESCRIPTION
        Function to start parallel host ping with port.
        We can use port in host name.
    .EXAMPLE
        Start-ParallelPortPing -Hosts $Hosts [-Count $Count=1] [-Delay $Delay=1]
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true,  Position = 1, HelpMessage = "Network hosts array.")]
        [string[]] $Hosts,
        [Parameter(Mandatory = $false, Position = 2, HelpMessage = "Number of ping counts.")]
        [int16] $Count = 1,
        [Parameter(Mandatory = $false, Position = 3, HelpMessage = "Delay in seconds.")]
        [int16] $Delay = 1
    )

    $Jobs = @()
    foreach ($Item in $Hosts) {
        $ScriptBlock = {
            param(
                [string] $NetworkHost,
                [int16]  $Count,
                [int16]  $Delay,
                [int16]  $Port
            )
            if ($port) {
                $Ping = Test-Connection $NetworkHost -TcpPort $Port -Quiet
            }
            Else {
                $Ping = Test-Connection $NetworkHost -Quiet -Count $Count -Delay $Delay
            }
            $PSO = [PSCustomObject]@{
                Host  = [string]$NetworkHost
                Port  = [int16] $Port
                Count = [int16] $Count
                Delay = [int16] $Delay
                Ping  = [bool]  $Ping
            }
            Return  $PSO
        }

        $HostArray = @($item.split(":"))
        if ($HostArray.count -eq 2) {
            $NetworkHost = $HostArray[0]
            $Port = [int16]$HostArray[1]
        }
        Else {
            $NetworkHost = $item
            $Port = 0
        }
        $Jobs += (Start-Job $ScriptBlock -ArgumentList $NetworkHost, $Count, $Delay, $Port)
    }

    While ( $Jobs.state -contains "Running" ) {
        Start-Sleep -Milliseconds 300
    }

    $Res = $Jobs | Receive-Job
    $Jobs | Remove-Job | Out-Null

    Return $Res
}
Function Convert-FSPath {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   29.04.20
        VER    1
    .DESCRIPTION
        Function to convert path from UNC to local or from local to UNC.
    .EXAMPLE
        Convert-FSPath -CurrentPath $CurrentPath [-Computer $Computer]
#>
    [CmdletBinding()]
    param
    (
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Full path in UNC or local." )]
        [string] $CurrentPath,
        [Parameter( Mandatory = $false, Position = 1, HelpMessage = "Remote host name." )]
        [string] $Computer
    )
    if ( $Computer ) {
        #Convert to UNC.
        if (!($CurrentPath.Contains("\\")) -and ($CurrentPath.Contains(":"))) {
            $Res = "\\$Computer\$($CurrentPath.Replace(":","$"))"
        }
        Else {

        }
    }
    Else {
        if (!($CurrentPath.Contains(":")) -and ($CurrentPath.Contains("\\"))) {
            $Array = $CurrentPath.Split("\")
            $Array = $Array | Select-Object -Last ($Array.count - 3)
            $Res = ($array -join "\").replace("$", ":")
        }
    }
    return $Res
}
function Get-ListByGroups {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   06.10.20
        VER    1
    .DESCRIPTION
        Create console menu columned by data groups. Add digits for selection.
    .EXAMPLE
        Get-ListByGroups -GroupArray $GroupArray
#>
    [OutputType([String[]])]
    [CmdletBinding()]
    param(
        [Parameter( Mandatory = $True, Position = 0, HelpMessage = "Array of columns with data.")]
        [array] $GroupArray
    )

    $TempArray   =  @("Exit")
    $TempArray  += ($GroupArray | Where-Object {$null -ne $_})
    $GroupArray  =  $TempArray

    [array] $List = @()
    foreach ( $Item in $GroupArray ) {
        [array] $List += $Item
    }

    $MaxNumLen = ([string]$List.Count).Length
    #$PadSymbol    = "*"
    $Padding = " "
    $ColDistance = 4
    $MaxItemLen = ($List | Measure-Object length -Maximum).maximum + $MaxNumLen + 2 + $Padding.Length + $ColDistance
    $MaxGroupCount = ($GroupArray | ForEach-Object { ($_ | Measure-Object).count } | Measure-Object -Maximum).maximum - 1
    $GroupCounter = 0
    #$StringLen    = $MaxItemLen * ( $GroupArray.count - 1 )

    [string[]]$RowArray = @(0..$MaxGroupCount)
    $RowArray.Clear()

    foreach ( $Group in $GroupArray ) {
        If ( $GroupCounter -eq 0 ) {
            foreach ( $Item in $Group ) {
                $ItemNumber = $List.IndexOf($Item)
                #Write-Host "".PadRight($StringLen, $PadSymbol) -ForegroundColor blue
                Write-Host "`n[ $ItemNumber] " -ForegroundColor Cyan -NoNewLine
                Write-Host "$Item."            -ForegroundColor red
                Write-Host ""
            }
        }
        Else {
            foreach ( $Item in (0..$MaxGroupCount) ) {
                $GroupItem         = $Group[$Item]
                $GroupItemSplitted = $GroupItem
                if ( $GroupItem ) {
                    $ItemNumber            = $List.IndexOf($GroupItem)
                    $ItemNumberWithPadding = ([string]$ItemNumber).PadLeft($MaxNumLen , " ")
                    $ItemView              = "[$ItemNumberWithPadding]$Padding$GroupItemSplitted.".PadRight($MaxItemLen, " ")
                }
                Else {
                    $ItemView = "".PadRight($MaxItemLen , " ")
                }

                $RowArray[$Item] += $ItemView
            }
        }
        $GroupCounter ++
    }

    foreach ($item in $RowArray) {
        if ( $Color -eq "Cyan" ) {
            $Color = "Blue"
        }
        Else {
            $Color = "Cyan"
        }

        Write-Host "$Item"-ForegroundColor $Color
    }
    #Write-Host "".PadRight($StringLen, $PadSymbol) -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Select items: " -ForegroundColor Cyan -NoNewline
    $SelectedList = Read-Host
    while ( -not ($SelectedList -match '[0-9\-,\s]') ) {
        Write-Host "Wrong input [$SelectedList]! Allow only digit [0-9], interval [-], space [ ], separator [,]." -ForegroundColor Red -NoNewline
        $SelectedList = Read-Host
    }

    $SelectedArray = Convert-StringToDigitArray -UserInput $SelectedList
    $SelectedList  = $List | Where-Object {$List.IndexOf($_) -in $SelectedArray}

    return $SelectedList
}
Function Get-EventList {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        Function to event list from log file in interval or not.
    .EXAMPLE
        Get-EventList -LogFilePath $LogFilePath [-Event $Event] [-Interval $Interval=0]
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Log file path." )]
        [ValidateNotNullOrEmpty()]
        [string] $LogFilePath,
        [Parameter(Mandatory = $false, Position = 1, HelpMessage = "Event string." )]
        [string] $Event,
        [Parameter(Mandatory = $false, Position = 2, HelpMessage = "Time interval in seconds." )]
        [int32] $Interval = 0
    )
    $Res = @()
    if (test-path $LogFilePath) {
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
                    Catch {
                        Write-Error $_
                    }
                }

            }
        }
    }
    Else {
        Add-ToLog -Message "Log file [$LogFilePath] does not exist!" -logFilePath $Global:gsScriptLogFilePath -Status "Error" -Display -Level ($Global:gsParentLevel + 1)
    }

    return $Res
}
Function Get-HelpersData {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   11.04.20
        VER    1
    .DESCRIPTION
        Function return row in array from helpers CSV
    .EXAMPLE
        Get-HelpersData -CSVFilePath $CSVFilePath -Column $Column -Value $Value
#>
    [CmdletBinding()]
    Param (
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Full path to CSV helper file." )]
        [ValidateNotNullOrEmpty()]
        [string] $CSVFilePath,
        [Parameter( Mandatory = $true, Position = 1, HelpMessage = "Column name." )]
        [ValidateNotNullOrEmpty()]
        [string] $Column,
        [Parameter( Mandatory = $true, Position = 2, HelpMessage = "Column value." )]
        [ValidateNotNullOrEmpty()]
        [string] $Value
    )

    $Res = $Null
    if (Test-Path $CSVFilePath){
        $CSVFile = Import-Csv -path $CSVFilePath -Encoding utf8
        $Res = $null
        foreach ($item in $CSVFile) {
            if ($item.$Column -eq $Value) {
                Return $item
            }
        }
    }
    Else {
        Write-host "File path [$CSVFilePath] does not exist!"
    }
    Return $Res
}
function Get-CopyByBITS {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        Copy content of source path to destination path.
    .EXAMPLE
        Get-CopyByBITS -Source $Source -Destination $Destination [-Replace $Replace] [-ShowStatus $ShowStatus]
#>
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Source path." )]
        [ValidateNotNullOrEmpty()]
        [string]$Source,
        [Parameter( Mandatory = $true, Position = 1, HelpMessage = "Destination path." )]
        [ValidateNotNullOrEmpty()]
        [string]$Destination,
        [Parameter( Mandatory = $false, Position = 2, HelpMessage = "Replace files and folders." )]
        [switch]$Replace,
        [Parameter( Mandatory = $false, Position = 3, HelpMessage = "Show operation status." )]
        [switch]$ShowStatus
    )

    Function Show-CopyStatus {
    <#
        .SYNOPSIS
            AUTHOR Alexk
            DATE   25.10.20
            VER    1
        .DESCRIPTION
            Show status of bits copy process.
        .EXAMPLE
            Show-CopyStatus -CommonData $CommonData -Array $Array
    #>
        [CmdletBinding()]
        Param(
            [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Array of common parameters." )]
            [ValidateNotNullOrEmpty()]
            [array]$CommonData,
            [Parameter( Mandatory = $true, Position = 1, HelpMessage = "Array of parameters." )]
            [ValidateNotNullOrEmpty()]
            [array]$Array
        )

        Clear-Host
        Write-Host $CommonData.ScreenBuffer
        Write-Host "================================================================================================================================================================" -ForegroundColor Green
        Write-Host "Overall: " -NoNewline -ForegroundColor Blue ; Write-Host "$($CommonData.OverallCompletion) % " -NoNewline -ForegroundColor Yellow; Write-Host "till: " -NoNewline -ForegroundColor Blue ; Write-Host "$($CommonData.ApproxCompleteTime)" -ForegroundColor Yellow
        Write-Host "Run: " -NoNewline -ForegroundColor Blue ; Write-Host "$($CommonData.SecondsRun) sec. " -NoNewline -ForegroundColor Yellow; Write-Host "remain: " -NoNewline -ForegroundColor Blue ; Write-Host "$($CommonData.SecondsRemaining) sec." -ForegroundColor Yellow -NoNewline ; Write-Host " speed: " -ForegroundColor Blue -NoNewline ; Write-Host "$($CommonData.MBSec) MB/sec" -ForegroundColor Yellow
        foreach ($Pso in $Array) {
            if ($Pso.JobState -ne "Transferred") {
                Write-Host "----------------------------------------------------------------------------------------------------------------------------------------------------------------" -ForegroundColor Green
                Write-Host "    Current: " -NoNewline -ForegroundColor Blue ; Write-Host "$($PSO.FileCompletion) %" -ForegroundColor Yellow
                Write-Host "    $($Pso.JobState) ($($PSO.Size) MB.) " -NoNewline -ForegroundColor Blue ; Write-Host "$($PSO.RemoteFile)" -ForegroundColor Yellow -NoNewline; Write-Host " -> " -ForegroundColor Blue -NoNewline; Write-Host "$($PSO.CurrentFile)" -ForegroundColor Red
            }
        }
        Write-Host "================================================================================================================================================================"  -ForegroundColor Green
    }

    Import-Module BitsTransfer
    $GlobalTransferred = 0
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
                    $ScreenBuffer += "Error: $_.exception `n"
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
                        $ScreenBuffer += "      Error: $_.exception `n"
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
        $CountTransferringAndConnecting = @($BitsJobs | Where-Object { $_.JobState -eq "Transferring" -or $_.JobState -eq "Connecting" }).count
        Write-Host "$(Get-BitsTransfer | Out-String)"
        while ( $BitsJobs.count -gt 0 -and $CountTransferringAndConnecting -gt 0) {
            $FileArray = @()
            foreach ($BitsJob in $BitsJobs) {
                $Status = $BitsJob.JobState
                $File = $BitsJob.FileList[$BitsJob.FilesTransferred]
                if ($null -ne $File) {
                    $CurrentFile = $File.localName
                    $RemoteFile = $File.remoteName
                    $Size = [math]:: Round(($File.BytesTotal / 1MB), 2)
                }
                else {
                    $CurrentFile = $BitsJob.FileList.localName
                    $RemoteFile = $BitsJob.FileList.remoteName
                    $Size = [math]:: Round(($BitsJob.FileList.BytesTotal / 1MB), 2)
                }
                $FileCompletion = 0
                switch ($Status) {
                    { $_ -eq "Transferring" -or $_ -eq "Connecting" } {
                        $CurrentTransferred = 0
                        foreach ($Item in $BitsJob.FileList) {
                            $CurrentTransferred += $Item.BytesTransferred
                        }

                        $OverallCompletion = [math]:: Round(($GlobalTransferred + $CurrentTransferred) / $GlobalSize * 100, 2)
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
                        $ApproxCompleteTime = ($GlobalStartTime).AddSeconds($SecondsTotal)
                        try {
                            $MBSec = [math]:: Round(($GlobalTransferred + $CurrentTransferred) / 1Mb / $SecondsRun, 2)
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
                    CurrentFile    = $CurrentFile
                }
                $FileArray += $PSO
            }
            $CommonData = [PSCustomObject]@{
                ScreenBuffer      = $ScreenBuffer
                OverallCompletion = $OverallCompletion
                ApproxCompleteTime = $ApproxCompleteTime
                SecondsRun        = $SecondsRun
                SecondsRemaining  = $SecondsRemaining
                MBSec             = $MBSec
            }

            Show-CopyStatus $CommonData $FileArray

            Start-Sleep 1

            $CountTransferringAndConnecting = @($BitsJobs | Where-Object { $_.JobState -eq "Transferring" -or $_.JobState -eq "Connecting" }).count
        }
        $CommonData = [PSCustomObject]@{
            ScreenBuffer      = $ScreenBuffer
            OverallCompletion = 100
            ApproxCompleteTime = Get-Date
            SecondsRun        = $SecondsRun
            SecondsRemaining  = 0
            MBSec             = $MBSec
        }

        $GlobalTransferred += $CurrentTransferred
        Show-CopyStatus $CommonData $null
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
function Get-ACLArray {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   08.04.20
        VER    1
    .DESCRIPTION
        Function return Array of ACL for all objects in the Path
        Use Type to filter item. "file", "folder", "all"
    .EXAMPLE
        Parameter set: "Remote"
            Get-ACLArray -Path $Path [-Computer $Computer] [-Credentials $Credentials=$null] [-Type $Type="all"]
#>
    [CmdletBinding()]
    Param (
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Full path to folder or file." )]
        [ValidateNotNullOrEmpty()]
        [string] $Path,
        [Parameter( Mandatory = $False, Position = 1, HelpMessage = "Remote computer name.", ParameterSetName = "Remote"  )]
        [string] $Computer,
        [Parameter( Mandatory = $false, Position = 2, HelpMessage = "Remote credentials.", ParameterSetName = "Remote"  )]
        [System.Management.Automation.PSCredential]  $Credentials = $null,
        [Parameter( Mandatory = $false, Position = 3, HelpMessage = "File system object type." )]
        [ValidateSet("all", "folder", "file")]
        [string] $Type = "all"
    )
    $Res = $null

    $ScriptBlock = {`
            [array]$Array = @()
        $Type = $Using:Type
        switch ($Type.tolower()) {
            "all" {
                $ACLItems = Get-ChildItem -Path $Using:Path -Recurse | Sort-Object FullName
                $Root = Get-Item -Path $Using:Path
                $ACLItems += $Root
            }
            "folder" {
                $ACLItems = Get-ChildItem -Path $Using:Path -Recurse -Directory | Sort-Object FullName
                $Root = Get-Item -Path $Using:Path
                $ACLItems += $Root
            }
            "file" { $ACLItems = Get-ChildItem -Path $Using:Path -Recurse -File | Sort-Object FullName }
            Default { }
        }



        foreach ($Item1 in $ACLItems) {
            $Acl = Get-Acl -Path $Item1.FullName
            #$Acl | Select-Object -ExpandProperty Access
            foreach ($item in ($Acl | Select-Object -ExpandProperty Access)) {
                $ParentPath = split-path -path (split-path -path $Item1.FullName -Parent) -leaf
                If ((Split-Path -path $Using:Path -leaf) -eq $ParentPath) {
                    $ParentPath = ""
                }
                $PSO = [PSCustomObject]@{
                    AbsolutePath      = $Item1.FullName
                    Path              = $Item1.FullName.Replace($Using:Path, "")
                    ParentPath        = $ParentPath
                    BaseName          = $Item1.BaseName
                    Extension         = $Item1.Extension
                    Owner             = $Acl.Owner
                    Group             = $Acl.Group
                    FileSystemRights  = $item.FileSystemRights
                    AccessControlType = $item.AccessControlType
                    IdentityReference = [string]$item.IdentityReference.value
                    IsInherited       = $item.IsInherited
                    InheritanceFlags  = $item.InheritanceFlags
                    PropagationFlags  = $item.PropagationFlags
                }
                $Array += $PSO
            }
        }
        return $Array
    }

    $Res = Invoke-PSScriptBlock -ScriptBlock $ScriptBlock -Computer $Computer -Credentials $Credentials
    return $Res
}
function Resolve-IPtoFQDNinArray {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   10.04.20
        VER    1
    .DESCRIPTION
        Add FQDN column to IP array.
    .EXAMPLE
        Resolve-IPtoFQDNinArray -Array $Array
#>
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Data array with uniq IP column." )]
        [ValidateNotNullOrEmpty()]
        [array] $Array
    )

    [datetime]$lastSeen = Get-Date
    [array]   $Res = @()
    foreach ($item in $Array) {
        $Ip = $Item | Select-Object -ExpandProperty *
        try {
            $FQDN     = [System.Net.Dns]::GetHostEntry($Ip).HostName
            $Domen    = ($FQDN.split(".") | Select-Object -last  2) -join "."
            $HostName = ($FQDN.split(".") | Select-Object -first 1)
        }
        catch {
            $Err = $_.Exception.InnerException.ErrorCode
            switch ($Err) {
                11001   {$FQDN = "Unknown"  }
                10060   {$FQDN = "Timeout"  }
                11002   {$FQDN = "TempError"}
                Default {
                    $FQDN = "Error"
                }
            }
        }
        $PSO = [PSCustomObject]@{
            IP       = $Ip
            FQDN     = $FQDN
            Domen    = $Domen
            Host     = $HostName
            LastSeen = $LastSeen
        }
        $Res      += $PSO
        $FQDN      = ""
        $HostName  = ""
        $Domen     = ""
    }
    Return $Res
}

#endregion
#region Dialog
Function Show-OpenDialog{
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        Show windows open file dialog.
    .EXAMPLE
        Show-OpenDialog -Type $Type [-InitPath $InitPath] [-Description $Description] [-FileFilter $FileFilter] [-FileMultiSelect $FileMultiSelect]
#>
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Type of dialog." )]
        [ValidateSet("folder", "file")]
        [string]$Type,
        [Parameter( Mandatory = $false, Position = 1, HelpMessage = "Initial dialog path." )]
        [string]$InitPath,
        [Parameter( Mandatory = $false, Position = 2, HelpMessage = "Dialog description." )]
        [string]$Description,
        [Parameter( Mandatory = $false, Position = 3, HelpMessage = "File filter." )]
        [string]$FileFilter,
        [Parameter( Mandatory = $false, Position = 4, HelpMessage = "Allow multi select." )]
        [switch]$FileMultiSelect
    )

    Add-Type -AssemblyName System.Windows.Forms
    if (!$InitPath) {$InitPath = Get-Location}
    switch ($type.tolower()) {
        "file" {
            $File                  = New-Object Windows.Forms.OpenFileDialog
            $File.InitialDirectory = $InitPath
            $File.Filter           = $FileFilter
            $File.ShowHelp         = $true
            $File.MultiSelect      = $FileMultiSelect
            $File.Title            = $Description
            $File.ShowDialog() | Out-Null
            if ($File.MultiSelect) { return $File.FileNames } else { return $File.FileName }
        }
        "folder" {
            $Folder                        = New-Object Windows.Forms.FolderBrowserDialog
            $Folder.SelectedPath           = $InitPath
            $Folder.Description            = $Description
            $Folder.UseDescriptionForTitle = $true
            $Folder.ShowDialog() | Out-Null
            return $Folder.SelectedPath
        }
        Default {}
    }
}
Function Show-Notification {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        Function to show notification in the system tray.
    .EXAMPLE
        Show-Notification -MsgTitle $MsgTitle -MsgText $MsgText -Status $Status [-FilePath $FilePath=""] [-Timeout $Timeout=5]
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Message title." )]
        [ValidateNotNullOrEmpty()]
        [string] $MsgTitle,
        [Parameter(Mandatory = $true, Position = 1, HelpMessage = "Message text." )]
        [ValidateNotNullOrEmpty()]
        [string] $MsgText,
        [Parameter(Mandatory = $true, Position = 2, HelpMessage = "Message status." )]
        [ValidateSet("Error", "Info", "None", "Warning")]
        [string] $Status,
        [Parameter(Mandatory = $false, Position = 3, HelpMessage = "Path to file with details. Like log file." )]
        [string] $FilePath="",
        [Parameter(Mandatory = $false, Position = 4, HelpMessage = "Wait-Event timeout" )]
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

    $retSourceIdentifier = $retEvent.SourceIdentifier

    If ($retSourceIdentifier -eq "event_BalloonTipClicked") {
        if ($FilePath -ne ""){
            Start-Process "C:\Windows\System32\notepad.exe" -ArgumentList "C:\DATA\PROJECTS\ConnectVPN\VPN.log" -WindowStyle Normal -Verb Open
        }
    }

    $notification.Dispose()

    Unregister-Event -SourceIdentifier event_BalloonTip*
    Get-Event event_BalloonTip* | Remove-Event

}


#endregion
#region Module
function Get-SettingsFromFile {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        Load variables from external file.
    .EXAMPLE
        Get-SettingsFromFile -SettingsFile $SettingsFile
#>
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Settings file path." )]
        [ValidateNotNullOrEmpty()]
        [string]$SettingsFile
    )

    if(Test-path $SettingsFile){
        . ("$SettingsFile")
    }
    Else {
        Write-Host "Setting file [$SettingsFile] not found!" -ForegroundColor Red
    }
}
function Get-ErrorReporting {
<#
    .SYNOPSIS
        AUTHOR Alexk
        DATE   25.10.20
        VER    1
    .DESCRIPTION
        Visualize errors and save it to file.
    .EXAMPLE
        Get-ErrorReporting -Trap $Trap
#>
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Error trap." )]
        [ValidateNotNullOrEmpty()]
        $Trap
    )
    [string]$PreviousCommand = $Trap.InvocationInfo.line.Trim()
    try{
        [string]$PreviousCommandReplacedArgs = (Invoke-Expression -command "return `"$PreviousCommand`"").trim()
        [string]$PreviousCommandReplacedArgs = $PreviousCommandReplacedArgs.Insert(($Trap.InvocationInfo.OffsetInLine-1), '!')
    }
    Catch {
        Write-Error $_
    }
    [string]$Trap1             = $Trap
    [string]$Trap1             = ($Trap1.replace("[", "")).replace("]", "")
    [string]$line              = $Trap.InvocationInfo.ScriptLineNumber
    [string]$Script            = $Trap.InvocationInfo.ScriptName
    [string]$StackTrace        = $Trap.ScriptStackTrace
    [array]  $UpDownStackTrace = @($StackTrace.Split("`n"))
    [int16]  $ItemCount        = $UpDownStackTrace.Count
    [array]  $TempStackTrace   = @(1..$ItemCount )

    foreach ($item in $UpDownStackTrace) {
        $Data = $Item.Split(",")
        $TempStackTrace[$ItemCount - 1]  = "$($Data[0]), `"$($Data[1].trim())`""
                        $ItemCount      -= 1
    }
    $UpDownStackTrace = $TempStackTrace -join "`n"

    [string]$Trace  = $UpDownStackTrace | ForEach-Object { ((($_ -replace "`n", "`n    ") -replace " line ", "") -replace "at ", "") -replace "<ScriptBlock>", "ScriptBlock" }
    [string]$Trace1 = $UpDownStackTrace | ForEach-Object { ((($_ -replace "`n", "`n ") -replace " line ", "") -replace "at ", "") -replace "<ScriptBlock>", "ScriptBlock" }
    if ($Script -ne $Trap.Exception.ErrorRecord.InvocationInfo.ScriptName) {
        [string]$Module   = (($Trap.ScriptStackTrace).split(",")[1]).split("`n")[0].replace(" line ", "").Trim()
        [string]$Function = (($Trap.ScriptStackTrace).split(",")[0]).replace("at ", "")
        [string]$ToScreen = $Trap #"$Trap `n    Script:   `"$($Script):$($line)`"`n    Module:   `"$Module`"`n    Function: `"$Function`""
        [string]$Message  = "$Trap1 [script] `'$PreviousCommandReplacedArgs`' $Trace1"
    }
    else {
        [string]$Message = "$Trap1 [script] `'$PreviousCommandReplacedArgs`' $Trace1"
        $ToScreen        = "$Trap `n   $($Script):$($line)"
    }

    $Message = $Message.Replace("`n", "|")
    $Message = $Message.Replace("`r", "")
    try {
        Add-ToLog -Message "[Error] $Message" -logFilePath "$(Split-Path -path $Global:MyScriptRoot -parent)\LOGS\Errors.log" -Status "Error" -Format "dd.MM.yyyy HH:mm:ss" -ErrorAction SilentlyContinue
    }
    Catch {Write-host "Cant save error info!" -ForegroundColor Red}
    #& Code -r --goto "$((($Trace -split ",")[1].trim() -split " ")[0])"
    Write-Host "$(Get-date) SCRIPT EXIT DUE TO ERROR!!!" -ForegroundColor Red
    Write-Host "====================================================================================================================================================" -ForegroundColor Red
    Write-Host $ToScreen -ForegroundColor Blue
    Write-Host "Stack trace:" -ForegroundColor green
    Write-Host "    $Trace" -ForegroundColor green
    Write-Host "Previous command:" -ForegroundColor Yellow
    Write-Host "    $PreviousCommand" -ForegroundColor Yellow
    Write-Host "    $PreviousCommandReplacedArgs" -ForegroundColor Yellow
    Write-Host "====================================================================================================================================================" -ForegroundColor Red
}
#endregion

<#
    # Function Import-SettingsFromFile {
    # <#
    #     .SYNOPSIS
    #         AUTHOR Alexk
    #         DATE   25.10.20
    #         VER    1
    #     .DESCRIPTION
    #         Function to import variables from XML file
    #     .EXAMPLE
    #         Import-SettingsFromFile -RootPath $RootPath
    # #>
    #     [CmdletBinding()]
    #     param
    #     (
    #         [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Full path, where params files are." )]
    #         [string] $RootPath
    # )

    #     $Org = get-content ($RootPath + "\org.txt") -Encoding UTF8
    #     $ParamsFilePath = $RootPath + "\params-" + $ORG + ".xml"
    #     $Params = Import-Clixml $ParamsFilePath
    #     Initialize-Vars $Params
    #     return $Params
    # }
    # Function Initialize-Vars {
    # <#
    #     .SYNOPSIS
    #         AUTHOR Alexk
    #         DATE   25.10.20
    #         VER    1
    #     .DESCRIPTION
    #         Function to replace params with its value.
    #     .EXAMPLE
    #         Initialize-Vars -PSO $PSO
    # #>
    #     [CmdletBinding()]
    #     param
    #     (
    #         [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Object with params." )]
    #         [pscustomobject]
    #         $PSO
    #     )

    #     $NoteProperties = $PSO | get-member -type NoteProperty

    #     foreach ($item in $NoteProperties) {
#         $Param = "%" + $Item.name + "%"
#         $Value = $pso."$($item.name)"
#         Foreach ($item1 in $NoteProperties) {
#             if (($pso."$($item1.name)".gettype()).name -eq "String") {
#                 $pso."$($item1.name)" = ($pso."$($item1.name)").replace($Param, $Value)
#             }
#         }
#     }
# }
#>

Export-ModuleMember -Function Get-NewAESKey, Get-VarFromAESFile, Set-VarToAESFile, Disconnect-VPN, Connect-VPN, Add-ToLog, Restart-Switches, Restart-SwitchInInterval, Get-EventList, Send-Email, Start-PSScript, Restart-LocalHostInInterval, Show-Notification, Restart-ServiceInInterval, New-TelegramMessage, Get-SettingsFromFile, Get-HTMLTable, Get-HTMLCol, Get-ContentFromHTMLTemplate, Get-ErrorReporting, Get-CopyByBITS, Show-OpenDialog, Import-ModuleRemotely, Invoke-PSScriptBlock, Get-ACLArray, Set-PSModuleManifest, Get-VarToString, Get-UniqueArrayMembers, Resolve-IPtoFQDNinArray, Get-HelpersData, Get-DifferenceBetweenArrays, Test-Credentials, Convert-FSPath, Start-Program, Test-ElevatedRights, Invoke-CommandWithDebug, Format-TimeSpan, Start-ParallelPortPing, Join-Array, Set-State, Send-Alert, Start-Module, Convert-SpecialCharacters, Get-ListByGroups, Convert-StringToDigitArray, Invoke-TrailerIncrease

<#

AES
    Get-NewAESKey, Get-VarFromAESFile, Set-VarToAESFile, Get-VarToString
VPN
    Disconnect-VPN, Connect-VPN
Restart
    Restart-LocalHostInInterval, Restart-Switches, Restart-SwitchInInterval, Restart-ServiceInInterval
Credentials
    Test-Credentials, Test-ElevatedRights
Logging
    Add-ToLog, Send-Alert, Set-State, Send-Email, New-TelegramMessage
HTML
    Get-HTMLTable, Get-HTMLCol, Get-ContentFromHTMLTemplate
Array
    Get-UniqueArrayMembers, Get-DifferenceBetweenArrays, Join-Array
Invoke
    Start-PSScript, Import-ModuleRemotely, Invoke-PSScriptBlock, Start-Program, Start-Module, Invoke-CommandWithDebug
Utils
    Convert-SpecialCharacters, Invoke-TrailerIncrease, Convert-StringToDigitArray, Start-ParallelPortPing, Format-TimeSpan, Convert-FSPath, Get-ListByGroups, Get-EventList Get-HelpersData, Get-CopyByBITS, Get-ACLArray, Resolve-IPtoFQDNinArray
Dialog
    Show-OpenDialog, Show-Notification
Module
    Get-SettingsFromFile, Get-ErrorReporting

#>