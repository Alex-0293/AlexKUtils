<#
    .SYNOPSIS
        AlexK utility module.
    .DESCRIPTION
        This module contains utility functions.
        Use inside AlexkFramework.
    .COMPONENT
        AlexKUtils
    .LINK
        https://github.com/Alex-0293/AlexKUtils
    .NOTES
        AUTHOR  Alexk
        CREATED 25.04.19
        MOD     23.02.21
        VER     7
#>


[bool]   $Global:modSuppressOutput   = $false
[int]    $Global:modPSSessionCounter = 0
[int]    $Global:modDialogNumber     = 1
[array]  $Global:modGroupListArray = @()

$res = Get-Module -ListAvailable "Pansies"
if ( $res ){
    $res = Import-Module "Pansies" -PassThru
}

if ( $res ){
    $Global:modPansiesModule = $true
}
Else {
    $Global:modPansiesModule = $false
}
#$Global:modPansiesModule = $false

#region AES
function Get-NewAESKey {
<#
    .SYNOPSIS
        Get new AES key
    .DESCRIPTION
        This function create a new AES key and save it to file
    .EXAMPLE
        Get-NewAESKey [-AESKeyFilePath $AESKeyFilePath] [-PassThru $PassThru]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Get var from AES file
    .DESCRIPTION
        Function to read variable from file encrypted with AES key.
    .EXAMPLE
        Get-VarFromAESFile -VarFilePath $VarFilePath [-AESKeyFilePath $AESKeyFilePath]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
#>
    [OutputType([SecureString])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false, Position = 0, HelpMessage = "Path to AES key file." )]
        [string]$AESKeyFilePath,
        [Parameter(Mandatory=$true, Position=1, HelpMessage = "Encrypted file path." )]
        [ValidateNotNullOrEmpty()]
        [string]$VarFilePath
    )

    if ( !$AESKeyFilePath ){
        try {
            $AESKeyFilePath = Get-Content -path $VarFilePath -Stream "Key.Path"
            if ( $AESKeyFilePath[0] -ne '"' ) {
                $AESKeyFilePath = Invoke-Expression -Command '"' + $AESKeyFilePath + '"'
            }
            Else {
                $AESKeyFilePath = Invoke-Expression -Command $AESKeyFilePath
            }
        }
        Catch {}
    }

    if (!(test-path $AESKeyFilePath)) {
        write-host "AESKeyFilePath [$AESKeyFilePath] not exist" -ForegroundColor Red
        $AESKeyFilePathExist = $false
    }
    else { $AESKeyFilePathExist = $true }

    if (!(test-path $VarFilePath)) {
        Write-Host "VarFilePath [$VarFilePath] not exist" -ForegroundColor Red
        $VarFilePathExist = $false
    }
    else { $VarFilePathExist = $true }

    if ( $VarFilePathExist -and $AESKeyFilePathExist ) {
            $Content = Get-Content $VarFilePath
            $Key     = Get-content $AESKeyFilePath
            trap {

            }
            try{
                $Res = ConvertTo-SecureString -Key $Key -String $Content -ErrorVariable LastError -ErrorAction stop
            }
            Catch {
                if ( $LastError ){
                    switch ( $LastError.ErrorRecord ) {
                        "Padding is invalid and cannot be removed." {
                            Add-ToLog -Message "Validate AES key [$AESKeyFilePath] for data [$VarFilePath]!" -Display -Status "Error" -logFilePath $Global:gsScriptLogFilePath
                        }
                        Default {
                            Add-ToLog -Message $LastError -Display -Status "Error" -logFilePath $Global:gsScriptLogFilePath
                        }
                    }
                }
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
        Set var to AES file
    .DESCRIPTION
        Function to write variable to file with encryption with AES key file
    .EXAMPLE
        Set-VarToAESFile -Var $Var -AESKeyFilePath $AESKeyFilePath -VarFilePath $VarFilePath [-Force $Force] [-PassThru $PassThru]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
#>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Value." )]
        [ValidateNotNullOrEmpty()]
        $Var,
        [Parameter(Mandatory = $true, Position = 1, HelpMessage = "Path to AES key file." )]
        [ValidateNotNullOrEmpty()]
        [string] $AESKeyFilePath,
        [Parameter(Mandatory = $true, Position = 2, HelpMessage = "Path to encrypted file." )]
        [ValidateNotNullOrEmpty()]
        [string] $VarFilePath,
        [Parameter(Mandatory = $false, Position = 4, HelpMessage = "Force overwrite file." )]
        [switch] $Force,
        [Parameter(Mandatory = $false, Position = 5, HelpMessage = "Return object." )]
        [switch] $PassThru
    )

    function Set-AESContent ([string] $VarFilePath, [string] $AESKeyFilePath) {
    <#
        .SYNOPSIS
            Set AES content
        .EXAMPLE
            Set-AESContent
        .NOTES
            AUTHOR  Alexk
            CREATED 17.01.21
            VER     1
    #>
        if ( test-path -path $AESKeyFilePath ){
            $AESData | Set-Content -path $VarFilePath
            $NewAESKeyFilePath = '"' + $AESKeyFilePath.replace($Global:gsGlobalSettingsPath,'$($Global:gsGlobalSettingsPath)').replace($Global:gsKEYSFolder,'$($Global:gsKEYSFolder)').replace($Global:ProjectRoot,'$($Global:ProjectRoot)') + '"'

            Set-Content -Path $VarFilePath -Value $NewAESKeyFilePath -Stream "Key.Path"
        }
        Else {
            Write-host "AES key file [$AESKeyFilePath] not found!" -ForegroundColor Red
            $AESData = $Null
        }

        Return $AESData
    }

    if ( $Var.GetType().name -eq "PSCustomObject" ) {
        $Var = $Var | ConvertTo-Json -Compress
    }

    if ( $Var.GetType().name -ne "SecureString" ) {
            $AESData = ConvertTo-SecureString -String $Var -AsPlainText | ConvertFrom-SecureString -Key (get-content $AESKeyFilePath)
    }
    else {
        $AESData = $Var
    }

    if ( !(test-path -path $VarFilePath) ) {
        $AESData = Set-AESContent -VarFilePath $VarFilePath -AESKeyFilePath $AESKeyFilePath
    }
    Else{
        if ( $Force ) {
            $AESData = Set-AESContent -VarFilePath $VarFilePath -AESKeyFilePath $AESKeyFilePath
        }
        Else {
            $Answer = Get-Answer -Title "File [$VarFilePath], already exist! Do you want to replace it? " -ChooseFrom "y", "n" -DefaultChoose "n" -Color "Cyan", "DarkMagenta" -AddNewLine
            if ( $Answer -eq "Y" ){
                $AESData = Set-AESContent -VarFilePath $VarFilePath -AESKeyFilePath $AESKeyFilePath
            }
            Else {
                Write-host "AES file [$VarFilePath] overwrite canceled!" -ForegroundColor Yellow
                $AESData = $Null
            }
        }
    }

    if ( $PassThru ){
        Return $AESData
    }
}
Function Get-VarToString {
<#
    .SYNOPSIS
        Get var to string
    .DESCRIPTION
        Function to make string from secure string.
    .EXAMPLE
        Get-VarToString -Var $Var
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
    Else {
        if ( $Res -like "*{*}"){
            $Res = $Res | ConvertFrom-JSON
        }
    }
    return $Res
}

Function Get-AESData {
<#
    .SYNOPSIS
        Get AES data
    .DESCRIPTION
        Function to read data from AES settings.
    .EXAMPLE
        Get-AESData -DataFilePath $DataFilePath -DataFileType $DataFileType
    .NOTES
        AUTHOR  Alexk
        CREATED 28.01.21
        VER     1
#>
    [OutputType([SecureString])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "AES data file path." )]
        [ValidateNotNullOrEmpty()]
        [string] $DataFilePath,
        [Parameter(Mandatory = $true, Position = 1, HelpMessage = "AES data file type." )]
        [ValidateNotNullOrEmpty()]
        [string] $DataFileType
    )

    switch ( $DataFileType ) {
        "Account" {
            $Settings          = Get-VarFromAESFile -VarFilePath $DataFilePath
            $Settings          = Get-VarToString -Var $Settings
            $Settings.Password = ConvertTo-SecureString -AsPlainText $Settings.Password -Force
            $Res               = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList ($Settings.UserName), ($Settings.Password)
        }
        Default {}
    }

    return  $Res
}
#endregion
#region VPN
Function Connect-VPN {
<#
    .SYNOPSIS
        Connect VPN
    .DESCRIPTION
        Function to establish VPN connection
    .EXAMPLE
        Connect-VPN -VPNConnectionName $VPNConnectionName -logFilePath $logFilePath -Login $Login -Password $Password
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Disconnect VPN
    .DESCRIPTION
        Function to break VPN connection
    .EXAMPLE
        Disconnect-VPN -VPNConnectionName $VPNConnectionName -logFilePath $logFilePath
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Restart local host in interval
    .DESCRIPTION
        Function to restart computer in time interval based on last restart.
    .EXAMPLE
        Restart-LocalHostInInterval -LogFilePath $LogFilePath [-MinIntervalBetweenReboots $MinIntervalBetweenReboots] [-PassThru $PassThru]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Restart switches
    .DESCRIPTION
        Function to reboot device
    .EXAMPLE
        Parameter set: "Login"
        Restart-Switches -SwitchesIP $SwitchesIP -logFilePath $logFilePath -PLinkPath $PLinkPath -SshConString $SshConString -SshCommand $SshCommand [-Login $Login] [-Password $Password]
        Parameter set: "Cert"
        Restart-Switches -SwitchesIP $SwitchesIP -logFilePath $logFilePath -PLinkPath $PLinkPath -SshConString $SshConString -SshCommand $SshCommand [-CertFilePath $CertFilePath]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Restart switch in interval
    .DESCRIPTION
        Function to restart devices in time interval.
    .EXAMPLE
        Parameter set: "Login"
        Restart-SwitchInInterval -SwitchesIP $SwitchesIP -logFilePath $logFilePath -PLinkPath $PLinkPath -SshConString $SshConString -SshCommand $SshCommand [-Login $Login] [-Password $Password] [-MinIntervalBetweenReboots $MinIntervalBetweenReboots]
        Parameter set: "Cert"
        Restart-SwitchInInterval -SwitchesIP $SwitchesIP -logFilePath $logFilePath -PLinkPath $PLinkPath -SshConString $SshConString -SshCommand $SshCommand [-CertFilePath $CertFilePath] [-MinIntervalBetweenReboots $MinIntervalBetweenReboots]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Restart service in interval
    .DESCRIPTION
        Function to create logger object.
    .EXAMPLE
        Restart-ServiceInInterval -EventLogPath $EventLogPath -ServiceName $ServiceName [-MinIntervalBetweenRestarts $MinIntervalBetweenRestarts=0]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Test credentials
    .DESCRIPTION
        Test user credentials.
    .EXAMPLE
        Test-Credentials -Credentials $Credentials
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Test elevated rights
    .EXAMPLE
        Test-ElevatedRights [-Identity $Identity=[Security.Principal.WindowsIdentity]::GetCurrent()]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
#>
    [CmdletBinding()]
    [OutputType([Bool])]
    Param (
        [Parameter( Mandatory = $false,  ValueFromPipeLine = $true,  ValueFromPipelineByPropertyName = $true )]
        [ValidateNotNull()]
        [Security.Principal.WindowsIdentity]
        $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    )

    process {
        $Principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $Identity
        $Res       = $principal.IsInRole( [Security.Principal.WindowsBuiltInRole]::Administrator )
        return $Res
    }
}
#endregion
#region Logging
Function Add-ToLog {
<#
    .SYNOPSIS
        Add to log
    .DESCRIPTION
        Function to write message into a log file
    .EXAMPLE
        Add-ToLog -Message $Message -logFilePath $logFilePath [-Mode $Mode="append"] [-Display $Display] [-Status $Status] [-Format $Format] [-Level $Level] [-Category $Category] [-ShowLogName $ShowLogName]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        [int16] $Level,
        [Parameter(Mandatory = $false, Position =7, HelpMessage = "Action category." )]
        [string] $Category,
        [Parameter(Mandatory = $false, Position =8, HelpMessage = "Display log name." )]
        [switch] $ShowLogName
    )

    if ( -not $Global:modSuppressOutput ) {
        if ( -not $PSBoundParameters.ContainsKey("Level") ) {
            if( -not $Global:gsParentLevel ){
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
            foreach ( $item in (1..($Level * $LevelMultiplier - 1))) {
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
                    $PSO = [PSCustomObject]@{
                        DateTime = Get-Date
                        Level    = $Level
                        Category = $Category
                        Status   = $Status.ToLower()
                        Location = ( Get-PSCallStack | Select-Object -SkipLast 1 | Select-Object -Last 1 ).Location.replace(" line ","")
                        Message  = $Message
                    }
                    $FilePath = "$logFilePath.csv"

                    switch ($Mode.ToLower()) {
                    "append" {
                        Out-File -FilePath $logFilePath -Encoding utf8 -Append -Force -InputObject $Text
                        Add-ToDataFile -Data $PSO -FilePath $FilePath -DontCheckStructure
                    }
                    "replace" {
                        Out-File -FilePath $logFilePath -Encoding utf8 -Force -InputObject $Text
                        Add-ToDataFile -data $PSO -FilePath $FilePath -Replace -DontCheckStructure
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
            if ($logFilePath -ne $Global:gsScriptLogFilePath -and $ShowLogName ){
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
                        Get-ColorText -text $NewText -TextColor "Green"
                        #Write-Host $NewText  -ForegroundColor Green
                    }
                    "warning" {
                        Get-ColorText -text $NewText -TextColor "Yellow"
                        #Write-Host $NewText  -ForegroundColor Yellow
                    }
                    "error" {
                        Get-ColorText -text $NewText -TextColor "Red"
                        #Write-Host $NewText  -ForegroundColor Red
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
        Send alert
    .DESCRIPTION
        Send alert by custom transport.
    .EXAMPLE
        Send-Alert -Plugin $Plugin -AlertMessage $AlertMessage [-AlertSubject $AlertSubject] [-AlertFilePath $AlertFilePath] [-TextFilesAsHTML $TextFilesAsHTML]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
#>
    [CmdletBinding()]
    Param (
        [Parameter( Mandatory = $True, Position = 1, HelpMessage = "Alert parameters.")]
        $Plugin,
        [Parameter( Mandatory = $True, Position = 2, HelpMessage = "Alert message.")]
        [string] $AlertMessage,
        [Parameter( Mandatory = $false, Position = 3, HelpMessage = "Alert subject.")]
        [string] $AlertSubject,
        [Parameter( Mandatory = $false, Position = 4, HelpMessage = "File attachments.")]
        [string[]] $AlertFilePath,
        [Parameter( Mandatory = $false, Position = 5, HelpMessage = "Convert text file attachments to HTML.")]
        [switch] $TextFilesAsHTML
    )

    $PluginSettings = $Plugin.Settings

    switch ([string]$Plugin.name.ToLower()) {
        "telegram" {
            New-TelegramMessage @PluginSettings -Message $AlertMessage
        }
        "email" {
            Send-Email @PluginSettings -SSL -Subject $AlertSubject -Body $AlertMessage
        }
        Default {}
    }

    $Jobs = Get-Job -HasMoreData $false -State "Completed"
    if ( $Jobs ){
        $Jobs | Remove-Job
    }
}
Function Set-State {
<#
    .SYNOPSIS
        Set state
    .DESCRIPTION
        Save object state to file
    .EXAMPLE
        Set-State -StateObject $StateObject -StateFilePath $StateFilePath [-AlertType $AlertType] [-AlertOnChange $AlertOnChange] [-SaveOnChange $SaveOnChange]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
#>
    [CmdletBinding()]
    Param (
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "State object." )]
        [PSCustomObject] $StateObject,
        [Parameter( Mandatory = $true, Position = 1, HelpMessage = "State file path." )]
        [String] $StateFilePath,
        [Parameter( Mandatory = $false, Position = 2, HelpMessage = "Send alert to." )]
        [string] $AlertType,
        [Parameter( Mandatory = $false, Position = 3, HelpMessage = "Alert only on global state change." )]
        [switch] $AlertOnChange,
        [Parameter( Mandatory = $false, Position = 4, HelpMessage = "Save only on global state change." )]
        [switch] $SaveOnChange
    )

    if (Test-Path -path $StateFilePath) {
        $States = Get-FromDataFile -FilePath $StateFilePath
    }
    Else {
        $States = @()
    }

    $LastState            = $States | Select-Object -Last 1
    $StateChanged         = ( $LastState.State -ne $StateObject.State ) -or ( $LastState.GlobalState -ne $StateObject.GlobalState ) -or ( -not $LastState )
    $StateObject.DateTime = Get-Date
    $AlertMessage         = @"
$($StateObject.Application)@$($StateObject.Host)[$(Get-Date $StateObject.DateTime -Format HH:mm)]
$($StateObject.Action)
$($StateObject.State)
Global state: $($StateObject.GlobalState)
"@
    if ( $AlertOnChange ) {
        if ($StateChanged) {
            switch ($AlertType.ToLower()) {
                "telegram" {
                    if ( $Global:gsPlugins.SelectPlugin("telegram") ) {
                        Send-Alert -Plugin $Global:gsPlugins.SelectPlugin("telegram") -AlertMessage $AlertMessage
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
                if ($Global:gsPlugins.SelectPlugin("telegram")) {
                    Send-Alert -Plugin $Global:gsPlugins.SelectPlugin("telegram") -AlertMessage $AlertMessage
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
            Add-ToDataFile -FilePath $StateFilePath -Data $StateObject
        }
    }
    Else {
        Add-ToDataFile -FilePath $StateFilePath -Data $StateObject
    }
}
Function Send-Email {
<#
    .SYNOPSIS
        Send email
    .DESCRIPTION
        Function to send email message
    .EXAMPLE
        Parameter set: "Auth"
        Send-Email -SmtpServer $SmtpServer -From $From -To $To [-Subject $Subject] [-Body $Body] [-HtmlBody $HtmlBody] [-User $User] [-Password $Password] [-Port $Port=25] [-SSL $SSL] [-Attachment $Attachment] [-AttachmentContentId $AttachmentContentId] [-TTL $TTL=(New-TimeSpan -days 1)] [-PauseBetweenTries $PauseBetweenTries=30]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
    if ( $user ) {
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
        New telegram message
    .DESCRIPTION
        Function to send telegram message.
    .EXAMPLE
        Parameter set: "Proxy"
        New-TelegramMessage -APIKey $APIKey -ChatID $ChatID -Message $Message [-SummaryInterval $SummaryInterval] [-ProxyURL $ProxyURL] [-Credentials $Credentials] [-TTL $TTL=(New-TimeSpan -Days 1)] [-PauseBetweenTries $PauseBetweenTries=30]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
#>
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Telegram token." )]
        [ValidateNotNullOrEmpty()]
        [securestring] $APIKey,
        [Parameter( Mandatory = $true, Position = 1, HelpMessage = "Telegram chat id." )]
        [ValidateNotNullOrEmpty()]
        [securestring] $ChatID,
        [Parameter( Mandatory = $false, Position = 2, HelpMessage = "Group telegram message in interval." )]
        [int16] $SummaryInterval,
        [Parameter( Mandatory = $true, Position = 3, HelpMessage = "Message." )]
        [ValidateNotNullOrEmpty()]
        [string] $Message,
        [Parameter( Mandatory = $false, Position = 4, HelpMessage = "Proxy URL." , ParameterSetName = "Proxy")]
        [string] $ProxyURL,
        [Parameter( Mandatory = $false, Position = 5, HelpMessage = "Proxy credentials." , ParameterSetName = "Proxy")]
        [System.Management.Automation.PSCredential] $Credentials,
        [Parameter( Mandatory = $false, Position = 6, HelpMessage = "Message time to live in seconds. Use in case of errors." )]
        [TimeSpan] $TTL = (New-TimeSpan -Days 1),
        [Parameter(Mandatory  = $false, Position = 7, HelpMessage = "Pause between retries in seconds." )]
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

    [uri] $URI  = "https://api.telegram.org/bot" + ( Get-VarToString -var $APIKey ) + "/sendMessage?chat_id=" + ( Get-VarToString -var $ChatID ) + "&text=" + $Message

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
        #Start-Transcript -Path "C:\DATA\trans.log"
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
                    $false {
                        Add-ToLog -Message "Error[$($Response.error_code)][$($Response.description)]" -logFilePath $logFilePath -Status "Error"
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
            $Interval = New-TimeSpan -Start $Start
            #stop-Transcript
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
        Get HTML table
    .DESCRIPTION
        Create html table code.
    .EXAMPLE
        Get-HTMLTable -Array $Array
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Get HTML row
    .DESCRIPTION
        Create html table row code.
    .EXAMPLE
        Get-HTMLRow -Line $Line [-ColSpan $ColSpan=0]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
            Get HTML row fullness
        .DESCRIPTION
            Return number of not empty columns.
        .EXAMPLE
            Get-HTMLRowFullness -Line $Line
        .NOTES
            AUTHOR  Alexk
            CREATED 05.11.20
            VER     1
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
        Get HTML col
    .DESCRIPTION
        Create html table row code.
    .EXAMPLE
        Get-HTMLCol -Column $Column [-ColSpan $ColSpan=0] [-Bold $Bold=$false]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Get content from HTML template
    .DESCRIPTION
        Create html file from template.
    .EXAMPLE
        Get-ContentFromHTMLTemplate -HTMLData $HTMLData -ColNames $ColNames -HTMLTemplateFile $HTMLTemplateFile [-HTMLFile $HTMLFile]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Get unique array members
    .DESCRIPTION
        Return row with unique elements in column.
    .EXAMPLE
        Get-UniqueArrayMembers -Array $Array -ColumnName $ColumnName
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Get difference between arrays
    .DESCRIPTION
        First and second arrays should be the same structure.
        Return array with objects absent in first array.
    .EXAMPLE
        Get-DifferenceBetweenArrays -FirstArray $FirstArray -SecondArray $SecondArray
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
            $Cnt      = 0
            $NoteType = $Null
            do {
                if ( $FirstArray[$Cnt].$note ) {
                    $NoteType = $FirstArray[$cnt].$note.GetType()
                }
                $Cnt ++
            } until ( $NoteType -or $Cnt -gt $FirstArrayCount )

            $PSO = [PSCustomObject]@{
                Name = $note
                Type = $NoteType
            }
            $NoteProperties1WithType += $PSO
            $NoteProperties1WithTypeText += "$note($($PSO.type)),"
        }
    }
    if ($SecondArrayCount) {
        foreach ($note in $NoteProperties2) {
            $Cnt      = 0
            $NoteType = $Null
            do {
                if ( $SecondArray[$Cnt].$note ) {
                    $NoteType = $SecondArray[$Cnt].$note.GetType()
                }
                $Cnt ++
            } until ( $NoteType -or $Cnt -gt $SecondArrayCount)

            $PSO = [PSCustomObject]@{
                Name = $note
                Type = $NoteType
            }
            $NoteProperties2WithType += $PSO
            $NoteProperties2WithTypeText += "$note($($PSO.type)),"
        }
    }

    $NoteProperties1WithTypeText = $NoteProperties1WithTypeText.Remove($NoteProperties1WithTypeText.ToCharArray().count - 1)
    $NoteProperties2WithTypeText = $NoteProperties2WithTypeText.Remove($NoteProperties2WithTypeText.ToCharArray().count - 1)

    $Compare = Compare-Object -ReferenceObject $NoteProperties2WithType -DifferenceObject $NoteProperties1WithType -Property "name"
    if ( !$Compare ) {
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
        Join array
    .DESCRIPTION
        Function to union two array by key argument.
    .EXAMPLE
        Join-Array -PrimaryPSO $PrimaryPSO -SecondaryPSO $SecondaryPSO -Key $Key [-MergeColumns $MergeColumns]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
Function Compare-Arrays {
<#
    .SYNOPSIS
        Compare arrays
    .DESCRIPTION
        Function to compare two arrays. If equal return $true else $false.
    .EXAMPLE
        Compare-Arrays -Array1 $Array1 -Array2 $Array2
    .NOTES
        AUTHOR  Alexk
        CREATED 08.02.21
        VER     1
#>
    [OutputType([bool])]
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Array 1." )]
        [ValidateNotNullOrEmpty()]
        [PSObject[]] $Array1,
        [Parameter( Mandatory = $true, Position = 1, HelpMessage = "Array 2." )]
        [ValidateNotNullOrEmpty()]
        [PSObject[]] $Array2
    )
    begin {
        $Array1Property     = ($Array1 | get-member -MemberType NoteProperty).name
        $Array1PropertyType = @()
        foreach ( $Property in $Array1Property ){
            $PSO = [PSCustomObject]@{
                Name = $Property
                Type = $Array1[0].$Property.gettype()
            }
            $Array1PropertyType += $PSO
        }

        $Array2Property = ($Array2 | get-member -MemberType NoteProperty).name
        $Array2PropertyType = @()
        foreach ( $Property in $Array2Property ){
            $PSO = [PSCustomObject]@{
                Name = $Property
                Type = $Array2[0].$Property.gettype()
            }
            $Array2PropertyType += $PSO
        }
        $CompareArrayProperty = Compare-Object -ReferenceObject $Array1PropertyType -DifferenceObject $Array2PropertyType -Property "name", "type"
        if ( $CompareArrayProperty ) {
            Add-ToLog -Message "Arrays have different structure [$($CompareArrayProperty | out-string)]!" -logFilePath $Global:gsScriptLogFilePath -Display -Status "error"
            return $false
        }

    }
    process {
        $CompareArray = Compare-Object -ReferenceObject $Array1 -DifferenceObject $Array1 -Property $Array1Property
        if ( $CompareArray ) {
            return $false
        }
        Else {
            return $true
        }
    }
    end {

    }
}

Function Get-MembersType {
<#
    .SYNOPSIS
        Get members type
    .DESCRIPTION
        Return object with noteproperty names and types.
    .EXAMPLE
        Get-MembersType -PSO $PSO [-ExpandPSO $ExpandPSO]
    .NOTES
        AUTHOR  Alexk
        CREATED 09.03.21
        VER     1
#>
    [OutputType([PSObject[]])]
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "PS object." )]
        [PSObject] $PSO,
        [Parameter( Mandatory = $false, Position = 1, HelpMessage = "Expand PS objects." )]
        [switch] $ExpandPSO
    )
    begin {
        $Res = @()
    }
    process {
        $NoteProperties = $PSO | Get-Member -MemberType NoteProperty


        foreach ( $item  in $NoteProperties ){
            #$item.Name
            $ItemType = ( $item.definition -split " " )[0]
            if ( (($ItemType -like "*.PSCustomObject") -or ($ItemType -like "*psobject*") ) -and $ExpandPSO ){
                $ExpandedData = $PSO | Select-Object -ExpandProperty $item.name -ErrorAction SilentlyContinue
                $ExMembers = Get-MembersType -PSO $ExpandedData -ExpandPSO
                foreach ( $ExMember in $ExMembers ){
                    $NewPSO = [PSCustomObject]@{
                        Name = "$($item.name).$($ExMember.name)"
                        Type = $ExMember.Type
                    }
                }
            }
            Else {
                $NewPSO = [PSCustomObject]@{
                    Name = $item.Name
                    Type = $ItemType
                }
            }

            $Res += $NewPSO
        }
    }
    end {
        return $Res
    }
}

Function Compare-ArraysVisual {
<#
    .SYNOPSIS
        Compare arrays visual
    .DESCRIPTION
        Function to get complex array for visual compare.
    .EXAMPLE
        Compare-ArraysVisual -ReferenceObject $ReferenceObject -DifferenceObject $DifferenceObject -KeyField $KeyField [-ExcludeMembers $ExcludeMembers] [-MandatoryMembers $MandatoryMembers] [-IncludeUnchanged $IncludeUnchanged] [-SuppressOutput $SuppressOutput]
    .NOTES
        AUTHOR  Alexk
        CREATED 09.03.21
        VER     1
#>
    [OutputType([PSObject])]
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Array." )]
        [PSObject[]] $ReferenceObject,
        [Parameter( Mandatory = $true, Position = 1, HelpMessage = "Array." )]
        [PSObject[]] $DifferenceObject,
        [Parameter( Mandatory = $true, Position = 2, HelpMessage = "Key field for binding." )]
        [string] $KeyField,
        [Parameter( Mandatory = $false, Position = 3, HelpMessage = "Members to not compare." )]
        [string[]] $ExcludeMembers,
        [Parameter( Mandatory = $false, Position = 4, HelpMessage = "Members to add to changes." )]
        [string[]] $MandatoryMembers,
        [Parameter( Mandatory = $false, Position = 5, HelpMessage = "Include unchanged member." )]
        [switch] $IncludeUnchanged,
        [Parameter( Mandatory = $false, Position = 6, HelpMessage = "Suppress output." )]
        [switch] $SuppressOutput
    )
    begin {
        $ReferenceObjectMembers  = Get-MembersType -PSO $ReferenceObject
        $DifferenceObjectMembers = Get-MembersType -PSO $DifferenceObject

        $Compare = Compare-Object -ReferenceObject $ReferenceObjectMembers -DifferenceObject $DifferenceObjectMembers -Property "Name", "Type"

        if ( $Compare ){
            $Compare = Compare-Object -ReferenceObject $ReferenceObjectMembers -DifferenceObject $DifferenceObjectMembers -IncludeEqual -Property "Name", "Type"

            Add-ToLog -Message "Objects are not equal!" -logFilePath $Global:gsScriptLogFilePath -Display -category "Compare-ArraysVisual" -Status "error"

            Show-ColoredTable -Data $Compare -Title "Objects compare" -AddRowNumbers -AddNewLine
        }

        if ( $KeyField -notin $ReferenceObjectMembers.Name ) {
            Add-ToLog -Message "Objects does not contain member [$KeyField]!" -logFilePath $Global:gsScriptLogFilePath -Display -category "Compare-ArraysVisual" -Status "error"
        }

        $MembersArray = ($ReferenceObjectMembers | Where-Object { $_.name -notin $ExcludeMembers }).name
        $MembersArrayWithMandatory = $MandatoryMembers + $MembersArray  | Select-Object -Unique
        $PSO = [PSCustomObject]@{
            Changed    = $null
            Removed    = $null
            Added      = $null
        }

        if ( $IncludeUnchanged ) {
            $PSO | Add-Member -NotePropertyValue "Unchanged" -NotePropertyValue $null
            $Unchanged   = @()
        }

        $Changed = @()
        $Removed = @()
        $Added   = @()
    }
    process {
        Function Get-Difference {
        <#
            .SYNOPSIS
                Get difference
            .DESCRIPTION
                Return difference between two PSO.
            .EXAMPLE
                Get-Difference -Reference $Reference -Difference $Difference -members $members -KeyField $KeyField [-MandatoryMembers $MandatoryMembers]
            .NOTES
                AUTHOR  Alexk
                CREATED 09.03.21
                VER     1
        #>
            [OutputType([string])]
            [CmdletBinding()]
            Param(
                [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Reference PSO." )]
                [PSObject] $Reference,
                [Parameter( Mandatory = $true, Position = 1, HelpMessage = "Difference PSO." )]
                [PSObject] $Difference,
                [Parameter( Mandatory = $true, Position = 2, HelpMessage = "Members names." )]
                [PSObject] $members,
                [Parameter( Mandatory = $true, Position = 3, HelpMessage = "Key field." )]
                [string] $KeyField,
                [Parameter( Mandatory = $false, Position = 4, HelpMessage = "Members to add to changes." )]
                [string[]] $MandatoryMembers
            )
            begin {
                $Changes = @()

                $PSORef  = [PSCustomObject]@{ $KeyField = $Reference.$KeyField }
                $PSODiff = [PSCustomObject]@{ $KeyField = $Difference.$KeyField }
                foreach ( $item in $MandatoryMembers ){
                    $PSORef  | Add-Member -NotePropertyName $item -NotePropertyValue $null
                    $PSODiff | Add-Member -NotePropertyName $item -NotePropertyValue $null
                }
            }
            process {
                foreach ( $item in $members ) {
                    if ( $item -in $MandatoryMembers ){
                        $PSORef.$item  = $Reference.$item
                        $PSODiff.$item = $difference.$item
                    }
                    Else {
                        if ( !( $null -eq $Reference.$item )){
                            $compare = Compare-Object -ReferenceObject $Reference.$item -DifferenceObject $difference.$item -CaseSensitive

                            if ( $compare ){
                                $PSORef  | Add-Member -NotePropertyName $item -NotePropertyValue $Reference.$item
                                $PSODiff | Add-Member -NotePropertyName $item -NotePropertyValue $difference.$item
                            }
                        }
                        else {
                            if ( $Reference.$item -ne $difference.$item ) {
                                $PSORef  | Add-Member -NotePropertyName $item -NotePropertyValue $Reference.$item
                                $PSODiff | Add-Member -NotePropertyName $item -NotePropertyValue $difference.$item
                            }
                        }
                    }
                }

                if ( $PSORef ) {
                    $Changes += $PSORef
                    $Changes += $PSODiff
                }
            }
            end {
                return $Changes
            }
        }
        if ( !$Compare ){
            $Compare = Compare-Object -ReferenceObject $ReferenceObject -DifferenceObject $DifferenceObject -CaseSensitive -Property $MembersArray | Where-Object { $_.SideIndicator -eq "<="}

            foreach ( $Item in $Compare ) {
                $Key = $Item.$KeyField

                $Diff =  $DifferenceObject | where-object { $_.$KeyField -eq $Key }
                $Ref  =  $ReferenceObject  | where-object { $_.$KeyField -eq $Key }

                if ( $Ref -and $Diff ) {
                    $Changed += get-difference -reference $Ref -difference $Diff -members $MembersArrayWithMandatory -KeyField $KeyField -MandatoryMembers $MandatoryMembers
                }
            }

            if ( $IncludeUnchanged ) {
                $Unchanged += $ReferenceObject | Where-Object { $_.$KeyField -NotIn $Changed.$KeyField }
            }

            $RemovedItems = $ReferenceObject | Where-Object { $_.$KeyField -NotIn $DifferenceObject.$KeyField }
            if ( $RemovedItems ) {
                $Removed = $RemovedItems
            }

            $AddedItems = $DifferenceObject | Where-Object { $_.$KeyField -NotIn $ReferenceObject.$KeyField }
            if ( $AddedItems ) {
                $Added = $AddedItems
            }

            $PSO.Changed = $Changed
            $PSO.Removed = $Removed
            $PSO.Added   = $Added
            if ( $IncludeUnchanged ) {
                $PSO.Unchanged = $Unchanged
            }
        }

        $View  = @()
        $View += $KeyField
        $View += $MandatoryMembers
        $View += ($Changed | get-member -MemberType NoteProperty).name | Where-Object { $_ -notin $View }

        if ( $Changed ) {
            Show-ColoredTable -Data $Changed -View $View -Title "Changed items" -AddRowNumbers -AddNewLine
        }
        if ( $Removed ) {
            Show-ColoredTable -Data $Removed -View $View -Title "Removed items" -AddRowNumbers -AddNewLine
        }
        if ( $Added ) {
            Show-ColoredTable -Data $Added -View $View -Title "Added items" -AddRowNumbers -AddNewLine
        }
        if ( $Unchanged ) {
            Show-ColoredTable -Data $Unchanged -View $View -Title "Unchanged items" -AddRowNumbers -AddNewLine
        }
    }
    end {
        return $PSO
    }
}

#endregion
#region Invoke
Function Start-PSScript {
<#
    .SYNOPSIS
        Start PS script
    .DESCRIPTION
        Function to start powershell script or command.
    .EXAMPLE
        Parameter set: "Script"
        Start-PSScript -ScriptPath $ScriptPath -logFilePath $logFilePath [-Arguments $Arguments] [-Credentials $Credentials] [-WorkDir $WorkDir] [-Evaluate $Evaluate] [-DebugRun $DebugRun] [-Wait $Wait] [-Program $Program="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"]
        Parameter set: "ScriptBlock"
        Start-PSScript -ScriptBlock $ScriptBlock -logFilePath $logFilePath [-Arguments $Arguments] [-Credentials $Credentials] [-WorkDir $WorkDir] [-Evaluate $Evaluate] [-DebugRun $DebugRun] [-Wait $Wait] [-Program $Program="C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Import module remotely
    .DESCRIPTION
        Import powershell module to the remote session.
    .EXAMPLE
        Import-ModuleRemotely -Modules $Modules -Session $Session
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        MOD     Import module remotely
        VER     1
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
        [string]   $Global:gsGlobalDateTimeFormat = "dd.MM.yyyy HH:mm:ss"
        [string]   $Global:gsScriptLocalHost      = $using:gsScriptLocalHost
        [array]    $Global:gsLogBuffer            = @()
        [string]   $Global:gsScriptLogFilePath    = $using:gsScriptLogFilePath
        [int16 ]   $Global:gsParentLevel          = $using:gsParentLevel
        [string]   $Global:gsLogFileNamePosition  = $using:gsLogFileNamePosition
        $Global:gsRunningCredentials              = [System.Security.Principal.WindowsIdentity]::GetCurrent()

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

    invoke-command -session $Session -scriptblock $ScriptBlock
}
function Invoke-PSScriptBlock {
<#
    .SYNOPSIS
        Invoke PS script block
    .DESCRIPTION
        Function to automate remote PS session or execute scripts locally
    .EXAMPLE
        Parameter set: "Remote"
        Invoke-PSScriptBlock -ScriptBlock $ScriptBlock [-Computer $Computer] [-Credentials $Credentials] [-ImportLocalModule $ImportLocalModule] [-TestComputer $TestComputer] [-ExportedParameters $ExportedParameters] [-SessionOptions $SessionOptions] [-NewSession $NewSession] [-DebugSession $DebugSession]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        [Parameter( Mandatory = $False, Position = 7, ParameterSetName = "Remote", HelpMessage = "Run new session with host and credentials if already exist." )]
        [switch] $NewSession,
        [Parameter( Mandatory = $False, Position = 8, ParameterSetName = "Remote", HelpMessage = "Debug remote session." )]
        [switch] $DebugSession
    )

    Function New-RemoteSession {
    <#
        .SYNOPSIS
            New remote session
        .DESCRIPTION
            Function to create new powershell session.
        .EXAMPLE
            New-RemoteSession -StartParams $StartParams [-SessionOptions $SessionOptions]
        .NOTES
            AUTHOR  Alexk
            CREATED 23.02.21
            VER     1
    #>
        [OutputType([string])]
        [CmdletBinding()]
        Param(
            [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Parameters." )]
            [PSObject] $StartParams,
            [Parameter( Mandatory = $false, Position = 1, HelpMessage = "PS session options." )]
            [PSObject] $SessionOptions
        )
        begin {
            $PSSessionConfigurationName = 'PowerShell.7'
        }
        process {
            try {
                Add-ToLog -Message "Creating new [https] session to [$($StartParams.computer)]." -logFilePath $Global:gsScriptLogFilePath -Display -category "session" -Status "info"
                $Global:modSession  = New-PSSession @StartParams -UseSSL -ErrorVariable LastError -ErrorAction stop
                Add-ToLog -Message "Successfull created session [$($Global:modSession.Id)]. Transport [$($Global:modSession.transport)], state [$($Global:modSession.state)], availability [$($Global:modSession.availability)]." -logFilePath $Global:gsScriptLogFilePath -Display -category "session" -Status "info"
            }
            Catch {
                if ( $LastError ) {
                    Add-ToLog -Message $LastError.ErrorRecord -logFilePath $Global:gsScriptLogFilePath -Display -Status "Error"
                    switch ( $LastError.ErrorRecord.Exception.TransportMessage ) {
                        "A security error occurred " {
                            #$Answer = Get-Answer -Title "Do you want to connect without SSL sertificate validation?" -ChooseFrom "y","n" -DefaultChoose "y" -AddNewLine
                            $Answer = "N"
                            if ( $Answer -eq "Y" ) {
                                $SessionOptions += New-PSSessionOption -SkipCACheck
                                $StartParams += @{ SessionOption = $SessionOptions }
                                $Global:modSessionParams = $StartParams
                                try {
                                    Add-ToLog -Message "Creating new [https] session to [$($StartParams.computer)]." -logFilePath $Global:gsScriptLogFilePath -Display -category "session" -Status "info"
                                    $Global:modSession       = New-PSSession @StartParams -UseSSL -ErrorVariable LastError -ErrorAction stop
                                    Add-ToLog -Message "Successfull." -logFilePath $Global:gsScriptLogFilePath -Display -category "session" -Status "info"
                                }
                                Catch {
                                    if ( $LastError ) {
                                        Add-ToLog -Message $LastError.ErrorRecord -logFilePath $Global:gsScriptLogFilePath -Display -Status "Error"
                                    }
                                    Add-ToLog -Message "Creating new [http] session to [$($StartParams.computer)]." -logFilePath $Global:gsScriptLogFilePath -Display -category "session" -Status "info"
                                    $Global:modSession       = New-PSSession @StartParams
                                    Add-ToLog -Message "Successfull." -logFilePath $Global:gsScriptLogFilePath -Display -category "session" -Status "info"
                                }
                            }
                            Else {
                                Add-ToLog -Message "Creating new [http] session to [$($StartParams.computer)]." -logFilePath $Global:gsScriptLogFilePath -Display -category "session" -Status "info"
                                $Global:modSession       = New-PSSession @StartParams
                                Add-ToLog -Message "Successfull." -logFilePath $Global:gsScriptLogFilePath -Display -category "session" -Status "info"
                            }
                        }
                        Default {
                            Add-ToLog -Message "Creating new [http] session to [$($StartParams.computer)]." -logFilePath $Global:gsScriptLogFilePath -Display -category "session" -Status "info"
                            $Global:modSession       = New-PSSession @StartParams
                            Add-ToLog -Message "Successfull." -logFilePath $Global:gsScriptLogFilePath -Display -category "session" -Status "info"
                        }
                    }
                }
            }
            $Global:modPSSessionCounter ++
        }
        end {

        }
    }
    #https://stackoverflow.com/questions/28362175/powershell-debug-invoke-command
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
                # Else {
                #     $SessionOptions = New-PSSessionOption -SkipCACheck
                #     $StartParams += @{ SessionOption = $SessionOptions }
                # }

                if ( $Credentials ) {
                    $StartParams += @{ Credential = $Credentials }
                }
                ElseIf ( $Global:modCredentials ){
                    $StartParams += @{ Credential = $Global:modCredentials }
                }

                If ( $NewSession ) {
                    New-RemoteSession -StartParams $StartParams -SessionOptions $SessionOptions
                }
                Else {
                    if ( $Global:modSession.State -eq "Opened" ) {
                        $Diff = $False
                        foreach ( $Item in $Global:modSessionParams.Keys ){
                            if ( $Global:modSessionParams.$Item -ne $StartParams.$Item ) {
                                if ( $Item -eq "SessionOption" ){
                                    $CompareSessionOptions = Compare-Object -ReferenceObject $Global:modSessionParams.$Item -DifferenceObject  (New-PSSessionOption -SkipCACheck)
                                }
                                Else {
                                    $CompareSessionOptions = $null
                                }
                                if ( ($Item -ne "Credential") -and ( $CompareSessionOptions )) {
                                    $Diff = $True
                                }
                                Else {
                                    if ( $StartParams.$Item.UserName -ne $Global:modSessionParams.$Item.UserName  ) {
                                        $Diff = $True
                                    }
                                }
                            }
                        }
                        foreach ( $Item in $StartParams.Keys ){
                            if ( $Global:modSessionParams.$Item -ne $StartParams.$Item ) {
                                if ( $Item -ne "Credential" ) {
                                    $Diff = $True
                                }
                                Else {
                                    if ( $StartParams.$Item.UserName -ne $Global:modSessionParams.$Item.UserName  ) {
                                        $Diff = $True
                                    }
                                }
                            }
                        }
                        if ( $Diff ){
                            $Global:modSessionParams = $StartParams
                            New-RemoteSession -StartParams $StartParams -SessionOptions $SessionOptions
                        }
                        Else {
                            #Write-host "Reuse session $($Global:modSession.id)." -ForegroundColor green
                        }
                    }
                    Else {
                        $Global:modSessionParams = $StartParams
                        New-RemoteSession -StartParams $StartParams -SessionOptions $SessionOptions
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
            Write-host "Remove session $($Global:modSession.id)." -ForegroundColor green
        }
        Get-ErrorReporting $_
        # Write-Host "Invoke-PSScriptBlock: Unable to establish remote session to $Computer" -ForegroundColor Red
        # Write-Host "$_" -ForegroundColor Red
        $Global:modSession = $Null
        exit
    }

    if ( $Global:modSession.State -eq "Opened" ) {
        if ( $ExportedParameters ){
            Set-Variable -Name "GlobalExportedParameters" -Value $ExportedParameters -Scope "Global" #-Visibility Private
            try {
                $GlobalExportedParameters.Remove("Computer")    | Out-Null
                $GlobalExportedParameters.Remove("Credentials") | Out-Null
            }
            Catch {    }

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

            if ( $DebugSession ){
                $AttachDebugger = '
                    Set-PSBreakpoint -Variable "Params"
                '
            }
            Else{
                $AttachDebugger = ""
            }
            $ScriptBlockWithExportedParams = [scriptblock]::Create(($AttachDebugger + $ScriptBlockWithExportedParams))

            if ( $FirstString -notlike "*param*(*)*" ) {
                $Res = Invoke-Command -Session $Global:modSession -ScriptBlock $ScriptBlockWithExportedParams
            }
            Else {
                $ArgsArray = @()
                foreach ( $Item in $GlobalExportedParameters.keys ) {
                    $ArgsArray += ,$GlobalExportedParameters.$Item
                }
                # if ($ArgsArray.count -eq 0 ) {
                #     foreach ( $Item in $GlobalExportedParameters ) {
                #         $ArgsArray += ,$Item
                #     }
                # }

                $Res = Invoke-Command -Session $Global:modSession -ScriptBlock $ScriptBlockWithExportedParams -ArgumentList $ArgsArray
            }
            Remove-Variable -Name "GlobalExportedParameters"  -Scope "Global" -Force | Out-Null
        }
        Else {
            $Res = Invoke-Command -Session $Global:modSession -ScriptBlock $ScriptBlock
        }
        if ( $NewSession ){
            Remove-PSSession $Session
            $Global:modPSSessionCounter --
            Write-host "Remove session $($Global:modSession.id)." -ForegroundColor green
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
        Start program
    .DESCRIPTION
        Function to start os executable file.
    .EXAMPLE
        Start-Program -LogFilePath $LogFilePath [-Program $Program] [-Arguments $Arguments] [-Credentials $Credentials] [-WorkDir $WorkDir] [-Evaluate $Evaluate] [-DebugRun $DebugRun] [-Wait $Wait]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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

    $Message               = "User [$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)]. Starting program [$Program]"

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
        Start module
    .DESCRIPTION
        Install if not installed and start module.
    .EXAMPLE
        Start-Module -Module $Module [-Force $Force] [-InstallScope $InstallScope] [-AllowClobber $AllowClobber]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        MOD     23.02.21
        VER     2
#>
    [CmdletBinding()]
    Param (
        [Parameter( Mandatory = $True, Position = 0, HelpMessage = "Module name.")]
        [string] $Module,
        [Parameter( Mandatory = $False, Position = 1, HelpMessage = "Force reload module.")]
        [switch] $Force,
        [Parameter( Mandatory = $False, Position = 2, HelpMessage = "Install scope.")]
        [string] $InstallScope,
        [Parameter( Mandatory = $False, Position = 3, HelpMessage = "Force rewrite module functions.")]
        [switch] $AllowClobber
    )

     if ($Force) {

        $Res = Import-Module $Module -Force -PassThru -Scope Global
        $ModuleData = [PSCustomObject]@{
            Owner  = ( $ScriptStackItem | Select-Object -last 1 ).ScriptName
            Module = $Module
        }
        $Global:gsImportedModule += $ModuleData
    }
    Else {
        $Res = Import-Module $Module -PassThru -Scope Global

        $ModuleData = [PSCustomObject]@{
            Owner  = ( $ScriptStackItem | Select-Object -last 1 ).ScriptName
            Module = $Module
        }
        $Global:gsImportedModule += $ModuleData
    }

    if ( -not $Res ) {
        if ($InstallScope) {
            if ( $AllowClobber ) {
                Install-Module -Name $Module -Scope $InstallScope -AllowClobber
            }
            Else {
                Install-Module -Name $Module -Scope $InstallScope
            }

        }
        Else {
            if ( $AllowClobber ) {
                Install-Module -Name $Module -AllowClobber
            }
            Else {
                Install-Module -Name $Module
            }
        }

        if ($Force) {
            $Res = Import-Module $Module -Force -PassThru -Scope Global
        }
        Else {
            $Res = Import-Module $Module -PassThru -Scope Global
        }

        if (-not $res) {
            Add-ToLog "Module [$Module] could not be loaded!" -Display -Status "error" -logFilePath $Global:gsScriptLogFilePath
            exit 1
        }
        Else {
            $ModuleData = [PSCustomObject]@{
                Owner  = ( $ScriptStackItem | Select-Object -last 1 ).ScriptName
                Module = $Module
            }
            $Global:gsImportedModule += $ModuleData
        }
    }
}
function Remove-Modules {
<#
    .SYNOPSIS
        Remove modules
    .EXAMPLE
        Remove-Modules -Module $Module [-Force $Force]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
#>
    [CmdletBinding()]
    param (
        [Parameter( Mandatory = $True, Position = 0, HelpMessage = "Module name.")]
        [string[]] $Module,
        [Parameter( Mandatory = $False, Position = 1, HelpMessage = "Force reload module.")]
        [switch] $Force
    )

    $Modules = get-module | Where-Object {$_.name -in $Module} | Select-Object Name, RequiredModules | Sort-Object RequiredModules, Name

    foreach ( $item in $modules ){
        if ( $Force ){
            Remove-Module -Name $item.name -force
        }
        Else {
            Remove-Module -Name $item.name
        }
    }
}
Function Invoke-CommandWithDebug {
<#
    .SYNOPSIS
        Invoke command with debug
    .DESCRIPTION
        Function to invoke command or script with debug info.
    .EXAMPLE
        Parameter set: "Script"
        Invoke-CommandWithDebug -ScriptPath $ScriptPath [-Arguments $Arguments]
        Parameter set: "ScriptBlock"
        Invoke-CommandWithDebug -ScriptBlock $ScriptBlock [-Arguments $Arguments]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Convert special characters
    .DESCRIPTION
        Replace special characters in string.
    .EXAMPLE
        Convert-SpecialCharacters -String $String [-Mode $Mode="wildcard"]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Convert string to digit array
    .DESCRIPTION
        Convert string to array of digit.
    .EXAMPLE
        Convert-StringToDigitArray -UserInput $UserInput -DataSize $DataSize
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
#>
    [CmdletBinding()]
    param(
        [Parameter( Mandatory = $True, Position = 0, HelpMessage = "String input data.")]
        [string] $UserInput,
        [Parameter( Mandatory = $True, Position = 1, HelpMessage = "Data size.")]
        [int] $DataSize
    )

    $SelectedArray = ($UserInput -split ",").trim()
    if ( "e" -in $SelectedArray ) {
        return "e"
    }
    if ( "b" -in $SelectedArray ) {
        return "b"
    }
    Else {
        if ( $SelectedArray[0] -eq "*" ){
            $SelectedArray = @()
            foreach ( $Element in ( 1..( $DataSize-1 ) ) ) {
                $SelectedArray += $Element
            }
        }
        Else {
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
        }
    }

    return $SelectedArray
}

function Convert-PSCustomObjectToHashTable {
<#
    .SYNOPSIS
        Convert PS custom object to hash table
    .DESCRIPTION
        Convert string to array of digit.
    .EXAMPLE
        Convert-PSCustomObjectToHashTable -PSO $PSO
    .NOTES
        AUTHOR  Alexk
        CREATED 17.01.21
        VER     1
#>
    [OutputType([HashTable])]
    [CmdletBinding()]
    param(
        [Parameter( Mandatory = $True, Position = 0, HelpMessage = "PSCustom object.")]
        [PSCustomObject] $PSO
    )

    $Result = @{}
    $PSO.psobject.properties | ForEach-Object { $Result[$_.Name] = $_.Value }

    return $Result
}
function Invoke-TrailerIncrease {
<#
    .SYNOPSIS
        Invoke trailer increase
    .EXAMPLE
        Invoke-TrailerIncrease -String $String
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Format time span
    .DESCRIPTION
        Function to set time span presentation.
    .EXAMPLE
        Format-TimeSpan -TimeSpan $TimeSpan [-Format $Format="Auto"] [-Round $Round=0]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
                $Main = "days"
                $Res  = "$([math]::round($TimeSpan.TotalDays,$Round)) $Main"
            }
            ElseIf ( $TimeSpan.TotalHours -ge 1 ) {
                $Main = "hours"
                $Res  = "$([math]::round($TimeSpan.TotalHours,$Round)) $Main"
            }
            ElseIf ( $TimeSpan.TotalMinutes -ge 1 ) {
                $Main = "minutes"
                $Res  = "$([math]::round($TimeSpan.TotalMinutes,$Round)) $Main"
            }
            ElseIf ( $TimeSpan.TotalSeconds -ge 1 ) {
                $Main = "seconds"
                $Res  = "$([math]::round($TimeSpan.TotalSeconds,$Round)) $Main"
            }
            ElseIf ( $TimeSpan.TotalMilliseconds -ge 1 ) {
                $Main = "milliseconds"
                $Res  = "$([math]::round($TimeSpan.TotalMilliseconds,$Round)) $Main"
            }
            ElseIf ( $TimeSpan.Ticks -ge 1 ) {
                $Main = "Ticks"
                $Res  = "$([math]::round($TimeSpan.Ticks,$Round)) $Main"
            }
        }
        "TotalDays" {
            $Main = "days"
            $Res  = "$([math]::round($TimeSpan.TotalDays,$Round)) $Main"
        }
        "TotalHours" {
            $Main = "hours"
            $Res  = "$([math]::round($TimeSpan.TotalHours,$Round)) $Main "
        }
        "TotalMinutes" {
            $Main = "minutes"
            $Res  = "$([math]::round($TimeSpan.TotalMinutes,$Round)) $Main"
        }
        "TotalSeconds" {
            $Main = "seconds"
            $Res  = "$([math]::round($TimeSpan.TotalSeconds,$Round)) $Main"
        }
        "TotalMilliseconds" {
            $Main = "milliseconds"
            $Res  = "$([math]::round($TimeSpan.TotalMilliseconds,$Round)) $Main"
        }
        "Ticks" {
            $Main = "ticks"
            $Res  = "$($TimeSpan.ticks) $Main"
        }
        Default {}
    }

    if ( $main -eq "days" ){
        if ( $TimeSpan.TotalDays -ge 365){
            $Main = "years"
            $Res  = "$([math]::round($TimeSpan.TotalDays/365,$Round)) $Main"
        }
        Elseif ( $TimeSpan.TotalDays -ge 30 ){
            $Main = "months"
            $Res  = "$([math]::round($TimeSpan.TotalDays/30,$Round)) $Main"
        }
        Elseif ( $TimeSpan.TotalDays -ge 7 ){
            $Main = "weeks"
            $Res  = "$([math]::round($TimeSpan.TotalDays/7,$Round)) $Main"
        }
    }

    return $res
}
Function Start-ParallelPortPing {
<#
    .SYNOPSIS
        Start parallel port ping
    .DESCRIPTION
        Function to start parallel host ping with port.
        We can use port in host name.
    .EXAMPLE
        Start-ParallelPortPing -Hosts $Hosts [-Count $Count=1] [-Delay $Delay=1]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Convert FS path
    .DESCRIPTION
        Function to convert path from UNC to local or from local to UNC.
    .EXAMPLE
        Convert-FSPath -CurrentPath $CurrentPath [-Computer $Computer]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Get list by groups
    .DESCRIPTION
        Create console menu columned by data groups. Add digits for selection.
    .EXAMPLE
        Parameter set: "Select"
        Get-ListByGroups -GroupArray $GroupArray [-Title $Title] [-SelectMessage $SelectMessage] [-SelectSource $SelectSource] [-SelectKey $SelectKey] [-RowItemsColors $RowItemsColors=@("Cyan", "Blue")] [-RowGroupsColors $RowGroupsColors=@("DarkYellow", "DarkYellow")] [-SplitWords $SplitWords]
        Parameter set: "View"
        Get-ListByGroups -GroupArray $GroupArray [-Title $Title] [-SplitWords $SplitWords] [-PassThru $PassThru]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        MOD     23.02.21
        VER     2
#>
    [OutputType([String[]])]
    [CmdletBinding()]
    param(
        [Parameter( Mandatory = $True, Position = 0, HelpMessage = "Array of columns with data.")]
        [array] $GroupArray,
        [Parameter( Mandatory = $false, Position = 1, HelpMessage = "Title message.")]
        [string] $Title,
        [Parameter( Mandatory = $false, Position = 2, HelpMessage = "Select message.", ParameterSetName = "Select")]
        [string] $SelectMessage,
        [Parameter( Mandatory = $false, Position = 3, HelpMessage = "Select source array.", ParameterSetName = "Select")]
        [PSObject[]] $SelectSource,
        [Parameter( Mandatory = $false, Position = 4, HelpMessage = "Select key field.", ParameterSetName = "Select")]
        [string] $SelectKey,
        [Parameter( Mandatory = $false, Position = 5, HelpMessage = "Two row colors for items.", ParameterSetName = "Select")]
        [string[]] $RowItemsColors = @("Cyan", "Blue"),
        [Parameter( Mandatory = $false, Position = 5, HelpMessage = "Two row colors for groups.", ParameterSetName = "Select")]
        [string[]] $RowGroupsColors = @("DarkYellow", "DarkYellow"),
        [Parameter( Mandatory = $False, Position = 6, HelpMessage = "Split words in menu.")]
        [switch] $SplitWords,
        [Parameter( Mandatory = $False, Position = 7, HelpMessage = "Return object.", ParameterSetName = "View")]
        [switch] $PassThru
    )

    $Global:modDialogNumber ++

    $Header = "[$( get-date -format $Global:gsGlobalTimeFormat )][$Global:modDialogNumber][$($global:modComputer)\"
    foreach ($item in $Global:modGroupListArray ) {
        $Header += "$item\"
    }
    $Header += "][$Title] |"
    $Header = $Header.PadRight($Host.UI.RawUI.WindowSize.Width - $header.Length - 5,"-") + "-> |"
    Get-ColorText -Text $Header -TextColor "Magenta"

    $TempArray   =  @(,@("[e] Exit", "[b] Back"))
    $TempArray  += (@(,$GroupArray) | Where-Object {$null -ne $_})
    $GroupArray  = $TempArray

    [array] $List = @()
    foreach ( $Item in $GroupArray ) {
        [array] $List += $Item
    }

    $MaxNumLen     = ([string]$List.Count).Length
    #$PadSymbol    = "*"
    $Padding       = " "
    $ColDistance   = 4
    $MaxItemLen    = ($List | Measure-Object length -Maximum).maximum + $MaxNumLen + 2 + $Padding.Length + $ColDistance
    $MaxGroupCount = ($GroupArray | ForEach-Object { ($_ | Measure-Object).count } | Measure-Object -Maximum).maximum - 1
    $GroupCounter  = 0

    [string[]]$RowArray = @(0..$MaxGroupCount)
    $RowArray.Clear()

    foreach ( $Group in $GroupArray ) {
        If ( $GroupCounter -eq 0 ) {
            $Defaults = "`n"
            foreach ( $Item in $Group ) {
                #$ItemNumber = $List.IndexOf($Item) - 1
                #Write-Host "".PadRight($StringLen, $PadSymbol) -ForegroundColor blue
                $Defaults += "$Item.   "
            }

            $Defaults += "`n"
            Get-ColorText -text $Defaults -TextColor "DarkRed" -ParameterColor $RowGroupsColors[0]
        }
        Else {
            foreach ( $Item in ( 0..( $MaxGroupCount ) ) ) {
                if ( $Group.count -gt 1 ){
                    $GroupItem = $Group[$Item]
                }
                Else {
                    if ( $Item -eq 0){
                        $GroupItem  = ([string[]]$Group)[0]
                    }
                    Else {
                        $GroupItem  = $Null
                    }
                }

                if ( $SplitWords ) {
                    #write-host $Group[$Item]
                    if ( $GroupItem ) {
                        $GroupItemSplitted = Split-Words -Word $GroupItem
                    }
                    Else {
                        $GroupItemSplitted = ""
                    }
                }
                Else {
                    $GroupItemSplitted = $GroupItem
                }

                if ( $GroupItem ){
                    if ( $GroupItem.contains("  ") ){
                        $GroupItemSplitted = $GroupItemSplitted.toupper()
                    }
                }


                if ( $GroupItem ) {
                    $ItemNumber            = $List.IndexOf( $GroupItem ) - 1
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
        if ( $Color -eq $RowItemsColors[0] ) {
            $Color = $RowItemsColors[1]
            $GroupColor = $RowGroupsColors[1]
        }
        Else {
            $Color = $RowItemsColors[0]
            $GroupColor = $RowGroupsColors[0]
        }

        Get-ColorText -Text $Item -TextColor $Color -ParameterColor $GroupColor
    }

    Write-Host ""
    if ( $SelectMessage ) {
        Write-Host "$SelectMessage " -ForegroundColor Cyan -NoNewline
    }
    Else {
        Write-Host "Select items: " -ForegroundColor Cyan -NoNewline
    }
    $SelectedList = Read-Host
    while ( -not ($SelectedList -match '[0-9\-*eb,\s]') ) {
        Write-Host "Wrong input [$SelectedList]! Allow only [0-9],[-],[ ],[,],[*]. Please input again: " -ForegroundColor Red -NoNewline
        $SelectedList = Read-Host
    }

    $SelectedArray = Convert-StringToDigitArray -UserInput $SelectedList -DataSize $List.count
    $SelectedList = @()
    foreach ( $item in $SelectedArray ){
        if ( $item -eq "e" ){
            #$SelectedList  += "Exit"
            Get-ColorText -TextColor "Green" -Text "[Exit]"
            . "$($Global:gsGlobalSettingsPath)\$($Global:gsSCRIPTSFolder)\Finish.ps1"
            exit 0
        }
        elseif ( $item -eq "b" ){
            $SelectedList  += "Back"
        }
        Else {
            $SelectedList  += $List[$item+1]
        }
    }

    if ( !( "Back" -in $SelectedList ) ){

        if ( $SelectSource ){
            if ( $SelectKey ) {
                $Result    = $SelectSource | where-object {$_.$SelectKey -like "*$SelectedList*" }
            }
            Else {
                $Result    = $SelectSource | where-object {$_ -like "*$SelectedList*" }
            }
            return $Result
        }

        $HasChild = $SelectedList | where-object { $_.Contains("  ") -eq $true }
        if ( (0 -notin $SelectedArray) -and $HasChild ){
            $Global:modGroupListArray += $SelectedList[0].trim()
        }
        ElseIf (0 -in $SelectedArray ) {
            $Global:modGroupListArray = $Global:modGroupListArray | select-object -SkipLast 1
        }

        if ( $SelectedList ){
            $SelectedText = ""
            foreach ( $item in $SelectedList ){
                $SelectedText += "[$($item.trim())] "
            }
            Get-ColorText -TextColor "Green" -Text $SelectedText.trim()
        }

        write-host ""

        if ( $PassThru ) {
            return $SelectedList.trim()
        }
    }
    Else {
        return "Back"
    }
}
Function Get-EventList {
<#
    .SYNOPSIS
        Get event list
    .DESCRIPTION
        Function to event list from log file in interval or not.
    .EXAMPLE
        Get-EventList -LogFilePath $LogFilePath [-Event $Event] [-Interval $Interval=0]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Get helpers data
    .DESCRIPTION
        Function return row in array from helpers CSV
    .EXAMPLE
        Get-HelpersData -CSVFilePath $CSVFilePath -Column $Column -Value $Value
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Get copy by BITS
    .DESCRIPTION
        Copy content of source path to destination path.
    .EXAMPLE
        Get-CopyByBITS -Source $Source -Destination $Destination [-Replace $Replace] [-ShowStatus $ShowStatus]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
            Show copy status
        .DESCRIPTION
            Show status of bits copy process.
        .EXAMPLE
            Show-CopyStatus -CommonData $CommonData -Array $Array
        .NOTES
            AUTHOR  Alexk
            CREATED 05.11.20
            VER     1
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
        Get ACL array
    .DESCRIPTION
        Function return Array of ACL for all objects in the Path
        Use Type to filter item. "file", "folder", "all"
    .EXAMPLE
        Parameter set: "Remote"
        Get-ACLArray -Path $Path [-Computer $Computer] [-Credentials $Credentials=$null] [-Type $Type="all"]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Resolve I pto FQD nin array
    .DESCRIPTION
        Add FQDN column to IP array.
    .EXAMPLE
        Resolve-IPtoFQDNinArray -Array $Array
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
function Split-Words {
<#
    .SYNOPSIS
        Split words
    .DESCRIPTION
        Split words by capital letter.
    .EXAMPLE
        Split-Words -Word $Word
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
#>
    [OutputType([string])]
    [CmdletBinding()]
    param (
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Word to be splitted." )]
        [ValidateNotNullOrEmpty()]
        [string] $Word
    )
    $PrevCharHi = $null
    $Result     = ""
    $Turn       = $False
    $Word       = $Word.Replace("-","")

    foreach ( $Char in $Word.ToCharArray() ) {
        $CharHi = ($Char -cmatch '[A-Z]')
        if ($CharHi -and (-not $PrevCharHi) -and ($null -ne $PrevCharHi) ) {
            $Result += " $Char"
            $Turn = $true
        }
        Else {
            if (( -not $CharHi) -and ($PrevCharHi) -and ($Result.Length -gt 2) -and ($null -ne $PrevCharHi) -and (-not $turn)) {
                $LastChar = $Result.substring($result.Length - 1).ToLower()
                $Result = "$($Result.substring(0, ($result.Length - 1))) $LastChar$Char"
                $Turn = $true
            }
            Else {
                $Result += "$Char"
                $Turn = $False
            }
        }
        $PrevCharHi = $CharHi
    }
    $WordsArray = $Result.Split(" ")
    $Result = "$($WordsArray[0]) "

    foreach ($item in $WordsArray[1..$WordsArray.count]) {
        if($Item -ceq ($item.ToUpper())){
            $Result += "$Item "
        }
        else {
            if ( $Item.Substring(1) -ceq ($Item.Substring(1).ToLower() )){
                $Result += "$($Item.ToLower()) "
            }
            Else {
                $Result += "$Item "
            }
        }
    }

    return $Result.trim()
}
function Get-TextLengthPreview {
<#
    .SYNOPSIS
        Get text length preview
    .DESCRIPTION
        Preview text with length number.
    .EXAMPLE
        Get-TextLengthPreview -Text $Text [-ShowUnprintableChars $ShowUnprintableChars] [-RemoveCR $RemoveCR]
    .NOTES
        AUTHOR  Alexk
        CREATED 06.11.20
        VER     1
#>
    [OutputType([PSObject])]
    [CmdletBinding()]
    param (
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Text array." )]
        [ValidateNotNullOrEmpty()]
        [string[]] $Text,
        [Parameter( Mandatory = $false, Position = 1, HelpMessage = "Show unprintable characters." )]
        [switch] $ShowUnprintableChars,
        [Parameter( Mandatory = $false, Position = 2, HelpMessage = "Remove Cr char." )]
        [switch] $RemoveCR
    )

    $NewText = @()
    $MaxLineLen = 0
    $AddNewLine = $false

    if ( @($Text.Count) -eq 1 ){
        $AddNewLine = $true
        $SplittedText = $Text[0].split("`n")
    }
    Else {
        $SplittedText = $Text
    }

    foreach ( $line in $SplittedText ){
        if ( $AddNewLine ){
            $line = $line.replace("`n","")
        }
        if ( $RemoveCR ){
            $line = $line.replace("`r","")
        }
        if ( $ShowUnprintableChars ){
            if ( $line ){
                $line = Show-UnprintableChars -String $line
            }
        }
        $PSO = [PSCustomObject]@{
            Length = $line.Length
            Text   = $line
        }
        $NewText += $PSO
    }

    return $NewText
}
function Show-UnprintableChars {
<#
    .SYNOPSIS
        Show unprintable chars
    .DESCRIPTION
        Replace ASCII unprintable characters with their names.
    .EXAMPLE
        Show-UnprintableChars -String $String [-HTMLCodes $HTMLCodes] [-Dec $Dec] [-Hex $Hex]
    .NOTES
        AUTHOR  Alexk
        CREATED 06.11.20
        VER     1
#>
    [OutputType([String])]
    [CmdletBinding()]
    param (
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Text string." )]
        [ValidateNotNullOrEmpty()]
        [string[]] $String,
        [Parameter( Mandatory = $false, Position = 1, HelpMessage = "Show HTML codes." )]
        [switch] $HTMLCodes,
        [Parameter( Mandatory = $false, Position = 1, HelpMessage = "Show decimal numbers." )]
        [switch] $Dec,
        [Parameter( Mandatory = $false, Position = 1, HelpMessage = "Show hex numbers." )]
        [switch] $Hex

    )

    if ( !$HTMLCodes -and !$Dec -and !$Hex ){
        $ASCIITable = import-csv -path "$($Global:gsHelpers)\$Global:gsDATAFolder\ASCII table.csv"
    }
    [int[]] $ASCIICodeArray = @()

    foreach ( $Char in $string.ToCharArray() ){
        $ASCIICodeArray += [int][char]$Char
    }

    $NewString = ""
    $Count     = $ASCIICodeArray.count - 1
    $Cntr      = 0
    $Repeat    = 1
    foreach ( $item in (0..$Count) ){
        if ( $ItemCntr -lt $Count ){
            $Cntr ++
        }
        if ( $ASCIICodeArray[$item]-ne $ASCIICodeArray[$Cntr]) {
            $Decimal = $ASCIICodeArray[$item]
            if ( $Dec ){
                $NewString += "`'" + $Decimal + "`'"
            }
            ElseIf ( $Hex ){
                $NewString += "`'" + ($Decimal).ToString("X") + "`'"
            }
            ElseIf ( $HTMLCodes ) {
                if ( $Decimal -ge 32 ){
                    $NewString += "`'&#" + ($Decimal).ToString("X") + ";`'"
                }
            }
            if ( ($Decimal -le 32) -or ($Decimal -eq 34) -or ($Decimal -eq 127) ) {
                if ( $repeat -eq 1){
                    $NewString += "`'" + ($ASCIITable | Where-Object {$_.dec -eq $Decimal}).char + "`'"
                }
                Else {
                    $NewString += "`'" + ($ASCIITable | Where-Object {$_.dec -eq $Decimal}).char + "*$repeat`'"
                }
            }
            Else{
                if ( $Decimal -le 127 ){
                    $NewString += ($ASCIITable | Where-Object {$_.dec -eq $Decimal}).char
                }
                Else {
                    $NewString += [char][int]$item
                }
            }
            $Repeat = 1
        }
        Else {
            $Repeat++
        }
    }
    return $NewString
}
function Export-RegistryToFile {
<#
    .SYNOPSIS
        Export registry to file
    .DESCRIPTION
        Export registry fields to the file.
    .EXAMPLE
        Export-RegistryToFile [-FilePath $FilePath] [-Path $Path] [-Property $Property] [-Hive $Hive]
    .NOTES
        AUTHOR  Alexk
        CREATED 07.12.20
        MOD     23.02.21
        VER     2
#>
    [CmdletBinding()]
    Param (
        [string] $FilePath,
        [string] $Path,
        [string] $Property,
        [switch] $Hive
    )

    if ( $FilePath ) {
        $Export = $Path.replace(':','')
        $ExportFind = ($Export.split("\") | Select-Object -skip 1) -join "\"
        if ( Test-path -path $FilePath ){
            $TmpFilePath = "$([Environment]::ExpandEnvironmentVariables($env:TEMP))\tmp_reg.reg"
            & reg export $Export $TmpFilePath

            $Content = Get-Content $TmpFilePath | Where-Object { $_ -ne 'Windows Registry Editor Version 5.00' -and  (($_ -like "*$ExportFind]*") -or ($_ -like "*`"$Property`"*")) }
            $Content.trim() | Add-Content $FilePath
            "`n"| Add-Content $FilePath
            #write-host "$Content"
            Remove-Item -path $TmpFilePath -Force
        }
        Else {
            $TmpFilePath = "$([Environment]::ExpandEnvironmentVariables($env:TEMP))\tmp_reg.reg"
            & reg export $Export $TmpFilePath
            if ( $hive ){
                Get-Content $TmpFilePath | Set-Content $FilePath
            }
            Else {
                Get-Content $TmpFilePath | Where-Object {($_ -eq 'Windows Registry Editor Version 5.00') -or  ($_ -like "*$ExportFind]*") -or ($_ -like "*`"$Property`"*") -or ( $_ -eq "" ) }  | Set-Content $FilePath
            }
            Remove-Item -path $TmpFilePath -Force
        }
    }
}

Function Get-DataStatistic {
<#
    .SYNOPSIS
        Get data statistic
    .DESCRIPTION
        Show data statistics
    .EXAMPLE
        Get-DataStatistic [-Data $Data] [-Statistic $Statistic] [-Color $Color=@("Cyan", "DarkMagenta", "Magenta")] [-PassThru $PassThru]
    .NOTES
        AUTHOR  Alexk
        CREATED 16.03.21
        VER     1
#>
    [OutputType([string])]
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $false, Position = 0, HelpMessage = "PsObject data." )]
        [psObject[]] $Data,
        [Parameter( Mandatory = $false, Position = 1, HelpMessage = "Show statistic for fields.")]
        [PSObject[]] $Statistic,
        [Parameter( Mandatory = $false, Position = 2, HelpMessage = "Change each line color.")]
        [String[]] $Color = @("Cyan", "DarkMagenta", "Magenta"),
        [Parameter( Mandatory = $false, Position = 3, HelpMessage = "Return PSO.")]
        [switch] $PassThru
    )
    begin {
        $MessageArray = @()
    }
    process {
        $PSO    = [PSCustomObject]@{}
        foreach ( $item1 in $Statistic){
            $item = $item1.name
            $ItemType = $item1.type
            $Message  = ""

            if ( $ItemType  ) {

                $Detail = [PSCustomObject]@{}
                switch ($ItemType) {
                    "string" {
                        if ( $item.Contains(".") ){
                            $itemData = $Item.split(".")

                            $ExpandProperty = $itemData[0]
                            $Property       = $itemData[1]

                            $ExpandedData = $Data | Select-Object -ExpandProperty $ExpandProperty -ErrorAction SilentlyContinue
                            if ( $ExpandedData ) {
                                $ExpandedDataProperties = $ExpandedData | get-member -MemberType NoteProperty
                                if ( $Property -in $ExpandedDataProperties.name ){
                                    $Unique =  $ExpandedData | Select-Object $Property -Unique | Sort-Object $Property
                                    $Message = "Unique [$item]: [$(($Unique.$Property | where-object { $_ -ne $null }) -join ", " )]"
                                    $PSO  | Add-Member -NotePropertyName $Item -NotePropertyValue $Unique.$Property | where-object { $_ -ne $null }
                                }
                            }
                            Else {
                                $Stop
                            }
                        }
                        Else {
                            $Unique = $Data | Select-Object $item -Unique | where-object { $_.$item -ne $null } | Sort-Object $item
                            $Message = "Unique [$item]: [$($Unique.$item -join ", ")]"
                            $PSO  | Add-Member -NotePropertyName $Item -NotePropertyValue $Unique.$item
                        }
                    }
                    "datetime"{
                        $Sorted   = $Data | Sort-Object $item | Select-Object $item
                        $Start    = ($Sorted | Select-Object -First 1).$item
                        $End      = ($Sorted | Select-Object -Last 1).$item
                        $TimeSpan = New-TimeSpan -start $Start -end $End
                        $Interval = Format-TimeSpan -TimeSpan $TimeSpan
                        $Message  = "Interval [$item]: [$Interval] [$start]-[$end]"
                        $PSO  | Add-Member -NotePropertyName $Item -NotePropertyValue "[$Interval] [$start]-[$end]"
                    }
                    "int"{
                        try{
                            $Stat = $data | Measure-Object  -Property $item -AllStats
                            $Message = "Count [$item]: [$($Stat.Count)], Sum [$item]: [$($Stat.sum)], Avg [$item]: [$($Stat.Average)], Max [$item]: [$($Stat.Maximum)], Min [$item]: [$($Stat.Minimum)], Dev [$item]: [$($Stat.StandardDeviation)]"

                            $StatMembers = $Stat | Get-Member -MemberType Property
                            foreach ( $Member in $StatMembers.name) {
                                $Detail | Add-Member -NotePropertyName $Member -NotePropertyValue $Stat.$Member
                            }

                            $DetailProperties = $Detail | Get-Member -MemberType NoteProperty
                            if ( $DetailProperties ){
                                $PSO  | Add-Member -NotePropertyName $Item -NotePropertyValue $Detail
                            }

                        }
                        Catch {}
                    }
                    Default {}
                }
            }

            if ( $Message ) {
                $MessageArray += $Message
            }
        }

        if ( $MessageArray ){
            write-host "Statistics" -ForegroundColor $Color[0]
            $MaxLen   = 0
            $TotalLen = 0
            foreach ( $item in $MessageArray) {
                $ItemLen0 = $item.split(":")[0].length
                if ( $ItemLen0 -gt $MaxLen ){
                    $MaxLen = $ItemLen0
                }
            }

            $AlignedMessageArray = @()
            foreach ( $item in $MessageArray) {
                $itemData = $item.split(":")
                $Part1 = $itemData[0]
                $Part2 = ($itemData | select-object -skip 1 ) -join ":"

                $Part1Data = $Part1.split(" ")
                $Part1Part1 = $Part1Data[0]
                $Part1Part2 = ($Part1Data | select-object -skip 1 ) -join " "
                $lenToAdd = $MaxLen - $Part1.length + $Part1Part2.Length + 1

                $Part1 = $Part1Part1 + $Part1Part2.PadLeft($lenToAdd, " ")
                $Newitem = $Part1 + ":" + $Part2
                $AlignedMessageArray += $Newitem
            }

            foreach ( $item in $AlignedMessageArray) {
                $ItemLen = $item.length
                if ( $ItemLen -gt $TotalLen ){
                    $TotalLen = $ItemLen
                }
            }

            if( $TotalLen -gt $Host.UI.RawUI.WindowSize.Width ){
                $TotalLen = $Host.UI.RawUI.WindowSize.Width
            }

            $Messages = $AlignedMessageArray -join ("`n")
            $Sign = "-"
            write-host "$(''.padleft($TotalLen, $Sign))" -ForegroundColor $Color[0]
            Get-ColorText -Text $Messages  -TextColor "DarkBlue" -ParameterColor "DarkYellow"
            write-host "$(''.padleft($TotalLen, $Sign))`n"   -ForegroundColor $Color[0]
        }
    }
    end {
        if ( $PassThru ){
            return $PSO
        }
    }
}
function Show-ColoredTable {
<#
    .SYNOPSIS
        Show colored table
    .DESCRIPTION
        Show table in color view.
    .EXAMPLE
        Parameter set: "Alerts"
        Show-ColoredTable -Field $Field [-Data $Data] [-Definition $Definition] [-View $View] [-Title $Title] [-SelectField $SelectField] [-SelectMessage $SelectMessage] [-Confirmation $Confirmation] [-Statistic $Statistic] [-NotNull $NotNull] [-Single $Single]
        Parameter set: "Color"
        Show-ColoredTable [-Data $Data] [-View $View] [-Color $Color=@("Cyan", "DarkMagenta", "Magenta")] [-Title $Title] [-SelectField $SelectField] [-SelectMessage $SelectMessage] [-Confirmation $Confirmation] [-Statistic $Statistic] [-AddRowNumbers $AddRowNumbers] [-NotNull $NotNull] [-Single $Single] [-AddNewLine $AddNewLine=$true] [-NoBackOption $NoBackOption] [-NoOptions $NoOptions] [-PassThru $PassThru]
    .NOTES
        AUTHOR  Alexk
        CREATED 02.12.20
        MOD     23.02.21
        VER     2
#>
    [CmdletBinding()]
    Param (
        [Parameter( Mandatory = $false, Position = 0, HelpMessage = "PsObject data." )]
        [psObject[]] $Data,
        [Parameter( Mandatory = $true, Position = 1, HelpMessage = "Field.", ParameterSetName = "Alerts" )]
        [ValidateNotNullOrEmpty()]
        [string] $Field,
        [Parameter( Mandatory = $false, Position = 2, HelpMessage = "Color rules definition.", ParameterSetName = "Alerts" )]
        [psObject] $Definition,
        [Parameter( Mandatory = $false, Position = 3, HelpMessage = "Selected fields view." )]
        $View,
        [Parameter( Mandatory = $false, Position = 4, HelpMessage = "Change each line color.", ParameterSetName = "Color")]
        [String[]] $Color = @("Cyan", "DarkMagenta", "Magenta"),
        [Parameter( Mandatory = $false, Position = 5, HelpMessage = "Table title.")]
        [String] $Title,
        [Parameter( Mandatory = $false, Position = 6, HelpMessage = "Select field.")]
        [string] $SelectField,
        [Parameter( Mandatory = $false, Position = 7, HelpMessage = "Select message.")]
        [string] $SelectMessage,
        [Parameter( Mandatory = $false, Position = 8, HelpMessage = "Select message.")]
        [string] $Confirmation,
        [Parameter( Mandatory = $false, Position = 9, HelpMessage = "Show statistic for fields.")]
        [PSObject[]] $Statistic,
        [Parameter( Mandatory = $false, Position = 10, HelpMessage = "Add row numbers.", ParameterSetName = "Color" )]
        [switch] $AddRowNumbers,
        [Parameter( Mandatory = $false, Position = 11, HelpMessage = "Allow only not null results.")]
        [switch] $NotNull,
        [Parameter( Mandatory = $false, Position = 12, HelpMessage = "Allow only single result.")]
        [switch] $Single,
        [Parameter( Mandatory = $false, Position = 13, HelpMessage = "Add new line at the end.", ParameterSetName = "Color" )]
        [switch] $AddNewLine = $true,
        [Parameter( Mandatory = $false, Position = 14, HelpMessage = "Show back option.", ParameterSetName = "Color" )]
        [switch] $NoBackOption,
        [Parameter( Mandatory = $false, Position = 15, HelpMessage = "Show no options.", ParameterSetName = "Color" )]
        [switch] $NoOptions,
        [Parameter( Mandatory = $false, Position = 16, HelpMessage = "Return object.", ParameterSetName = "Color" )]
        [switch] $PassThru
    )

    if ( $Data ){
        $SerialData = [System.Management.Automation.PSSerializer]::Serialize($Data)
        $DataCopy   = [System.Management.Automation.PSSerializer]::Deserialize($SerialData)

        $Header = "[$( get-date -format $Global:gsGlobalTimeFormat )][$Global:modDialogNumber][$($global:modComputer)][$Title] |"
        $Header = $Header.PadRight(200,"-") + "-> |"
        Get-ColorText -Text $Header -TextColor "Magenta"
        $Global:modDialogNumber ++

        if ( !$NoOptions ){
            if (  $NoBackOption ){
                $Exit = "`n[e] Exit.`n"
            }
            Else {
                $Exit = "`n[e] Exit.   [b] Back.`n"
            }
            Get-ColorText -text $Exit -TextColor $Color[1] -ParameterColor "DarkYellow"
        }

        if ( $Statistic ) {
            Get-DataStatistic -Data $Data -Statistic $Statistic -Color $Color
        }

        If ( !$View ){
            $View = "*"
        }
        $First = $true

        if ( $Field ) {
            if ( !$Definition ){
                $Definition = [PSCustomObject]@{
                    Information = @{Field = "Information"; Color = "Green"}
                    Verbose     = @{Field = "Verbose"    ; Color = "Green"}
                    Error       = @{Field = "Error"      ; Color = "Red"}
                    Warning     = @{Field = "Warning"    ; Color = "Yellow"}
                }
            }

            foreach ( $Item in $DataCopy ){
                switch ( $Item.$Field ) {
                    $Definition.Information.Field {
                        if ( $First ) {
                            write-host ""
                            write-host "$(($Item | format-table -property $View -AutoSize | Out-String).trim() )" -ForegroundColor $Definition.Information.Color
                            $First = $false
                        }
                        Else {
                            write-host "$(($Item | format-table -property $View -AutoSize -HideTableHeaders | Out-String).trim() )" -ForegroundColor $Definition.Information.Color
                        }
                    }
                    $Definition.Verbose.Field {
                        if ( $First ) {
                            write-host ""
                            write-host "$(($Item | format-table -property $View -AutoSize | Out-String).trim() )" -ForegroundColor $Definition.Verbose.Color
                            $First = $false
                        }
                        Else {
                            write-host "$(($Item | format-table -property $View -AutoSize -HideTableHeaders | Out-String).trim() )" -ForegroundColor $Definition.Verbose.Color
                        }
                    }
                    $Definition.Error.Field {
                        if ( $First ) {
                            write-host "$(($Item | format-table -property $View -AutoSize | Out-String).trim() )" -ForegroundColor $Definition.Error.Color
                            $First = $false
                        }
                        Else {
                            write-host "$(($Item | format-table -property $View -AutoSize -HideTableHeaders | Out-String).trim() )" -ForegroundColor $Definition.Error.Color
                        }
                    }
                    $Definition.Warning.Field {
                        if ( $First ) {
                            write-host "$(($Item | format-table -property $View -AutoSize | Out-String).trim() )" -ForegroundColor $Definition.Warning.Color
                            $First = $false
                        }
                        Else {
                            write-host "$(($Item | format-table -property $View -AutoSize -HideTableHeaders | Out-String).trim() )" -ForegroundColor $Definition.Warning.Color
                        }
                    }
                    Default {
                        Write-host "$(($Item | format-table -property $View -AutoSize -HideTableHeaders | Out-String).trim() )" -ForegroundColor "White"
                    }
                }
            }
        }
        Else {
            if ( $AddRowNumbers ){
                [Int16] $Counter = 1
                $Result = @()
                $HasNum = ( $DataCopy | get-member -MemberType NoteProperty ).name | where-object {$_ -eq "Num"}

                if ( !$HasNum ) {
                    try {
                        $DataCopy | Add-Member -MemberType NoteProperty -Name "Num" -Value 0
                    }
                    Catch {
                        ( $DataCopy | get-member -MemberType NoteProperty ).name
                        $stop
                    }
                }

                foreach ( $item in $DataCopy ) {
                    try {
                        $item.Num = $Counter
                    }
                    Catch {
                        ( $item | get-member -MemberType NoteProperty ).name
                        $stop
                    }
                    $Result  += $item
                    $Counter ++
                }

                $NewView  = @("Num")
                if ( $View -ne "*" ){
                    $NewView += $View
                }
                Else {
                    $Fields   = ($DataCopy | get-member -MemberType NoteProperty).name | where-object {$_ -ne "Num"}
                    $NewView += $Fields
                }

                $View = $NewView
                $Data.PSObject.Properties.Remove("Num")
            }

            if ( !$Result ) {
                $Result = $DataCopy
            }

            if ( !$Color ){
                $Exclude   = "White", "Black", "Yellow", "Red"
                $ColorList = [Enum]::GetValues([System.ConsoleColor])
                $Basic     = $ColorList | where-object {$_ -notlike "Dark*"} | where-object {$_ -notin $Exclude}

                $Pairs = @()
                foreach ( $Item in $basic ){
                    $Pairs += ,@("$Item", "Dark$Item")
                }

                $ColorPair = , @($Pairs) | Get-Random
                $Header    = $ColorList | where-object {$_ -notin $ColorPair} | get-random
                $Color     = @($Header)
                $Color    += $ColorPair
            }

            $Cnt        = 1
            $FirstCnt   = 0
            $ColorCount = $Color.Count - 1

            $TableData  = ( $Result | format-table -property $View -AutoSize | Out-String ).trim().split("`r")
            foreach ( $line in $TableData ){
                if ( $First ) {
                    write-host $line -ForegroundColor $Color[0] -NoNewLine
                    $FirstCnt ++
                    if ( $FirstCnt -gt 1 ){
                        $First = $false
                    }
                }
                Else {
                    write-host $line -ForegroundColor $Color[$Cnt] -NoNewLine
                }

                if ( $Cnt -lt $ColorCount){
                    $Cnt++
                }
                Else {
                    $Cnt = 1
                }
            }

            write-host ""
        }

        if ( $SelectMessage ){
            while ( (!$SelectedArray) -and $Result ) {
                Write-Host "`n$SelectMessage" -NoNewline -ForegroundColor $Color[0]
                $Selected = $null
                while( !$Selected -and $Result ){
                    $Selected       = Read-Host
                    if ( !$Selected -and $Result ){
                        write-host "Select correct number! 0 to exit." -ForegroundColor red
                        Write-Host "`n$SelectMessage" -NoNewline -ForegroundColor $Color[0]
                    }
                    Else {
                        if ( $Single ){
                            if ( $Selected.Contains("-") -or $Selected.Contains("*")  -or $Selected.Contains(",") ) {
                                $Selected = $null
                                write-host "Allow only single value!" -ForegroundColor red
                                Write-Host "`n$SelectMessage" -NoNewline -ForegroundColor $Color[0]
                            }
                        }
                    }
                }

                if ( $Result ) {
                    $First = $true
                    $SelectedNum    = Convert-StringToDigitArray -UserInput $Selected -DataSize $Result.count

                    if ( "e" -in $SelectedNum ){
                        Get-ColorText -TextColor "Green" -Text "[Exit]"
                        . "$($Global:gsGlobalSettingsPath)\$($Global:gsSCRIPTSFolder)\Finish.ps1"
                        exit 0
                    }
                    if ( !( "b" -in $SelectedNum ) ) {

                        $SelectedArray = ( $Result | Where-Object { ( $Result.IndexOf($_) + 1) -in $SelectedNum })

                        $Cnt        = 1
                        $ColorCount = $Color.Count - 1
                        $FirstCnt   = 0

                        $TableData  = ( $SelectedArray  | format-table -property $View -AutoSize | Out-String ).trim().split("`r`n")
                        foreach ( $line in $TableData ){
                            if ( $First ) {
                                #write-host $line -ForegroundColor $Color[0] -NoNewLine
                                if ( $line -ne "" ) {
                                    $FirstCnt ++
                                }
                                if ( $FirstCnt -gt 1 ){
                                    $First = $false
                                }
                            }
                            Else {
                                if ( $line -ne "" ) {
                                    write-host $line -ForegroundColor $SelectedColor #-NoNewLine
                                }
                            }

                            if ( $SelectedColor -eq "Green" ){
                                $SelectedColor = "DarkGreen"
                            }
                            Else {
                                $SelectedColor = "Green"
                            }
                        }
                        if ( $AddNewLine ){
                            Write-host ""
                        }

                        if ( !$NotNull ){
                            if ( $Confirmation -and $SelectedArray ){
                                $Answer = Get-Answer -Title $Confirmation -ChooseFrom "y", "n" -DefaultChoose "y" -AddNewLine
                                if ( $Answer -eq "Y" ){
                                    return $SelectedArray | select-object -ExcludeProperty "num"
                                }
                                Else {
                                    return $null
                                }
                            }
                            Else {
                                return $SelectedArray | select-object -ExcludeProperty "num"
                            }
                        }
                        else {
                            if ( $null -eq $SelectedArray ){
                                write-host "Choose correct option!" -ForegroundColor red
                            }
                        }
                    }
                    Else {
                        return "Back"
                    }
                }
            }

            if ( $Confirmation -and $SelectedArray ){
                $Answer = Get-Answer -Title $Confirmation -ChooseFrom "y", "n" -DefaultChoose "y" -AddNewLine
                if ( $AddNewLine ){
                    Write-host ""
                }
                if ( $Answer -eq "Y" ){
                    return $SelectedArray | select-object -ExcludeProperty "num"
                }
                Else {
                    return $null
                }
            }
            Else {
                if ( $AddNewLine ){
                    Write-host ""
                }
                return $SelectedArray | select-object -ExcludeProperty "num"
            }
        }
        Else {
            if ( $AddNewLine ){
                Write-host ""
            }
            if ( $PassThru ){
                return $Result | select-object -ExcludeProperty "num"
            }
        }
    }
    Else {
        Add-ToLog -Message "Data parameter of [show-coloredtable] is empty." -logFilePath $Global:gsScriptLogFilePath -Display -category "Show-ColoredTable" -Status "warning"
        return $null
    }
}
Function Get-Answer {
<#
    .SYNOPSIS
        Get answer
    .DESCRIPTION
        Colored read host with features.
    .EXAMPLE
        Get-Answer -Title $Title [-ChooseFrom $ChooseFrom] [-DefaultChoose $DefaultChoose] [-Color $Color=@("Cyan", "DarkMagenta", "Magenta")] [-AllowType $AllowType] [-Format $Format] [-Example $Example] [-AddNewLine $AddNewLine] [-AsSecureString $AsSecureString] [-MaskInput $MaskInput] [-NotNull $NotNull] [-HideInput $HideInput]
    .NOTES
        AUTHOR  Alexk
        CREATED 26.12.20
        VER     1
#>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, Position = 0, HelpMessage = "Title message." )]
        [ValidateNotNullOrEmpty()]
        [string] $Title,
        [Parameter(Mandatory = $false, Position = 1, HelpMessage = "Choose from list." )]
        [string[]] $ChooseFrom,
        [Parameter(Mandatory = $false, Position = 2, HelpMessage = "Default option." )]
        [string] $DefaultChoose,
        [Parameter(Mandatory = $false, Position = 3, HelpMessage = "Firs color - text, second options and parameters, third color examples." )]
        [String[]] $Color = @("Cyan", "DarkMagenta", "Magenta"),
        [Parameter(Mandatory = $false, Position = 4, HelpMessage = "Array of allowed result types." )]
        [String[]] $AllowType,
        [Parameter(Mandatory = $false, Position = 5, HelpMessage = "Array of allowed result types." )]
        [String] $Format,
        [Parameter(Mandatory = $false, Position = 6, HelpMessage = "Input example." )]
        [String] $Example,
        [Parameter(Mandatory = $false, Position = 7, HelpMessage = "Add new line at the end." )]
        [Switch] $AddNewLine,
        [Parameter(Mandatory = $false, Position = 8, HelpMessage = "Read as secure string." )]
        [Switch] $AsSecureString,
        [Parameter(Mandatory = $false, Position = 9, HelpMessage = "Mask * input." )]
        [Switch] $MaskInput,
        [Parameter(Mandatory = $false, Position = 10, HelpMessage = "Result should not be empty." )]
        [Switch] $NotNull,
        [Parameter(Mandatory = $false, Position = 11, HelpMessage = "Not repeat input value." )]
        [Switch] $HideInput
    )

    function Test-TypeAllowed ( $Res, [String[]] $AllowType ) {
    <#
        .SYNOPSIS
            Test type allowed
        .EXAMPLE
            Test-TypeAllowed
        .NOTES
            AUTHOR  Alexk
            CREATED 17.01.21
            VER     1
    #>
        if ( $AllowType -and $res ){
            $AllowedType = $false
            foreach ( $type in $AllowType ){
                switch ( $type ) {
                    "string" {
                        try {
                            $Res.ToString()
                            $AllowedType = $true
                            break
                        }
                        Catch{}
                    }
                    "int" {
                        try {
                            $Res = [Convert]::ToUInt64( $Res )
                            $AllowedType = $true
                            break
                        }
                        Catch{}
                    }
                    "URI" {
                        try {
                            [URI]$Res
                            $AllowedType = $true
                            break
                        }
                        Catch{}
                    }
                    Default {}
                }
            }
        }
        Else {
            $AllowedType = $true
        }

        return $AllowedType
    }
    function Test-Format ( $Res, $FormatRegex ) {
    <#
        .SYNOPSIS
            Test format
        .EXAMPLE
            Test-Format
        .NOTES
            AUTHOR  Alexk
            CREATED 17.01.21
            VER     1
    #>
        if ( $FormatRegex -and $Res ) {
            $Formatted = $Res -match $FormatRegex
        }
        Else {
            $Formatted = $true
        }

        return $Formatted
    }
    Function Get-OutputString ( $Color, $AllowType, $Format, $Title, $Example, $ChoseFromString, $DefaultChoose, [Switch] $ReadOnNewLine, $NotNull, $MaskInput ){
    <#
        .SYNOPSIS
            Get output string
        .EXAMPLE
            Get-OutputString
        .NOTES
            AUTHOR  Alexk
            CREATED 17.01.21
            VER     1
    #>
        if ( $color ) {
            $ColorString = @()

            if ( $Format ){
                $PSO = [PSCustomObject]@{
                    String = "[format]"
                    Color  = $Color[1]
                }
                $ColorString += $PSO
            }
            If ( $AllowType ){
                $AllowedTypeList  = $AllowType -join ", "
                $PSO = [PSCustomObject]@{
                    String = "[$AllowedTypeList] "
                    Color  = $Color[1]
                }
                $ColorString     += $PSO
            }
            if ( $Title ) {
                $PSO = [PSCustomObject]@{
                    String = $Title
                    Color  = $Color[0]
                }
                $ColorString     += $PSO
            }
            if ( $Example ){
                $PSO = [PSCustomObject]@{
                    String = " (e.g. $Example)"
                    Color  = $Color[2]
                }
                $ColorString     += $PSO
            }
            if ( $ChoseFromString ){
                $PSO = [PSCustomObject]@{
                    String = "["
                    Color  = $Color[0]
                }
                $ColorString     += $PSO

                $PSO = [PSCustomObject]@{
                    String = $ChoseFromString
                    Color  = $Color[1]
                }
                $ColorString     += $PSO

                $PSO = [PSCustomObject]@{
                    String = "]"
                    Color  = $Color[0]
                }
                $ColorString     += $PSO
            }

            $PSO = [PSCustomObject]@{
                String = ": "
                Color  = $Color[0]
            }
            $ColorString     += $PSO

            foreach ( $String in $ColorString ){
                write-host -Object $String.string -NoNewline -ForegroundColor $String.Color
            }
        }
        Else {
            $OutString = ""
            if ( $Format ) {
                $OutString = $OutString + "[format]"
            }
            If ( $AllowType ) {
                $AllowedTypeList = $AllowType -join ", "
                $OutString = $OutString + "[$AllowedTypeList] "
            }
            if ( $Title ) {
                $OutString = $OutString + $Title
            }
            if ( $Example ) {
                $OutString = $OutString + " (e.g. $Example)"
            }
            if ( $ChoseFromString ) {
                $OutString = $OutString + "[" + $ChoseFromString + "]"
            }

            $OutString = $OutString + ": "
            write-host -Object $OutString -NoNewline
        }

        if ( $ReadOnNewLine ) {
            write-host ""
        }
        if ( $ChoseFromString ) {
            $Res = Read-Host
            if ( $DefaultChoose ){
                if ( $Res -eq "" ) {
                    $Res = $DefaultChoose
                }
            }
            $Res = $Res.ToUpper()
        }
        Else {
            if ( !$NotNull ) {
                if ( $MaskInput) {
                    $res = Read-Host -MaskInput
                }
                ElseIf ( $AsSecureString ) {
                    $res = Read-Host -AsSecureString
                }
                Else {
                    $res = Read-Host
                }
            }
            Else {
                while ( !$Res ) {
                    if ( $MaskInput) {
                        $res = Read-Host -MaskInput
                    }
                    ElseIf ( $AsSecureString ) {
                        $res = Read-Host -AsSecureString
                    }
                    Else {
                        $res = Read-Host
                    }
                    if ( !$Res ){
                        write-host "Empty not allowed!" -ForegroundColor Red
                    }
                }
            }
        }

        return $Res
    }

    $Res = $null

    # $Header = "`n[$( get-date -format $Global:gsGlobalTimeFormat )][$Global:modDialogNumber][$($global:modComputer)][$Title] |"
    # $Header = $Header.PadRight($Host.UI.RawUI.WindowSize.Width - $header.Length - 4,"-") + "-> |"
    # Get-ColorText -Text $Header -TextColor "Magenta"

    $Formatted   = $false
    if ( $Format ) {
        switch ( $Format ) {
            "Email" {
                $Format = "[a-z0-9!#\$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#\$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
            }
            "FQDN" {
                $Format = "(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)"
            }
            "IPv4" {
                $Format = "\b(([01]?\d?\d|2[0-4]\d|25[0-5])\.){3}([01]?\d?\d|2[0-4]\d|25[0-5])\b"
            }
            Default { }
        }
        try {
            $FormatRegex = [regex]::new( $Format )
        }
        Catch {
            write-host "Error in format [$format] regex!" -ForegroundColor Red
            $FormatRegex = $null
            $Format      = $null
        }

    }

    $AllowedType = $false

    while ( !$AllowedType -or !$Formatted ) {
        if ( $ChooseFrom ) {

            $OptionSeparator = "/"
            $ChoseFromString = ""

            foreach ( $item in $ChooseFrom ) {
                if ( $item.toupper() -ne $DefaultChoose.toupper() ){
                    $ChoseFromString += "$($item.toupper())$OptionSeparator"
                }
                Else {
                    $ChoseFromString += "($($item.toupper()))$OptionSeparator"
                }
            }

            $ChoseFromString = $ChoseFromString.Substring(0,($ChoseFromString.Length-$OptionSeparator.Length))

            $Message = "$Title [$ChoseFromString]"

            $ChooseFromUpper = @()
            foreach ( $item in $ChooseFrom ){
                $ChooseFromUpper += $item.ToUpper()
            }
            if ( $DefaultChoose ){
                $ChooseFromUpper += ""
            }

            while ( $res -notin $ChooseFromUpper ) {
                $Res = Get-OutputString -color $Color -AllowType $AllowType -Format $Format -Title $Title -Example $Example -ChoseFromString $ChoseFromString -DefaultChoose $DefaultChoose -NotNull $NotNull -MaskInput $MaskInput

            }
        }
        Else {
            $Res = Get-OutputString -color $Color -AllowType $AllowType -Format $Format -Title $Title -Example $Example -ChoseFromString $ChoseFromString -DefaultChoose $DefaultChoose -NotNull $NotNull -MaskInput $MaskInput
        }

        $AllowedType = Test-TypeAllowed -Res $Res -AllowType $AllowType
        if ( !$AllowedType -and $AllowType ){
            write-host "Unexpected result type, allowed only [$($AllowType -join ", ")] " -ForegroundColor Red
            $Res = $null
        }

        $Formatted = Test-Format  -Res $Res -AllowType $FormatRegex
        if ( !$Formatted -and $FormatRegex ) {
            write-host "Unexpected result format, allowed only [$FormatRegex] " -ForegroundColor Red
            $Res = $null
        }
    }

    if ( !$HideInput ){
        if ( $color ) {
            if ( $MaskInput -or $AsSecureString ){
                Write-Host -Object "Selected: " -ForegroundColor $Color[0] -NoNewline
                Write-Host -Object "*" -ForegroundColor $Color[1] -NoNewline
            }
            Else {
                write-host -object "Selected: " -ForegroundColor $Color[0] -NoNewline
                write-host -object "$Res" -ForegroundColor $Color[1] -NoNewline
            }
        }
        Else {
            if ( $MaskInput -or $AsSecureString ) {
                Write-Host -Object "Selected: *"
            }
            Else {
                Write-Host -Object "Selected: $Res"
            }
        }
    }

    if ( $AddNewLine ){
        Write-host ""
    }

    return $Res

}
Function Add-ToDataFile {
<#
    .SYNOPSIS
        Add to data file
    .DESCRIPTION
        Function add or replace data array to csv, xml, json data file.
    .EXAMPLE
        Add-ToDataFile -Data $Data -FilePath $FilePath [-Replace $Replace] [-Remove $Remove] [-DontCheckStructure $DontCheckStructure] [-PassThru $PassThru]
    .NOTES
        AUTHOR  Alexk
        CREATED 02.02.21
        VER     1
#>
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $True, Position = 0, HelpMessage = "Data array." )]
        [ValidateNotNullOrEmpty()]
        [PSObject[]] $Data,
        [Parameter( Mandatory = $true, Position = 1, HelpMessage = "File path." )]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath,
        [Parameter( Mandatory = $false, Position = 2, HelpMessage = "Replace data in file." )]
        [switch] $Replace,
        [Parameter( Mandatory = $false, Position = 3, HelpMessage = "Replace data in file." )]
        [switch] $Remove,
        [Parameter( Mandatory = $false, Position = 4, HelpMessage = "Allow data with different structure." )]
        [switch] $DontCheckStructure,
        [Parameter( Mandatory = $false, Position = 5, HelpMessage = "Return object." )]
        [switch] $PassThru
    )
    begin {
        $res         = $true
        $Array       = @()
        $FileMembers = $null

        $FileExtention = split-path -path $FilePath -Extension

        $FileData = @()
        if ( ( test-path -path $FilePath ) -and ( -not $Replace ) ){
            try{
                switch ( $FileExtention ) {
                    ".XML" {
                        $FileData += import-cliXML -path $FilePath
                    }
                    ".CSV" {
                        $FileData += import-csv -path $FilePath
                    }
                    ".JSON" {
                        $FileData += get-content -path $FilePath
                    }
                    Default {}
                }
            }
            Catch{
                Add-ToLog -Message "Error while importing data from file [$FilePath]!" -logFilePath $Global:gsScriptLogFilePath -Display -category "File import" -Status "error"
                exit 1
            }

            switch ( $FileExtention ) {
                ".XML" {
                }
                ".CSV" {
                    $DateFields = @()
                    $BoolFields = @()
                    $IntFields  = @()
                    foreach ( $item in ($FileData | get-member -MemberType NoteProperty).name  ){
                        try {
                            $Date        =  [System.DateTime](get-date $FileData[0].$item)
                            $DateFields += $item
                        }
                        Catch {}
                        try {
                            $Bool        =  [System.Convert]::ToBoolean( $FileData[0].$item )
                            $BoolFields += $item
                        }
                        Catch {}
                    }
                    foreach ( $item in $FileData ) {
                        foreach ( $Date in $DateFields ){
                            try {
                                $item.$Date = [System.DateTime]( get-date $item.$Date )
                            }
                            Catch {}
                        }
                        foreach ( $Bool in $BoolFields ){
                            try {
                                $item.$Bool = [System.Convert]::ToBoolean( $item.$Bool )
                            }
                            Catch {}
                        }
                    }
                }
                ".JSON" {
                    $FileData  = $FileData | ConvertFrom-JSON

                    $DateFields = $FileData.PSobject.members | where-object { $_.TypeNameOfValue -eq "System.Management.Automation.PSCustomObject"}
                    foreach ( $Date in $DateFields ){
                        if ( $Date.DateTime ) {
                            $Date.value = [System.DateTime](get-date $Date.Value.Value)
                        }
                    }
                }
                Default {}
            }
            $FileMembers = ($FileData | get-member -MemberType NoteProperty | where-object { $_.name -ne "Value"}).name | Select-Object -Unique
        }
        Else {
            $FileData  = $null
        }

        if ( $FileMembers ) {
            $DataMembers =  ($Data |  get-member -MemberType NoteProperty | where-object { $_.name -ne "Value"}).name | Select-Object -Unique
            $Compare = Compare-Object -ReferenceObject $DataMembers -DifferenceObject $Filemembers -Property $DataMembers.name
            if ( $Compare -and ( -not $DontCheckStructure) ){
                Add-ToLog -Message "There is a difference between data properties and file properties! `n $Compare" -logFilePath $Global:gsScriptLogFilePath -Display -Status "Error"
                if ( $PassThru ){
                    $res =  $false
                }
            }
        }
    }
    process {
        if ( ( -not $compare ) -or ( $DontCheckStructure )){
            if ( $FileData ){
                $Array += $FileData
            }

            if ( $Remove ) {
                $Array1 = @()
                if ( $FileData ) {
                    foreach ( $item in $Array ) {
                        foreach ( $item1 in $Data ) {
                            if ( Compare-Object -ReferenceObject $Item1 -DifferenceObject $Item -Property $DataMembers.name  ){
                                #Compare-Object -ReferenceObject $Item1 -DifferenceObject $Item -Property $DataMembers.name
                                $Array1 += $item
                            }
                        }
                    }
                }
                $Array = $Array1
            }
            Else {
                if ( $Compare ) {
                    $Diff = $compare | Where-Object {$_.sideindicator -eq "<="}
                    foreach ( $item in $diff ){
                        $Array | Add-Member -NotePropertyName $item.InputObject -NotePropertyValue ""
                    }
                    $Array += $Data
                }
                Else {
                    $Array += $Data
                }
            }

            switch ( $FileExtention ) {
                ".XML" {
                    $Array | Export-CliXML -path $FilePath -force
                }
                ".CSV" {
                    $Array | export-csv -path $FilePath -force
                }
                ".JSON" {
                    $Array | ConvertTo-Json | Set-Content -path $FilePath -force
                }
                Default {}
            }
        }
    }
    end {
        if ( $PassThru ){
            return $Res
        }
    }
}
Function Get-FromDataFile {
<#
    .SYNOPSIS
        Get from data file
    .DESCRIPTION
        Function to get data array from csv, xml, json data file.
    .EXAMPLE
        Get-FromDataFile -FilePath $FilePath
    .NOTES
        AUTHOR  Alexk
        CREATED 02.02.21
        VER     1
#>
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "File path." )]
        [ValidateNotNullOrEmpty()]
        [string] $FilePath
    )
    begin {
        $Array       = @()
        $FileExtention = split-path -path $FilePath -Extension
        $FileExist = test-path -path $FilePath
        if ( -not ( $FileExist )){
            Add-ToLog -Message "File [$FilePath] doesn't exist!" -logFilePath $Global:gsScriptLogFilePath -Display -Status "Warning"
        }
    }
    process {
        if ( $FileExist ) {
            $FileData = @()
            try{
                switch ( $FileExtention ) {
                    ".XML" {
                        $FileData += import-cliXML -path $FilePath
                    }
                    ".CSV" {
                        $FileData += import-csv -path $FilePath
                    }
                    ".JSON" {
                        $FileData += get-content -path $FilePath
                    }
                    Default {}
                }
            }
            Catch{
                Add-ToLog -Message "Error while importing data from file [$FilePath]!" -logFilePath $Global:gsScriptLogFilePath -Display -category "File import" -Status "error"
                exit 1
            }

            switch ( $FileExtention ) {
                ".XML" {
                }
                ".CSV" {
                    $DateFields = @()
                    $BoolFields = @()
                    $IntFields  = @()
                    foreach ( $item in ($FileData | get-member -MemberType NoteProperty).name  ){
                        try {
                            $Date        =  [System.DateTime](get-date $FileData[0].$item)
                            $DateFields += $item
                        }
                        Catch {}
                        try {
                            $Bool        =  [System.Convert]::ToBoolean( $FileData[0].$item )
                            $BoolFields += $item
                        }
                        Catch {}
                        try {
                            $Int        =  [System.Convert]::ToUInt64( $FileData[0].$item )
                            $IntFields += $item
                        }
                        Catch {}
                    }
                    foreach ( $item in $FileData ) {
                        foreach ( $Date in $DateFields ){
                            try {
                                $item.$Date = [System.DateTime]( get-date $item.$Date )
                            }
                            Catch {}
                        }
                        foreach ( $Bool in $BoolFields ){
                            try {
                                $item.$Bool = [System.Convert]::ToBoolean( $item.$Bool )
                            }
                            Catch {}
                        }
                        foreach ( $Int in $IntFields ){
                            try {
                                $item.$Int = [System.Convert]::ToUInt64( $item.$Int )
                            }
                            Catch {}
                        }
                    }
                }
                ".JSON" {
                    $FileData  = $FileData | ConvertFrom-JSON

                    $DateFields = $FileData.PSobject.members | where-object { $_.TypeNameOfValue -eq "System.Management.Automation.PSCustomObject"}
                    foreach ( $Date in $DateFields ){
                        if ( $Date.DateTime ) {
                            $Date.value = [System.DateTime](get-date $Date.Value.Value)
                        }
                    }
                }
                Default {}
            }
            $FileMembers = $FileData | get-member -MemberType NoteProperty | where-object { $_.name -ne "Value"}

            return $FileData
        }
        Else {
            return $null
        }
    }
}
Function Get-ColorText {
<#
    .SYNOPSIS
        Get color text
    .DESCRIPTION
        Set text color by rules
    .EXAMPLE
        Get-ColorText -Text $Text -TextColor $TextColor [-ParameterColor $ParameterColor="Blue"] [-DateColor $DateColor="Yellow"] [-AddNewLine $AddNewLine]
    .NOTES
        AUTHOR  Alexk
        CREATED 23.02.21
        VER     1
#>
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Text." )]
        $Text,
        [Parameter( Mandatory = $true, Position = 1, HelpMessage = "Text foreground color." )]
        #[ValidateSet([Enum]::GetValues([System.ConsoleColor]))]
        [string] $TextColor,
        [Parameter( Mandatory = $false, Position = 2, HelpMessage = "Parameter color." )]
        [string] $ParameterColor = "Blue",
        [string] $DateColor = "Yellow",
        [switch] $AddNewLine
    )

    begin {
    }
    process {
        #set parameters color
        if ( $Global:modPansiesModule ){
            $ParamArray = $Text.split("[") | Select-Object -skip 1
            foreach ( $item in $ParamArray ){
                $item = $item.split("]")[0]
                #$item = [uri] $item
                # if ( $item.AbsoluteUri ){
                #     $Text = $Text.Replace("[$item]","[$(New-Hyperlink -Object $item -Uri $item.AbsoluteUri -fg $ParameterColor)$(New-Text -object ']' -fg $TextColor -leaveColor)")
                # }
                # Else {
                $Text = $Text.Replace("[$item]","[$(New-Text $item -fg $ParameterColor)$(New-Text -object ']' -fg $TextColor -leaveColor)")
                # }
            }

            #set date color
            $DateText = ($Text.split(" ") | Select-Object -First 2) -join " "

            if ( $DateText.ToString().Contains(":") -and $DateText.ToString().Contains(".") ){
                $Text = $Text.Replace("$DateText","$(New-Text $DateText -fg $DateColor)$(New-Text -object '' -fg $TextColor -leaveColor)")
            }
            if ( $AddNewLine ){
                $Text = "$Text`n"
            }

            write-host -object $Text -ForegroundColor $TextColor
        }
        Else {
            if ( $AddNewLine ){
                $Text = "$Text`n"
            }
            write-host -object $Text -ForegroundColor $TextColor
        }
    }
    end {

    }
}
Function Get-DiskVolumeInfo {
<#
    .SYNOPSIS
        Get disk volume info
    .DESCRIPTION
        Get disk volume information.
    .EXAMPLE
        Get-DiskVolumeInfo
    .NOTES
        AUTHOR  Alexk
        CREATED 23.02.21
        VER     1
#>
    [OutputType([PSObject])]
    [CmdletBinding()]
    Param()
    begin {
        $LogicalDisks    = Get-volume
        $Disks           = Get-disk
        $VolumeArray     = @()
        $BitLockerVolume = Get-BitLockerVolume -ErrorAction SilentlyContinue
    }
    process {
        foreach ( $LogicalDisk in $LogicalDisks ){
            if ( $LogicalDisk.DriveLetter ) {
                $DiskIndex = (Get-CimInstance -Query "Associators of {Win32_LogicalDisk.DeviceID='$($LogicalDisk.DriveLetter):'} WHERE ResultRole=Antecedent" | Select-Object DiskIndex).DiskIndex

                $Disk = $Disks | where-object { $_.number -eq $DiskIndex }

                if ( $Disk.SerialNumber ){
                    $DiskSerial = $Disk.SerialNumber.trim()
                }
                Else {
                    $DiskSerial = ""
                }

                $PSO = [PSCustomObject]@{
                    DiskNumber            = [uint32] $DiskIndex
                    DiskModel             = $Disk.Model
                    DiskSerial            = $DiskSerial
                    DiskHealth            = $Disk.HealthStatus
                    DiskOperationalStatus = $Disk.OperationalStatus
                    DiskTotalSizeGB       = [math]::round($Disk.Size / 1gb,2)
                    DiskPartitionStyle    = $Disk.PartitionStyle
                    DriveLetter           = $LogicalDisk.DriveLetter
                    Label                 = $LogicalDisk.FileSystemLabel
                    Type                  = $LogicalDisk.FileSystemType
                    DriveType             = $LogicalDisk.DriveType
                    HealthStatus          = $LogicalDisk.HealthStatus
                    OperationalStatus     = $LogicalDisk.OperationalStatus
                    SizeRemainingGB       = [math]::round($LogicalDisk.SizeRemaining / 1gb,2)
                    SizeGB                = [math]::round($LogicalDisk.Size / 1gb,2)
                    AllocationUnitSizeKB  = [math]::round($LogicalDisk.AllocationUnitSize / 1kb,2)
                    ProtectionStatus      = ""
                    VolumeStatus          = ""
                    VolumeType            = ""
                }

                if ( $BitLockerVolume ) {
                    $BitLocker = $BitLockerVolume | where-object {$_.MountPoint -eq "$($LogicalDisk.DriveLetter):"}
                    $PSO.ProtectionStatus = $BitLocker.ProtectionStatus
                    $PSO.VolumeStatus     = $BitLocker.VolumeStatus
                    $PSO.VolumeType       = $BitLocker.VolumeType
                }

                $VolumeArray += $PSO
            }
        }
    }
    end {
        return $VolumeArray
    }
}
Function Remove-ItemToRecycleBin {
<#
    .SYNOPSIS
        Remove item to recycle bin
    .DESCRIPTION
        Remove file or directory to recycle bin.
    .EXAMPLE
        Remove-ItemToRecycleBin -Path $Path [-PassThru $PassThru]
    .NOTES
        AUTHOR  Alexk
        CREATED 09.03.21
        VER     1
#>
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Path to file or folder." )]
        [string] $Path,
        [Parameter( Mandatory = $false, Position = 1, HelpMessage = "Return object." )]
        [string] $PassThru
    )
    begin {
        $PathExist = test-path -path $Path
        if ( !$PathExist ){
            Add-ToLog -Message "Path [$Path] does not exist!" -logFilePath $Global:gsScriptLogFilePath -Display -category "Remove-ItemToRecycleBin" -Status "error"
        }
        $Res = $False
    }
    process {
        if ( $PathExist ){
            Add-ToLog -Message "Sending file [$Path] to recyclebin." -logFilePath $Global:gsScriptLogFilePath -Display -category "Remove-ItemToRecycleBin" -Status "info"
            $shell = new-object -comobject "Shell.Application"
            $item = $shell.Namespace(0).ParseName("$Path")
            $item.InvokeVerb("delete")

            $Res = $true

        }
    }
    end {
        if ( $PassThru ){
            return $Res
        }
    }
}

Function Get-FileName {
<#
    .SYNOPSIS
        Get file name
    .DESCRIPTION
        Generate new file name.
    .EXAMPLE
        Get-FileName -Name $Name -Extension $Extension [-Prefix $Prefix] [-Suffix $Suffix] [-UseDateTime $UseDateTime] [-UseComputerName $UseComputerName]
    .NOTES
        AUTHOR  Alexk
        CREATED 09.03.21
        VER     1
#>
    [OutputType([string])]
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $True, Position = 0, HelpMessage = "Core name." )]
        [string] $Name,
        [Parameter( Mandatory = $false, Position = 1, HelpMessage = "Suffix." )]
        [string] $Prefix,
        [Parameter( Mandatory = $false, Position = 2, HelpMessage = "Suffix." )]
        [string] $Suffix,
        [Parameter( Mandatory = $True, Position = 3, HelpMessage = "Extention." )]
        [string] $Extension,
        [Parameter( Mandatory = $False, Position = 4, HelpMessage = "Use date and time in file name." )]
        [switch] $UseDateTime,
        [Parameter( Mandatory = $False, Position = 5, HelpMessage = "Use computer name in file name." )]
        [switch] $UseComputerName
    )
    begin {
        $Res = ""
    }
    process {
        if ( $UseComputerName ){
            $Res = "$($env:COMPUTERNAME)-"
        }
        if ( $prefix ){
            $Res = "$Res$prefix-"
        }
        if ( $name ){
            $Res = "$Res$name"
        }
        if ( $UseDateTime ) {
            $Date = ( get-date -format $Global:gsGlobalDateTimeFormat ).replace(".","-").replace(":","-")
            $Res = "$Res-$Date"
        }
        if ( $Suffix ){
            $Res = "$Res-$Suffix"
        }
        if ( $Extension ){
            $Res = "$Res.$Extension"
        }

    }
    end {
        return $res
    }
}

#endregion
#region Dialog
Function Show-OpenDialog{
<#
    .SYNOPSIS
        Show open dialog
    .DESCRIPTION
        Show windows open file dialog.
    .EXAMPLE
        Show-OpenDialog -Type $Type [-InitPath $InitPath] [-Description $Description] [-FileFilter $FileFilter] [-FileMultiSelect $FileMultiSelect]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Show notification
    .DESCRIPTION
        Function to show notification in the system tray.
    .EXAMPLE
        Show-Notification -MsgTitle $MsgTitle -MsgText $MsgText -Status $Status [-FilePath $FilePath=""] [-Timeout $Timeout=5]
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Get settings from file
    .DESCRIPTION
        Load variables from external file.
    .EXAMPLE
        Get-SettingsFromFile -SettingsFile $SettingsFile
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
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
        Get error reporting
    .DESCRIPTION
        Visualize errors and save it to file.
    .EXAMPLE
        Get-ErrorReporting -Trap $Trap
    .NOTES
        AUTHOR  Alexk
        CREATED 05.11.20
        VER     1
#>
    [CmdletBinding()]
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Error trap." )]
        [ValidateNotNullOrEmpty()]
        $Trap
    )
    [string]$PreviousCommand = $Trap.InvocationInfo.line.Trim()
    try{
        [string]$PreviousCommandReplacedArgs = ( Invoke-Expression -command "return `"$PreviousCommand`"" ).trim()
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
    [array] $UpDownStackTrace  = @($StackTrace.Split("`n"))
    [int16] $ItemCount         = $UpDownStackTrace.Count
    [array] $TempStackTrace    = @(1..$ItemCount )

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


Export-ModuleMember -Function Get-NewAESKey, Get-VarFromAESFile, Set-VarToAESFile, Disconnect-VPN, Connect-VPN, Add-ToLog, Restart-Switches, Restart-SwitchInInterval, Get-EventList, Send-Email, Start-PSScript, Restart-LocalHostInInterval, Show-Notification, Restart-ServiceInInterval, New-TelegramMessage, Get-SettingsFromFile, Get-HTMLTable, Get-HTMLCol, Get-ContentFromHTMLTemplate, Get-ErrorReporting, Get-CopyByBITS, Show-OpenDialog, Import-ModuleRemotely, Invoke-PSScriptBlock, Get-ACLArray, Set-PSModuleManifest, Get-VarToString, Get-UniqueArrayMembers, Resolve-IPtoFQDNinArray, Get-HelpersData, Get-DifferenceBetweenArrays, Test-Credentials, Convert-FSPath, Start-Program, Test-ElevatedRights, Invoke-CommandWithDebug, Format-TimeSpan, Start-ParallelPortPing, Join-Array, Set-State, Send-Alert, Start-Module, Convert-SpecialCharacters, Get-ListByGroups, Convert-StringToDigitArray, Convert-PSCustomObjectToHashTable, Invoke-TrailerIncrease, Split-words, Remove-Modules, Get-TextLengthPreview, Export-RegistryToFile, Show-ColoredTable, Get-Answer,  Get-AESData, Add-ToDataFile, Get-FromDataFile, Compare-Arrays, Get-ColorText, Get-DiskVolumeInfo, Remove-ItemToRecycleBin, Get-MembersType, Compare-ArraysVisual, Get-FileName, Get-DataStatistic, Show-UnprintableChars

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