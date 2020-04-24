function Get-NewAESKey {
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     This function create a new AES key and save it to file
    .EXAMPLE
    Get-NewAESKey -AESKeyFilePath "d:\key1.aes"
#>  
   
    [CmdletBinding()]
    param
    (
        [Parameter( Mandatory=$true, Position = 0,HelpMessage = "Full path, where we make AES key file."  )]
        [string] $AESKeyFilePath
    )

    $AESKey = New-Object Byte[] 32
    [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($AESKey)
    $AESKey | out-file $AESKeyFilePath
}    
Function Import-SettingsFromFile {
    #Get-SettingsFromFile
<#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Function to import variables from XML file
    .EXAMPLE
    Import-SettingsFromFile -RootPath "d:\test"
#>  
    [CmdletBinding()]
    param
    (
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Full path, where params files are." )]
        [string] $RootPath
    )
    
    $Org = get-content ($RootPath + "\org.txt") -Encoding UTF8
    $ParamsFilePath = $RootPath + "\params-" + $ORG + ".xml"
    $Params = Import-Clixml $ParamsFilePath
    Initialize-Vars $Params
    return $Params
}
Function Initialize-Vars {
#ReplaceVars 
<#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Function to replace params with its value.
    .EXAMPLE
    Initialize-Vars -PSO $PSO
#>  
    [CmdletBinding()]
    param
    (
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Object with params." )]
        [pscustomobject]
        $PSO
    )
    
    $NoteProperties = $PSO | get-member -type NoteProperty

    foreach ($item in $NoteProperties) {
        $Param = "%" + $Item.name + "%"
        $Value = $pso."$($item.name)"
        Foreach ($item1 in $NoteProperties) {
            if (($pso."$($item1.name)".gettype()).name -eq "String") {
                $pso."$($item1.name)" = ($pso."$($item1.name)").replace($Param, $Value)
            }
        }
    }
}
Function Get-VarFromAESFile  {  
#Get-VarFromFile  
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Function to read variable from file with decryption with AES key file
    .EXAMPLE
    Get-VarFromAESFile -AESKeyFilePath "d:\1.txt" -VarFilePath "d:\vars.txt"
#>      
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
                $Res = Get-Content $VarFilePath | ConvertTo-SecureString -Key (get-content $AESKeyFilePath)                
                return $Res
            }
            Catch {
                write-host "Error [$($_.exception)], check your key!" - -ForegroundColor red
                return $Null 
            }
            

        }
    Else { return $null }   
}
Function Set-VarToAESFile {
#Set-VarToFile  
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Function to write variable to file with encryption with AES key file
    .EXAMPLE
    Set-VarToAESFile -Var "Some text" -AESKeyFilePath "d:\1.txt" -VarFilePath "d:\new-var.txt"
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
        [string] $VarFilePath
    )
    
    
    ConvertTo-SecureString $Var -AsPlainText | ConvertFrom-SecureString -Key (get-content $AESKeyFilePath) | Set-Content $VarFilePath
}
Function Get-VarToString {
<#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 09.04.2020
        .VER 1   
    .DESCRIPTION
     Function to make string from secure string.
    .EXAMPLE
    Get-VarToString -Var $Var
#>   
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
Function Add-ToLog {
<#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Function to write message into a log file
    .EXAMPLE
    Add-ToLog -Message "Some text" -logFilePath "d:\1.log" -Mode "replace"
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
        [ValidateSet("Info", "Warning", "Error")]
        [string] $Status,
        [Parameter(Mandatory = $false, Position = 5, HelpMessage = "Date format string." )]
        [string] $Format

    )

    if($Format) {
        $Date = Get-Date -Format $Format
    }
    Else {
        $Date = Get-Date
    }
    
    $Text = ($Date.ToString()  + " " + $Message)
    switch ($Mode.ToLower()) {
        "append" { Out-File -FilePath $logFilePath -Encoding utf8 -Append -Force -InputObject $Text }
        "replace" { Out-File -FilePath $logFilePath -Encoding utf8 -Force -InputObject $Text }
        Default { }    
    }
    If ($Display){
       if($status){ 
            switch ($Status) {
                "Info" { 
                    Write-Host $Message -ForegroundColor Green
                 }
                 "Warning" { 
                    Write-Host $Message -ForegroundColor Yellow
                 }
                 "Error" { 
                    Write-Host $Message -ForegroundColor Red
                 }
                Default {}
            }
       }
       Else{
            Write-Host $Message 
       }

    }
}
function Disconnect-VPN {
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Function to break VPN connection
    .EXAMPLE
    Disconnect-VPN -VPNConnectionName "Ras con" -logFilePath "d:\1.log"
#>   

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
Function Connect-VPN {
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Function to establish VPN connection
    .EXAMPLE
    Connect-VPN -VPNConnectionName "Ras con" -logFilePath "d:\1.log" -Login "User" -Password "some pass"
#>    
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
        [securestring] $Login,
        [Parameter(Mandatory = $true, Position = 3, HelpMessage = "VPN Password." )]
        [ValidateNotNullOrEmpty()]
        [securestring] $Password
    )

    [string] $LoginText = Get-VarToString $Login
    Add-ToLog "Try to connect VPN - $VPNConnectionName under $LoginText" $logFilePath
    $Res = (& rasdial $VPNConnectionName  $LoginText ( Get-VarToString $Password)) -join " "
    if (($Res -like "*success*") -or ($Res -like "*успешно*")) {
        Add-ToLog $Res $logFilePath
        return $true         
    }
    else {
        Add-ToLog $Res $logFilePath
        #Add-ToLog $false $logFilePath
        return $false
    }
}
Function Restart-Switches {
#RebootSwitches
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Function to reboot device
    .EXAMPLE
    Restart-Switches -SwitchesIP $IPs -logFilePath "d:\1.log" -PLinkPath "c:\plink.exe" -SshConString "" -SshCommand "" -Login "User" -Password "some password"
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
Function Get-EventList {
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Function to event list from log file in interval or not.
    .EXAMPLE
    Get-EventList -logFilePath "d:\1.log" -Event "localhost reboot" -Interval 3600
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
<#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Function to send email message
    .EXAMPLE
    Send-Email -SmtpServer "mail.example.com" -From "user@example.com" -To  "user1@mail.com" 
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
        [int16]  $Port                = 25,
        [Parameter(Mandatory = $false, Position = 9, HelpMessage = "Use SSL." )]
        [switch]   $SSL,
        [Parameter(Mandatory = $false, Position = 10, HelpMessage = "Email attachment." )]
        [string] $Attachment,
        [Parameter(Mandatory = $false, Position = 11, HelpMessage = "Email attachment content id." )]
        [string] $AttachmentContentId,
        [Parameter(Mandatory = $false, Position = 12, HelpMessage = "Retry counter." )]
        [int16]  $Counter             = 100,
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
        }
        Catch {}
        [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        #[System.Net.ServicePointManager]::CertificatePolicy = 
        $smtp.EnableSSL = $SSL
    }
    if ($user) {
        $smtp.Credentials = New-Object System.Net.NetworkCredential((Get-VarToString $user), (Get-VarToString $Password))
    }
    try {
        $smtp.Send($emailMessage)  
    }
    catch {
        #Get-ErrorReporting $_  
        write-host "Send-Email exception $($_.Exception)" -foreground red         
        if ($Counter -gt 0) {
            
            $Counter = $Counter - 1
            Write-host ""
            Write-host "$(get-date) Try $Counter"
            Start-Sleep -Seconds $PauseBetweenTries
            
            $params = @{
                SmtpServer          = $SmtpServer
                Subject             = $Subject
                Body                = $Body
                HtmlBody            = $HtmlBody
                User                = $User
                Password            = $Password
                From                = $From
                To                  = $To
                Port                = $Port
                SSL                 = $SSL
                Attachment          = $Attachment
                AttachmentContentId = $AttachmentContentId
                Counter             = $Counter
                PauseBetweenTries   = $PauseBetweenTries  
            }

            Send-Email @params     
        }  

    }
}
Function Start-PSScript {
#StartPSScript
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Function to start powershell script or command.
    .EXAMPLE
    Start-PSScript -ScriptPath "c:\script.ps1" -logFilePath "c:\1.log""
#>    
    [CmdletBinding()]   
    param (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Script path." , ParameterSetName = "Script" )]
        [ValidateNotNullOrEmpty()]
        [string] $ScriptPath,
        [Parameter(Mandatory = $true, Position = 1, HelpMessage = "Script block to execute." , ParameterSetName = "ScriptBlock" )]
        [scriptblock] $ScriptBlock,
        [Parameter(Mandatory = $false, Position = 2, HelpMessage = "Script block arguments." , ParameterSetName = "ScriptBlock" )]
        [Array] $ScriptBlockArguments,
        [Parameter(Mandatory = $false, Position = 3, HelpMessage = "Credentials." )]
        [System.Management.Automation.PSCredential]  $Credentials, 
        [Parameter(Mandatory = $true, Position = 4, HelpMessage = "Log file path." )]
        [ValidateNotNullOrEmpty()] 
        [string] $logFilePath,
        [Parameter(Mandatory = $false, Position = 5, HelpMessage = "Output file path." )]
        [string] $OutputFilePath,
        [Parameter(Mandatory = $false, Position = 6, HelpMessage = "Working directory." )]
        [string] $WorkDir,
        [Parameter(Mandatory = $false, Position = 7, HelpMessage = "Use elevated rights." )]
        [switch]   $Evaluate,
        [Parameter(Mandatory = $false, Position = 8, HelpMessage = "Debug run." )]
        [switch]   $DebugRun             
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

    [string] $PowerShellPrgPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"   

    if($Credentials){
        if(!(Test-Credentials $Credentials)){
            Write-Host "Supplied credentials [$($credentials.username)] error!" -ForegroundColor red            
        }
    }

    if ($OutputFilePath) {
        $Arguments += " -RedirectStandardOutput ""$OutputFilePath""" 
    }

    if ($Evaluate) {
        $Verb = "RunAs" 
    }

    if ($DebugRun){
        $Arguments = " -NoExit"        
    }
    Else {     
        $Arguments = " -WindowStyle Hidden -NonInteractive -NoLogo"
    }      

    if ($ScriptBlock) {
        if ($ScriptBlockArguments){
            $Command = "& {Invoke-Command -ScriptBlock {$ScriptBlock} -ArgumentList $($ScriptBlockArguments -join ", ")}"
            #$Arguments += " -ExecutionPolicy Bypass –NoProfile -Command $Command"
        }
        Else{    
            $Arguments += " -ExecutionPolicy Bypass –NoProfile  -Command $ScriptBlock"      
        }      
    }
    else {
        $Arguments += " -ExecutionPolicy Bypass –NoProfile  -file ""$ScriptPath"""     
    } 

    if ($Evaluate -and (($Credentials) -or ($OutputFilePath) )) {
        if($Credentials){
            if ($DebugRun){
                [string]$NestedScriptBlock = {
                    param([string]$Test, $ScriptBlock);  write-host $Test;  Write-Host $ScriptBlock;  $Res = Start-PSScript -ScriptBlock $ScriptBlock -logFilePath '%LogFilePath%' -DebugRun -Evaluate;    $Res
                }
                $OutputXMLPath     = "$ProjectRoot\$DATAFolder\ScriptBlockOutput.xml"
                [string]$End = {
                    if($Res){
                        $Res | Export-Clixml -path "%OutputXMLPath%" -Encoding utf8 -Force 
                    }
                }                
                $ScriptBlockNew    = [string]$ScriptBlock + $End
                $NestedScriptBlock = $NestedScriptBlock.Replace("%ScriptBlock%", $ScriptBlockNew)
                $NestedScriptBlock = $NestedScriptBlock.Replace("%LogFilePath%", $logFilePath)
                $NestedScriptBlock = $NestedScriptBlock.Replace("%OutputXMLPath%", $OutputXMLPath)
                $NestedScriptBlock = $NestedScriptBlock.Replace("%DATAFolder%", $DATAFolder)
                write-host $NestedScriptBlock                
                [scriptblock]$NestedScriptBlock = [scriptblock]::Create($NestedScriptBlock)
                $Test = "'Some test string!'"
                [array]$SBArgs += "($Test)"
                [array]$SBArgs += "($ScriptBlock)"
               
                Start-PSScript -ScriptBlock $NestedScriptBlock -ScriptBlockArguments $SBArgs -logFilePath $logFilePath -Credentials $Credentials -DebugRun
            }
            Else{
                [string]$NestedScriptBlock = {
                    $ScriptBlock = { %ScriptBlock% }                    
                    Start-PSScript -ScriptBlock $ScriptBlock -logFilePath "%LogFilePath%" -Evaluate
                }
                $OutputXMLPath = "$ProjectRoot\$DATAFolder\ScriptBlockOutput.xml"
                [string]$End = {
                    if ($Res) {
                        $Res | Export-Clixml -path "%OutputXMLPath%" -Encoding utf8 -Force 
                    }
                }                
                $ScriptBlockNew = [string]$ScriptBlock + $End
                $NestedScriptBlock = $NestedScriptBlock.Replace("%ScriptBlock%", $ScriptBlockNew)
                $NestedScriptBlock = $NestedScriptBlock.Replace("%LogFilePath%", $logFilePath)
                $NestedScriptBlock = $NestedScriptBlock.Replace("%OutputXMLPath%", $OutputXMLPath)
                $NestedScriptBlock = $NestedScriptBlock.Replace("%DATAFolder%", $DATAFolder)
                [scriptblock]$NestedScriptBlock = [scriptblock]::Create($NestedScriptBlock)               
                
                Start-PSScript -ScriptBlock $NestedScriptBlock -logFilePath $logFilePath -Credentials $Credentials 
            }
        }
    }
    Else  {
        if ($Credentials) {
            Add-ToLog "Start script [$ScriptPath] as [$($Credentials.UserName)]." $logFilePath  
            
            if ($Command){
                $ToRun = "`$Command = `"$Command`" `n`nStart-Process -FilePath `"$PowerShellPrgPath`" -PassThru -ArgumentList `"$Arguments -Command $Command`""
                $ToRun | out-file -path "C:\DATA\Projects\EventLogsAnalyzer\LOGS\text.ps1" -force
                $Res = Start-Process -FilePath "`"$PowerShellPrgPath`"" -Credential $Credentials -PassThru -ArgumentList "$Arguments -Command $Command"
            }
            Else {
                $Res = Start-Process -FilePath "`"$PowerShellPrgPath`"" -Credential $Credentials -PassThru -ArgumentList $Arguments
            }
            $Res.WaitForExit()               
        }  
        Else {
            if($Evaluate){
                Add-ToLog "Start script [$ScriptPath] with evaluate." $logFilePath 
                $Res = Start-Process -FilePath $PowerShellPrgPath -Verb $Verb -ArgumentList $Arguments -PassThru -Wait
            }
            Else {
                Add-ToLog "Start script [$ScriptPath]." $logFilePath 
                $Res = Start-Process -FilePath $PowerShellPrgPath  -ArgumentList $Arguments -PassThru -Wait
            }
        }   
    }

    Return $Res
}
Function Restart-SwitchInInterval {
#RebootSwitchesInInterval
<#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Function to restart devices in time interval.
    .EXAMPLE
    Restart-SwitchInInterval -SwitchesIP $IPs -logFilePath "c:\1.log" -PLinkPath  "c:\plink.exe" -SshConString "" -SshCommand "" 
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
        $Event = "Start switch reboot $($switch.SwitchIp)"
        $EventList = Get-EventList $logFilePath $Event
        
        
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
                Restart-Switches $Switch $logFilePath $PlinkPath $SshConString $SshCommand $Login $Password $CertFilePath
            }
        }
        Else {
            #Add-ToLog $Event $EventLogPath
            RebootSwitches $Switch $EventLogPath $PlinkPath $SshConString $SshCommand $Null $Null $CertFilePath
            ShowNotification "RebootSwitchesInInterval" "Try to reboot switch $($Switch.SwitchIp)!" "Info" "C:\DATA\PROJECTS\ConnectVPN\VPN.log" 10
        } 
    }

}
Function Restart-LocalHostInInterval {
#RestartLocalHostInInterval
<#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Function to restart computer in time interval.
    .EXAMPLE
    Restart-LocalHostInInterval -SwitchesIP $IPs -logFilePath "c:\1.log" -PLinkPath  "c:\plink.exe" -SshConString "" -SshCommand "" 
#>    
    [CmdletBinding()]   
    param (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Log file path." )]
        [ValidateNotNullOrEmpty()] 
        [string] $LogFilePath,
        [Parameter(Mandatory = $false, Position = 1, HelpMessage = "Minimal interval between localhost reboots." )]
        [int16]  $MinIntervalBetweenReboots
    )
    $Event = "Restart localhost"
    $EventList = Get-EventList $LogFilePath $Event
     
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
            Restart-Computer localhost -Force 
        }
    }
    Else {
        Add-ToLog "Restart localhost in $MinIntervalBetweenReboots time interval" $LogFilePath
        Restart-Computer localhost -Force 
    } 
}
Function Show-Notification { 
#ShowNotification
<#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Function to show notification in the system tray.
    .EXAMPLE
    Show-Notification -MsgTitle "My message" -MsgText "message text" -Status  "Info"
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
function Get-Logger {
<#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Function to create logger object.
    .EXAMPLE
    Get-Logger -LogPath "c:\1.log"
#>    
    [CmdletBinding()]   
    param (
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Log file path." )]
        [ValidateNotNullOrEmpty()] 
        [string] $LogPath,
        [Parameter(Mandatory = $false, Position = 1, HelpMessage = "Time format." )]
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
Function Restart-ServiceInInterval {
    #RestartServiceInInterval
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Function to create logger object.
    .EXAMPLE
    Restart-ServiceInInterval -EventLogPath "c:\1.log" -ServiceName "MyService"
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
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Function to send telegram message.
    .EXAMPLE
    Set-TelegramMessage -Token "356555737657367365" -ChatID "44265536465" -Message "Some text"

    With proxy: 
    Set-TelegramMessage -Token "356555737657367365" -ChatID "44265536465" -Message "Some text" -ProxyURL "1.1.1.1" -Credentials $Credentials

#>    
    [CmdletBinding()]   
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Telegram token." )]
        [ValidateNotNullOrEmpty()] 
        [string]$Token,
        [Parameter( Mandatory = $true, Position = 1, HelpMessage = "Telegram chat id." )]
        [ValidateNotNullOrEmpty()] 
        [string]$ChatID,
        [Parameter( Mandatory = $true, Position = 2, HelpMessage = "Message." )]
        [ValidateNotNullOrEmpty()] 
        [string]$Message,
        [Parameter( Mandatory = $false, Position = 3, HelpMessage = "Proxy URL." , ParameterSetName = "Proxy")]
        [string]$ProxyURL = $null,
        [Parameter( Mandatory = $false, Position = 4, HelpMessage = "Proxy credentials." , ParameterSetName = "Proxy")]
        [System.Management.Automation.PSCredential] $Credentials = $null

    ) 

    try {
        if ([Net.ServicePointManager]::SecurityProtocol -notcontains 'Tls12') {
            [Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12
        }
    }
    Catch {}
    [System.Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    $URI = "https://api.telegram.org/bot" + $Token + "/sendMessage?chat_id=" + $ChatID + "&text=" + $Message
     
    if ($null -ne $ProxyURL) {    
        [system.net.webrequest]::defaultwebproxy = New-Object system.net.webproxy($ProxyURL)
        [system.net.webrequest]::defaultwebproxy.credentials = $Credentials
        [system.net.webrequest]::defaultwebproxy.BypassProxyOnLocal = $true
        
        $Response = Invoke-RestMethod -Uri $URI
    }
    else {
        $Response = Invoke-RestMethod -Uri $URI
    }

    return $Response
}
function Initialize-Logging {
 #InitLogging
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Function to set initial logging parameters.
    .EXAMPLE
    Initialize-Logging -MyScriptRoot "c:\script"
#>    
    [CmdletBinding()]   
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Error log file path." )]
        [ValidateNotNullOrEmpty()]
        [string]$ErrorLogFilePath,
        [Parameter( Mandatory = $false, Position = 1, HelpMessage = "Powershell strict version." )]
        [string]$StrictVer = "Latest"
    )
    Set-StrictMode -Version $StrictVer
    
    $LogFolder = split-path $ErrorLogFilePath
    If(!(Test-path $LogFolder)){
        New-Item -path $LogFolder -ItemType Directory
    }
    
    $Global:Logger = Get-Logger $ErrorLogFilePath
    Write-Debug $Global:Logger
    
    $ScriptFolder = Split-Path $LogFolder -parent
    if (Test-Path "$ScriptFolder\debug.txt") {
        $TranscriptPath = "$LogFolder\Transcript.log"
        Start-Transcript -Path $TranscriptPath -Force -append
    }
    else {
            $Global:ErrorActionPreference = 'Stop'
    }
}
function Get-SettingsFromFile {
#Get-Vars
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Load variables from external file.
    .EXAMPLE
    Get-SettingsFromFile -MyScriptRoot "c:\script\var.ps1"
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
Function Get-HTMLTable {
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
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
    #Get-Row
<#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Create html table row code.
    .EXAMPLE
    Get-HTMLRow -Line $Line 
#>    
    [CmdletBinding()]   
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Array with row data." )]
        [ValidateNotNullOrEmpty()]
        [array]$Line,
        [Parameter( Mandatory = $false, Position = 1, HelpMessage = "HTML column span data." )]
        [int16]$ColSpan = 0
    )    
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
            $rows     += (Get-HTMLCol $Line.$col $ColSpan $bold) + "`n"
            $row       = $Row.Replace("%row%", $rows)
        }
    }
    return $row
}
Function Get-HTMLCol  {
#Get-Col    
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Create html table row code.
    .EXAMPLE
    Get-HTMLCol -Column "some text" 
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
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Create html file from template.
    .EXAMPLE
    Get-ContentFromHTMLTemplate -HTMLData $HTMLData  -ColNames "1,2,3" -HTMLTemplateFile "c:\HTMLTemplate.html"
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
function Get-ErrorReporting {
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Visualize errors and save it to file.
    .EXAMPLE
    Get-ErrorReporting -Trap $_
#>    
    [CmdletBinding()]   
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Error trap." )]
        [ValidateNotNullOrEmpty()]
        $Trap
    )
    [string]$PreviousCommand = $Trap.InvocationInfo.line
    [string]$Trap1 = $Trap
    [string]$Trap1 = ($Trap1.replace("[", "")).replace("]", "")
    [string]$line = $Trap.InvocationInfo.ScriptLineNumber
    [string]$Script = $Trap.InvocationInfo.ScriptName
    [string]$StackTrace = $Trap.ScriptStackTrace
    [array] $UpDownStackTrace = @($StackTrace.Split("`n"))
    [int16] $ItemCount = $UpDownStackTrace.Count
    [array] $TempStackTrace = @(1..$ItemCount )
    
    foreach ($item in $UpDownStackTrace) {
        $TempStackTrace[$ItemCount - 1] = $item
        $ItemCount -= 1
    }
    $UpDownStackTrace = $TempStackTrace -join "`n"

    [string]$Trace = $UpDownStackTrace | ForEach-Object { ((($_ -replace "`n", "`n    ") -replace " line ", "") -replace "at ", "") -replace "<ScriptBlock>", "ScriptBlock" }
    [string]$Trace1 = $UpDownStackTrace | ForEach-Object { ((($_ -replace "`n", "`n ") -replace " line ", "") -replace "at ", "") -replace "<ScriptBlock>", "ScriptBlock" }
    if ($Script -ne $Trap.Exception.ErrorRecord.InvocationInfo.ScriptName) {
        [string]$Module = (($Trap.ScriptStackTrace).split(",")[1]).split("`n")[0].replace(" line ", "").Trim()
        [string]$Function = (($Trap.ScriptStackTrace).split(",")[0]).replace("at ", "")
        [string]$ToScreen = "$Trap `n    Script:   `"$($Script):$($line)`"`n    Module:   `"$Module`"`n    Function: `"$Function`""
        [string]$Message = "$Trap1 [script] $Trace1"         
    }
    else { 
        [string]$Message = "$Trap1 [script] $Trace1"        
        $ToScreen = "$Trap `n   $($Script):$($line)"
    }
 
    $Message = $Message.Replace("`n", "|") 
    $Message = $Message.Replace("`r", "")
    $Global:Logger.AddErrorRecord( $Message )

    Write-Host "SCRIPT EXIT DUE TO ERROR!!!" -ForegroundColor Red
    Write-Host "====================================================================================================================================================" -ForegroundColor Red
    Write-Host $ToScreen -ForegroundColor Blue
    Write-Host "Stack trace:" -ForegroundColor green     
    Write-Host "    $Trace" -ForegroundColor green
    Write-Host "Previous command:" -ForegroundColor Yellow
    Write-Host "    $PreviousCommand" -ForegroundColor Yellow
    Write-Host "====================================================================================================================================================" -ForegroundColor Red
}
function Get-HTMLRowFullness {
# Get-RowFullness    
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Return number of not empty columns.
    .EXAMPLE
    Get-HTMLRowFullness -Line $Array
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
function Get-CopyByBITS {
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Copy content of source path to destination path.
    .EXAMPLE
    Get-CopyByBITS -Source "c:\1.txt" -Destination "d:\1.txt"
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
Function Show-CopyStatus {
    #Set-CopyStatus
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
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
Function Show-OpenDialog{
    #Get-OpenDialog
   <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Show windows open file dialog.
    .EXAMPLE
    Show-OpenDialog -Type "file"
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
            $File.ShowDialog() | Out-Null
            if ($File.MultiSelect) { return $File.FileNames } else { return $File.FileName }  
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
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 
        .VER 1   
    .DESCRIPTION
     Import powershell module to the remote session.
    .EXAMPLE
    Import-ModuleRemotely -ModuleName "Module" -Session $Session
#>    
    [CmdletBinding()]   
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Local powershell module name." )]
        [ValidateNotNullOrEmpty()]
        [string] $ModuleName,
        [Parameter( Mandatory = $true, Position = 1, HelpMessage = "Powershell session." )]
        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.RunSpaces.PSSession] $Session
    )

    $Module = Import-Module $ModuleName -PassThru
    if (!$Module)
    { 
        write-warning "Local module does not exist $ModuleName"; 
        return; 
    }  
    
    $ScriptBlock = {`
        $ScriptBlock = {`
        if (get-module $using:ModuleName)
        {
            remove-module $using:ModuleName;
        }
            New-Module -name $using:ModuleName -scriptblock { $($using:Module.Definition) } | import-module
        }
        . ([ScriptBlock]::Create($ScriptBlock))
    }

    invoke-command -session $Session -scriptblock $ScriptBlock;      
}
function Invoke-PSScriptBlock {
    <#
    .SYNOPSIS 
        .AUTHOR Alex
        .DATE   08.04.2020
        .VER    1
    .DESCRIPTION
        Function to automate remote PS session or execute scripts locally
    .EXAMPLE
        Run script on remote host:
        Invoke-PSScriptBlock -ScriptBlock $ScriptBlock -Computer $Computer -Credentials $Credentials 
        
        Run script on local host:
        Invoke-PSScriptBlock -ScriptBlock $ScriptBlock 
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
        [Parameter( Mandatory = $False, Position = 3, ParameterSetName = "Remote", HelpMessage = "Remote credentials." )]
        [string]  $ImportLocalModule,  
        [Parameter( Mandatory = $False, Position = 4, ParameterSetName = "Remote", HelpMessage = "Test-connection before session." )]
        [Switch]  $TestComputer  
    )
    
    $Res = $null

    try {
        if ($Computer) {            
            if ($TestComputer) {
                $Connection = Test-Connection -ComputerName $Computer -count 2 -Delay 1 -Quiet
                if (!$Connection){
                    Write-host  "Unable to connect $Computer!" -ForegroundColor red
                }
            }
            Else {
                $Connection = $true
            }
            if ($Credentials) {            
                if($Connection) {
                    $Session = New-PSSession -ComputerName $Computer -Credential  $Credentials
                }
            }
            Else {
                if($Connection) {
                    $Session = New-PSSession -ComputerName $Computer
                }
            }
            if ($ImportLocalModule){
                Import-ModuleRemotely -ModuleName $ImportLocalModule -Session $Session
            }
        }
        Else {
            $Session = $Null  
        }
    }
    Catch {
        if ($session){
            Remove-PSSession $Session
        }
        Get-ErrorReporting $_
        # Write-Host "Invoke-PSScriptBlock: Unable to establish remote session to $Computer" -ForegroundColor Red
        # Write-Host "$_" -ForegroundColor Red
        $Session = $Null
        exit
    }

    if ($Session) {
        $Res = Invoke-Command -Session $Session -ScriptBlock $ScriptBlock
        Remove-PSSession $Session
    }
    Else {
        $LocalScriptBlock = [scriptblock]::Create($ScriptBlock.ToString().Replace("Using:", ""))        
        $Res = Invoke-Command -ScriptBlock $LocalScriptBlock
        Remove-PSSession $Session
    }

    return $Res
}
function Get-ACLArray {
    <#
    .SYNOPSIS 
        .AUTHOR Alex
        .DATE   08.04.2020
        .VER    1
    .DESCRIPTION
        Function return Array of ACL for all objects in the Path
        Use Type to filter item. "file", "folder", "all"
    .EXAMPLE
        To run locally:
        Get-ACLArray -Path $Path1
        
        To run in PSSession:
        Get-ACLArray -Path $Path2 -Computer $Computer -Credentials $Credentials
        
        To run in PSSession and filter:
        Get-ACLArray -Path $Path2 -Computer $Computer -Credentials $Credentials -Type "folder"
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
            "all" { $ACLItems = Get-ChildItem -Path $Using:Path -Recurse | Sort-Object FullName }
            "folder" { $ACLItems = Get-ChildItem -Path $Using:Path -Recurse -Directory | Sort-Object FullName }
            "file" { $ACLItems = Get-ChildItem -Path $Using:Path -Recurse -File | Sort-Object FullName }
            Default { }
        }
        

        foreach ($Item1 in $ACLItems) {
            $Acl = Get-Acl -Path $Item1.FullName
            #$Acl | Select-Object -ExpandProperty Access    
            foreach ($item in ($Acl | Select-Object -ExpandProperty Access)) {
                [string]$Parent = $Item1.Parent
                $PSO = [PSCustomObject]@{
                    AbsolutePath      = $Item1.FullName
                    Path              = $Item1.FullName.Replace($Using:Path, "")
                    ParentPath        = $Parent.Replace($Using:Path, "")
                    Owner             = $Acl.Owner
                    Group             = $Acl.Group
                    FileSystemRights  = $item.FileSystemRights
                    AccessControlType = $item.AccessControlType
                    IdentityReference = $item.IdentityReference
                    IsInherited       = $item.IsInherited
                    InheritanceFlags  = $item.InheritanceFlags
                    PropagationFlags  = $item.PropagationFlags
                }   
                $Array += $PSO
            }
        }
        return $Array
    }   
    
    $Res = Invoke-PSScriptBlock $ScriptBlock $Computer $Credentials
    return $Res 
}
Function Set-PSModuleManifest {
    <#
    .SYNOPSIS 
        .AUTHOR Alex
        .DATE   08.04.2020
        .VER    1
    .DESCRIPTION
        Function return Array of ACL for all objects in the Path
        Use Type to filter item. "file", "folder", "all"
    .EXAMPLE
 
        Set-PSModuleManifest -ModulePath "C:\Program Files\WindowsPowerShell\Modules\AlexkUtils\AlexkUtils.psd1" -Author "AlexK (1928311@tuta.io)" -ModuleVersion "0.9" -RootModule "AlexkUtils.psm1" -ExportedFunctions $Array

    #>
    [CmdletBinding()]    
    Param (
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Full path to module file." )]
        [ValidateNotNullOrEmpty()]
        [string] $ModulePath,   
        [Parameter( Mandatory = $true, Position = 1, HelpMessage = "Module author." )] 
        [ValidateNotNullOrEmpty()]  
        [string] $Author,
        [Parameter( Mandatory = $true, Position = 2, HelpMessage = "Module version." )]
        [ValidateNotNullOrEmpty()]
        [string] $ModuleVersion,  
        [Parameter( Mandatory = $true, Position = 3, HelpMessage = "Root module file name." )]
        [ValidateNotNullOrEmpty()] 
        [string] $RootModule ,  
        [Parameter( Mandatory = $true, Position = 4, HelpMessage = "Exported functions array." )]
        [ValidateNotNullOrEmpty()] 
        [array] $ExportedFunctions   
    )

    $PowerShellVersion = $PSVersionTable.PSVersion
    $CLRVersion = $PSVersionTable.CLRVersion
    $DotNetFrameworkVersion = $PSVersionTable.DotNetFrameworkVersion 

    New-ModuleManifest -Path $ModulePath -ModuleVersion $ModuleVersion  -Author $Author -PowerShellVersion $PowerShellVersion -ClrVersion $CLRVersion  -DotNetFrameworkVersion $DotNetFrameworkVersion -FunctionsToExport $ExportedFunctions -RootModule $RootModule
}
function Get-UniqueArrayMembers {
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 10.04.2020
        .VER 1   
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
function Resolve-IPtoFQDNinArray {
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 10.04.2020
        .VER 1   
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
Function Get-HelpersData {
    <#
    .SYNOPSIS 
        .AUTHOR Alex
        .DATE   11.04.2020
        .VER    1
    .DESCRIPTION
        Function return row in array from helpers CSV
    .EXAMPLE
        To run in PSSession and filter:
         Get-HelpersData -CSVFilePath "c:\helpers\helper.csv" -Column "RID" -Value "DOMAIN_ALIAS_RID_REMOTE_DESKTOP_USERS"
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
Function Get-DifferenceBetweenArrays {
    <#
    .SYNOPSIS 
        .AUTHOR Alexk
        .DATE 14.04.2020
        .VER 1   
    .DESCRIPTION
     First and second arrays should be the same structure.
     Return array with objects absent in first array.
    .EXAMPLE
    Get-DifferenceBetweenArrays -FirstArray $Array1 -SecondArray $Array2
    #>    
    [CmdletBinding()]   
    Param(
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "First array." )]
        [ValidateNotNullOrEmpty()]
        [Array] $FirstArray,
        [Parameter( Mandatory = $true, Position = 0, HelpMessage = "Second array." )]
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
                $ColumnEqual = $True
                foreach ($Column in  $Columns) {                    
                    if ($Item.$Column -ne $item1.$Column) {
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

function Test-Credentials {
     <#
    .SYNOPSIS 
        .AUTHOR Open source
        .DATE 16.04.2020
        .VER 1   
    .DESCRIPTION
     Test user credentials.
    .EXAMPLE
    Get-DifferenceBetweenArrays -FirstArray $Array1 -SecondArray $Array2
    #>       
    
    [CmdletBinding()]
    [OutputType([Bool])] 
       
    Param ( 
        [Parameter( Mandatory = $false,  ValueFromPipeLine = $true,  ValueFromPipelineByPropertyName = $true )] 
        [ValidateNotNull()] 
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()] 
        $Credentials
    )
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
  
    If (!$domain) {
        Write-Warning "Domain not found."
    }
    Else {
        If ($null -ne $domain.name) {
            return $True
        }
        Else {
            return $false
        }
    }
}

Export-ModuleMember -Function Get-NewAESKey, Import-SettingsFromFile, Get-VarFromAESFile, Set-VarToAESFile, Disconnect-VPN, Connect-VPN, Add-ToLog, Restart-Switches, Restart-SwitchInInterval, Get-EventList, Send-Email, Start-PSScript, Restart-LocalHostInInterval, Show-Notification, Get-Logger, Restart-ServiceInInterval, Set-TelegramMessage, Initialize-Logging, Get-SettingsFromFile, Get-HTMLTable, Get-HTMLCol, Get-ContentFromHTMLTemplate, Get-ErrorReporting, Get-CopyByBITS, Show-OpenDialog, Import-ModuleRemotely, Invoke-PSScriptBlock, Get-ACLArray, Set-PSModuleManifest, Get-VarToString, Get-UniqueArrayMembers, Resolve-IPtoFQDNinArray, Get-HelpersData, Get-DifferenceBetweenArrays, Test-Credentials