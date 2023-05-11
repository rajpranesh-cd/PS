# Check if the script is running as an administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # If not, re-run the script as an administrator
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    Exit
}

# Set the new hostname as a global variable
$global:computerName = "HOST_NAME"
$global:HName = " "
function EventLog_Error {

    # Define the log file path and name
    $logFile = "$PSScriptRoot\EventLog.txt"

    # Get the event log entries for the last two weeks
    $events = Get-EventLog -LogName System -After (Get-Date).AddDays(-14) -ErrorAction Stop

    # Filter the events by entry type and format the output
    $table = $events | Where-Object {$_.EntryType -match 'Error'} | Format-Table TimeWritten, EntryType, Source, Message -AutoSize

    # Save the formatted output to the log file
    $table | Out-File -FilePath $logFile
}

function Machinename_Change {

    #Write-Output $global:computerName
    Rename-Computer -NewName $global:computerName -Force 
}
function Converter {
   
    $prefix = $global:computerName.Substring(0,3)
    $global:HName = "SRV-$prefix-ADMIN"
    #Write-Output $result
}
function Domain_Join {

    $domain = "rchsd.org"
    $username = "your_username"
    $password = ConvertTo-SecureString "your_password" -AsPlainText -Force
    $credential = New-Object System.Management.Automation.PSCredential($username,$password)
    Add-Computer -DomainName $domain -Credential $credential -Restart
    

}

function RegistryEdit {
    # Define the registry values to add
    $regContent = @"
    Windows Registry Editor Version 5.00

    [HKEY_LOCAL_MACHINE\Software\Microsoft\Cryptography\Wintrust\Config]
    "EnablecertPaddingCheck"="1"

    [HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Cryptography\Wintrust\Config]
    "EnablecertPaddingCheck"="1"
"@

    # Save the registry values to a temporary file
    $regFile = "$env:TEMP\reg_changes.reg"
    $regContent | Out-File -Encoding ASCII -FilePath $regFile

    # Import the registry values
    reg.exe import $regFile

    # Delete the temporary file
    Remove-Item -Path $regFile
}

function GroupAdd {
    # Define the user accounts to add
    $user1 = "RCHSD\SVR-All Servers Person-Admin"
    $user2 = "RCHSD\SVR-All Servers Services-Admin"
    $user3 = $global:HName

    # Get the username and password of the account to add
    $username = Read-Host "Enter username of the account to be added"
    $password = Read-Host "Enter password of the account to be added" -AsSecureString
    
    # Add the first user account to the local administrators group
    $groupName = "Administrators"
    $group = [ADSI]("WinNT://./" + $groupName + ",group")

    $user1Object = [ADSI]("WinNT://./" + $user1 + ",user")
    $group.Add($user1Object.Path)

    # Add the second user account to the local administrators group
    $user2Object = [ADSI]("WinNT://./" + $user2 + ",user")
    $group.Add($user2Object.Path)

    $user3Object = [ADSI]("WinNT://./" + $user3 + ",user")
    $group.Add($user3Object.Path)


    $userObject = [ADSI]("WinNT://./$username,user")
    $userObject.SetPassword([System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)))
    $userObject.SetInfo()
    $group.Add($userObject.Path)
}


#EventLog_Error
#Machinename_Change
#Convertor
#Domain_Join
#GroupAdd
#RegistryEdit


