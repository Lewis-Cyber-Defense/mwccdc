
function Print-Header {
    $header = @'
   _____ __             __        ____        __  __  __          __        __  _           
  / ___// /_____ ______/ /_      / __ )____ _/ /_/ /_/ /__  _____/ /_____ _/ /_(_)___  ____ 
  \__ \/ __/ __ `/ ___/ __/_____/ __  / __ `/ __/ __/ / _ \/ ___/ __/ __ `/ __/ / __ \/ __ \
 ___/ / /_/ /_/ / /  / /_/_____/ /_/ / /_/ / /_/ /_/ /  __(__  ) /_/ /_/ / /_/ / /_/ / / / /
/____/\__/\__,_/_/   \__/     /_____/\__,_/\__/\__/_/\___/____/\__/\__,_/\__/_/\____/_/ /_/ 
'@
    
    Write-Host $header -ForegroundColor Cyan
    Write-Host "An00bRektn - https://an00brektn.github.io" -ForegroundColor Magenta
    Write-Host
}

function Check-Privileges {  
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
    if($isAdmin -eq $false){
        Write-Host "[!] This script needs to be run as an Administrator." -ForegroundColor Red
        Exit
    }
}

function Write-OSInfo{
    [string]$osname = (Get-WmiObject -class Win32_OperatingSystem).Caption
    [string]$osversion = [Environment]::OSVersion.version
    $IsVirtual=((Get-WmiObject win32_computersystem).model -eq 'VMware Virtual Platform' -or ((Get-WmiObject win32_computersystem).model -eq 'Virtual Machine'))
    Write-Host "-------------------------------------------" 
    Write-Host "Current Time:" (Get-Date)
    Write-Host "OS:" $osname "-" $osversion 
    Write-Host "Hostname:" (hostname) 
    Write-Host "Arch:" $env:PROCESSOR_ARCHITECTURE 
    Write-Host "Domain?: " -NoNewline 
    if ((Get-WmiObject win32_computersystem).partofdomain -eq $true) {
        Write-Host "Yes"
    } else {
        Write-Host "No"
    }
    Write-Host "VM?:"$IsVirtual
    Write-Host "-------------------------------------------"
    Write-Host "[*] Run 'systeminfo' to learn more about the system!" -ForegroundColor Cyan
    Write-Host
}

function Invoke-BattleStation(){
    <#
        .SYNOPSIS
        Automates initial blueteam setup for Windows Hosts
        Author:
            An00bRektn - https://github.com/An00bRektn
        .DESCRIPTION
        A Powershell-based Windows Hardening script for use in competitions like MWCCDC or Cyberforce
        .EXAMPLE
        > Invoke-BattleStation -AddUser
        Runs the script, adding a separate blueteam admin user
        > Invoke-BattleStation
        Runs the script, without a separate blueteam admin user
    #>

    Write-Host "[!!!!] STARTING BATTLESTATION [!!!!]" -ForegroundColor Yellow
    Write-Host
    Write-Host "[*] The following information is critically important" -ForegroundColor Cyan
    $AddUser = Read-Host "Would you like to add a separate blueteam admin user (y/n)? "
    if($AddUser -eq "y"){
        $user = "blueteam"
        Write-Host "[*] Adding User..." -ForegroundColor Green
        $Password = Read-Host "Enter blueteam password" -AsSecureString
        New-LocalUser "blueteam" -Password $Password -FullName "blooteam" -Description "Blue team account"
        Add-LocalGroupMember -Group "Administrators" -Member "blueteam"
    } else {
        $user = "Administrator"
    }
    $tools = "c:\Users\$user\"
    Write-Host "[*] Setting up C:\Users\$user\Tools folder..."
    New-Item -Path $tools -Name "Tools" -ItemType "directory"

    Invoke-WebRequest "https://github.com/Lewis-Cyber-Defense/mwccdc/blob/main/utilities/SysinternalsSuite.zip?raw=true" -OutFile $tools"\SysinternalsSuite.zip"
    Invoke-WebRequest "https://github.com/Lewis-Cyber-Defense/mwccdc/blob/main/scripts/enumeration/windows/HardeningKitty-master.zip?raw=true" -OutFile $tools"\HardeningKitty.zip"
    Invoke-WebRequest "https://github.com/Lewis-Cyber-Defense/mwccdc/blob/main/scripts/setup-hardening/posh-dsc-windows-hardening.zip" -OutFile $tools"\posh-dsc-windows-hardening.zip"
}

function Write-Checklist{
    Write-Host "[+] aaand DONE!" -ForegroundColor Yellow
    Write-Host "  \\ Since CCDC is scuffed and won't let us look at the infra before writing scripts, here are some things to remember" -ForegroundColor Yellow
    Write-Host "    [**] READ THE RULES" -ForegroundColor Yellow
    Write-Host "    [**] Identify the necessary services running on the system. Remove unnecessary ones." -ForegroundColor Yellow
    Write-Host "    [**] Check the other users on the system and see what's up with them" -ForegroundColor Yellow
    Write-Host "    [**] Identify and take care of any and all files you wouldn't normally find on a Windows install" -ForegroundColor Yellow
    Write-Host "    [**] Here's a decent hardening guide: https://security.utexas.edu/os-hardening-checklist/windows-r2" -ForegroundColor Yellow
    Write-Host "    [**] Use our team repo: https://github.com/Lewis-Cyber-Defense/mwccdc" -ForegroundColor Yellow
    Write-Host "    [**] Disable IPv6, LLMNR, turn on SMB signing" -ForegroundColor Yellow
    Write-Host "    [++] Good luck, have fun, ask questions, and happy defending! o7" -ForegroundColor Green
}
Print-Header
Check-Privileges
Write-OSInfo
Invoke-BattleStation
Write-Checklist