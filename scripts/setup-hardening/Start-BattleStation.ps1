
function Print-Header {
    $header = @'
   _____ __             __        ____        __  __  __          __        __  _           
  / ___// /_____ ______/ /_      / __ )____ _/ /_/ /_/ /__  _____/ /_____ _/ /_(_)___  ____ 
  \__ \/ __/ __ `/ ___/ __/_____/ __  / __ `/ __/ __/ / _ \/ ___/ __/ __ `/ __/ / __ \/ __ \
 ___/ / /_/ /_/ / /  / /_/_____/ /_/ / /_/ / /_/ /_/ /  __(__  ) /_/ /_/ / /_/ / /_/ / / / /
/____/\__/\__,_/_/   \__/     /_____/\__,_/\__/\__/_/\___/____/\__/\__,_/\__/_/\____/_/ /_/ 
'@
    
    Write-Host $header -ForegroundColor Cyan
    Write-Host "An00bRektn - https://notateamserver.xyz" -ForegroundColor Magenta
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
        > Invoke-BattleStation
        Runs the script, remember to import using . .\Start-BattleStation.ps1
    #>
    Print-Header
    Check-Privileges
    Write-OSInfo

    Write-Host "[!!!!] STARTING BATTLESTATION [!!!!]" -ForegroundColor Yellow
    Write-Host
        $user = "blueteam"
        Write-Host "[*] Adding User..." -ForegroundColor Green
        do {
            $Password = Read-Host "Enter blueteam password" -AsSecureString
            $verify = Read-Host "Re-enter Password" -AsSecureString
            $tmp1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))
            $tmp2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($verify))
            if ($tmp1 -ne $tmp2) {
                Write-Host "[!] Passwords did not match! Try again." -ForegroundColor Red
            }
        } while ($tmp1 -ne $tmp2)
        New-LocalUser "blueteam" -Password $Password -FullName "blooteam" -Description "Blue team account"
        Add-LocalGroupMember -Group "Administrators" -Member "blueteam"
        Invoke-Install("Administrator") # This might need to be changed depending on the circumstance
}

function Invoke-Install($user){
    $tools = "c:\Users\$user\Desktop"
    Write-Host "[*] Setting up C:\Users\$user\Desktop\Tools folder..."
    New-Item -Path $tools -Name "Tools" -ItemType "directory"
    $tools = "c:\Users\$user\Desktop\Tools"
    Invoke-WebRequest "https://github.com/Lewis-Cyber-Defense/mwccdc/blob/main/utilities/SysinternalsSuite.zip?raw=true" -OutFile $tools"\SysinternalsSuite.zip"
    Invoke-WebRequest "https://github.com/Lewis-Cyber-Defense/mwccdc/blob/main/scripts/enumeration/windows/HardeningKitty-0.9.0.zip?raw=true" -OutFile $tools"\HardeningKitty.zip"
    Invoke-WebRequest "https://raw.githubusercontent.com/Lewis-Cyber-Defense/mwccdc/main/scripts/setup-hardening/windows_harden.cmd" -Outfile $tools"\windows_harden.cmd"
    Invoke-WebRequest "https://github.com/Lewis-Cyber-Defense/mwccdc/blob/main/utilities/systeminformer-3.0.5988-bin.zip?raw=true" -Outfile $tools"\sysinformer.zip"


    # Install Sysmon
    Expand-Archive -Force $tools\SysinternalsSuite.zip $tools\SysinternalsSuite
    Invoke-WebRequest "https://raw.githubusercontent.com/Lewis-Cyber-Defense/mwccdc/main/utilities/configuration-files/sysmonconfig-export.xml" -Outfile $tools"\sysmonconfig-export.xml"
    Move-Item $tools\SysinternalsSuite\Sysmon64.exe C:\Windows\System32\Sysmon64.exe
    C:\Windows\System32\Sysmon64.exe -i $tools"\sysmonconfig-export.xml" -accepteula
    
    # Set Banner
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticecaption" -Value "SYSTEM AUTHORIZATION WARNING"
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext" -Value "######################################## \n AUTHORIZED USERS ONLY \n UNAUTHORIZED ACCESS WILL BE PROSECUTED TO THE FULL EXTENT OF THE LAW \n########################################"

    Write-Checklist
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
    Write-Host "    [**] MAKE SURE SMB SERVER IS ONLY ACCESSIBLE TO AUTHENTICATED USERS" -ForegroundColor Red
    Write-Host "    [++] Good luck, have fun, ask questions, and happy defending! o7" -ForegroundColor Green
}

Invoke-BattleStation