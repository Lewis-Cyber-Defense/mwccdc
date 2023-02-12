# Lewis MWCCDC Toolkit
> Lewis University | January 21, 2022

This repository contains all of the open-source scripts and tools to be used in the CCDC competitions. Ideally, this grows over time and covers more bases than it did the year before.

## Current State
```text
.
├── checklists
│   ├── README.md
│   ├── Ubuntu.md
│   └── Windows.md
├── documentation
│   ├── Asset-Inventory.xlsx
│   ├── Incident-Report-Template.docx
│   ├── Inject-Tracker.xlsx
│   └── README.md
├── README.md
├── scripts
│   ├── enumeration
│   │   ├── linux
│   │   │   ├── LinEnum.sh
│   │   │   ├── linpeas.sh
│   │   │   └── rkhunter-1.4.6.tar.gz
│   │   ├── README.md
│   │   └── windows
│   │       ├── HardeningKitty-0.9.0.zip
│   │       ├── Seatbelt.exe
│   │       └── winPEAS.exe
│   └── setup-hardening
│       ├── README.md
│       ├── sb-an00b.sh
│       ├── setup_docker.sh
│       ├── Start-BattleStation.ps1
│       ├── start-battlestation.sh
│       └── windows_harden.cmd
└── utilities
    ├── anti-virus
    │   └── clamav
    │       ├── clamav-0.104.2.win.x64.msi
    │       └── clamav-0.104.2.win.x64.zip
    ├── configuration-files
    │   ├── collect-all.xml
    │   ├── README.md
    │   ├── sshd_config
    │   ├── sysmonconfig-export.xml
    │   └── win-banner.ps1
    ├── DeepBlue
    │   ├── DeepBlue.ps1
    │   ├── DeepBlue.zip
    │   ├── regexes.txt
    │   └── safelist.txt
    ├── john-1.9.0-jumbo-1-win64.zip
    ├── lynis-3.0.7.zip
    ├── pspy
    │   ├── pspy32
    │   └── pspy64
    ├── README.md
    ├── SysinternalsSuite.zip
    ├── SysmonForLinux.zip
    ├── systeminformer-3.0.5988-bin.zip
    └── Wireshark-4.0.3.exe

13 directories, 41 files
```

- `documentation/`: Contains all documents necessary to respond to injects, incidents, and track inventory
- `scripts/`: Scripts that enumerate, harden, and more.
- `utilities/`: Programs that are intended to be use during the "mid-game" of the competition to monitor the various systems

## Additional References
- [JShielder Templates](https://github.com/Jsitech/JShielder)
- [dev-sec ansible templates](https://github.com/dev-sec/ansible-collection-hardening)
- [awesome-security-hardening](https://github.com/decalage2/awesome-security-hardening)
- [adsecurity.org](https://adsecurity.org/)
- [TheMayor's Pentesting Notes](https://themayor.notion.site/Pentesting-Notes-9c46a29fdead4d1880c70bfafa8d453a)
- [explainshell.com](https://explainshell.com/#)
- [CyberChef](https://gchq.github.io/CyberChef/)