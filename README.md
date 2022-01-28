# Lewis MWCCDC Toolkit
> Lewis University | January 21, 2022

This repository contains all of the open-source scripts and tools to be used in the CCDC competitions. Ideally, this grows over time and covers more bases than it did the year before.

## Current State
```text
.
├── documentation
│   ├── Asset-Inventory.xlsx
│   ├── Incident-Report-Template.docx
│   └── Inject-Tracker.xlsx
├── README.md
├── scripts
│   └── enumeration
│       ├── linux
│       │   ├── LinEnum.sh
│       │   └── linpeas.sh
│       ├── README.md
│       └── windows
│           ├── Seatbeltx64.exe
│           ├── Seatbeltx86.exe
│           ├── winPEAS.bat
│           ├── winPEASx64_ofs.exe
│           └── winPEASx86_ofs.exe
└── utilities
    ├── lynis-3.0.7.zip
    ├── pspy
    │   ├── pspy32
    │   └── pspy64
    └── SysinternalsSuite.zip
```

- `documentation/`: Contains all documents necessary to respond to injects, incidents, and track inventory
- `misc/`: Anything that doesn't really fit in the other categories
- `scripts/`: Scripts that enumerate, harden, and more.
- `utilities/`: Programs that are intended to be use during the "mid-game" of the competition to monitor the various systems
