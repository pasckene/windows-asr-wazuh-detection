# Recommended Repository Structure

```text
windows-asr-wazuh-detection/
│
├── README.md
│
├── architecture/
│   └── architecture.png
│
├── images/
│   ├── attack-overview.png
│   ├── defender-overview.png
│   ├── wazuh-overview.png
│   ├── mitre-overview.png
│   │
│   ├── wmi-attack.png
│   ├── wmi-defender.png
│   ├── wmi-wazuh.png
│   ├── wmi-mitre.png
│   │
│   ├── wmi-persistence-attack.png
│   ├── wmi-persistence-defender.png
│   ├── wmi-persistence-wazuh.png
│   │
│   ├── masquerading-attack.png
│   ├── masquerading-defender.png
│   ├── masquerading-wazuh.png
│   │
│   ├── office-child-process-attack.png
│   ├── office-child-process-defender.png
│   ├── office-child-process-wazuh.png
│   │
│   ├── office-executable-attack.png
│   ├── office-executable-defender.png
│   ├── office-executable-wazuh.png
│   │
│   ├── asr-tampering.png
│   ├── defender-5007.png
│   └── asr-tampering-wazuh.png
│
├── wazuh/
│   ├── rules/
│   │   └── windows-asr-rules.xml
│   └── decoders/
│
├── defender/
│   └── asr-configuration.md
│
├── attacks/
│   ├── wmi.md
│   ├── wmi-persistence.md
│   ├── masquerading.md
│   ├── office-child-process.md
│   └── asr-tampering.md
│
└── documentation/
    ├── detection-matrix.md
    └── lessons-learned.md
```