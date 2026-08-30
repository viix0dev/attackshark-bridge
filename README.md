# AttackShark Bridge 🦈

> Reverse-engineering AttackShark gaming mice to bring native driver support to the **OpenMouse** project—freeing hardware from bloated proprietary software.

---

## Overview

Many budget-friendly AttackShark mice feature impressive hardware specifications, but rely on closed-source, OS-restricted, and bloatware-heavy configuration software. **AttackShark Bridge** aims to map out the underlying USB HID communications, packet layouts, and hardware registers to provide clean, native, open-source support across Linux, macOS, and Windows.

This repository includes:
* **Protocol Specifications:** Reverse-engineered USB/2.4GHz HID report maps (DPI, polling rates, RGB lighting, key remapping, and battery status).
* **Wireshark Analysis Tools:** Custom scripts, dissectors, and filters to parse and decode USB packet captures (`.pcapng`) automatically.
* **OpenMouse Drivers:** Integration code to connect reverse-engineered protocols directly to the OpenMouse Project.

---

## Supported Devices

| Model | Connection | Status | Notes |
| :--- | :--- | :--- | :--- |
| **AttackShark X11** | Wired / 2.4G / BT | 🟢 Partily Supported | https://github.com/viix0dev/OpenMouse-Bridge |
| **AttackShark X8se** | Wired / 2.4G | 🟡 Working on it | Testing.. |
| **AttackShark X3** | Wired / 2.4G / BT | 🔴 Planned | Captures needed |

---

## Included Analysis Tools
Take a look on the Helpers.md