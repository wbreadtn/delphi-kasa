# delphi-kasa
Delphi lib that provides direct interface to Kasa IOT devices

Scope:
- Circumvent dependency on TP-Link cloud-based control of Kasa IOT devices
- Summary of functionality:
   - Get device info
   - Get device state on/off
   - Turn the device on/off
 - Missing/desired improvements
   - Device discovery (I currently use reserved mac address->IP)

Special thanks to the creators of python-kasa wherein I found lots of code that helped me in this project!
- https://github.com/python-kasa

Dependencies:
- https://github.com/CHERTS/DCPcrypt
- https://github.com/hgourvest/superobject

Notes:
- This project is in its infant stage.
- This is my first public project in Github, so there's a lot that I don't know. Suggestions/guidance is welcomed.
- Contribution is welcomed.
- Delphi version is XE7, but I think it should compile in latest Delphi versions.
- Supports older/legacy XOR protocol KASA devices (hw version 5.0) and newer KLAP protocol devices (hw version 5.26)
- Some devices get migrated from the legacy XOR protocol to KLAP by a firmware update (e.g. HS210 hw3.0 on firmware 1.1.0+), but their firmware still only accepts the older IOT-style commands (set_relay_state/get_sysinfo) for actual control/info, not the newer set_device_info/get_device_info commands - even though KLAP v2 auth itself works correctly. Confirmed via live testing; verified byte-for-byte against python-kasa's actual auth-hash implementation, so this is a genuine device-side command-set quirk, not an auth/protocol bug. TKasaKLAPClient.UseLegacyControlCommands handles this: set it True for devices in this category (auth/transport stays on whatever KlapVersion you set; only the command format changes).

Getting started:
- Download the demo, DemonstrateKasa.dpr, which is a Windows console program (..\Demo)
- Download the Kasa lib units (..\Kasa)
- Get Superobject and DCPCrypt, if you don't already have it
- Assign file paths, etc.

Known defects:
- I don't know of any yet, but I'm sure their are some.
