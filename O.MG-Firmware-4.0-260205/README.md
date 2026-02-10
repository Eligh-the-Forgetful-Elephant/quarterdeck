This is for all versions of the O.MG Cable, O.MG Adapter, and O.MG Plug

# [Setup Instructions & Latest Firmware](https://github.com/O-MG/O.MG-Firmware/wiki)

## Running the flasher (macOS / Linux)

The flasher needs Python 3 and **pyserial**. To avoid system Python restrictions:

1. **Use the helper script** (creates a venv and installs pyserial if needed):
   ```bash
   cd O.MG-Firmware-4.0-260205
   chmod +x run_flash.sh
   ./run_flash.sh
   ```
2. Or **manually**: create a venv, install pyserial, then run:
   ```bash
   python3 -m venv .venv
   .venv/bin/pip install pyserial
   .venv/bin/python3 flash.py
   ```

**Programmer not detected?** On macOS, install the [CP210x USB‑UART driver](https://www.silabs.com/products/development-tools/software/usb-to-uart-bridge-vcp-drivers) so the programmer board shows up as a serial port (e.g. `/dev/cu.usbserial-*`).



<img src="https://o.mg.lol/OMGCable-pkg.jpg" >