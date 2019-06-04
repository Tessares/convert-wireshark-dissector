# 0-RTT TCP Convert Wireshark dissector

Wireshark dissector plugin for the 0-RTT TCP Convert Internet draft.
See the IETF draft [draft-ietf-tcpm-converters-06](https://datatracker.ietf.org/doc/draft-ietf-tcpm-converters) for more information.

This dissector makes the following assumptions:
* Convert is running on port 5124. This port can be changed via the protocol
preferences in Wireshark.
* A Convert TCP stream starts with a SYN carrying a payload. In particular, in
case of an MPTCP connection using Convert, any subflow joining the Convert port
will thus not be dissected as Convert.

### Usage

Simply drop this file into your Wireshark plugin folder.

On **Unix-like** systems, the personal plugin folder is
`~/.local/lib/wireshark/plugins`.

If you are running on **macOS** and Wireshark is installed as an application
bundle, the global plugin folder is `%APPDIR%/Contents/PlugIns/wireshark`,
otherwise it's `<INSTALLDIR>/lib/wireshark/plugins`.

On **Windows**, the personal plugin folder is `%APPDATA%\Wireshark\plugins` while the
global plugin folder is `WIRESHARK\plugins`.

### Contributing

Code contributions are more than welcome.

Support for the following should still be added:
* Info TLV
* Supported TCP Extensions TLV
* Cookie TLV
* Connect TLV TCP Options value
* Convert Message split over multiple TCP segments

### Contact

* [Gregory Vander Schueren](mailto:gregory.vanderschueren@tessares.net)
* [Gregory Detal](mailto:gregory.detal@tessares.net)
* [Olivier Bonaventure](mailto:olivier.bonaventure@tessares.net)

### License

This project is licensed under the 3-Clause BSD License - see the
[LICENSE](LICENSE) file for details.
