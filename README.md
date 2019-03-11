# Wireshark Convert dissector

Wireshark dissector plugin for the 0-RTT TCP Converter Internet draft.
See the IETF draft [draft-ietf-tcpm-converters-06](https://datatracker.ietf.org/doc/draft-ietf-tcpm-converters) for more information.

Tessares released this plugin under the 3-Clause BSD License.

Author is Gregory Vander Schueren <gregory.vanderschueren@tessares.net>

## Usage

Simply drop this file into your Wireshark plugin folder.

On Unix-like systems, the personal plugin folder is
~/.local/lib/wireshark/plugins.

If you are running on macOS and Wireshark is installed as an application
bundle, the global plugin folder is %APPDIR%/Contents/PlugIns/wireshark,
otherwise it’s INSTALLDIR/lib/wireshark/plugins.

On Windows, the personal plugin folder is %APPDATA%\Wireshark\plugins while the
global plugin folder is WIRESHARK\plugins.
