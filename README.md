## Zeek OUI Logging Module

This adds an orig_mac_oui field to the conn and dhcp logs. This field contains the name of the device manufacturer/vendor based on the mac address.

### ZKG Installation

Ensure the mac-logging script is loaded in your local.zeek path

```
@load protocols/conn/mac-logging
```

Then proceed with the installation

```
zkg install https://github.com/iamckn/oui-logging
zkg load https://github.com/iamckn/oui-logging
```
