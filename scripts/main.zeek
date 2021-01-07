##! Adds the OUI name based on Mac Address

module OUI;
## This script adds link-layer address (MAC) information to the connection logs and dhcp logs

export {
    # Idx is used as an identifier to load an input file into a table.
    type Idx: record {
        # OUI is the unique identifier for an organization that manufactures hardware.
        oui: string;
    };

    # Val is the record that is read in from the input file
    type Val: record {
        # vendor is the name of the vendor that created the device marked with an OUI.
        vendor: string;
    };

    # vendors is a table of OUI references paired with manufacturer names to be used to identify network devices.
    global mac_vendors: table[string] of Val = table()
        &default=Val($vendor="unknown");

    # lookup_oui is used to lookup a mac address and return the name of an organization that has manufactured the device.
    global lookup_oui: function(mac_addr: string): string;
}

# lookup_oui is used to lookup a mac address and return the name of an organization that has manufactured the device.
# Args:
# mac_addr: string
#   the mac address to lookup the OUI for
# Returns:
# string:
#   the manufacturer/organization that the OUI for the device identifies.
function lookup_oui(mac_addr: string): string {
    local prefix = mac_addr[:8];
    return mac_vendors[prefix]$vendor;
}

event zeek_init() {
    # Create an input file to be used to learn OUI data. 
    # This input reads the data into the vendors table and will reread the table if the file is rewritten.
    Input::add_table([$source=fmt("%s/oui.dat", @DIR),
        $name="mac_vendors",
        $idx=Idx,
        $val=Val, 
        $destination=mac_vendors,
        $mode=Input::REREAD]);
}
