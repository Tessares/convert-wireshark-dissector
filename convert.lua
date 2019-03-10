convert_protocol = Proto("Convert",  "0-RTT TCP Converter")

version      = ProtoField.uint8( "convert.version",      "Version",       base.DEC)
total_length = ProtoField.uint8( "convert.total_length", "Total Length",  base.DEC)
unassigned   = ProtoField.uint16("convert.unassigned",   "Unassigned",    base.DEC)

convert_protocol.fields = { version, total_length, unassigned }

function convert_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = convert_protocol.name

    local subtree = tree:add(convert_protocol, buffer(), "Convert Protocol Data")

    subtree:add(version,        buffer(0,1))
    subtree:add(total_length,   buffer(1,1))
    subtree:add(unassigned,     buffer(2,2))
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(5124, convert_protocol)
