convert_protocol = Proto("Convert",  "0-RTT TCP Converter")

convert_protocol.fields = {}

function convert_protocol.dissector(buffer, pinfo, tree)
    length = buffer:len()
    if length == 0 then return end

    pinfo.cols.protocol = convert_protocol.name

    local subtree = tree:add(convert_protocol, buffer(), "Convert Protocol Data")
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(5124, convert_protocol)
