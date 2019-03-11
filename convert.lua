HDR_LEN = 4

convert_protocol = Proto('Convert',  '0-RTT TCP Converter')

version_f      = ProtoField.uint8( 'convert.version',      'Version',       base.DEC)
total_length_f = ProtoField.uint8( 'convert.total_length', 'Total length',  base.DEC)
unassigned_f   = ProtoField.uint16('convert.unassigned',   'Unassigned',    base.DEC)

tlv_f          = ProtoField.bytes( 'convert.tlv',          'TLV')
tlv_type_f     = ProtoField.uint8( 'convert.tlv_type',     'Type',          base.DEC)
tlv_length_f   = ProtoField.uint8( 'convert.tlv_length',   'Length',        base.DEC)
tlv_value_f    = ProtoField.bytes( 'convert.tlv_value',    'Value')

convert_protocol.fields = {
    version_f, total_length_f, unassigned_f,
    tlv_f, tlv_type_f, tlv_length_f, tlv_value_f
}

tcp_stream_f    = Field.new('tcp.stream')
ip_src_f        = Field.new('ip.src')
ip_dst_f        = Field.new('ip.dst')
tcp_srcport_f   = Field.new('tcp.srcport')
tcp_dstport_f   = Field.new('tcp.dstport')

function get_tlv_name(tlv_type)
    local tlv_name = 'Unknown TLV type'

        if tlv_type == 1    then tlv_name = 'Info TLV'
    elseif tlv_type == 10   then tlv_name = 'Connect TLV'
    elseif tlv_type == 20   then tlv_name = 'Extended TCP Header TLV'
    elseif tlv_type == 21   then tlv_name = 'Supported TCP Extensions TLV'
    elseif tlv_type == 22   then tlv_name = 'Cookie TLV'
    elseif tlv_type == 30   then tlv_name = 'Error TLV'
    end

    return tlv_name
end

-- For a given TCP connection, we need to remember when we finished parsing the
-- Convert message in each direction. After that point the dissector is a NOOP.
-- We thus store the last pkt number that contained Convert protocol data in
-- each direction for each tcp.stream. For the moment, we assume the first pkt
-- with Convert data contains the full Convert message.
convert_end_pkt_num = {}

function convert_protocol.dissector(buffer, pinfo, tree)
    -- Empty TCP packets do not have Convert data. Ignore.
    local msg_length = buffer:len()
    if msg_length == 0 then return end

    local tcp_stream    = tostring(tcp_stream_f())
    local ip_src        = tostring(ip_src_f())
    local ip_dst        = tostring(ip_dst_f())
    local tcp_srcport   = tostring(tcp_srcport_f())
    local tcp_dstport   = tostring(tcp_dstport_f())
    local key           = tcp_stream .. ip_src .. ip_dst .. tcp_srcport .. tcp_dstport

    -- We are past the end of the Convert message. Ignore.
    if convert_end_pkt_num[key] and
       pinfo.number > convert_end_pkt_num[key] then
        return
    end

    pinfo.cols.protocol = convert_protocol.name
    local subtree = tree:add(convert_protocol, buffer(), 'Convert Protocol Data')
    local total_length = buffer(1,1):uint() * 4

    subtree:add(version_f,        buffer(0,1))
    subtree:add(total_length_f,   buffer(1,1)):append_text(' (' .. total_length .. ' bytes)')
    subtree:add(unassigned_f,     buffer(2,2))

    local offset = HDR_LEN
    while offset < msg_length do
        local tlv_type   = buffer(offset,1):uint()
        local tlv_length = buffer(offset+1,1):uint()
        local tlv_name   = get_tlv_name(tlv_type)
        local tlv_bytes  = tlv_length * 4

        tlv_tree = subtree:add(tlv_f, buffer(offset, tlv_bytes))
        tlv_tree:set_text(tlv_name)

        tlv_tree:add(tlv_type_f,   buffer(offset,1)):append_text(' (' .. tlv_name .. ')')
        tlv_tree:add(tlv_length_f, buffer(offset+1,1)):append_text(' (' .. tlv_bytes .. ' bytes)')
        tlv_tree:add(tlv_value_f,  buffer(offset+2,tlv_bytes-2))

        offset = offset + tlv_bytes
    end

    convert_end_pkt_num[key] = pinfo.number
end

local tcp_port = DissectorTable.get('tcp.port')
tcp_port:add(5124, convert_protocol)
