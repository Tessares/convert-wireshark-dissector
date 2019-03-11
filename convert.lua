HDR_LEN = 4
DEFAULT_PORT = 5124

convert_protocol = Proto('Convert',  '0-RTT TCP Converter')

convert_protocol.prefs.port = Pref.uint('port', DEFAULT_PORT, 'Converter port')

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

tcp_syn_f       = Field.new('tcp.flags.syn')
tcp_ack_f       = Field.new('tcp.flags.ack')
tcp_len_f       = Field.new('tcp.len')

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

function get_stream_dir_key()
    return tostring(tcp_stream_f()) ..
           tostring(ip_src_f()) ..
           tostring(ip_dst_f()) ..
           tostring(tcp_srcport_f()) ..
           tostring(tcp_dstport_f())
end

function is_past_convert_msg(key, pkt_num)
    return convert_end_pkt_num[key] and
           pkt_num > convert_end_pkt_num[key]
end

-- Assume for the time being that any TCP stream that starts with a SYN with
-- a payload carries Convert data.
function is_convert_syn()
    return tostring(tcp_syn_f()) == '1' and
           tostring(tcp_ack_f()) == '0' and
           tostring(tcp_len_f()) ~= '0'
end

function belongs_to_convert_stream()
    return is_convert_stream[tostring(tcp_stream_f())] == true
end

function mark_stream_as_convert()
    is_convert_stream[tostring(tcp_stream_f())] = true
end

-- For a given TCP connection, we need to remember when we finished parsing the
-- Convert message in each direction. After that point the dissector is a NOOP.
-- We thus store the last pkt number that contained Convert protocol data in
-- each direction for each tcp.stream. For the moment, we assume the first pkt
-- with Convert data contains the full Convert message.
convert_end_pkt_num = {}
is_convert_stream = {}

function convert_protocol.dissector(buffer, pinfo, tree)
    -- Empty TCP packets, cannot be Convert. Ignore.
    local msg_length = buffer:len()
    if msg_length == 0 then return end

    -- Past the end of the Convert message. Ignore.
    local stream_dir_key = get_stream_dir_key()
    if is_past_convert_msg(stream_dir_key, pinfo.number) then
        return
    end

    if is_convert_syn() then
        mark_stream_as_convert()
    end

    -- Does not belong to a Convert stream. Ignore.
    if not belongs_to_convert_stream() then
        return
    end

    -- We are now parsing a Convert message.
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

    -- Mark end of Convert for stream direction.
    convert_end_pkt_num[stream_dir_key] = pinfo.number
end

function convert_protocol.prefs_changed()
    tcp_port:remove(registered_port, convert_protocol)
    registered_port = convert_protocol.prefs.port
    tcp_port:add(registered_port, convert_protocol)
end

-- Initial registration
tcp_port = DissectorTable.get('tcp.port')
registered_port = convert_protocol.prefs.port
tcp_port:add(registered_port, convert_protocol)
