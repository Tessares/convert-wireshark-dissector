VERSION                 = 1 -- draft-ietf-tcpm-converters-06
HDR_LEN                 = 4
DEFAULT_PORT            = 5124

TLV_TYPE_INFO           = 1
TLV_TYPE_CONNECT        = 10
TLV_TYPE_EXT_TCP_HDR    = 20
TLV_TYPE_SUP_TCP_EXT    = 21
TLV_TYPE_COOKIE         = 22
TLV_TYPE_ERROR          = 30

convert_prot            = Proto('Convert',  '0-RTT TCP Convert Protocol')
convert_prot.prefs.port = Pref.uint('port', DEFAULT_PORT, 'Converter Port')

version_f               = ProtoField.uint8( 'convert.version',                  'Version')
total_length_f          = ProtoField.uint8( 'convert.total_length',             'Total Length')
unassigned_f            = ProtoField.uint16('convert.unassigned',               'Unassigned')
tlv_f                   = ProtoField.bytes( 'convert.tlv',                      'TLV')
tlv_type_f              = ProtoField.uint8( 'convert.tlv_type',                 'Type')
tlv_length_f            = ProtoField.uint8( 'convert.tlv_length',               'Length')
tlv_value_f             = ProtoField.bytes( 'convert.tlv_value',                'Value')
connect_port_f          = ProtoField.uint16('convert.connect.port',             'Port')
connect_addr_f          = ProtoField.ipv6(  'convert.connect.addr',             'Address')
connect_tcp_opts_f      = ProtoField.bytes( 'convert.connect.tcp_optons',       'TCP Options')
ext_tcp_hdr_una_f       = ProtoField.uint16('convert.ext_tcp_hdr.unassigned',   'Unassigned')
ext_tcp_hdr_hdr_f       = ProtoField.bytes( 'convert.ext_tcp_hdr.tcp_header',   'TCP Header')
error_code_f            = ProtoField.uint8( 'convert.error.code',               'Error Code')
error_value_f           = ProtoField.bytes( 'convert.error.value',              'Value')

convert_prot.fields = {
    version_f, total_length_f, unassigned_f,
    tlv_f, tlv_type_f, tlv_length_f, tlv_value_f,
    connect_port_f, connect_addr_f, connect_tcp_opts_f,
    ext_tcp_hdr_una_f, ext_tcp_hdr_hdr_f,
    error_code_f, error_value_f
}

tcp_stream_f            = Field.new('tcp.stream')
ip_src_f                = Field.new('ip.src')
ip_dst_f                = Field.new('ip.dst')
ipv6_src_f              = Field.new('ipv6.src')
ipv6_dst_f              = Field.new('ipv6.dst')
tcp_srcport_f           = Field.new('tcp.srcport')
tcp_dstport_f           = Field.new('tcp.dstport')
tcp_syn_f               = Field.new('tcp.flags.syn')
tcp_ack_f               = Field.new('tcp.flags.ack')
tcp_len_f               = Field.new('tcp.len')

-- For packet for both ipv6 and ipv4, we need to check its availability here
function get_ip_src()
	local ip_src = ip_src_f()
	local ipv6_src = ipv6_src_f()
	if ip_src then 
		return ip_src
	elseif ipv6_src then 
		return ipv6_src
	end
end

-- For packet for both ipv6 and ipv4, we need to check its availability here
function get_ip_dst()
	local ip_dst = ip_dst_f()
	local ipv6_dst = ipv6_dst_f()
	if ip_dst then
		return ip_dst
	elseif ipv6_dst then 
		return ipv6_dst
	end
end

function get_tlv_name(tlv_type)
    local tlv_name = 'Unknown TLV Type'

        if tlv_type == TLV_TYPE_INFO        then tlv_name = 'Info TLV'
    elseif tlv_type == TLV_TYPE_CONNECT     then tlv_name = 'Connect TLV'
    elseif tlv_type == TLV_TYPE_EXT_TCP_HDR then tlv_name = 'Extended TCP Header TLV'
    elseif tlv_type == TLV_TYPE_SUP_TCP_EXT then tlv_name = 'Supported TCP Extensions TLV'
    elseif tlv_type == TLV_TYPE_COOKIE      then tlv_name = 'Cookie TLV'
    elseif tlv_type == TLV_TYPE_ERROR       then tlv_name = 'Error TLV'
    end

    return tlv_name
end

function get_error_name(error_code)
    local error_name = 'Unknown Error Code'

         if  error_code == 0    then error_name = 'Unsupported Version'
     elseif  error_code == 1    then error_name = 'Malformed Message'
     elseif  error_code == 2    then error_name = 'Unsupported Message'
     elseif  error_code == 3    then error_name = 'Missing Cookie'
     elseif  error_code == 32   then error_name = 'Not Authorized'
     elseif  error_code == 33   then error_name = 'Unsupported TCP Option'
     elseif  error_code == 64   then error_name = 'Resource Exceeded'
     elseif  error_code == 65   then error_name = 'Network Failure'
     elseif  error_code == 96   then error_name = 'Connection Reset'
     elseif  error_code == 97   then error_name = 'Destination Unreachable'
     end

    return error_name
end

function get_stream_dir_key()
    return tostring(tcp_stream_f()) ..
           --tostring(ip_src_f()) ..
           tostring(get_ip_src()) ..
           --tostring(ip_dst_f()) ..
           tostring(get_ip_dst()) ..
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

function parse_tlv_value(tlv_tree, tlv_type, buffer, val_offset, val_length)
    if tlv_type == TLV_TYPE_CONNECT then
        tlv_tree:add(connect_port_f, buffer(val_offset, 2))
        tlv_tree:add(connect_addr_f, buffer(val_offset + 2 ,16))
        tlv_tree:add(connect_tcp_opts_f, buffer(val_offset + 18, val_length - 18))
    elseif tlv_type == TLV_TYPE_EXT_TCP_HDR then
        tlv_tree:add(ext_tcp_hdr_una_f, buffer(val_offset, 2))
        tlv_tree:add(ext_tcp_hdr_hdr_f, buffer(val_offset + 2, val_length - 2))
    elseif tlv_type == TLV_TYPE_ERROR then
        local error_code = buffer(offset, 1):uint()
        local error_name = get_error_name(error_code)
        tlv_tree:add(error_code_f, buffer(val_offset, 1)):append_text(' (' .. error_name .. ')')
        tlv_tree:add(error_value_f, buffer(val_offset + 1, val_length - 1))
    else
        tlv_tree:add(tlv_value_f, buffer(val_offset, val_length))
    end
end

-- For a given TCP connection, we need to remember when we finished parsing the
-- Convert message in each direction. After that point the dissector is a NOOP.
-- We thus store the last pkt number that contained Convert protocol data in
-- each direction for each tcp.stream. For the moment, we assume the first pkt
-- with Convert data contains the full Convert message.
convert_end_pkt_num = {}
is_convert_stream = {}

function convert_prot.dissector(buffer, pinfo, tree)
    -- Empty TCP packets, cannot be Convert. Ignore.
    local msg_length = buffer:len()
    if msg_length == 0 then
        return
    end

    -- Past the end of the Convert message. Ignore.
    local stream_dir_key = get_stream_dir_key()
    if is_past_convert_msg(stream_dir_key, pinfo.number) then
        return
    end

    -- Assume Convert Header sits in the SYN. Otherwise Ignore.
    if is_convert_syn() then
        mark_stream_as_convert()
    end

    -- Does not belong to a Convert stream. Ignore.
    if not belongs_to_convert_stream() then
        return
    end

    -- We are now parsing a Convert message.
    pinfo.cols.protocol = convert_prot.name
    local subtree = tree:add(convert_prot, buffer(), '0-RTT TCP Convert Protocol Data')
    local version = buffer(0, 1):uint()
    local total_length = buffer(1, 1):uint() * 4

    -- Different version. Stop parsing this stream direction.
    if version ~= VERSION then
        convert_end_pkt_num[stream_dir_key] = pinfo.number
        return
    end

    -- Parse Header.
    subtree:add(version_f,        buffer(0, 1))
    subtree:add(total_length_f,   buffer(1, 1)):append_text(' (' .. total_length .. ' Bytes)')
    subtree:add(unassigned_f,     buffer(2, 2))

    -- Parse TLVs.
    local offset = HDR_LEN
    while offset < msg_length do
        local tlv_type   = buffer(offset, 1):uint()
        local tlv_length = buffer(offset + 1, 1):uint()
        local tlv_name   = get_tlv_name(tlv_type)
        local tlv_bytes  = tlv_length * 4

        tlv_tree = subtree:add(tlv_f, buffer(offset, tlv_bytes))
        tlv_tree:set_text(tlv_name)
        tlv_tree:add(tlv_type_f,   buffer(offset, 1)):append_text(' (' .. tlv_name .. ')')
        tlv_tree:add(tlv_length_f, buffer(offset + 1, 1)):append_text(' (' .. tlv_bytes .. ' Bytes)')

        parse_tlv_value(tlv_tree, tlv_type, buffer, offset + 2, tlv_bytes - 2)

        offset = offset + tlv_bytes
    end

    -- Mark end of Convert for stream direction.
    convert_end_pkt_num[stream_dir_key] = pinfo.number
end

function convert_prot.prefs_changed()
    tcp_port:remove(registered_port, convert_prot)
    registered_port = convert_prot.prefs.port
    tcp_port:add(registered_port, convert_prot)
end

-- Initial registration
tcp_port = DissectorTable.get('tcp.port')
registered_port = convert_prot.prefs.port
tcp_port:add(registered_port, convert_prot)
