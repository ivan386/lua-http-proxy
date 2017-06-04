--[[
dns_packet ={
	id 2 int, 
	flags 2 int, 
	queries 2 int, 
	answers 2 int, 
	authority answers 2 int, 
	additional answers 2 int,
	query = {
		name = {
			{
				string_length 2 int,
				string string_length bytes
			}
			...
		},
		type 2 int,
		class 2 int
	}+
	...
	answer = {
		name = {
			{
				string_length 2 int,
				string string_length bytes
			}*
			...
			{
				pointer_head 2bit = 11b,
				pointer 14bit int
			}?
		},
		type 2 int,
		class 2 int,
		ttl 2 int,
		data_length 2 int,
		data data_length bytes
	}*
	...
}
]]

function pack_int(number, length)
	length = length or 1
	if length == 1 then
		return string.char(number % 256)
	end
	
	local packed = ""
	for i = 1, length do
		packed = string.char(number % 256) .. packed 
		number = math.floor(number / 256)
	end
	return packed
end

function pack_string(str)
	return pack_int(#str)..str
end

function dns_request_pack(host, qtype, id)
	qtype = qtype or 255
	id = id or math.random(0, 65535)
	return  pack_int(id, 2) ..
			"\1\0\0\1\0\0\0\0\0\0" ..
			string.gsub(host, "([^.]+)%.?", function(name)
				return pack_string(name)
			end) ..
			"\0" ..
			pack_int(qtype, 2) ..
			"\0\1"
end

function tcp_dns_request_pack(host, qtype, id)
	local data = dns_request_pack(host, qtype, id)
	return pack_int(#data, 2)..data
end

function tcp_dns_parse(data, packet_start, debug)
	local function read_ip(data, pos)
		return string.format("%s.%s.%s.%s", data:byte(pos, pos+3)), pos+4
	end

	local function read_ipv6(data, pos)
		return string.format("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", data:byte(pos,pos+15)), pos+16
	end

	local function read_int(data, pos, length)
		local int = 0
		pos = pos or 1
		length = length or 1
		if #data - pos < length - 1 then
			if debug then 
				print("read_int incomplete data", #data, pos, length)
			end
			return nil, "incomplete data"
		end
		for i = 0, length - 1 do
			int = int * 256 + data:byte(pos + i)
		end
		return int
	end

	local function read_string(data, pos)
		local length, err = read_int(data, pos)
		if not length then
			if debug then 
				print("read_string no length", pos)
			end
			return nil, err
		end
		local str = data:sub(pos + 1, pos + length)
		return str, pos + length + 1
	end

	local function read_strings(data, pos, limit)
		local strings = {}
		local start = pos
		while (pos - start < limit) do
			local str
			str, pos = read_string(data, pos)
			if not str then
				if debug then
					print("read_strings no string", start, pos, limit)
				end
				return nil, pos
			end
			table.insert(strings, str)
		end
		return strings, pos
	end

	local function read_name(data, pos, poiner, packet_start)
		pos = pos or 1
		local length, err = read_int(data, pos)
		if not length then
			if debug then
				print("read_name no length:", err,  pos, poiner or "", packet_start or "")
			end
			return nil, err
		end
		local name = ""
		local dot = ""
		while (length > 0) do
			if poiner and length >= 192 then
				local point, err = read_int(data, pos + 1)
				if not point then
					if debug then
						print("read_name no point:", err, pos, poiner or "", packet_start or "")
					end
					return nil, err
				end
				point = packet_start + (length - 192) * 256 + point
				local name_part, err = read_name(data, point, poiner, packet_start)
				if not name_part then
					if debug then
						print("read_name no name_part:", err, pos, point,  poiner or "", packet_start or "")
					end
					return nil, err
				end
				return name .. dot .. name_part, pos + 2
			end
		
			name = name .. dot .. data:sub(pos+1, pos+length)
			
			pos = pos + length + 1
			length, err = read_int(data, pos)
			if not length then
				if debug then 
					print("read_name no length:", err, pos, poiner or "", packet_start or "")
				end
				return nil, err
			end
			dot = "."
		end
		return name, pos + 1
	end

	local function read_query(data, pos)
		if #data - pos < 4 then
			if debug then
				print("read_query incomplete data:", #data,  pos)
			end
			return nil, "incomplete data"
		end
		local name
		name, pos = read_name(data, pos)
		if not name or #data - pos < 3 then
			return nil, "incomplete data"
		end
		return {
			name = name,
			type = read_int(data, pos, 2),
			class = read_int(data, pos + 2, 2)
		}, pos + 4
	end

	local function read_answer(data, pos, packet_start)
		local name
		name, pos = read_name(data, pos, true, packet_start)
		if not name then
			if debug then
				print("read_answer no name:", pos, #data)
			end
			return nil, pos
		end
		local data_length, err = read_int(data, pos + 8, 2)
		if not data_length then
			if debug then
				print("read_answer no data_length:", err, pos, #data)
			end
			return nil, err
		end
		if #data - ( pos - 1 + 10 + data_length ) < 0 then
			if debug then
				print("read_answer incomplete data:", #data, pos, data_length, #data - ( pos - 1 + 10 + data_length ))
			end
			return nil, "incomplete data"
		end
		local rtype = read_int(data, pos, 2)
		local ip, ipv6, txt, cname
		if rtype == 1 then
			if #data - (pos - 1 + 10) < 4 then
				if debug then
					print("read_answer incomplete data:", #data, pos, #data - (pos - 1 + 10))
				end
				return nil, "incomplete data"
			end
			ip = read_ip(data, pos + 10)
		elseif rtype == 28 then
			if #data + 1 - (pos - 1 + 10) < 16 then
				if debug then
					print("read_answer incomplete data:", #data, pos, #data + 1 - (pos - 1 + 10))
				end
				return nil, "incomplete data"
			end
			ipv6 = read_ipv6(data, pos + 10)
		elseif rtype == 16 then
			local err
			txt, err = read_strings(data, pos + 10, data_length)
			if not txt then
				if debug then
					print("read_answer no txt:", err, #data, pos + 10)
				end
				return nil, err
			end
		elseif rtype == 5 then
			local err
			cname, err = read_name(data, pos + 10, true, packet_start)
			if not cname then
				if debug then
					print("read_answer no cname:", err, #data, pos + 10)
				end
				return nil, err
			end
		end
		return {
			name = name,
			type = rtype,
			class = read_int(data, pos + 2, 2),
			ttl = read_int(data, pos + 4, 4),
			data_length = data_length,
			data = data:sub(pos + 10, pos + 10 + data_length - 1),
			ip = ip,
			ipv6 = ipv6,
			txt = txt,
			cname = cname
		}, pos + 10 + data_length
	end

	local function insert_answers(dns, key, data, pos, packet_start)
		local count = dns[key]
		if count > 0 then
			dns[key] = {}
		end
		
		for i = 1, count do
			local answer
			answer, pos = read_answer(data, pos, packet_start + 2)
			if not answer then
				if debug then
					print("insert_answers no answer:", pos)
				end
				return nil, pos
			end
			table.insert(dns[key], answer)
		end
		
		return pos
	end
	
	packet_start = packet_start or 1
	local pos = packet_start
	if not data then return nil, "no data" end
	if #data - pos + 1 < 13 then return nil, "incomplete data" end
	local size = read_int(data, pos, 2)
	if size > #data - pos + 1 then return nil, "incomplete data" end
	local queries = read_int(data, pos + 6, 2)

	dns = {
		id = read_int(data, pos + 2, 2),
		flags = read_int(data, pos + 4, 2),
		answers = read_int(data, pos + 8, 2),
		authority_answers = read_int(data, pos + 10, 2),
		additional_answers = read_int(data, pos + 12, 2)
	}

	pos = pos + 14
	
	if queries > 0 then
		dns.queries = {}
	end
	for i = 1, queries do
		local query 
		query, pos = read_query(data, pos)
		if not query then 
			return nil, pos, dns
		end
		table.insert(dns.queries, query)
	end
	
	local err
	pos, err = insert_answers(dns, "answers", data, pos, packet_start)
	if not pos then
		return nil, err, dns
	end
	pos, err = insert_answers(dns, "authority_answers", data, pos, packet_start)
	if not pos then
		return nil, err, dns
	end
	pos, err = insert_answers(dns, "additional_answers", data, pos, packet_start)
	if not pos then
		return nil, err, dns
	end
	
	return dns, pos
end