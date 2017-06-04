require "socket"
require "serialize3"
require "lua-dns"

local cors = {}
local cors_id = {}
local last_id = 1
local dns_cache = {}

print_old = print

function reset_coroutine_index(co)
	if cors_id[co] then
		cors_id[co] = nil
	end
end

function get_coroutine_index(co)
	if not co then co = coroutine.running() end
	if co then
		local index = cors_id[co]
		if not index then
			index = last_id
			cors_id[co] = last_id
			last_id = last_id + 1
		end
		return index
	else
		return 0
	end
end

function print(...)
	print_old(get_coroutine_index(), ...)
end

function temp_print(...)
	io.stdout:write(get_coroutine_index(), "\t")
	io.stdout:write(table.concat({...},"\t"))
	io.stdout:write("\r")
end

function new_client(client)

	local address
	local ip -- v4 or v6

	local function get_data(data, err, part, marker)
		data = (data or part)
		return data, err
	end

	local function connect_to(host, port, timeout)
		if not (host and port) then
			return
		end
		timeout = timeout or 60
		local server = socket.tcp()
		server:settimeout(0.001)
		local connected, err = server:connect(host, port)
		if not connected then
			if err == "timeout" then
				local start_time = socket.gettime()
				repeat
					coroutine.yield() -- Даём скрипту обработать другие подключения
					local _, ready = socket.select(nil, {server}, 0)
					if ready[server] then
						return server
					end
					if (socket.gettime() - start_time >= timeout) then
						print("err connect to", host, "timeout", timeout)
						break
					end
				until false
			else
				print("err connect to", host, err)
			end
		else
			return server
		end
	end

	local function get_index(index, err, partial_index)
		return (index or partial_index), err
	end

	local function send_data(out, data, index, stop, timeout)
		timeout = timeout or 0.001
		out:settimeout(timeout)
		if not index then index = 1 end
		if not stop then stop = #data end
		repeat
			
			index, err = get_index(out:send(data, index, stop))
			local all_sended = index >= stop or (err and (err ~= "timeout"))
			if not(all_sended) then
				coroutine.yield() -- Даём скрипту обработать другие подключения
			end
		until all_sended
		
		return index, err
	end

	local function split_send(out, data, ...)
		local positions = {...}
		local from = 1
		for i, to in ipairs( positions ) do
			--print("split:", to)
			send_data(out, data, from, to, 1)
			from = to + 1
			--socket.sleep(0.1)
			local t = socket.gettime()
			while (socket.gettime() - t < 0.1) do
				coroutine.yield()
			end
		end
		send_data(out, data, from)
	end
	
	local function filtred(out, data)
		
		local split_pos = {}
		
		local _, host_pos = data:find("Host:", 1, true)
		if (host_pos) then
			table.insert(split_pos, host_pos)
			local line_end = data:find("[\n\r]", host_pos)
			print("Host detected:", data:sub(host_pos+1, line_end-1))
		end
		
		local start_index = 1
		repeat
			local address_pos, address_pose = data:find(address, start_index, true)
			if start_index == 1 and address_pos then
				if host_pos then
					data = data:gsub("Host:", "HOST:", 1)
				end
			end
			if (address_pos) then
				table.insert(split_pos, address_pos + math.floor(#address / 2))
				table.insert(split_pos, address_pos + #address)
				print("Address detected:", address, address_pos)
				start_index = address_pose
			end
		until (not address_pos)
		
		if (#split_pos > 0) then
			split_send(out, data, unpack(split_pos))
			return true 
		end

		return false
	end

	local function cycle_data(client, server)
		local _in_, out = client, server
		local stat = {}
		local receive_err, send_err, data, index
		repeat
			_in_:settimeout(0)
			data, receive_err = get_data(_in_:receive("*a"))

			if data and (#data > 0) then
				stat[_in_] = (stat[_in_] or 0) + #data 
				temp_print(address ,stat[client], stat[server])
				if _in_ == server or not filtred( out, data ) then
					index, send_err = send_data(out, data)
				end
			end
			coroutine.yield() -- Даём скрипту обработать другие подключения
			_in_, out = out, _in_
			
		until (receive_err and (receive_err ~= "timeout")) or (send_err and (send_err ~= "timeout"))
		
	end

	local function wait_for_data(_in_, check, start, plain)
		local buf, err
		local part
		repeat
			_in_:settimeout(0.001)
			part, err = get_data(_in_:receive("*a"))
			if part and #part > 0 then
				buf = (buf or "")..part
			
				if check and type(check) == "number" then
					if #buf >= check then
						return buf
					end
				elseif check and type(check) == "string" then
					local res = {buf:find(check, start, plain)}
					if res[1] then 
						return buf, unpack(res)
					end
				elseif check and type(check) == "function" then
					local res = {check(buf)}
					if res[1] then
						return buf, unpack(res)
					end
				else
					if #buf > 0 then
						return buf
					end
				end
			end
			coroutine.yield() -- Даём скрипту обработать другие подключения
		until (err and (err ~= "timeout"))
		
		return nil, err, buf
	end
	
	local function to_ip(name, dns_address, dns_port)
		dns_address = dns_address or "8.8.8.8"
		dns_port = dns_port or 53
		print("to ip:", name)
		if name:find(":") then -- ipv6
			print("this ipv6")
			return name
		elseif name:find("^[0-9.]+$") then -- ipv4
			print("this ipv4")
			return name
		elseif name:find("^[0-9a-zA-Z-_.]+$") then
			if name:sub(#name) == "." then
				name = name:sub(1, #name - 1)
			end
			function get_ip(name, dns_packet)
				for _, answer in pairs(dns_packet.answers) do
					if os.difftime(os.time(), dns_packet.time) <= answer.ttl and
					   answer.name == name then
						if answer.ip and answer.type == 1 then
							return answer.ip
						elseif answer.cname and answer.type == 5 then
							return get_ip(answer.cname, dns_packet)
						end
					end
				end
			end
			if dns_cache[name] then
				print("cached:", name)
				cached = dns_cache[name]
				local ip = get_ip(name, cached)
				if ip then
					print("resolved from cache:", name, ip)
					return ip
				end
			end
		
			local dns_server = connect_to(dns_address, dns_port)
			if not dns_server then return end
			print("dns connected:", dns_address, dns_port)
			dns_server:send(tcp_dns_request_pack(name, 1))
			print("resolving:", name)
			local data, parsed, part = wait_for_data(dns_server, tcp_dns_parse)
			if not data then
				print("no valid data from dns:", parsed, serialize(part))
				return 
			end
			dns_server:close()
			print("resolving:", name, #data)
			print("resolving:", name, serialize(parsed))
			parsed.time = os.time()
			local ip = get_ip(name, parsed)
			if ip then 
				dns_cache[name] = parsed
				print("resolved:", name, ip)
				return	ip
			end
			print("no ip found for:", serialize(name))
		else
			print("this not domain name: ", serialize(name))
		end
	end

	if not client then return end

	print "new client"
	client:settimeout(0)
	local header, err = wait_for_data(client, 2)
	if not header then
		print("no header from client:", err)
		client:close()
		return
	end
	
	-- Версия socks протокола должна быть 5
	if ( header:byte(1) ~= 5 ) then
		print("wrong wersion: ", safe_string(header), safe_string(err))
		client:close()
		return
	end
	
	-- Количество методов авторизации
	local autority_count = header:byte(2)
	if ( #header < autority_count + 2 ) then
		print("partial data: ", autority_count + 2, #header)
		client:close()
		return
	else
		print("autority count:", autority_count)
	end
	
	-- Есть ли в списке "Без авторизации"
	if ( header:find("\0", 1, true) ) then
		print("'no autority' found")
	else
		print("'no autority' not found")
		client:close()
		return
	end
	
	client:send("\5\0")
	header, err = wait_for_data(client, 8)
	if not header then
		print("no header from client:", err)
		client:close()
		return
	end
	
	-- Принимаем запросы только на TCP/IP соеденение
	if ( header:sub(1,3) == "\5\1\0" ) then
		print("tcp connection request")
	else
		print("wrong responce: ", #header, header)
		client:close()
		return
	end
	
	local next_pos
	if ( header:byte(4) == 1 ) then -- IPv4
		address = string.format("%s.%s.%s.%s", header:byte(5,8))
		ip = address
		print("ipv4:", address)
		next_pos = 9
	elseif ( header:byte(4) == 3 ) then -- [len] domain
		address = header:sub(6, 6 + header:byte(5) - 1)
		print("domain:", address)
		next_pos = 6 + header:byte(5)
	elseif ( header:byte(4) == 4 ) then
		address = string.format("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", header:byte(5,20))
		ip = address
		print("ipv6:", address)
		next_pos = 21
	end
	
	local port = header:byte(next_pos) * 256 + header:byte(next_pos + 1)
	print("port:", port)
	
	ip = ip or to_ip(address)
	local server = connect_to(ip, port)
	if (server) then
		client:send("\5\0\0\1\0\0\0\0\0\0")
		print("conected to:", address, port)
		cycle_data(client, server)

		print("stats server:", server:getpeername(), server:getstats())
		
		server:close()
	else
		client:send("\5\0\0\4\0\0\0\0\0\0")
		print("not conected to:", address, port)
	end
	
	print("stats client:", client:getpeername(), client:getstats())
	
	client:close()
	print("closed:", address, port)
end

function main()
	local proxy_bind = socket.tcp()
	proxy_bind:setoption("reuseaddr", true) -- На всякий случай
	proxy_bind:bind("localhost", 8080) -- Принимаем подключения только от локального клиента
	proxy_bind:listen(100) -- 100 подключений в очереди
	proxy_bind:settimeout(0) -- 0s Позволяет не задерживаться ожидая данных и забрать из буфера сразу всё.
	repeat -- Главный цикл который принимает подключения
		local client, accept_err = proxy_bind:accept()
		if (client) then
			local new_cor = coroutine.create(new_client)
			local ok, err = coroutine.resume(new_cor, client)
			if (ok) then
				table.insert(cors, new_cor)
			else
				print(get_coroutine_index(cor), err)
				reset_coroutine_index(cor)
			end
		end
		local new_list = {}
		for id, cor in ipairs(cors) do
			local ok, err = coroutine.resume(cor)
			if (ok) then
				table.insert(new_list, cor)
			else
				print(get_coroutine_index(cor), err)
				reset_coroutine_index(cor)
			end
		end
		cors = new_list
		socket.sleep(0.001) -- Чтоб не сильно нагружать процессор
	until accept_err and (accept_err ~= "timeout")
end

main()