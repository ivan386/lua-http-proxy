require "socket"
require "serialize3"

local cors = {}
local cors_id = {}
local last_id = 1

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

	local function get_data(data, err, part, marker)
		data = (data or part)
		return data, err
	end

	local function connect_to(host, port)
		local server = socket.tcp()
		server:settimeout(0)
		local connected = server:connect(host, port)
		if not connected then
			repeat
				coroutine.yield() -- Даём скрипту обработать другие подключения
				local _, ready = socket.select({}, {server}, 0)
				if #ready > 0 then
					return server
				end
			until false
		else
			return server
		end
	end

	local function get_index(index, err, partial_index)
		return (index or partial_index), err
	end

	local function send_data(out, data, index, stop)
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

	local function split_send(socket, data, ...)
		local positions = {...}
		local from = 1
		for i, to in ipairs( positions ) do
			send_data(socket, data, from, to)
			from = to + 1
		end
		send_data(socket, data, from)
	end

	local function filtred(out, data)
		
		
		local split_pos = {}
		
		local _, host_pos = data:find("Host:", 1, true)
		if (host_pos) then
			--table.insert(split_pos, host_pos)
			local line_end = data:find("[\n\r]", host_pos)
			print("Host detected:", data:sub(host_pos+1, line_end-1))
		end
		
		local start_index = 1
		repeat
			local address_pos, address_pose = data:find(address, start_index, true)
			if (address_pos) then
				table.insert(split_pos, address_pos + math.floor(#address / 2))
				print("Address detected:", address, address_pos, address_pos + math.floor(#address / 2))
				start_index = address_pose
			end
		until (not address_pos)
		
		if (#split_pos > 0) then
			split_send(out, data, host_pos, address_pos)
			return true 
		end

		return false
	end

	local function cycle_data(server, client)
		local _in_, out = server, client
		local receive_err, send_err, data, index
		repeat
			_in_:settimeout(0)
			out:settimeout(0.1)
			
			data, receive_err = get_data(_in_:receive("*a"))

			if data and (#data > 0) then
				temp_print(#data)
				if not filtred( out, data ) then
					index, send_err = send_data(out, data)
				end
			end
			coroutine.yield() -- Даём скрипту обработать другие подключения
			_in_, out = out, _in_
			
		until (receive_err and (receive_err ~= "timeout")) or (send_err and (send_err ~= "timeout"))
		
	end

	local function wait_for_data(_in_, min_count)
		local buf, err = ""
		local part
		repeat
			part, err = get_data(_in_:receive("*a"))
			if part and #part > 0 then
				buf = buf..part
			end
		until (#buf >= min_count or (err and (err ~= "timeout")))
		
		return buf, err
	end

	if not client then return end

	print "new client"
	client:settimeout(0)
	local header, err = wait_for_data(client, 2)
	
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
	header = wait_for_data(client, 8)
	
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
		address = string.format("%s.%s.%s.%s", header:byte(5,6,7,8))
		print("ipv4:", address)
		next_pos = 9
	elseif ( header:byte(4) == 3 ) then -- [len] domain
		address = header:sub(6, 6 + header:byte(5) - 1)
		print("domain:", address)
		next_pos = 6 + header:byte(5)
	elseif ( header:byte(4) == 4 ) then
		address = string.format("%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x", header:byte(5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20))
		print("ipv6")
		next_pos = 21
	end
	
	local port = header:byte(next_pos) * 256 + header:byte(next_pos + 1)
	print("port:", port)
	
	local server = connect_to(address, port)
	if (server) then
		client:send("\5\0\0\1\0\0\0\0\0\0")
		print("conected to:", address, port)
		cycle_data(client, server)

		print("stats srv:", server:getpeername(), server:getstats())

		server:close()
	else
		client:send("\5\0\0\4\0\0\0\0\0\0")
		print("not conected to:", address, port)
	end
	
	print("stats clt:", client:getpeername(), client:getstats())
	
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
				reset_coroutine_index(cor)
			end
		end
		local new_list = {}
		for id, cor in ipairs(cors) do
			local ok, err = coroutine.resume(cor)
			if (ok) then
				table.insert(new_list, cor)
			else
				reset_coroutine_index(cor)
			end
		end
		cors = new_list
		socket.sleep(0.001) -- Чтоб не сильно нагружать процессор
	until accept_err and (accept_err ~= "timeout")
end

main()