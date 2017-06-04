require "socket"

local cors = {}
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
			end
		end
		local new_list = {}
		for id, cor in ipairs(cors) do
			local ok, err = coroutine.resume(cor)
			if (ok) then
				table.insert(new_list, cor)
			end
		end
		cors = new_list
		socket.sleep(0.001) -- Чтоб не сильно нагружать процессор
	until accept_err and (accept_err ~= "timeout")
end

function connect_to(host, port)
	local server = socket.tcp()
	server:settimeout(0)
	local connected = server:connect(host, port)
	if not connected then
		repeat
			local _, ready = socket.select({}, {server}, 0)
			if #ready > 0 then
				return server
			end
			coroutine.yield() -- Даём скрипту обработать другие подключения
		until false
	else
		return server
	end
end


direct_hosts={}

-- Читаем хедеры и соединяемся с конечным сайтом сквозь фильтрующий прокси
function new_client(client)
	client:settimeout(0)
	local headers, err = get_data(client:receive("*a"))
	local host, port = get_host_port(headers)
	--headers = headers:gsub("( HTTP/1.1)\13(\10Host: )", "%1%2")
	if not (host and port) then client:close(); return end
	
	print("address:", host, port)
	local server = connect_to(host, port)
	
	if ( server and headers:sub(1,8) == "CONNECT ") then
		client:send(
[[HTTP/1.1 200 Connection established
Proxy-agent: Lua-Proxy/1.1]].."\n\n"
		)
		print("CONNECT DETECTED")
		print("headers:", headers)
		headers = "";
	elseif( server ) then
		print("headers:", headers)
	else
		client:close()
		return
	end

	if (server) then
		-- if (not direct_hosts[host]) or (os.difftime(os.time(), direct_hosts[host]) > 10) then
			-- if (not send_connect(server, string.format("%s:%s", socket.dns.toip(host), port))) then
				-- server:close()
				-- print("DIRECT", host, port)
				-- direct_hosts[host] = os.time();
				-- server = socket.connect(host, port)
			-- end
		-- end
		if (server) then
			headers = headers:gsub("\10Connection%: keep%-alive\13\10", "\10Connection: close\13\10")

			local host_split = headers:find("Host:", 1, true)
			if host_split then
				print("host_split: ", host_split)
				split_send(headers, server, host_split+2)
			else
				server:send(headers)
			end

			
			cycle_data(server, client, host)
		end
	end
	print("CLOSED", host, port)
	server:close()
	client:close()
end

function split_send(data, socket, ...)
	local positions = {...}
	local from = 1
	for i, pos in ipairs( positions ) do
		socket:send(data, from, pos)
		from = pos + 1
	end
	socket:send(data, from)
end

function get_data(data, err, part, marker)
	data = (data or part)
	return data, err
end

function get_host_port(headers)
	if headers and (#headers > 0) then
		if not (headers:find("\13\10Host: ", 1, true)) then
			return
		end
		local _, _, host, port = headers:find("\13\10Host: ([a-z0-9%.%-]+):?([0-9]*)\13\10")
		if (#port > 0) then
			port = tonumber(port)
		else
			port = 80
		end
		return host, port
	end
end

-- Используем метод CONNECT который превращает фильтрующий прокси в TCP трубу
local connect = "CONNECT %s HTTP/1.1\13\10Host: %s\13\10\13\10"
function send_connect(server, address)
	server:send(string.format(connect, address, address))
	server:settimeout(0)
	local headers, err = get_data(server:receive("*a"))
	while ((not headers) or (#headers <= 12)) and not (err and (err ~= "timeout")) do
		coroutine.yield() -- Даём скрипту обработать другие подключения
		local data, err = get_data(server:receive("*a"))
		if (data and #data > 0) then
			headers = (headers or "") .. data
		end
	end
	print ("send_connect", headers)
	return headers:find("^HTTP/1.[01] 200")
end

-- Пересылаем данные в обе стороны

function cycle_data(server, client, host, port)
	local _in_, out = server, client
	local receive_err, send_err, data, index
	repeat
		_in_:settimeout(0)
		out:settimeout(1)
		
		data, receive_err = get_data(_in_:receive("*a"))

		if data and (#data > 0) then
			--data = data:gsub("\13\10Connection%: keep%-alive\13\10", "\13\10Connection: close\13\10")
			index, send_err = send_data(out, data)
		end
		coroutine.yield() -- Даём скрипту обработать другие подключения
		_in_, out = out, _in_
		
	until (receive_err and (receive_err ~= "timeout")) or (send_err and (send_err ~= "timeout"))
	print("cycle:", receive_err, send_err)
end

function send_data(out, data)
	local index = 0
	repeat
		index = index +1
		index, err = get_index(out:send(data, index))
		local all_sended = index >= #data or (err and (err ~= "timeout"))
		if not(all_sended) then
			print ("index:", index)
			coroutine.yield() -- Даём скрипту обработать другие подключения
		end
	until all_sended
	
	return index, err
end

function get_index(index, err, partial_index)
	return (index or partial_index), err
end

main()