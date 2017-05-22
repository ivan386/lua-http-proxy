require "socket"

local cors = {}


function get_data(data, err, part, marker)
	data = (data or part)
	return data, err
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

function get_index(index, err, partial_index)
	return (index or partial_index), err
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

function cycle_data(server, client)
	local _in_, out = server, client
	local receive_err, send_err, data, index
	repeat
		_in_:settimeout(0)
		out:settimeout(1)
		
		data, receive_err = get_data(_in_:receive("*a"))

		if data and (#data > 0) then
			index, send_err = send_data(out, data)
		end
		coroutine.yield() -- Даём скрипту обработать другие подключения
		_in_, out = out, _in_
		
	until (receive_err and (receive_err ~= "timeout")) or (send_err and (send_err ~= "timeout"))
	print("cycle:", receive_err, send_err)
end

function new_client(client)
	client:settimeout(0.3)
    local header = get_data(client:receive("*a"))
    if ( header:byte(1) ~= 5 ) then
        print("wrong wersion: ", header:byte(1))
        client:close()
        return
    end
    local autority_count = header:byte(2)
    if ( #header < autority_count + 2 ) then
        print("partial data: ", autority_count + 2, #header)
        client:close()
        return
    else
        print("count:", autority_count)
    end
    
    if ( header:find("\0", 1, true) ) then
        print("no autority found")
    end
    client:send("\5\0")
    header = get_data(client:receive("*a"))
    
    if ( header:sub(1,3) == "\5\1\0" ) then
        
    else
        print("wrong responce: ", #header, header)
        client:close()
    end
    
    local address
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
        print("ipv6")
        next_pos = 20
    end
    
    local port = header:byte(next_pos) * 256 + header:byte(next_pos + 1)
    print("port:", port)
    
    local server = connect_to(address, port)
    if (server) then
        client:send("\5\0\0\1\0\0\0\0\0\0")
        print("conected to:", address, port)
        cycle_data(client, server)
        server:close()
    else
        client:send("\5\0\0\4\0\0\0\0\0\0")
        print("not conected to:", address, port)
    end
    
    client:close()
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
 
 main()