require "socket"

local dns_cache = {
	
}

function to_ip(host)
	if not dns_cache[host] then
		return socket.dns.toip(host)
	end
	return dns_cache[host] 
end

function get_data(data, err, part)
	--if err then print(err) end
	return (data or part), err
end

function get_headers(_in_)
	local headers, end_index = ""
	repeat
		data, err = get_data(_in_:receive("*a"))
		if (err and (err ~= "timeout")) then
			_in_:close()
			return
		end
		if data then
			headers = headers..data
			end_index = headers:find("\r\n\r\n", 1, true)
			if end_index then
				break
			end
		end
		coroutine.yield()
	until false
	return headers, end_index
end

function send_data(out, data)
	local index = 0
	repeat
		index = index +1
		index, err = get_data(out:send(data, index))
	until index == #data or (err and (err ~= "timeout"))
end

function cycle_data(p, tp)
	local _in_, out = p, tp
	repeat
		_in_:settimeout(0)
		local data, err = get_data(_in_:receive("*a"))
		if data and (#data > 0) then
			out:settimeout(1)
			send_data(out, data) 
		end
		_in_, out = out, _in_
		coroutine.yield()
	until err and (err ~= "timeout")
end
local hard_replace = true

function new_client(client)
	client:settimeout(0)
	local data, err 
	local headers, end_index = get_headers(client)
	local hots, path

	if headers then
		local path_st, path_en
		path_st, path_en, method, path = headers:find("([PpGg][OoEe][SsTt][Tt]?)%s([^%s]+)")
		_, _, host = headers:find("\r\n[Hh][Oo][Ss][Tt]:%s([^%s]+)%s")
		local _, end_idx = path:find(host, 1, true)
		if end_idx then
			start_idx, end_idx = path:find("/", end_idx)
			local new_path = path:sub(end_idx)
			if hard_replace then
				headers = string.format("%s %s HTTP/1.0\r\nHost: %s", method, new_path, host,headers:sub(end_index))
			else
				headers = string.format("%s %s%s", method, new_path, headers:sub(path_en+1))
			end
			
		end
		headers = headers:gsub("\r\nHost: ", "\r\nhost: ") --antifilter
	else
		return
	end
	
	if path and host then
		print(headers)
		local server = socket.connect(to_ip(host), 80)
		if server then
			server:send(headers)
			cycle_data(server, client)
			server:close()
		end
	end
	client:close()
end

local cors = {}
function main()
	local proxy_bind = socket.tcp()
	proxy_bind:setoption("reuseaddr", true)
	proxy_bind:bind("localhost", 80)
	proxy_bind:listen(100)
	proxy_bind:settimeout(0)
	while true do
		local client = proxy_bind:accept()
		if client then
			local new_cor = coroutine.create(new_client)
			local ok, err = coroutine.resume(new_cor, client)
			if ok then
				table.insert(cors, new_cor)
			end
		end
		local new_list = {}
		for id, cor in ipairs(cors) do
			local ok, err = coroutine.resume(cor)
			if ok then
				table.insert(new_list, cor)
			end
		end
		cors = new_list
	end
end

local mainco = coroutine.create(main)
local ok, err = coroutine.resume(mainco)
if not ok then
	print(debug.traceback(mainco, err))
end