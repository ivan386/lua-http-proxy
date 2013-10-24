require "socket"
require "serialize3"

--OEM866

local url, host, port, path
repeat
	io.write("Пример URL: http://example.com\n")
	io.write("Введите URL: ")
	url = io.read("*l")
	_, _, host, port, path = url:find("http://([a-z0-9%.]+):?([0-9]*)(.*)")
	
until host

port = tonumber((#port > 0 and port) or 80)
if not (#path > 0) then
	path = "/"
end 

print("Host: ", host)
print("Port: ", port)
print("Path: ", path)
print""
print("IP адрес.")
print ""
local ip, ip_info = socket.dns.toip(host)

if not ip then
	print("Не удалось")
	print(ip_info)
	print("Смена DNS на 8.8.8.8 может помочь")
	return
end

print(ip, serialize(ip_info))
print ""
print "OK"
print ""

local server, err, good_ip
for index, ip in ipairs(ip_info.ip) do
	print("Пробуем подключиться по ip:", ip)
	server, err = socket.connect(ip, port)
	if server then
		good_ip = ip
		print("OK")
		break
	else
		print(err)
		print"Не получилось"
		print""
	end
end

if not server then
	print(err)
	print "Воспользуйтесь внешним проксисервером или анонимайзером."
	return
end



r = string.format([[GET %s HTTP/1.1
Host: %s
Connection: close

]], path, host)

local try = 0
local data, err, part
local msg, description = "0. Cтандартный запрос", ""
repeat
	print (msg, description)
	try = try + 1
	
	if try > 1 then
		print "Через 5 секунд повтор"
		socket.sleep(5)
		server, err = socket.connect(good_ip, port)
		if not server then
			print(err)
			print "Не удалось заново соедениться с сервером."
			return
		end
	end
	
	print "Отправляем запрос"
	print ""
	print(r)

	local index, err, index2 = server:send(r)

	if err then
		print(err, index2)
		print "Не удалось отправить запрос либо он отправился частично."
		return
	end

	server:settimeout(20)
	data, err, part = server:receive("*a")
	print((data or part):sub(1, 100))
	print ""
	if not data and err then	
		print(err)
		print"Не удалось"
		print ""
	end

			
			
	if try==1 then
		msg = "1. Двойной слеш"
		description = string.format([[
В адресной строке браузера достаточно после имени хоста увоить слеш(/).
		
http://%s:%s/%s]], host, port, path)
		r = string.format([[
GET /%s HTTP/1.1
Host: %s
Connection: close

]], path, host)
	elseif try==2 then
		msg = "2. Cервер как прокси"
		description = string.format([[
В браузере в качестве прокси сервера для хоста необходимо указать ip и порт хоста. 

%s %s]], ip, port)
		
		r = string.format([[
GET %s HTTP/1.1
Host: %s
Connection: close

]], url, host)
	elseif try==3 then
		msg = "3. Host на host"
		description = string.format([[
В данном случае проксисервер меняет хедер
Host: %s
на 
host: %s]], host, host)
		r = string.format([[
GET %s HTTP/1.1
host: %s
Connection: close

]], path, host)
	end
	server:close()
until  try >= 4
	