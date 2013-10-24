require "socket"
require "serialize3"

--OEM866

local url, host, port, path
repeat
	io.write("�ਬ�� URL: http://example.com\n")
	io.write("������ URL: ")
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
print("IP ����.")
print ""
local ip, ip_info = socket.dns.toip(host)

if not ip then
	print("�� 㤠����")
	print(ip_info)
	print("����� DNS �� 8.8.8.8 ����� ������")
	return
end

print(ip, serialize(ip_info))
print ""
print "OK"
print ""

local server, err, good_ip
for index, ip in ipairs(ip_info.ip) do
	print("�஡㥬 ����������� �� ip:", ip)
	server, err = socket.connect(ip, port)
	if server then
		good_ip = ip
		print("OK")
		break
	else
		print(err)
		print"�� ����稫���"
		print""
	end
end

if not server then
	print(err)
	print "��ᯮ������ ���譨� �ப��ࢥ஬ ��� ����������஬."
	return
end



r = string.format([[GET %s HTTP/1.1
Host: %s
Connection: close

]], path, host)

local try = 0
local data, err, part
local msg, description = "0. C⠭����� �����", ""
repeat
	print (msg, description)
	try = try + 1
	
	if try > 1 then
		print "��१ 5 ᥪ㭤 �����"
		socket.sleep(5)
		server, err = socket.connect(good_ip, port)
		if not server then
			print(err)
			print "�� 㤠���� ������ ᮥ�������� � �ࢥ஬."
			return
		end
	end
	
	print "��ࠢ�塞 �����"
	print ""
	print(r)

	local index, err, index2 = server:send(r)

	if err then
		print(err, index2)
		print "�� 㤠���� ��ࠢ��� ����� ���� �� ��ࠢ���� ���筮."
		return
	end

	server:settimeout(20)
	data, err, part = server:receive("*a")
	print((data or part):sub(1, 100))
	print ""
	if not data and err then	
		print(err)
		print"�� 㤠����"
		print ""
	end

			
			
	if try==1 then
		msg = "1. ������� ᫥�"
		description = string.format([[
� ���᭮� ��ப� ��㧥� �����筮 ��᫥ ����� ��� 㢮��� ᫥�(/).
		
http://%s:%s/%s]], host, port, path)
		r = string.format([[
GET /%s HTTP/1.1
Host: %s
Connection: close

]], path, host)
	elseif try==2 then
		msg = "2. C�ࢥ� ��� �ப�"
		description = string.format([[
� ��㧥� � ����⢥ �ப� �ࢥ� ��� ��� ����室��� 㪠���� ip � ���� ���. 

%s %s]], ip, port)
		
		r = string.format([[
GET %s HTTP/1.1
Host: %s
Connection: close

]], url, host)
	elseif try==3 then
		msg = "3. Host �� host"
		description = string.format([[
� ������ ��砥 �ப��ࢥ� ����� 奤��
Host: %s
�� 
host: %s]], host, host)
		r = string.format([[
GET %s HTTP/1.1
host: %s
Connection: close

]], path, host)
	end
	server:close()
until  try >= 4
	