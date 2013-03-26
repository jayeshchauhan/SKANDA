req = Request.FromProxyLog(1)
f = Fuzzer.FromUi(req)


f.Reset()

timed_out_ports = []
non_res_ports = []
avg_res_time = (req.Send().RoundTrip + req.Send().RoundTrip + req.Send().RoundTrip)/3
timeout = avg_res_time + 5000

def port_scan(to_be_scanned,timeout,port_array):
  	for port in to_be_scanned:
			print "g"
			payload = "http://localhost:" +  str(port)
			try:
				res = f.Inject(payload,timeout)
				print "h"
			except:
				print str(port) + " timed out"
				port_array.append(port)
				continue
			if Tools.DiffLevel(res.BodyString,res_1.BodyString) <= 12:
				print str(port) + " is closed"
			else:
				print str(port) + " is open"
				
while f.HasMore():
	f.Next()
	print "A"
	res_1 = f.Inject("http://localhost:1")
	print "b"
	res_2 = f.Inject("http://localhost:2")
	print "c"
	if Tools.DiffLevel(res_1.BodyString,res_2.BodyString) <= 12:
		print "d"
		print "port 1 & 2 are closed"
	else:
		print "e"
		print "response from port 1 & 2 don't match"
	
	ports = [22, 23, 25, 80, 443, 3306]
	print "f"
	#scan and store the ports which are timed out.
	port_scan(ports,timeout,timed_out_ports)
	try:
		print "try block"
		port_scan(timed_out_ports,timeout,non_res_ports)
	except:
		print "Scan Complete"
	
	
