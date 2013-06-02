![Skanda Screenshot 1](https://raw.github.com/jayeshchauhan/SKANDA/master/Skanda.JPG)
[OWASP Skanda - SSRF Exploitation Framework v0.1](owasp.org/index.php/OWASP_Skanda_SSRF_Exploitation_Framework)
==========================================

About
=====
Skanda scans the ports on the server, using SSRF vulnerability. Select any SSRF vulnerable request in [IronWASP](http://ironwasp.org/) logs, right click and run this module. Select the vulnerable injection points(GET/POST parameters) and session plugins if any are required. Port Status will be printed in the CLI.
This first version is able to do port scan of the server. Future versions will able to scan and exploit the intranet of the vulnerable server.

Features
========
* Exploits SSRF vulnerability.
* Specially crafted payloads.
* Does a port scan on the vulnerable server and list out the ports.
* Error and time delay based analysis of payloads results in port status.
* Port Status : 
  * **Closed**: where the port is closed.
  * **Open**: the port status is determined based on the error message received when connecting to the port.
  * **Open (Blind XSPA)**: The port status is determined based on the response time. 
* Skanda also gives the user the ability to customize the scan.
* Instead of running the scan for all the ports, user can make the scan, port specific.

How to use
==========

* [Here] (https://github.com/jayeshchauhan/SKANDA/blob/master/Skanda.docx)is an article written by me, to use Skanda efficiently.
