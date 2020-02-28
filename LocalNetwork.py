import sys
import os
import subprocess
import socket
import netifaces
import platform

class LocalNetwork:

	def __init__( self ):
		self.map = {}
		self.platform = platform.system()
		self.GetCurrentIPAddress()
		self.GetInterfaces()
		self.GetGateWays()
		self.NMAPAllGateWays()
		self.ARPAllInterfaces()

	def GetCurrentIPAddress( self ):
		# https://stackoverflow.com/a/28950776
		s = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
		try:
			s.connect( ( '10.255.255.255' , 1 ) )
			IP = s.getsockname()[ 0 ]
		except:
			IP = '127.0.0.1'
		finally:
			s.close()
		self.map[ "current_ip" ] = IP

	def GetInterfaces( self ):
		interfaces = netifaces.interfaces()
		self.map[ "interfaces" ] = {}
		for index , interface in enumerate( interfaces ):
			self.map[ "interfaces" ][ str( interface ) ] = {}

	def GetGateWays( self ):
		gateways = netifaces.gateways()
		for index , gateway in enumerate( gateways ):
			for index_item , item in enumerate( gateways[ gateway ] ):
				if isinstance( item , tuple ):
					if item[ 1 ] in self.map[ "interfaces" ]:
						self.map[ "interfaces" ][ str( item[ 1 ] ) ][ "gateway_ip" ] = item[ 0 ]
						self.map[ "interfaces" ][ str( item[ 1 ] ) ][ "ips" ] = {}

	def NMAPAllGateWays( self ):
		# AKA a Network "Probe"
		if self.platform == "Linux":
			pass
		elif self.platform == "Darwin":
			for index , interface in enumerate( self.map[ "interfaces"] ):
				if "gateway_ip" in self.map[ "interfaces" ][ interface ]:
					print( "Maping " + interface )
					#shell_command = "nmap -sP " + self.map[ "interfaces" ][ interface ][ "gateway_ip" ] +"/24"
					#result = os.system( shell_command )
					#result = os.popen( shell_command )
					#result = subprocess.check_output([ "nmap" , "-sP" , self.map[ "interfaces" ][ interface ][ "gateway_ip" ] +"/24" ] )
					#print( result )
					shell_command = [ "nmap" , "-sP" , self.map[ "interfaces" ][ interface ][ "gateway_ip" ] + "/24" ]
					result = subprocess.run( shell_command , capture_output=True , universal_newlines=True )
					#print( result.returncode, result.stdout, result.stderr )
		elif self.platform == "Windows":
			pass
		else:
			sys.exit( 1 )

	def ARPAllInterfaces( self ):
		if self.platform == "Linux":
			pass
		elif self.platform == "Darwin":
			for index , interface in enumerate( self.map[ "interfaces"] ):
				if "gateway_ip" in self.map[ "interfaces" ][ interface ]:
					shell_command = [ "arp" , "-na" , "-i" , interface ]
					result = subprocess.run( shell_command , capture_output=True , universal_newlines=True )
					lines = result.stdout.split( "\n" )
					for index , line in enumerate( lines ):
						#print( str( index ) + " === " + line )
						if "incomplete" in line:
							continue
						if len( line ) < 3:
							continue
						mac_address = line.split( "at " )
						if len( mac_address ) < 1:
							continue
						mac_address = mac_address[ 1 ].split( " on" )
						if ( len( mac_address ) < 1 ):
							continue
						line_interface = mac_address[ 1 ].strip()
						mac_address = mac_address[ 0 ].strip()
						line_interface = line_interface.split( " ifscope" )
						if len( line_interface ) < 1:
							continue
						line_interface = line_interface[ 0 ]
						ip = line[ line.find( "(" ) + 1 : line.find( ")" ) ]
						# print( mac_address )
						# print( line_interface )
						# print( ip )
						self.map[ "interfaces" ][ line_interface ][ "ips" ][ ip ] = { "mac_address": mac_address }
		elif self.platform == "Windows":
			pass
		else:
			sys.exit( 1 )

	def GetIPFromMacAddress( self , mac_address ):
		for index , interface in enumerate( self.map[ "interfaces"] ):
			if "ips" in self.map[ "interfaces" ][ interface ]:
				for index_ip , ip in enumerate( self.map[ "interfaces" ][ interface ][ "ips" ] ):
					if "mac_address" in self.map[ "interfaces" ][ interface ][ "ips" ][ ip ]:
						if mac_address == self.map[ "interfaces" ][ interface ][ "ips" ][ ip ][ "mac_address" ]:
							return ip

if __name__ == '__main__':
	LocalNetwork = LocalNetwork()
	#print( LocalNetwork.map )
	ChromeCastIP = LocalNetwork.GetIPFromMacAddress( "f0:ef:86:9:c3:30" )
	print( ChromeCastIP )