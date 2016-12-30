#Headers
import sys
import pdb
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.link import TCLink	

#Function converts decimal value to corresponding 16 hex length dpid
def int2dpid( dpid ):
   try:
      dpid = hex( dpid )[ 2: ]
      dpid = '0' * ( 16 - len( dpid ) ) + dpid
      return dpid
   except IndexError:
      raise Exception( 'Unable to derive default datapath ID - '
                       'please either specify a dpid or use a '
               'canonical switch name such as s23.' )

#Main Topology class
class MyTopo( Topo ):

	def __init__( self ):
		Topo.__init__( self )
		
	#Devices

		#Hosts
		h1=self.addHost('h1', ip='100.0.0.10/24', defaultRoute = "via 100.0.0.1" )
		h2=self.addHost('h2', ip='100.0.0.11/24', defaultRoute = "via 100.0.0.1" )
		h3=self.addHost('h3', ip='10.0.0.50/24', defaultRoute = "via 10.0.0.1" )
		h4=self.addHost('h4', ip='10.0.0.51/24', defaultRoute = "via 10.0.0.1" )
		
		#DNS servers
		ds1=self.addHost('h5', ip='100.0.0.20/24')
		ds2=self.addHost('h6', ip='100.0.0.21/24')
		ds3=self.addHost('h7', ip='100.0.0.22/24')

		#Web Servers
		ws1=self.addHost('h8', ip='100.0.0.40/24')
		ws2=self.addHost('h9', ip='100.0.0.41/24')
		ws3=self.addHost('h10', ip='100.0.0.42/24')

		#Malicious packet logger
		insp=self.addHost('h11',ip='100.0.0.30/24', mac = '06:01:01:01:01:03')
	
		#Learning Switches
		sw1=self.addSwitch('s1', dpid=int2dpid(1))
		sw2=self.addSwitch('s2', dpid=int2dpid(2))
		sw3=self.addSwitch('s3', dpid=int2dpid(3))
		sw4=self.addSwitch('s4', dpid=int2dpid(4))
		sw5=self.addSwitch('s5', dpid=int2dpid(5))

		#Firewall Switches
		fw1=self.addSwitch('s6', dpid=int2dpid(6))
		fw2=self.addSwitch('s7', dpid=int2dpid(7))

		#NAPT Switch	
		napt=self.addSwitch('s8', dpid=int2dpid(8))

		#Load Balancer Switches
		lb1=self.addSwitch('s9', dpid=int2dpid(9))
		lb2=self.addSwitch('s10', dpid=int2dpid(10))

		#Malicious packet inspector
		ids=self.addSwitch('s11', dpid=int2dpid(11))
		
	#Connections

		#SW1
		self.addLink(h1,sw1)
		self.addLink(h2,sw1)
		self.addLink(fw1,sw1)
		#SW2
		self.addLink(fw1,sw2)
		self.addLink(fw2,sw2)
		self.addLink(lb1,sw2)
		self.addLink(ids,sw2)		
		#SW3
		self.addLink(ds1,sw3)
		self.addLink(ds2,sw3)
		self.addLink(ds3,sw3)
		self.addLink(lb1,sw3)
		#SW4
		self.addLink(ws1,sw4)
		self.addLink(ws2,sw4)
		self.addLink(ws3,sw4)
		self.addLink(lb2,sw4)
		#SW5
		self.addLink(h3,sw5)	
		self.addLink(h4,sw5)
		self.addLink(napt,sw5)
		#NAPT		
		self.addLink(fw2,napt)
		#IDS
		self.addLink(insp,ids)
		self.addLink(lb2,ids)

topos = { 'mytopo': ( lambda: MyTopo() ) }
