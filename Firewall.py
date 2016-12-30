#Headers and Imports
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_dpid
from pox.lib.util import str_to_bool
import time
from l2_learning import LearningSwitch
from pox.lib.addresses import EthAddr
from pox.lib.addresses import IPAddr
from pox.lib.packet import *
from pox.lib.packet.arp import arp
from pox.lib.packet.packet_base import packet_base
from types import *
import pox.lib.packet as pkt

log = core.getLogger()
# We don't want to flood immediately when a switch connects
_flood_delay = 0

#Base Firewall class, inherits LearningSwitch class
class Firewall(LearningSwitch):
	def __init__(self, connection, transparent):
		self.transparent = transparent
		self.connection = connection
		connection.addListeners(self)
		#log.debug("Enabling Firewall Module")
		self.in_port=0
		self.firewall_table = {}
		self.macToPort = {}
		self.hold_down_expired = _flood_delay == 0

	def _handle_PacketIn (self, event):
		self.in_port=event.port
		#Return value of ImplementFirewall (True/False) decides if the packet needs to be blocked by FW
		fw_reply = self.ImplementFirewall(event)
		if fw_reply == True:
			#log.debug("Packet forwarded by firewall.")
			#LearningSwitch's Handle_PacketIn should deal with this packet
			super(Firewall, self)._handle_PacketIn(event)
		else:
			#Packet dropped at Firewall
			log.debug("Packet dropped by firewall.")
	
	#Function checks the firewall's policy and decides if the packet needs to be forwarded
	def ImplementFirewall(self, event):
		packet = event.parsed
		if not packet.parsed:
			log.warning("Ignoring incomplete packet")
			return
		
		#log.debug("Incoming Packet type for Firewall %x", packet.type)
		if self.CheckPolicy(packet) == False :
			#log.debug("FW Policy denied forwarding")
			return False
		else :
			#log.debug("FW Policy allowed forwarding")
			return True

	#This is defined explicitly defined in the inherited classes
	def CheckPolicy(self, packet):
		log.warning("Why am I here!!!!")		
		return True

#Firewall-1; inherits base Firewall class and modifies CheckPolicy function to suit the requirements
class Fw1 (Firewall):

	def CheckPolicy(self, packet):
		# For traffic going from Pb_zone to DMZ_zone/Pvt_zone
		def fw1_south_bound_traffic():
			match = of.ofp_match.from_packet(packet)
  			#log.debug("FW1 N2S: pkt type:%s, src: %s, dst: %s"%(match.dl_type,match.nw_src, match.nw_dst,))
			# All ARP Packets allowed		
			if match.dl_type == packet.ARP_TYPE :
				#log.debug("FW1 n2s: allow at arp")
				return True
			# All IP packets to the specified IPs are allowed
			elif (	match.dl_type == packet.IP_TYPE and (match.nw_dst == IPAddr("100.0.0.45") or 
			      	match.nw_dst == IPAddr("100.0.0.25") or match.nw_dst == IPAddr("100.0.0.1") or
				match.nw_dst == IPAddr("10.0.0.50") or match.nw_dst == IPAddr("10.0.0.51"))):
				#log.debug("FW1 n2s: allow at ip+dest check")
  				return True
			# All other packets are dropped by FW-1			
			else :
				#log.debug("FW1 n2s: reject not arp,notIP_dest")
				return False
			
		# For traffic going from DMZ_zone/Pvt_zone to Pb_zone
		def fw1_north_bound_traffic():
			match = of.ofp_match.from_packet(packet)  			
			#log.debug("FW1 S2N: pkt type:%s, src: %s, dst: %s"%(match.dl_type,match.nw_src, match.nw_dst,))
			
			# All ARP to destination h1 or h2 allowed	
			if match.dl_type == packet.ARP_TYPE and (match.nw_dst == IPAddr("100.0.0.10") or match.nw_dst == IPAddr("100.0.0.11")):
				#log.debug("FW1 s2n: allow at arp")
				return True

			# All IP packets to h1 or h2 allowed
			elif ( match.dl_type == packet.IP_TYPE and (match.nw_dst == IPAddr("100.0.0.10") or 
			       match.nw_dst == IPAddr("100.0.0.11"))):
				#log.debug("FW1 s2n: allow at ip+dest")
				return True

			# All other packets dropped			
			else :
				#log.debug("FW1 s2n: reject not arp,notIP_dest")
				return False
		
		#log.debug("FW1 ingres= %s",self.in_port)
		if self.in_port == 1:
			return fw1_south_bound_traffic()
		elif self.in_port == 2:
			return fw1_north_bound_traffic()
		else :
			#log.debug("No matching port name in FW1!")
			return False


#Firewall-2; inherits base Firewall class and modifies CheckPolicy function to suit the requirements
class Fw2 (Firewall):

	def CheckPolicy(self, packet):
	
		# For traffic going from DMZ_zone/Pb_zone to Pvt_zone
		def fw2_south_bound_traffic():
			match = of.ofp_match.from_packet(packet)
  			#log.debug("FW2 N2S: pkt type:%s, src: %s, dst: %s"%(match.dl_type,match.nw_src, match.nw_dst,))
			
			# ARP packets to only public interface of NAPT allowed
			if ( match.dl_type == packet.ARP_TYPE and match.nw_dst == IPAddr("100.0.0.1")): 
				#log.debug("FW2 n2s: allow at arp to napt")
	  			return True
			
			# If IP packet is for public interface of NAPT then further investigated else dropped
			elif (match.dl_type == packet.IP_TYPE and match.nw_dst == IPAddr("100.0.0.1")) : 
				ip_packet=packet.find("ipv4")
				#log.debug("FW2 N2S ip: pkt proto: %s",ip_packet.protocol)
				
				# ICMP requests are blocked
			    	if packet.find("icmp"):
			      		icmp_packet = ip_packet.payload
					#log.debug("FW2 N2S ip,icmp: pkt type: %s",icmp_packet.type)
					if icmp_packet.type == 8: #echo request
						#log.debug("FW2 n2s: reject at icmp type")
						return False
					else:
						#log.debug("FW2 n2s: allow at icmp type")
						return True

				# SYN packet blocked, to avoid any initiation of TCP connection to Pvt network	
				elif packet.find("tcp"):
					tcp_packet = ip_packet.payload
					if tcp_packet.SYN and not tcp_packet.ACK :
						#log.debug("FW2 n2s: reject at tcp syn-ack")
						return False
					else :
						#log.debug("FW2 n2s: allow at tcp syn-ack")
						return True
				
				# DNS response allowed, but not querry
				elif packet.find("dns"):
					dns_packet=packet.find("dns")
					if dns_packet.qr == 1: #dnsResponse
						#log.debug("FW2 n2s: allow at dns resp")
						return True
					else:
						#log.debug("FW2 n2s: reject at dns resp")
						return False
				else :
					#log.debug("FW2 n2s: reject neither IP cond")
					return False
			else : 
				#log.debug("FW2 n2s: reject neither overall cond")
				return False

		# For traffic going from Pvt_zone to DMZ_zone/Pb_zone
		def fw2_north_bound_traffic():
			match = of.ofp_match.from_packet(packet)
  			#log.debug("FW2 S2N: pkt type:%s, src: %s, dst: %s"%(match.dl_type,match.nw_src, match.nw_dst,))
			
			# No restriction on ARP
			if match.dl_type == packet.ARP_TYPE :
				#log.debug("FW2 s2n: allow arp")
  				return True

			# IP packets only to specified IPs allowed	
			elif ( match.dl_type == packet.IP_TYPE and (match.nw_dst == IPAddr("100.0.0.45") or 
			      match.nw_dst == IPAddr("100.0.0.25") or match.nw_dst == IPAddr("100.0.0.10") or 
			      match.nw_dst == IPAddr("100.0.0.11"))):# done!change here 22 to 25 #Only to lb1, lb2, h1 or h2
				#log.debug("FW2 s2n: allow ip+dest")
				return True
			else :
				#log.debug("FW2 s2n: reject neither overall cond")
				return False

		#log.debug("FW2 ingres= %s", self.in_port)
		if self.in_port == 1:
			return fw2_south_bound_traffic()
		elif self.in_port == 2:
			return fw2_north_bound_traffic()
		else :
			#log.debug("No matching port name in FW2!")
			return False

"""
For personal reference:
#2048 ip; 2054 arp
int 	nox::lib::packet::icmp::TYPE_ECHO_REPLY = 0
int 	nox::lib::packet::icmp::TYPE_DEST_UNREACH = 3
int 	nox::lib::packet::icmp::TYPE_SRC_QUENCH = 4
int 	nox::lib::packet::icmp::TYPE_REDIRECT = 5
int 	nox::lib::packet::icmp::TYPE_ECHO_REQUEST = 8
int 	nox::lib::packet::icmp::TYPE_TIME_EXCEED = 11
int 	nox::lib::packet::icmp::CODE_UNREACH_NET = 0
int 	nox::lib::packet::icmp::CODE_UNREACH_HOST = 1
int 	nox::lib::packet::icmp::CODE_UNREACH_PROTO = 2
int 	nox::lib::packet::icmp::CODE_UNREACH_PORT = 3
int 	nox::lib::packet::icmp::CODE_UNREACH_FRAG = 4
int 	nox::lib::packet::icmp::CODE_UNREACH_SRC_RTE = 5	
"""	
