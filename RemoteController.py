#Headers and imports
from l2_learning import LearningSwitch
from l2_learning_test import LearningSwitch_test
from Firewall import Firewall
from Firewall import Fw1
from Firewall import Fw2
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_dpid
from pox.lib.util import str_to_bool
import pox.lib.packet as pkt
import time
import logging
import subprocess

log = core.getLogger()

# We don't want to flood immediately when a switch connects.
_flood_delay = 0

#This class runs learning Switch or Firewall modules on respective switches. It doesnot do anything in case CLICK handles the switches
class RemoteController(object):
	
	def __init__ (self, transparent):
		#Adding Listener
		core.openflow.addListeners(self)
		self.transparent = transparent

	def _handle_ConnectionUp (self, event):
		log.debug("Connection %s" % (event.connection,))
		dpid_in= dpid_to_str(event.dpid)
		split_str=dpid_in.split()
		#Altering the DPID in desired format
		dpid_in = split_str[0]
		log.info("DPID %s", dpid_in)
		dpid_1 = "00-00-00-00-00-01"
		dpid_2 = "00-00-00-00-00-02"
		dpid_3 = "00-00-00-00-00-03"
		dpid_4 = "00-00-00-00-00-04"
		dpid_5 = "00-00-00-00-00-05"
		dpid_6 = "00-00-00-00-00-06"
		dpid_7 = "00-00-00-00-00-07"
		dpid_8 = "00-00-00-00-00-08"
		dpid_9 = "00-00-00-00-00-09"
		dpid_10 = "00-00-00-00-00-0a"
		dpid_11 = "00-00-00-00-00-0b"

		
		if dpid_in == dpid_6:
			#Running Firewall-1 Module
			Fw1(event.connection, self.transparent) #Fw1 is defined in Firewall.py file
			log.info("firewall 1 initiated!")
		elif dpid_in == dpid_7:
			#Running Firewall-2 Module
			Fw2(event.connection, self.transparent) #Fw2 is defined in Firewall.py file
			log.info("firewall 2 initiated!")
		elif dpid_in == dpid_1 or dpid_in == dpid_2 or dpid_in == dpid_3 or dpid_in == dpid_4 or dpid_in == dpid_5:
			#Running Learning Switch Module
			LearningSwitch(event.connection, self.transparent) #LearningSwitch is defined in l2_learning.py file
			log.info("Learning Switch initiated!")
		else :
			#CLICK will handle this swich
			log.info("CLICK handles this switch!")


def launch (transparent=False, hold_down=_flood_delay):
	"""
	Starts a Firewall or L2 Learning switch.
	"""
	try:
		global _flood_delay
		_flood_delay = int(str(hold_down), 10)
		assert _flood_delay >= 0
	except:
		raise RuntimeError("Expected hold-down to be a number")

	core.registerNew(RemoteController, str_to_bool(transparent))
