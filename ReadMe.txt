Running Details:

Put mn_topology.py and all the *.click files in /home/click/ folder
Put RemoteController.py, Firewall.py and l2_learning.py in /home/click/pox/pox/forwarding/ folder

Open 5 ssh terminals to the VM

Terminal 1:
sudo mn --custom netw2.py --topo mytopo --controller=remote,ip=127.0.0.1

Terminal 2:
cd pox
./pox.py forwarding.RemoteController

Terminal 3:
sudo click ids.click

Terminal 4:
sudo click lb.click

Terminal 5:
sudo click napt.click


.........................................................

We are really sorry that we couldn't make the 'makefile', mainly due to lack of
coding abilities.

Please read the enclosed proj_report for a summary of our tests executed.

Group 3:
Ashutosh Mittal
Mustafa
Blanca
Burak
