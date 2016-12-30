//..................................
elementclass load_bal { $lb_ip_pub, $lb_ip_pvt, $lb_mac, $proto, $port, $srv1_ip, $srv2_ip, $srv3_ip | 
	
	elementclass Classify { 
		c	:: Classifier( 	12/0806 20/0001,
				       	12/0806 20/0002,
				       	12/0800,
					-); //Classifier(ARP req, ARP reply, IP,-);
		input[0] -> c;
		c[0] -> [0]output;
		c[1] -> [1]output;
		c[2] -> [2]output;
		c[3] -> [3]output;
	}

	pkt_classify_0	:: Classify;
	pkt_classify_1	:: Classify;

	ip_classify_0	:: IPClassifier(ip proto icmp and icmp type 8 and dst host $lb_ip_pub, 
			   		ip proto $proto and port $port and dst host $lb_ip_pub,
					-);   //IPClassfier(ICMP, UDP/TCP,-);

	ip_classify_1	:: IPClassifier(ip proto icmp and icmp type 8,
					ip proto $proto,
					-); //IPClassfier(ICMP req, UDP/TCP,-);

	arp_query_0	:: ARPQuerier($lb_ip_pub, $lb_mac);
	arp_query_1	:: ARPQuerier($lb_ip_pvt, $lb_mac);

	arp_resp_0	:: ARPResponder($lb_ip_pub $lb_mac); 

	arp_resp_1	:: ARPResponder($lb_ip_pvt $lb_mac, 
					100.0.0.0/24 $lb_mac); 

	round_robin	:: RoundRobinIPMapper(- - $srv1_ip $port 0 1, - - $srv2_ip $port 0 1, - - $srv3_ip $port 0 1);
	rw		:: IPRewriter(round_robin);

	// Packets from Hosts in the network
	input[0] -> pkt_classify_0;

	//t :: Tee(2);
	//t12 :: Tee(2);

	// ARP Request handler
	pkt_classify_0[0] -> arp_resp_0 -> [0]output;
	//t12[0] -> [0]output;
	//t12[1] -> [1]arp_query_0;
	//t12[2] -> [1]arp_query_1;

	// ARP Reply Handler
	pkt_classify_0[1]-> [1]arp_query_0;
	//t[0] -> [1]arp_query_0; //response stored in arpQuerier table
	//t[1] -> [1]arp_query_1;
	arp_query_0[0] -> [0]output;
	//arp_query_1[0] -> [1]output;

	// IP Packet handler
	pkt_classify_0[2] -> Strip(14) -> CheckIPHeader -> ip_classify_0; //let ip classifier handle
	pkt_classify_0[3] -> Discard;

	// PING req packet handler
	ip_classify_0[0] -> ICMPPingResponder() -> GetIPAddress(16) -> [0]arp_query_0;
	arp_query_0[0] -> [0]output;
	//arp_query_0[1] -> [0]output;

	// RoundRobbin of Protocol packet handler
	ip_classify_0[1] -> rw[0] -> GetIPAddress(16) -> [0]arp_query_1;
	arp_query_1[0] -> [1]output;
	//arp_query_1[1] -> [1]output;

	ip_classify_0[2] -> Discard;
	//--------------------------------------------------------------------------------------------------------

	// Packets from servers
	input[1] -> pkt_classify_1;

	//t2 :: Tee(2);
	//t22 :: Tee(2);

	// ARP Request handler
	pkt_classify_1[0] -> arp_resp_1 -> [1]output;
	//t22[0] -> [1]output; //arp reply to server
	//t22[1] -> [1]arp_query_0;
	//t22[1] -> [1]arp_query_1;

	// ARP Reply Handler
	pkt_classify_1[1] -> [1]arp_query_1;
	//t2[0] -> [1]arp_query_1; //response stored in arpQuerier table
	//t2[1] -> [1]arp_query_0;
	arp_query_1[0] -> [1]output;
	//arp_query_0[0] -> [0]output;


	// IP Packet handler
	pkt_classify_1[2] -> Strip(14) -> CheckIPHeader -> ip_classify_1;
	pkt_classify_1[3] -> Discard;

	// PING req packet handler
	ip_classify_1[0] -> ICMPPingResponder() -> GetIPAddress(16) -> [0]arp_query_1; //reply to http server's ping
	arp_query_1[0] -> [1]output;
	//arp_query_1[1] -> [1]output;	
	
	// RoundRobbin of Protocol reverse translation handler
	ip_classify_1[1] -> rw[1] -> GetIPAddress(16) -> [0]arp_query_0;
	arp_query_0[0] -> [0]output;
	//arp_query_0[1] -> [0]output;

	ip_classify_1[2] -> Discard;

}

lb1_c0		:: Counter;
lb1_c1		:: Counter;

lb1_avg_c0	:: AverageCounter;
lb1_avg_c1	:: AverageCounter;

lb2_c0		:: Counter;
lb2_c1		:: Counter;

lb2_avg_c0	:: AverageCounter;
lb2_avg_c1	:: AverageCounter;

lb1_c0_2	:: Counter;
lb1_c1_2	:: Counter;

lb1_avg_c0_2	:: AverageCounter;
lb1_avg_c1_2	:: AverageCounter;

lb2_c0_2	:: Counter;
lb2_c1_2	:: Counter;

lb2_avg_c0_2	:: AverageCounter;
lb2_avg_c1_2	:: AverageCounter;


//Load Balancer -1
lb1	:: load_bal (	100.0.0.25,
			100.0.0.23,
			06-01-01-01-01-01,
			udp,
			53,
			100.0.0.20,
			100.0.0.21,
			100.0.0.22);// inputs: $lb_ip_pub, $lb_ip_pvt, $lb_mac, $proto, $port, $srv1_ip, $srv2_ip, $srv3_ip

// From hosts in the network
FromDevice(s9-eth1, SNIFFER false, METHOD LINUX) -> lb1_c0 -> lb1_avg_c0 -> [0]lb1;
// From DNS Servers
FromDevice(s9-eth2, SNIFFER false, METHOD LINUX) -> lb1_c0_2 -> lb1_avg_c0_2 -> [1]lb1;

// Output to the hosts in the network
lb1[0] -> Queue(200) -> lb1_c1 -> lb1_avg_c1 -> ToDevice(s9-eth1, METHOD LINUX);
// Output to the DNS servers
lb1[1] -> Queue(200) -> lb1_c1_2 -> lb1_avg_c1_2 -> ToDevice(s9-eth2, METHOD LINUX);


//Load Balancer -2
lb2	:: load_bal (	100.0.0.45,
			100.0.0.43,
			06-01-01-01-01-02,
			tcp,
			80,
			100.0.0.40,
			100.0.0.41,
			100.0.0.42);// inputs: $lb_ip_pub, $lb_ip_pvt, $lb_mac, $proto, $port, $srv1_ip, $srv2_ip, $srv3_ip

// From hosts in the network
FromDevice(s10-eth2, SNIFFER false, METHOD LINUX) -> lb2_c0 -> lb2_avg_c0 -> [0]lb2;
// From HTTP Servers
FromDevice(s10-eth1, SNIFFER false, METHOD LINUX) -> lb2_c0_2 -> lb2_avg_c0_2 ->[1]lb2;

// Output to the hosts in the network
lb2[0] -> Queue(200) -> lb2_c1 -> lb2_avg_c1 -> ToDevice(s10-eth2, METHOD LINUX);
// Output to the HTTP servers
lb2[1] -> Queue(200) -> lb2_c1_2 -> lb2_avg_c1_2 -> ToDevice(s10-eth1, METHOD LINUX);



DriverManager(wait, print > lb_test.report "LB-1\n\nInput Packets:\tCount\tRate";
					"\nFrom hosts in network:\t"$(lb1_c0.count);"\t"$(lb1_avg_c0.rate);
					"\nFrom DNS servers:\t "$(lb1_c0_2.count);"\t"$(lb1_avg_c0_2.rate);
					"\n\nOutput Packets:\tCount\tRate";
					"\nTo hosts in network:\t"$(lb1_c1.count);"\t"$(lb1_avg_c1.rate);
					"\nTo DNS servers:\t "$(lb1_c1_2.count);"\t"$(lb1_avg_c0_2.rate);
					"\n\nLB-2\n\nInput Packets:\tCount\tRate";
					"\nFrom hosts in network:\t"$(lb2_c0.count);"\t"$(lb2_avg_c0.rate);
					"\nFrom DNS servers:\t "$(lb2_c0_2.count);"\t"$(lb2_avg_c0_2.rate);
					"\n\nOutput Packets:\tCount\tRate";
					"\nTo hosts in network:\t"$(lb2_c1.count);"\t"$(lb2_avg_c1.rate);
					"\nTo DNS servers:\t "$(lb2_c1_2.count);"\t"$(lb2_avg_c0_2.rate)
					, stop);






