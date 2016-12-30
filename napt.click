//.................................................................................................................................................
napt1_c0	:: Counter;
napt1_c1	:: Counter;

napt1_avg_c0	:: AverageCounter;
napt1_avg_c1	:: AverageCounter;

napt1_c0_2	:: Counter;
napt1_c1_2	:: Counter;

napt1_avg_c0_2	:: AverageCounter;
napt1_avg_c1_2	:: AverageCounter;

out_pub	:: Queue(200) -> napt1_c1 -> napt1_avg_c1 -> ToDevice(s8-eth2, METHOD LINUX);
out_pvt	:: Queue(200) -> napt1_c1_2 -> napt1_avg_c1_2 -> ToDevice(s8-eth1, METHOD LINUX);

pkt_classify_0	:: Classifier(	12/0806 20/0001,
				12/0806 20/0002,
				12/0800,-); //Classifier(ARP req, ARP reply, IP,-);

ip_classify_0	:: IPClassifier(ip proto icmp and dst 10.0.0.1 and icmp type 8,
				ip proto icmp and icmp type 8 and src 10.0.0.50 and not dst 10.0.0.1,
				ip proto icmp and icmp type 8 and src 10.0.0.51 and not dst 10.0.0.1,
				ip proto tcp or ip proto udp and src 10.0.0.50 and not dst 10.0.0.1 ,
				ip proto tcp or ip proto udp and src 10.0.0.51 and not dst 10.0.0.1, -);
				//IPClassfier(ICMP ping to napt, icmp ping to pub netw, other icmp, TCP or UDP,-);


arp_query_1	:: ARPQuerier(100.0.0.1, 06-01-01-01-01-05);
arp_query_0	:: ARPQuerier(10.0.0.1, 06-01-01-01-01-05);

arp_resp_1	:: ARPResponder(100.0.0.1 06-01-01-01-01-05);
arp_resp_0	:: ARPResponder(10.0.0.1 06-01-01-01-01-05,
				100.0.0.0/24 06-01-01-01-01-05);
				//also responds for ARP query for any other host in the network

rw_ip_1		:: IPRewriter(pattern 100.0.0.1 1088 - - 0 1);
rw_ip_2		:: IPRewriter(pattern 100.0.0.1 1089 - - 0 1);
rw_icmp_ping_1	:: ICMPPingRewriter(pattern 100.0.0.1 1088 - - 0 1);
rw_icmp_ping_2	:: ICMPPingRewriter(pattern 100.0.0.1 1089 - - 0 1);

//t12 :: Tee(2);

// From the Pvt Network
FromDevice(s8-eth1, SNIFFER false, METHOD LINUX) -> napt1_c0 -> napt1_avg_c0 -> [0]pkt_classify_0;

// ARP requests dealt by responder, and response sent to network as well as Querier for learning purposes
pkt_classify_0[0] -> arp_resp_0 -> out_pvt;
//t12[0] -> out_pvt;
//t12[1] -> [1]arp_query_0;

// ARP reply sent to Querier
pkt_classify_0[1] -> [1]arp_query_0; //response stored in arpQuerier table
arp_query_0[0] -> out_pvt;

// IP packets
pkt_classify_0[2] -> Strip(14) -> CheckIPHeader -> ip_classify_0; //let ip classifier handle

// Other type of packets dicarded
pkt_classify_0[3] -> Discard;


// PING requests are responded with help from Querier for ARP
ip_classify_0[0] -> ICMPPingResponder() -> GetIPAddress(16) -> [0]arp_query_0;
arp_query_0[0] -> out_pvt;
//arp_query_0[1] -> out_pvt; 

// H3 PING tanslated and sent in public network using Querier for ARP
ip_classify_0[1] -> rw_icmp_ping_1[0] -> GetIPAddress(16) -> [0]arp_query_1;
arp_query_1[0] -> out_pub;
//arp_query_1[1] -> out_pub; 

// H4 PING tanslated and sent in public network using Querier for ARP
ip_classify_0[2] -> rw_icmp_ping_2[0] -> GetIPAddress(16) -> [0]arp_query_1;
arp_query_1[0] -> out_pub;
//arp_query_1[1] -> out_pub; 

// H3 TCP/UDP packets translated
ip_classify_0[3] -> rw_ip_1[0] -> GetIPAddress(16) -> [0]arp_query_1;
arp_query_1[0] -> out_pub;
//arp_query_1[1] -> out_pub;

// H3 TCP/UDP packets translated
ip_classify_0[4] -> rw_ip_2[0] -> GetIPAddress(16) -> [0]arp_query_1;
arp_query_1[0] -> out_pub;
//arp_query_1[1] -> out_pub;

// Rest are Discarded
ip_classify_0[5] -> Discard;
//,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,

pkt_classify_1	:: Classifier(	12/0806 20/0001,
				12/0806 20/0002,
				12/0800,
				-); //Classifier(ARP req, ARP reply, IP,-);

ip_classify_1	:: IPClassifier(ip proto icmp and icmp type 8,
				ip proto icmp and icmp type 0,
				(ip proto tcp or ip proto udp) and dst port 1088,
				(ip proto tcp or ip proto udp) and dst port 1089);
				//IPClassfier(ICMP ping to napt, icmp ping reply to pvt netw, other icmp, TCP or UDP,-);

//t22 :: Tee(2);
t23 :: Tee(2);

// Towards Pvt Zone
FromDevice(s8-eth2, SNIFFER false, METHOD LINUX) -> napt1_c0_2 -> napt1_avg_c0_2 -> [0]pkt_classify_1;

// ARP requests dealt by responder, and response sent to network as well as Querier for learning purposes
pkt_classify_1[0] -> arp_resp_1 -> out_pub;
//t22[0] -> out_pub;
//t22[1] -> [1]arp_query_1;

// ARP reply sent to Querier
pkt_classify_1[1]-> [1]arp_query_1;
arp_query_1[0] -> out_pub;

// IP Packets are further investigated
pkt_classify_1[2] -> Strip(14) -> CheckIPHeader -> ip_classify_1; //let ip classifier handle

// Rest are discarded
pkt_classify_1[3] -> Discard;

// PING requests are responded with help from Querier for ARP
ip_classify_1[0] -> ICMPPingResponder() -> GetIPAddress(16) -> [0]arp_query_1;
arp_query_1[0] -> out_pub;
//arp_query_1[1] -> out_pub; 

// PING tanslated and sent in pvt network using Querier for ARP
ip_classify_1[1] -> t23;

t23[0] -> rw_icmp_ping_1[1] -> GetIPAddress(16) -> [0]arp_query_0;
arp_query_0[0] -> out_pvt;
//arp_query_0[1] -> out_pvt; 

t23[1] -> rw_icmp_ping_2[1] -> GetIPAddress(16) -> [0]arp_query_0;
arp_query_0[0] -> out_pvt;
//arp_query_0[1] -> out_pvt;

// TCP/UDP packets for H3 traslated
ip_classify_1[2] -> rw_ip_1[1] -> GetIPAddress(16) -> [0]arp_query_0;
arp_query_0[0] -> out_pvt;
//arp_query_0[1] -> out_pvt;

// TCP/UDP packets for H4 traslated
ip_classify_1[3] -> rw_ip_2[1] -> GetIPAddress(16) -> [0]arp_query_0;
arp_query_0[0] -> out_pvt;
//arp_query_0[1] -> out_pvt;

//.................................................................................................................................................



DriverManager(wait, print > napt_test.report "NAPT\n\nInput Packets:\tCount\tRate";
					"\nFrom Pvt Network:\t"$(napt1_c0.count);"\t"$(napt1_avg_c0.rate);
					"\nTowards Pvt Network::\t "$(napt1_c0_2.count);"\t"$(napt1_avg_c0_2.rate);
					"\n\nOutput Packets:\tCount\tRate";
					"\nTo Pb and DMZ network:\t"$(napt1_c1.count);"\t"$(napt1_avg_c1.rate);
					"\nTo Pvt Network:\t "$(napt1_c1_2.count);"\t"$(napt1_avg_c0_2.rate)
					, stop);

