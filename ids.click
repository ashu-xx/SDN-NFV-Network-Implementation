//...........................................................................

ids_c0	:: Counter;
ids_c1	:: Counter;

ids_avg_c0	:: AverageCounter;
ids_avg_c1	:: AverageCounter;

ids_c0_2	:: Counter;
ids_c1_2	:: Counter;

ids_avg_c0_2	:: AverageCounter;
ids_avg_c1_2	:: AverageCounter;

ids_c0_3	:: Counter;
ids_c1_3	:: Counter;

ids_avg_c0_3	:: AverageCounter;
ids_avg_c1_3	:: AverageCounter;


out_pub	:: Queue(200) -> ids_c1 -> ids_avg_c1 -> ToDevice(s11-eth1, METHOD LINUX);
out_pvt	:: Queue(200) -> ids_c1_2 -> ids_avg_c1_2 -> ToDevice(s11-eth3, METHOD LINUX);
out_log	:: Queue(200) -> ids_c1_3 -> ids_avg_c1_3 -> ToDevice(s11-eth2, METHOD LINUX);

pkt_classify		:: Classifier(	12/0806,
			       	      	12/0800,
					-); 	//Classifier(ARP , IP,-);

ip_classify		:: IPClassifier(dst host 100.0.0.45 and ip proto tcp,-); //IPClassifier(http,-)

http_method_check	:: Classifier(	32/5004, 52/504f5354, 52/505554, 52/474554, 52/48454144, 52/5452414345, 
					52/4f5054494f4e53, 52/44454c455445, 52/434f4e4e454354, -); //only allows post, put, SYN , ACK or FIN packets

http_content_check	:: Classifier(	199/636174202f6574632f706173737764,
					199/636174202f7661722f6c6f672f,
					199/494e53455254,
					199/555044415445,
					199/44454c455445,
					-);//check for malicious code

log_pkt			:: Strip(14) -> StoreIPAddress(100.0.0.30,16) -> Unstrip(14)-> StoreEtherAddress(06:01:01:01:01:03, 0) -> out_log;


FromDevice(s11-eth1, SNIFFER false, METHOD LINUX) -> ids_c0 -> ids_avg_c0 -> pkt_classify;

// Forward ARP
pkt_classify[0] -> out_pvt;
// Investigate IP packets
pkt_classify[1] -> Strip(14) -> CheckIPHeader -> ip_classify;
// Discard other packets
pkt_classify[2] -> Discard;

// Allow other IP packets
ip_classify[0] -> http_method_check;
// Check TCP packets further
ip_classify[1] -> Unstrip(14) -> out_pvt;

// Allow RST packets
http_method_check[0] -> Unstrip(14) -> out_pvt;
// Allow POST HTTP packets
http_method_check[1] -> Unstrip(14) -> out_pvt;
// Check PUT HTTP packets further
http_method_check[2] -> http_content_check;
// Don't Allow GET method packets
http_method_check[3] -> Unstrip(14) -> log_pkt;
// Don't Allow HEAD method packets
http_method_check[4] -> Unstrip(14) -> log_pkt;
// Don't Allow TRACE method packets
http_method_check[5] -> Unstrip(14) -> log_pkt;
// Don't Allow OPTIONS method packets
http_method_check[6] -> Unstrip(14) -> log_pkt;
// Don't Allow DELETE method packets
http_method_check[7] -> Unstrip(14) -> log_pkt;
// Don't Allow CONNECT method packets
http_method_check[8] -> Unstrip(14) -> log_pkt;
// Allow other TCP packets
http_method_check[9] -> Unstrip(14) -> out_pvt;

// Log malicious PUT requests
http_content_check[0] -> Unstrip(14) -> log_pkt;
http_content_check[1] -> Unstrip(14) -> log_pkt;
http_content_check[2] -> Unstrip(14) -> log_pkt;
http_content_check[3] -> Unstrip(14) -> log_pkt;
http_content_check[4] -> Unstrip(14) -> log_pkt;

// Allow non-malicious PUT requests
http_content_check[5] -> Unstrip(14) -> out_pvt;

//,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,

// Allow all packets from load balancer to network
FromDevice(s11-eth3, SNIFFER false, METHOD LINUX) -> ids_c0_2 -> ids_avg_c0_2 -> out_pub;

// Discard all Packets from logging server
FromDevice(s11-eth2, SNIFFER false, METHOD LINUX) -> ids_c0_3 -> ids_avg_c0_3 -> Discard;
//...........................................................................


//For personal reference:
//50 4f 53 54 : post ;; 505554 : PUT
//put content starts at 213 bytes (without stripping 14 eth bytes)
//636174202f6574632f706173737764:  cat /etc/passwd
//636174202f7661722f6c6f672f: cat /var/log/
//494e53455254: INSERT
//555044415445: UPDATE
//44454c455445: DELETE
//GET 47 45 54
//POST 50 4f 53 54
//HEAD 48 45 41 44
//TRACE 54 52 41 43 45
//OPTIONS 4f 50 54 49 4f 4e 53
//PUT 50 55 54
//DELETE 44 45 4c 45 54 45
//CONNECT 43 4f 4e 4e 45 43 54
//33/02%02, 33/10%10, 33/01%01,


DriverManager(wait, print > ids_test.report "IDS\n\nInput Packets:\tCount\tRate";
					"\nFrom Hosts in Network:\t"$(ids_c0.count);"\t"$(ids_avg_c0.rate);
					"\nFrom LB-2:\t "$(ids_c0_2.count);"\t"$(ids_avg_c0_2.rate);
					"\nFrom Log server:\t "$(ids_c0_3.count);"\t"$(ids_avg_c0_3.rate);
					"\n\nOutput Packets:\tCount\tRate";
					"\nTo Hosts in network:\t"$(ids_c1.count);"\t"$(ids_avg_c1.rate);
					"\nTo LB-2:\t "$(ids_c1_2.count);"\t"$(ids_avg_c0_2.rate);
					"\nTo Log Server:\t "$(ids_c1_3.count);"\t"$(ids_avg_c1_3.rate)
					, stop);





