//============================================================================
// Name        : Assignment2.cpp
// Author      : Kishore
// Version     :
// Copyright   : None
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <sniffer.h>

using namespace std;

mutex results_mutex;


void manage_packet_cnt(data_packet dp){
//	for (data_packet stored : g_results) {
	for (unsigned int i=0; i < g_results.size(); i++) {
		data_packet * stored = &g_results.at(i);

		if (memcmp(&stored->sd, &dp.sd, sizeof(stored->sd)) == 0) {
			results_mutex.lock();
			stored->info.total_packets += 1;
			stored->info.total_bytes += dp.info.total_bytes;
			if (stored->sd.protocol == ICMP)
				stored->state.icmp_type = dp.state.icmp_type;
			else if (stored->sd.protocol == ICMP)
				stored->state.tcp_state = dp.state.tcp_state;
			results_mutex.unlock();
			return;
		}
	}
	results_mutex.lock();
	gettimeofday(&dp.rtime, NULL);
	g_results.insert(g_results.end(), dp);
	results_mutex.unlock();
}

void packet_counter_thread() {
	while (1) {
		if (!packet_queue.empty()) {
			struct data_packet ldata_packet = packet_queue.front();
			packet_queue.pop();
			manage_packet_cnt(ldata_packet);
		} else
			usleep(10);
	}
}

void packet_printer_thread(){
	while (true) {
		results_mutex.lock();
		cout << "\033[2J\033[1;1H";
		printf("StartTime\t\tProto\tSrcAddr\t\tSport\tDir\tDstAddr\t\tDPort\tTotPkts\tTotBytes\tState\tDur\n");
		for (data_packet stored : g_results) {

			cout << stored.rtime.tv_sec << "." << stored.rtime.tv_usec << "\t"
				 << stored.sd.protocol << "\t"
				 << stored.sd.sadd     << "\t"
				 << stored.sd.sport    << "\t"
				 << " -> "    << "\t"
				 << stored.sd.dadd     << "\t"
				 << stored.sd.dport    << "\t"
				 << stored.info.total_packets << "\t"
				 << stored.info.total_bytes << "\t"
//				 << stored.state.tcp_state << "\t"
				 << endl;
		}
		results_mutex.unlock();
		sleep(1);
	}

}

void option_handler(int argc, char *argv[]) {
	char c;
	char errbuf[PCAP_ERRBUF_SIZE];

	memset(&opts, 0, sizeof(sniffer_opt));
	opts.file = stdout;
	memset(opts.interface, 0, sizeof(opts.interface));

//	gettimeofday(&opts.utime, NULL);
	opts.utime.tv_sec = 1485907200;
	opts.utime.tv_usec = 0;
	opts.time_offset.tv_sec = 157680000;

	snprintf(opts.interface, 50, "%s", pcap_lookupdev(errbuf));

	opterr = 0;

	if (argc == 1) {
		fprintf(stdout,
				"%s [-r filename] [-i interface] [-t time] [-o time_offset]\n\n",
				argv[0]);
		exit(0);
	}

	while ((c = getopt(argc, argv, "r:i:t:o:N:S:")) != -1) {
		switch (c) {
		case 'r':
			snprintf(opts.trace, 100, "%s", optarg);
			break;
		case 'i':
			snprintf(opts.interface, sizeof(opts.interface), "%s", optarg);
			break;
		case 't':
			opts.utime.tv_sec = atol(optarg);
			opts.utime.tv_usec = 0;
			break;
		case 'o':
			opts.time_offset.tv_usec = (long) ((atof(optarg) - atoi(optarg))
					* 1000000L);
			opts.time_offset.tv_sec = atoi(optarg);
			break;
		case 'N':
			opts.num_flows = atoi(optarg);
			break;
		case 'S':
			opts.flow_timeout = atoi(optarg);
			break;
		case '?':
			if (optopt == 'r')
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			else if (optopt == 'i')
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			else if (optopt == 't')
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			else if (optopt == 'o')
				fprintf(stderr, "Option -%c requires an argument.\n", optopt);
			else
				fprintf(stderr,
						"Invalid Option\n%s [-r filename] [-i interface] [-t time] [-o time_offset]\n\n",
						argv[0]);
			exit(0);
		default:
			//fprintf(stdout, "%s [-r filename] [-i interface] [-t time] [-o time_offset]\n\n", argv[0]);
			exit(0);
		}
	}

	printf("Start Time %ld.%ld | End time: %ld.%ld | Interface: %s \n",
			opts.utime.tv_sec, opts.utime.tv_usec, opts.time_offset.tv_sec,
			opts.time_offset.tv_usec,
			(strcmp(opts.trace, "") == 0) ? opts.interface : opts.trace);


}

void * byte_flip(void * data, size_t len) {
	char * temp = (char *) data;
	char * res;

	res = (char*) malloc(len * sizeof(char));
	for (uint8_t i = 0; i < len; i++)
		res[len - i - 1] = temp[i];

	return (void *) res;
}

void handle_packet(u_char *user, const struct pcap_pkthdr *h,
		const u_char * packet) {

	struct data_packet ldata_packet;
	memset(&ldata_packet, 0, sizeof(ldata_packet));
	u_int16_t type = *((u_int16_t *) byte_flip((&((struct ether_header *) packet)->ether_type), sizeof(u_int16_t)));
	auto time_diff = (((h->ts.tv_sec - opts.utime.tv_sec) * 1000000L) + h->ts.tv_usec);
	auto offset =
			(opts.time_offset.tv_sec * 1000000L + opts.time_offset.tv_usec);

	if (time_diff <= offset && time_diff > 0) {
		if (type == ETHERTYPE_IP) {
			iphdr * ip_ptr;
			ip_ptr = (iphdr *) (packet + sizeof(ether_header));

			switch (ip_ptr->protocol) {
			case IPPROTO_ICMP:
				icmphdr * icmp_ptr;
				icmp_ptr = (icmphdr *) (packet + sizeof(ether_header) + sizeof(iphdr));
				char type_str[50];

				if (icmp_ptr->type == ICMP_ECHO)
					snprintf(type_str, 50, "echo request");
				else if (icmp_ptr->type == ICMP_ECHOREPLY)
					snprintf(type_str, 50, "echo reply");
				else
					snprintf(type_str, 50, "%d", icmp_ptr->type);

				snprintf(ldata_packet.sd.sadd,25, "%s", inet_ntoa(*((in_addr*) &(ip_ptr->saddr))));
				snprintf(ldata_packet.sd.dadd,25, "%s", inet_ntoa(*((in_addr*) &(ip_ptr->daddr))));
				ldata_packet.sd.sport = 0;
				ldata_packet.sd.dport = 0;
				ldata_packet.info.total_bytes = h->len;

				ldata_packet.state.icmp_type = icmp_ptr->type;

				ldata_packet.sd.protocol = ICMP;

				packet_queue.push(ldata_packet);

				break;
			case IPPROTO_TCP:
				tcphdr * tcp_ptr;
				tcp_ptr = (tcphdr *) (sizeof(ether_header) + sizeof(iphdr) + packet);

				snprintf(ldata_packet.sd.sadd, 25, "%s",
						inet_ntoa(*((in_addr*) &(ip_ptr->saddr))));
				snprintf(ldata_packet.sd.dadd, 25, "%s",
						inet_ntoa(*((in_addr*) &(ip_ptr->daddr))));
				ldata_packet.sd.sport = ntohs(tcp_ptr->source);
				ldata_packet.sd.dport = ntohs(tcp_ptr->dest);
				ldata_packet.info.total_bytes = h->len;

				ldata_packet.state.tcp_state.syn = (tcp_ptr->syn);
				ldata_packet.state.tcp_state.fin = (tcp_ptr->fin);
				ldata_packet.state.tcp_state.rst = (tcp_ptr->rst);
				ldata_packet.state.tcp_state.psh = (tcp_ptr->psh);
				ldata_packet.state.tcp_state.urg = (tcp_ptr->urg);
				ldata_packet.state.tcp_state.ack = (tcp_ptr->ack);


				ldata_packet.sd.protocol = TCP;

				packet_queue.push(ldata_packet);

				break;
			case IPPROTO_UDP:
				udphdr * udp_ptr;
				udp_ptr = (udphdr *) (sizeof(ether_header) + sizeof(iphdr) + packet);

				snprintf(ldata_packet.sd.sadd, 25, "%s", inet_ntoa(*((in_addr*) &(ip_ptr->saddr))));
				snprintf(ldata_packet.sd.dadd, 25, "%s", inet_ntoa(*((in_addr*) &(ip_ptr->daddr))));
				ldata_packet.sd.sport = ntohs(udp_ptr->source);
				ldata_packet.sd.dport = ntohs(udp_ptr->dest);

				ldata_packet.sd.protocol = UDP;
				ldata_packet.info.total_bytes = h->len;

				packet_queue.push(ldata_packet);

				break;
			default:
				break;
			}
		}
	}

	fflush(opts.file);
}

int main(int argc, char *argv[]) {
	// From http://www.tcpdump.org/pcap.html
	option_handler(argc, argv);


	thread pack_cntr(packet_counter_thread);
	thread printer(packet_printer_thread);

	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	dev = opts.interface;

	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return (2);
	}
//      printf("Device: %s\n", dev);

	if (strcmp(opts.trace, "") == 0) {
		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return (2);
		}
	} else {
//              printf("Opening trace file");
		handle = pcap_open_offline(opts.trace, errbuf);
		if (handle == NULL) {
			fprintf(stderr, "Couldn't open file %s: %s\n", opts.trace, errbuf);
			return (2);
		}
	}

	pcap_loop(handle, 0, handle_packet, NULL);

	return 0;
}
