#include <pcap/pcap.h>
#include <unistd.h>
#include <stdlib.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <string.h>
#include <iostream>
#include <mutex>

#include <queue>
#include <thread>

#ifndef SNIFFER_H
#define SNIFFER_H

struct sniffer_opt {
	char trace[100];
	char interface[50];
	struct timeval utime;
	struct timeval time_offset;
	FILE * file;
	int num_flows;
	int flow_timeout;
} opts;

enum protocol_counter {
	ICMP = 0, UDP, TCP
};

struct data_packet {
	struct timeval rtime;

	struct _sd {
		char sadd[25];
		char dadd[25];
		int sport;
		int dport;
		enum protocol_counter protocol;
	} sd;

	union {
		struct _tcp_state {
			u_int16_t res1 :4;
			u_int16_t doff :4;
			u_int16_t fin :1;
			u_int16_t syn :1;
			u_int16_t rst :1;
			u_int16_t psh :1;
			u_int16_t ack :1;
			u_int16_t urg :1;
			u_int16_t res2 :2;
		} tcp_state;
		u_int8_t icmp_type;
	} state;

	struct _info {
		long int total_packets;
		long int total_bytes;
	} info;
};

std::queue<struct data_packet> packet_queue;

std::vector<struct data_packet> g_results;

#endif // SNIFFER_H
