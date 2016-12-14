#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <sstream>
#include <bitset>
#include <stdint.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

using std::cout;
using std::endl;
using std::vector;
using std::string;
using std::stringstream;
using std::bitset;
using std::hex;
using std::showbase;
using std::noshowbase;
using std::setfill;
using std::setw;
using std::dec;


int const MAC_ADDRESS_LENGTH = 6;
struct ethernet_header
{
	uint8_t destination_address[MAC_ADDRESS_LENGTH];
	uint8_t source_address[MAC_ADDRESS_LENGTH];
	uint16_t type;
};

string formatEthernetType(uint16_t ethernetType)
{
	stringstream formated;
	formated << "0x" << setfill('0') << setw(4) << hex << ntohs(ethernetType);
	// __builtin_bswap16(ethernetType);
	return formated.str();
}

string formatMacAddress(uint8_t* addressStart)
{
	stringstream formated;
	for (int i = 0; i < MAC_ADDRESS_LENGTH; ++i)
	{
		formated << setfill('0') << setw(2) << hex << int(addressStart[i]);
		if(i != MAC_ADDRESS_LENGTH - 1)
		{
			 formated << ":";
		}
	}
	return formated.str();
}

string formatIP(uint32_t ip)
{
	stringstream formated;
	formated << ((ip >> 24) & 0xff) << ".";
	formated << ((ip >> 16) & 0xff) << ".";
	formated << ((ip >> 8) & 0xff) << ".";
	formated << (ip & 0xff);
	return formated.str();
}

bool xmas(tcphdr* tcp)
{
	#define XMAS_FLAGS 0b00101001
	return tcp->th_flags == XMAS_FLAGS;
	// return tcp->th_flags == XMAS_FLAGS && ((tcp->th_x2 & 1) == 0);
}

bool null(tcphdr* tcp)
{
	return tcp->th_flags == 0;
	// return tcp->th_flags == 0 && ((tcp->th_x2 & 1) == 0);
}

bool validIPChecksum(const uint8_t* ip_packet, size_t length)
{
	const uint16_t* ip = (const uint16_t*)ip_packet;
	length /= 2;
	uint32_t sum = 0;
	for (int i = 0; i < length; ++i)
	{
		sum += ntohs(ip[i]);
	}
	while(sum >> 16)
	{
		sum = (sum >> 16) + (sum & 0xFFFF);
	}
	return sum == 0xFFFF;
}

bool validTCPChecksum(ip *ip_packet, const uint8_t* tcp_segment)
{
	uint16_t tcp_size = ntohs(ip_packet->ip_len) - (ip_packet->ip_hl * 4);
	uint32_t sum = 0;

	sum += (ntohl(ip_packet->ip_src.s_addr) & 0xFFFF);
	sum += (ntohl(ip_packet->ip_src.s_addr) >> 16);

	sum += (ntohl(ip_packet->ip_dst.s_addr) & 0xFFFF);
	sum += (ntohl(ip_packet->ip_dst.s_addr) >> 16);

	sum += ip_packet->ip_p;
	sum += tcp_size;

	uint16_t* tcp = (uint16_t*)tcp_segment;
	for (int i = 0; i < tcp_size / 2; ++i)
	{
		sum += ntohs(tcp[i]);
	}
	if(tcp_size & 1)
	{
		// padding
		sum += (tcp_segment[tcp_size - 1] << 8);
	}
	while(sum >> 16)
	{
		sum = (sum >> 16) + (sum & 0xFFFF);
	}
	return sum == 0xFFFF;
}

void printEthernetInfo(ethernet_header *ethernet)
{
	cout << formatMacAddress(ethernet->source_address) << " ";
	cout << formatMacAddress(ethernet->destination_address) << " ";
	cout << formatEthernetType(ethernet->type) << " ";
}

void printIpInfo(ip* ip_packet)
{
	cout << formatIP(ntohl(ip_packet->ip_src.s_addr)) << " ";
	cout << formatIP(ntohl(ip_packet->ip_dst.s_addr)) << " ";
	cout << (int)ip_packet->ip_p << " ";
}

void printTcpInfo(tcphdr* tcp)
{
	cout << ntohs(tcp->th_sport) << " " << ntohs(tcp->th_dport);
	if(null(tcp))
		cout << " Null";
	if(xmas(tcp))
		cout << " Xmas";
}

int main(int argc, char* argv[])
{
	if(argc < 2)
	{
		cout << "No filename found." << endl;
		return -1;
	}
	const char* pcapfile = argv[1];
	char errorBuffer[PCAP_ERRBUF_SIZE] = {};

	pcap_pkthdr pcapLines;
	pcap_t* packets;

	packets = pcap_open_offline(pcapfile, errorBuffer);

	if(packets == NULL)
	{
		cout << "An error occured while opening the file." << endl;
		cout << errorBuffer << endl;
		return -1;
	}

	const uint8_t* packet;
	const uint8_t* ip_start;
	const uint8_t* tcp_start;
	ethernet_header *ethernet;
	ip *ip_packet;
	size_t ip_header_size = 0;
	tcphdr *tcp;

	while(packet = pcap_next(packets, &pcapLines))
	{
		ethernet = (ethernet_header*)(packet);

		ip_start = packet + 2 * MAC_ADDRESS_LENGTH + 2;
		ip_packet = (ip*)(ip_start);
		ip_header_size = ip_packet->ip_hl * 4;

		tcp_start = ip_start + ip_header_size;
		tcp = (tcphdr*)(tcp_start);


		if(ntohs(ethernet->type) != 0x0800)
		{
			continue;
		}
		else if(!validIPChecksum(ip_start, ip_header_size))
		{
			printEthernetInfo(ethernet);
			cout << "bad_csum" << endl;
		}
		else if(ip_packet->ip_p != 6)
		{
			continue;
		}
		else if(!validTCPChecksum(ip_packet, tcp_start))
		{
			printEthernetInfo(ethernet);
			printIpInfo(ip_packet);
			cout << "bad_csum" << endl;
		}
		else if(null(tcp) || xmas(tcp))
		{
			printEthernetInfo(ethernet);
			printIpInfo(ip_packet);
			printTcpInfo(tcp);
			cout << endl;
		}

	}

	pcap_close(packets);

	return 0;
}
