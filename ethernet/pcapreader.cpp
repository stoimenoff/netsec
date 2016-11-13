#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <sstream>
#include <stdint.h>
#include <pcap.h>
#include <netinet/in.h>

using std::cout;
using std::endl;
using std::vector;
using std::string;
using std::stringstream;
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

int main(int argc, char* argv[])
{
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
	ethernet_header *ethernet;

	while(packet = pcap_next(packets, &pcapLines))
	{
		ethernet = (ethernet_header*)(packet);
		cout << formatMacAddress(ethernet->destination_address) << " ";
		cout << formatMacAddress(ethernet->source_address) << " ";
		cout << formatEthernetType(ethernet->type) << endl;
	}

	pcap_close(packets);

	return 0;
}
