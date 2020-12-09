#include <stdio.h>
#include <iostream>
#include <pcap.h>
#include <pthread.h>
#include <arpa/inet.h> // ntohs
#include <time.h>      
#include <stdlib.h>     // system, strtol
#include <unistd.h>     //sleepr
#include <map>          //map
#include <cstring>     //memcpy
#include "airodump.h"

using namespace std;

static struct data_map data;
static std::map<uint48, data_map > m;

void mac(uint48 mac_addr)
{
	u_int8_t *ptr = reinterpret_cast<u_int8_t*>(&mac_addr);
	printf("%02x:%02x:%02x:%02x:%02x:%02x ", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);
}

void *display(void* a)
{
	time_t t = time(nullptr);
	struct tm tm = *localtime(&t);
	while (true)
	{

		printf("CH: 3 || %d-%d-%d %d:%d \n", tm.tm_year + 1900, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min);
		printf("BSSID               PWR     Beacons  CH  MB  ENC  CIPHER  AUTH   ESSID\n");
		printf("----------------------------------------------------------------------\n");
		for (auto it = m.begin(); it != m.end(); ++it)
		{
			mac(it->first);
			printf("%5d ", it->second.it_Antennasignal);
			printf("%10d ", it->second.beacons);
			printf("%4d ", it->second.channel);
			if (it->second.cipher == CCMP)
			{
				printf("    WPA2");
				printf("    CCMP");
			}
			else if (it->second.cipher == TKIP)
			{
				printf("    WPA");
				printf("    TKIP");
			}
			else
			{
				printf("     OPN");
				printf("        ");
			}

			if (it->second.auth == PSK)
				printf("  PSK  ");
			else if (it->second.auth == MGT)
				printf("  MGT  ");
			else
				printf("       ");

			for (int i = 0; i<32; i++)
				printf("%c", it->second.ESSID[i]);

			printf("\n");
		}
		sleep(1);
		system("clear");
	}

}

void *save_data(void * arg)
{
	char errbuf[PCAP_ERRBUF_SIZE];      //size 256
	pcap_t* handle = pcap_open_live("wlan1", BUFSIZ, 1, 100, errbuf);
	//struct thread_data * data =(struct thread_data *)arg;             //?
	//pcap_t *handle = data->handle;
	while (true)
	{
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		struct ieee80211_radiotap_header *radiotap_header = (struct ieee80211_radiotap_header *)packet;
		if (radiotap_header->it_len == 0x000d) continue;         //len 13: only tcpreplay code
		struct ieee80211_beacon_frame * beacon_header = (struct ieee80211_beacon_frame *)(packet + radiotap_header->it_len);
		struct tag_ssid * ssid = (struct tag_ssid *)(packet + radiotap_header->it_len + 24 + 12);       // 24: beacon length ,12 fixed parameters length

		const u_int8_t * point = (packet + radiotap_header->it_len + 24 + 12);

		if (ntohs(beacon_header->j_Frame_control) == 0x8000)
		{

			m.insert(std::make_pair(beacon_header->j_BSSID, data));   
			uint16_t channel = ((radiotap_header->it_channelfrequency - 2412) / 5 + 1);
			map<uint48, data_map>::iterator iter;
			iter = m.find(beacon_header->j_BSSID);
			if (iter != m.end())
			{
				for (int i = 0; i<ssid->tag_length; i++)
					memcpy(&iter->second.ESSID[i], &ssid->SSID[i], 1);

				memcpy(&iter->second.it_Antennasignal, &radiotap_header->it_Antennasignal, 1);
				memcpy(&iter->second.channel, &channel, 1);
				++iter->second.beacons;

				int a = 0;
				while (true)
				{
					if (*(point) == 0x30)                //RSN number
					{
						if (*(point + 8) == 0x02)          //pairwise suite count : 1
							a = 4;

						switch (*(point + 13 + a))         //Cipher_Suite_type :
						{
						case 2:
						{
							iter->second.cipher = TKIP;
							break;
						}
						case 4:
						{
							iter->second.cipher = CCMP;
							break;
						}
						default:
							break;


						}

						switch (*(point + 19 + a))         //AKM type:
						{
						case 1:
						{
							iter->second.auth = MGT;
							break;
						}
						case 2:
						{
							iter->second.auth = PSK;
							break;
						}
						default:
							break;
						}

						break;
					}
					point += *(point + 1) + 2;        //point+1 = tag length
					if (*(point) == '\0')         // not found
						break;
				}

			}
		}
	}
}

void usage() {
	printf("syntax: airodump <interface>\n");
	printf("sample: airodump mon0\n");
}

int main(int argc, char* argv[])
{
	if (argc != 2) {
		usage();
		return -1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];      //size 256
	const char *dev = argv[1];

	pcap_t* handle = pcap_open_live("mon0", BUFSIZ, 1, 100, errbuf);
	if (handle == nullptr)
	{
		int i = 0;
		while (i <= 5)
		{
			if (handle != nullptr)
				break;
			i++;
		}
		if (i == 5)
		{
			printf("error.\n");
			return -1;
		}
	}

	pthread_t display_thread, back_thread;
	struct thread_data * data = static_cast<thread_data *>(malloc(sizeof(thread_data)));
	data->handle = handle;
	pthread_create(&display_thread, nullptr, display, nullptr);
	pthread_create(&back_thread, nullptr, save_data, static_cast<void*>(data));
	int x = 0;
	while (true)
	{
		scanf("%d", &x);
		if (x == 1) return 0;
	}
}