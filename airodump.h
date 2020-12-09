#pragma once
#include <pcap.h>
#include <map>
#include <cstring>
#include <string>
#include <iostream>

#define SAME_MAC 6
#define TKIP 10
#define CCMP 11
#define MGT 12
#define PSK 13

#ifndef AIRODUMP
#define AIRODUMP

#endif // AIRODUMP

#pragma once

struct uint48 {
	unsigned long long v : 48;
}__attribute__((packed));           // and push pop
									//!(n1.v<n2.v) && !(n1.v>n2.v)
bool operator<(uint48 const& n1, uint48 const& n2)
{
	return n1.v < n2.v;
}
bool operator>(uint48 const& n1, uint48 const& n2)
{
	return n1.v > n2.v;
}

struct ieee80211_radiotap_header {
	u_int8_t it_version;
	u_int8_t it_pad;
	u_int16_t it_len;
	u_int32_t it_present;
	u_int8_t it_Flags;
	u_int8_t it_dataRate;
	u_int16_t it_channelfrequency;
	u_int16_t it_channelflags;
	int8_t it_Antennasignal;
	u_int8_t it_Antenna;
	u_int16_t it_Rxflags;
};

struct ieee80211_beacon_frame {
	u_int16_t j_Frame_control;
	u_int16_t j_Duration;
	uint48 j_Destination_address;
	uint48 j_Source_address;
	uint48 j_BSSID;
	u_int16_t j_SequenceControl;
};

struct data_map {
	int8_t it_Antennasignal;
	u_int8_t beacons = 1;
	u_int8_t sharp_data;
	u_int8_t sharp_s;
	u_int16_t channel;
	u_int8_t MB;
	u_int8_t encrypt;
	u_int8_t cipher;
	u_int8_t auth;
	char ESSID[32];
};

struct tag_ssid {
	u_int8_t tag_number;
	u_int8_t tag_length;
	char SSID[32];
};

struct thread_data {
	pcap_t *handle;
};

