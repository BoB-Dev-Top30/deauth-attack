#include <stdio.h>
#include <string.h>

int check_deauth_input(int argc, char * argv[])
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
            printf("<ap_mac> %s Broadcast\n", argv[2]);
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
