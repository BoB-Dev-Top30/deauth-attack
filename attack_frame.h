#include <cstdint>
#include <pcap.h>

typedef struct{
    uint8_t header_revision;
    uint8_t header_pad;
    uint16_t header_length;

    // 시간 남으면 고정에서 가변으로 자세하게 제작 예정
    uint32_t present_flags[2];
    // 첫번째 시작
    uint8_t flags;
    uint8_t data_rate;
    uint16_t channel_frequency;
    uint16_t channel_flags;
    uint8_t antenna_signal1;
    uint8_t empty_field;
    // 두번째 시작 
    uint16_t rx_flags;
    uint8_t antenna_signal2;
    uint8_t antenna;
}Radiotap_Header;//24

typedef struct{
    uint16_t frame_control_field;
    uint16_t duration;
    
    uint8_t destination_address[6];
    uint8_t source_address[6];
    uint8_t bss_id[6]; 

    uint16_t fragment_sequence;
}Deauthentication_Main_Frame; // 24

typedef struct{
    uint16_t reason_code; // 2
}Wireless_Management;

// 최종프레임
typedef struct{
    Radiotap_Header radiotap_header;
    Deauthentication_Main_Frame deauthentication_main_frame;
    Wireless_Management wireless_management;
} __attribute__((packed)) Deauthentication_Frame;

void send_packet(Deauthentication_Frame frame, pcap_t *handle);
void send_deauth_broadcast(Deauthentication_Frame frame, pcap_t *handle, char * argv[]);
void send_deauth_to_bidirection(Deauthentication_Frame frame, pcap_t *handle, char *argv[]);