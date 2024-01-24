
void start_monitor_mode(char *interface);
int choose_deauth(int argc, char * argv[]);
void convert_mac_address(const char* mac_str, char* mac_bytes);
void fill_frame(Deauthentication_Frame & frame);