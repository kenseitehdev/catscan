#ifndef MON_HARDWARE_H
#define MON_HARDWARE_H
/* Platform hardware snapshot; a missing value is not equivalent to zero. */
typedef struct {
    int wifi_available, wifi_rssi, wifi_noise, wifi_tx_mbps, wifi_channel_valid;
    char wifi_ssid[96], wifi_channel[48], wifi_status[128];
    int bt_available, bt_powered, bt_connected;
    char bt_status[128];
    int battery_available, battery_pct, battery_minutes, charging, on_ac;
    char battery_status[128];
    int thermal_available, temperature_available;
    double cpu_temperature_c;
    char thermal_state[48], thermal_status[128], model[128];
    unsigned long wifi_samples;
} MonHardware;
int mon_hardware_start(void);
void mon_hardware_snapshot(MonHardware *out);
void mon_hardware_stop(void);
int mon_hardware_self_test(void);
#endif
