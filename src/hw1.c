#include "hw1.h"

unsigned int get_source_address(unsigned char packet[]) {
    unsigned int source_address = ((packet[0] << 24) | (packet[1] << 16) | (packet[2] << 8) | (packet[3])) >> 4;
    return source_address;
}

unsigned int get_dest_addr(unsigned char packet[]) {
    unsigned int dest_addr = ((packet[3] & 0x0F) << 24) | (packet[4] << 16) | (packet[5] << 8) | (packet[6]);
    return dest_addr;
}

unsigned int get_source_port(unsigned char packet[]) {
    unsigned int source_port = packet[7] >> 4;
    return source_port;
}

unsigned int get_dest_port(unsigned char packet[]) {
    unsigned int dest_port = packet[7] & 0x0F;
    return dest_port;
}

unsigned int get_fragment_offset(unsigned char packet[]) {
    unsigned int fragment_offset = (packet[8] << 6) | (packet[9] >> 2);
    return fragment_offset;
}

unsigned int get_packet_length(unsigned char packet[]) {
    unsigned int packet_length = ((packet[9] & 0x03) << 12) | (packet[10] << 4) | (packet[11] >> 4);
    return packet_length;
}

unsigned int get_maximum_hop_count(unsigned char packet[]) {
    unsigned int maximum_hop_count = ((packet[11] & 0x0F) << 1) | (packet[12] >> 7); // originally had (packet[12] & 1 << 7) >> 7, realized it's redundant. ask TA if there are any other cases like this in my code
    return maximum_hop_count;
}

unsigned int get_checksum(unsigned char packet[]) {
    unsigned int checksum = ((packet[12] & 127) << 16) | (packet[13] << 8) | (packet[14]); // ask if 127 is allowed instead of hex format
    return checksum;
}

unsigned int get_compression_scheme(unsigned char packet[]) {
    unsigned int compression_scheme = (packet[15] >> 6);
    return compression_scheme;
}

unsigned int get_traffic_class(unsigned char packet[]) {
    unsigned int traffic_class = packet[15] & 63;
    return traffic_class;
}

int get_payload_length(unsigned char packet[]) {
    int payload_length = get_packet_length(packet) - 16;
    return payload_length;
}

int get_payload_value(unsigned char packet[], int start_index) {
    int value = (packet[start_index] << 24) | (packet[start_index + 1] << 16) | (packet[start_index + 2] << 8) | packet[start_index + 3];
    return value;
}

void print_payload(unsigned char packet[]) {
    int payload_length = get_payload_length(packet);
    printf("Payload: ");
    for (int i = 0; i < payload_length; i += 4) {
        int payload_value = get_payload_value(packet, 16 + i);
        printf("%d", payload_value);
        if (i < payload_length - 4) {
            printf(" ");
        }
    }
    printf("\n");
}

int get_payload_sum(unsigned char packet[]) {
    int payload_length = get_payload_length(packet);
    int sum = 0;
    for (int i = 0; i < payload_length; i += 4) {
        int payload_value = get_payload_value(packet, 16 + i);
        sum += abs(payload_value);
    }

    return sum;
}

// int get_payload(unsigned char packet[]) {
//     int payload_length = get_packet_length(packet) - 16; 
//     for (int i = 0; i < payload_length;
// }



void print_packet_sf(unsigned char packet[])
{   printf("Source Address: %d\n", get_source_address(packet));
    printf("Destination Address: %d\n", get_dest_addr(packet));
    printf("Source Port: %d\n", get_source_port(packet));
    printf("Destination Port: %d\n", get_dest_port(packet));
    printf("Fragment Offset: %d\n", get_fragment_offset(packet));
    printf("Packet Length: %d\n", get_packet_length(packet));
    printf("Maximum Hop Count: %d\n", get_maximum_hop_count(packet));
    printf("Checksum: %d\n", get_checksum(packet));
    printf("Compression Scheme: %d\n", get_compression_scheme(packet));
    printf("Traffic Class: %d\n", get_traffic_class(packet));
    print_payload(packet);

    // printf("Source Address: %d\n", get_source_address(packet));
    
    // unsigned int dest_addr = ((packet[3] & 0x0F) << 24) | (packet[4] << 16) | (packet[5] << 8) | (packet[6]);  
    // printf("Destination Address: %d\n", dest_addr);

    // unsigned int source_port = packet[7] >> 4;
    // printf("Source Port: %d\n", source_port);

    // unsigned int dest_port = packet[7] & 0x0F;
    // printf("Destination Port: %d\n", dest_port);

    // unsigned int fragment_offset = (packet[8] << 6) | (packet[9] >> 2);
    // printf("Fragment Offset: %d\n", fragment_offset);

    // unsigned int packet_length = ((packet[9] & 0x03) << 12) | (packet[10] << 4) | (packet[11] >> 4);
    // printf("Packet Length: %d\n", packet_length);

    // unsigned int maximum_hop_count = ((packet[11] & 0x0F) << 1) | (packet[12] >> 7); // originally had (packet[12] & 1 << 7) >> 7, realized it's redundant. ask TA if there are any other cases like this in my code
    // printf("Maximum Hop Count: %d\n", maximum_hop_count);

    // unsigned int checksum = ((packet[12] & 127) << 16) | (packet[13] << 8) | (packet[14]); // ask if 127 is allowed instead of hex format
    // printf("Checksum: %d\n", checksum);

    // unsigned int compression_scheme = (packet[15] >> 6);
    // printf("Compression scheme: %d\n", compression_scheme);

    // unsigned int traffic_class = packet[15] & 63;
    // printf("Traffic Class: %d\n", traffic_class);

    // int payload_length = packet_length - 16;
    // for 


    // unsigned int fragment_offset = ((packet[7] & 0x0F) << 14 | (packet[8] << 6) | (packet[9]));
}

unsigned int compute_checksum_sf(unsigned char packet[])
{   unsigned int sum = get_source_address(packet) + get_dest_addr(packet) + get_source_port(packet) + get_dest_port(packet) + get_fragment_offset(packet) +
        get_packet_length(packet) + get_maximum_hop_count(packet) + get_compression_scheme(packet) + get_traffic_class(packet) + get_payload_sum(packet);
    
    unsigned int checksum = sum % 8388607;

    return checksum;

}

unsigned int reconstruct_array_sf(unsigned char *packets[], unsigned int packets_len, int *array, unsigned int array_len) {
    (void)packets;
    (void)packets_len;
    (void)array;
    (void)array_len;
    return -1;
}

unsigned int packetize_array_sf(int *array, unsigned int array_len, unsigned char *packets[], unsigned int packets_len,
                          unsigned int max_payload, unsigned int src_addr, unsigned int dest_addr,
                          unsigned int src_port, unsigned int dest_port, unsigned int maximum_hop_count,
                          unsigned int compression_scheme, unsigned int traffic_class)
{
    (void)array;
    (void)array_len;
    (void)packets;
    (void)packets_len;
    (void)max_payload;
    (void)src_addr;
    (void)dest_addr;
    (void)src_port;
    (void)dest_port;
    (void)maximum_hop_count;
    (void)compression_scheme;
    (void)traffic_class;
    return -1;
}
