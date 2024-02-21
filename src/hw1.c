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

unsigned int get_payload_length(unsigned char packet[]) {
    unsigned int payload_length = get_packet_length(packet) - 16;
    return payload_length;

}

int get_payload_value(unsigned char packet[], int start_index) {
    int value = (packet[start_index] << 24) | (packet[start_index + 1] << 16) | (packet[start_index + 2] << 8) | packet[start_index + 3];
    return value;

}

void print_payload(unsigned char packet[]) {
    unsigned int payload_length = get_payload_length(packet);
    printf("Payload: ");

    for (unsigned int i = 0; i < payload_length; i += 4) {
        int payload_value = get_payload_value(packet, 16 + i);
        printf("%d", payload_value);

        if (i < payload_length - 4) {
            printf(" ");
        }
    }
    printf("\n");

}

unsigned int get_payload_sum(unsigned char packet[]) {
    unsigned int payload_length = get_payload_length(packet); 
    unsigned int sum = 0;

    for (unsigned int i = 0; i < payload_length; i += 4) { 
        int payload_value = get_payload_value(packet, 16 + i); 
        sum += abs(payload_value);
    }
    return sum;
}

// int get_payload(unsigned char packet[]) {
//     int payload_length = get_packet_length(packet) - 16; 
//     for (int i = 0; i < payload_length;
// }

void print_packet_sf(unsigned char packet[]) {   
    printf("Source Address: %d\n", get_source_address(packet));
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
    // for   unsigned int fragment_offset = ((packet[7] & 0x0F) << 14 | (packet[8] << 6) | (packet[9]));
}

unsigned int compute_checksum_sf(unsigned char packet[]) {
    unsigned int sum = get_source_address(packet) + get_dest_addr(packet) + get_source_port(packet) + get_dest_port(packet) + get_fragment_offset(packet) +
        get_packet_length(packet) + get_maximum_hop_count(packet) + get_compression_scheme(packet) + get_traffic_class(packet) + get_payload_sum(packet);
    
    unsigned int checksum = sum % 8388607;

    return checksum;

}

unsigned int reconstruct_array_sf(unsigned char *packets[], unsigned int packets_len, int *array, unsigned int array_len) {
    unsigned int values_recovered = 0;

    for (unsigned int i = 0; i < packets_len; i++) {
        unsigned int checksum_field = get_checksum(packets[i]);
        unsigned int checksum_value = compute_checksum_sf(packets[i]);
        
        if (checksum_field != checksum_value) {
            continue;
        }

        unsigned int fragment_offset = get_fragment_offset(packets[i]) / 4;
        
        int payload_length = get_payload_length(packets[i]);
        unsigned int num_payload_values = payload_length / 4; 

        for (unsigned int j = 0; j < num_payload_values; j++) {
            if (fragment_offset + j >= array_len) {
                break;
            }

            int payload_value = get_payload_value(packets[i], 16 + j * 4);
            array[fragment_offset + j] = payload_value;
            values_recovered++;
        }
    }
    return values_recovered;

}
// remember to make set checksum
void set_header_fields(unsigned char *packet, unsigned int src_addr, unsigned int dest_addr, 
                      unsigned int src_port, unsigned int dest_port, unsigned int fragment_offset, 
                      unsigned int packet_size, unsigned int maximum_hop_count, 
                      unsigned int compression_scheme, unsigned int traffic_class);

void set_checksum(unsigned char *packet, unsigned int checksum);

unsigned int packetize_array_sf(int *array, unsigned int array_len, unsigned char *packets[], unsigned int packets_len,
                          unsigned int max_payload, unsigned int src_addr, unsigned int dest_addr,
                          unsigned int src_port, unsigned int dest_port, unsigned int maximum_hop_count,
                          unsigned int compression_scheme, unsigned int traffic_class)
{
    unsigned int payload_size = max_payload / sizeof(int);
    unsigned int total_packets = (array_len + payload_size - 1) / payload_size;
    unsigned int packets_generated = 0;

    for (unsigned int i = 0; i < total_packets && i < packets_len; i++) {
        unsigned int current_payload_size; // in bytes ***

        // figure out current payload size
        if (i < total_packets - 1) {
            current_payload_size = payload_size * sizeof(int);
        } else {
            unsigned int remaining_integers = array_len % payload_size;
            if (remaining_integers == 0) {
                current_payload_size = payload_size * sizeof(int);
            } else {
                current_payload_size = remaining_integers * sizeof(int);
            }
        }
        if (current_payload_size == 0) current_payload_size = payload_size * sizeof(int); 
        
        // allocate memoory
        unsigned int packet_size = 16 + current_payload_size;
        packets[i] = (unsigned char *)malloc(packet_size);

        // header
        set_header_fields(packets[i], src_addr, dest_addr, src_port, dest_port, i * payload_size * sizeof(int), packet_size, maximum_hop_count, compression_scheme, traffic_class);

        // payload
        for (unsigned int j = 0; j < current_payload_size / sizeof(int); j++) {
            int payload_index = 16 + j * 4;
            int value = array[i * payload_size + j];
            packets[i][payload_index] = (value >> 24) & 0xFF;
            packets[i][payload_index + 1] = (value >> 16) & 0xFF;
            packets[i][payload_index + 2] = (value >> 8) & 0xFF;
            packets[i][payload_index + 3] = value & 0xFF;
        }

        // checksum
        unsigned int checksum = compute_checksum_sf(packets[i]); 
        set_checksum(packets[i], checksum);

        packets_generated++;
    }

    return packets_generated;
}

void set_header_fields(unsigned char *packet, unsigned int src_addr, unsigned int dest_addr, 
                      unsigned int src_port, unsigned int dest_port, unsigned int fragment_offset, 
                      unsigned int packet_length, unsigned int maximum_hop_count, 
                      unsigned int compression_scheme, unsigned int traffic_class) {
 
    // source address
    packet[0] = (src_addr >> 20) & 0xFF;
    packet[1] = (src_addr >> 12) & 0xFF;
    packet[2] = (src_addr >> 4) & 0xFF;
    packet[3] = ((src_addr & 0xF) << 4) | ((dest_addr >> 24) & 0xF);
    
    // dest address
    packet[4] = (dest_addr >> 16) & 0xFF;
    packet[5] = (dest_addr >> 8) & 0xFF;
    packet[6] = dest_addr & 0xFF;
    
    // source + dest port
    packet[7] = (src_port << 4) | (dest_port & 0xF);
    
    // frag offset + packet length
    packet[8] = (fragment_offset >> 6) & 0xFF;
    packet[9] = (fragment_offset & 0x3F) << 2;

    packet[9] |= (packet_length >> 12) & 0x03;
    packet[10] = (packet_length >> 4) & 0xFF;
    packet[11] = (packet_length & 0x0F) << 4;
    
    // max hop count
    packet[11] |= (maximum_hop_count >> 1) & 0x0F;
    packet[12] = (maximum_hop_count & 0x01) << 7;

    // comp scheme
    packet[15] = compression_scheme << 6;
    
    // traffic class
    packet[15] |= traffic_class & 0x3F;

    // packet[11] = ((maximum_hop_count << 3) & 0xF8) | ((compression_scheme << 1) & 0x06) | ((traffic_class >> 5) & 0x01);
    // packet[12] = traffic_class & 0x1F;

}

void set_checksum(unsigned char *packet, unsigned int checksum) {
        packet[12] |= (checksum >> 16) & 0x7f;
        packet[13] = (checksum >> 8) & 0xFF;
        packet[14] = (checksum & 0xFF);
}
