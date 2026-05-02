
import sys
import struct
import math

def main():
    """
    Main function to parse pcap file and analyze TCP connections.
    Reads packet headers and data, extracts TCP connection info,
    and prints statistics about connections.
    """

    # -------------------------------------------------------
    # GLOBAL HEADER PARSING
    # Read the 24-byte pcap global header to determine
    # byte order (endianness) and timestamp precision
    # -------------------------------------------------------
 
    filename = sys.argv[1]
    with open(filename, 'rb') as f:
        
        global_header = f.read(24)
        if len(global_header)<24:
            raise ValueError("File too short to be a valid pcap file")
        

        # try little endian to read magic num
        magic, version_major,version_minor,thiszone,sigfigs,snaplen,network = \
            struct.unpack('<IHHIIII',global_header)
        

         # 0xa1b23c4d = nanosecond precision pcap (little-endian)
        if magic==0xa1b23c4d:
            endian='<'
            ts_multiplier=1e-9  #ns to sec

        # 0xd4c3b2a1 = big-endian pcap (microsecond precision)
        elif magic==0xd4c3b2a1:
            magic,version_major,version_minor,thiszone,sigfigs,snaplen,network=\
            struct.unpack('>IHHIIII',global_header)
            endian='>'
            ts_multiplier = 1e-6

        # 0xa1b2c3d4 = standard little-endian microsecond pcap
        else:
            endian='<'
            ts_multiplier = 1e-6

           
       

       
       
        # setting start time to null
        # timestamp of 1st packet 
        start_time_intial = None 


        #setting the mode to none
        mode = None

        src_ip = None   #source node IP;stored only once depending on each protocol
        dst_ip = None   #ultimate dst node IP;stored only once ;stored only once depending on each protocol
        track_routers= {}

        protocols_seen = set()  # unique protocol numbers seen in IP headers
        
        fragments={}    # {identification_number: {count, last_offset}} — fragment tracking


        #store outgoing probe packets 
        sent_packets = {} 


        #dictionary to store rtt value grouped by dets ip

        rtt_data = {}



        # -------------------------------------------------------
        # PACKET LOOP — process each packet in the pcap file
        # -------------------------------------------------------
        while True:
            packet_header = f.read(16)
            if len(packet_header)<16:
                break

            #EXTRACT TIMESTAMP
            ts_sec,ts_usec,incl_len,orig_len = struct.unpack(endian + 'IIII', packet_header)


            if incl_len==0:
                pass
               
          
            #READ PACKET DATA
            packet_data = f.read(incl_len)

            """
            extract timestamp
            """
            abs_time_packet1 = ts_sec+(ts_usec *ts_multiplier )#absolute time packet 1
            if start_time_intial is None:
                start_time_intial = abs_time_packet1
            relative_time = abs_time_packet1 -start_time_intial

            """
            ethernet and ip 
            """
            # change it to 34
            if len(packet_data)<34: 
                #sinceminimum ethernet is 14 bytes + Ip header is 20bytes
                continue

            dst_mac,src_mac,ethernet_type = struct.unpack('>6s6sH',packet_data[0:14])

            if ethernet_type != 0x800:  #ipv4= 0x800
                continue

            """
            parsing ip header
            """
            # minimum ihl
            ihl = (packet_data[14]&0x0F)*4  

            #protocol field at byte 9 of IP header
            protocol = packet_data[14+9]

            protocols_seen.add(protocol)

            ###New field

            #TTL is at byte 8  of IP header
            ttl = packet_data[14+8]

            #identification is at byte 4-5

            identification_number = struct.unpack(">H",packet_data[14+4:14+6])[0]
            flag_and_fragments_offset = struct.unpack(">H",packet_data[14+6:14+8])[0]

            mf_flag = ((flag_and_fragments_offset)>>13&0x1)  #mf flags bit13
            fragment_offset = ((flag_and_fragments_offset)&0x1FFF)*8


            """
            #Since icmp starts at end of ihl 
            #ihl ends at 14+ihl -1
            #at 0th byte of icmp is type 
            so 14+ihl
            """

            
            if(protocol==1):
                icmp_type = packet_data[14+ihl]
                #extract src and dest ip addresses

            src_ip_buffer1 = struct.unpack('BBBB',packet_data[14+12:14+16])
            dst_ip_buffer2 = struct.unpack('BBBB',packet_data[14+16:14+20])

            src_ip_val= '.'.join(str(b) for b in src_ip_buffer1)
            dst_ip_val = '.'.join(str(b) for b in dst_ip_buffer2)


            # ip total length ot of ethernet's length is H 
            ip_total_len = struct.unpack('>H', packet_data[14+2:14+4])[0]


            # -------------------------------------------------------
            # MODE DETECTION
            # Linux traceroute sends UDP probes (protocol 17)
            # Windows traceroute sends ICMP Echo Request probes (type 8)
            # Only detect once — first outgoing probe sets the mode
            # -------------------------------------------------------

            if mode is None:
                if (protocol==17): #UDP
                    mode ="linux"
                    if src_ip is None:
                        src_ip = src_ip_val
                        dst_ip = dst_ip_val

                    
                
                if(protocol==1 and icmp_type == 8): # ICMP Echo Request → Windows mode
                        mode="windows"
                        if src_ip is None:
                            src_ip = src_ip_val
                            dst_ip = dst_ip_val



            #checking for wrong packets to collect information abt ttls

            ##########===Fragmentation count
            
            if mode == 'linux' and protocol == 17 and src_ip_val == src_ip:
                if identification_number not in fragments:
                    fragments[identification_number] = {
                        "count": 1,
                        "last_offset": fragment_offset,
                        "seen_offsets": {fragment_offset}
                    }
                else:
                        if identification_number not in fragments:
                            fragments[identification_number] = {}
                            fragments[identification_number]["count"] = 1
                            fragments[identification_number]["last_offset"] = fragment_offset
                        else:
                            fragments[identification_number]["count"] += 1
                            if fragment_offset > fragments[identification_number]["last_offset"]:
                                fragments[identification_number]["last_offset"] = fragment_offset

            #check outgoing probes for udp
            if mode == 'linux' and protocol == 17:
                udp_header  = 14+ihl
                udp_src_port =  struct.unpack(">H",packet_data[udp_header:udp_header+2])[0]
                    
                sent_packets[udp_src_port] = (relative_time, ttl)

            
            if mode == 'windows' and protocol == 1 and icmp_type == 8:
                # Sequence number is at bytes 6-7 of ICMP header
                icmp_seq_num_pos= packet_data[14+ihl+6:14+ihl+8]
                icmp_seq_num_val = struct.unpack('>H',icmp_seq_num_pos)[0]
                sent_packets[icmp_seq_num_val] = (relative_time,ttl )


            # -------------------------------------------------------
            # LINUX RTT CALCULATION
            # ICMP type 11 = TTL exceeded (from intermediate routers)
            # ICMP type 3  = Port unreachable (from ultimate destination)
            # Both embed the original IP+UDP header inside them
            # Match via UDP source port from embedded UDP header
            # -------------------------------------------------------
            if mode=="linux" and protocol ==1  and (icmp_type ==11 or icmp_type==3):
                
                embedded_ip_header = 14+ihl+8
                embedded_ihl = (packet_data[embedded_ip_header]&0x0F)*4
                

                 # Update dst_ip from embedded destination (real traceroute target)
                embedded_dst_ip = '.'.join(str(b) for b in packet_data[embedded_ip_header+16:embedded_ip_header+20])
                dst_ip = embedded_dst_ip
                
                 # Extract UDP source port from embedded UDP header
                embedded_udp_header = embedded_ip_header +embedded_ihl
                embedded_udp_src_port = struct.unpack('>H',packet_data[embedded_udp_header:embedded_udp_header+2])[0]

                if embedded_udp_src_port in sent_packets:
                    send_time, org_ttl = sent_packets[embedded_udp_src_port]
                    rtt = relative_time-send_time
                    # embedded_dst_ip = '.'.join(str(b) for b in packet_data[embedded_ip_header+16:embedded_ip_header+20])
                    if org_ttl not in track_routers and src_ip_val!=dst_ip:
                        track_routers[org_ttl] = src_ip_val

                    if src_ip_val not in rtt_data:
                        rtt_data[src_ip_val]=[]
                    rtt_data[src_ip_val].append(rtt)


            # -------------------------------------------------------
            # WINDOWS RTT CALCULATION — Intermediate Routers
            # ICMP type 11 = TTL exceeded (from intermediate routers)
            # Embeds original IP+ICMP header — match via sequence number
            # -------------------------------------------------------

            if mode=="windows" and protocol ==1  and (icmp_type ==11):
                
                embedded_ip_header = 14+ihl+8
                embedded_ihl = (packet_data[embedded_ip_header]&0x0F)*4
                embedded_icmp_start = embedded_ip_header +embedded_ihl
                seq_nums = struct.unpack('>H',packet_data[embedded_icmp_start+6:embedded_icmp_start+8])[0]
                
                # Sequence number at bytes 6-7 of embedded ICMP header
                if seq_nums in sent_packets:
                    send_time,org_ttl = sent_packets[seq_nums]
                    rtt = relative_time - send_time
                    if org_ttl not in track_routers and src_ip_val!=dst_ip:
                        track_routers[org_ttl] = src_ip_val

                    if src_ip_val not in rtt_data:
                        rtt_data[src_ip_val]=[]
                    rtt_data[src_ip_val].append(rtt)

            # RTT CALCULATION for windowa ultimate destination

            # -------------------------------------------------------
            # WINDOWS RTT CALCULATION — Ultimate Destination
            # ICMP type 0 = Echo Reply (from ultimate destination)
            # No embedded packet — sequence number is directly in ICMP header
            # -------------------------------------------------------


            if mode=="windows" and protocol==1 and icmp_type==0:
                # now sequence nums for destination packet is not in embedded ip's udp/packets
                seq_nums = struct.unpack('>H',packet_data[14+ihl+6:14+ihl+8])[0]
                
                if seq_nums in sent_packets:
                    send_time, org_ttl = sent_packets[seq_nums]
                    rtt = relative_time - send_time

                    if src_ip_val not in rtt_data:
                        rtt_data[src_ip_val] = []
                    rtt_data[src_ip_val].append(rtt)

                    

            # -------------------------------------------------------
        # OUTPUT SECTION
        # Print all collected information in required format
        # -------------------------------------------------------
        
        print(f"The IP address of the source node: ", src_ip)
        print(f"The IP address of the destination node: ",dst_ip)


        
        print(f"The IP addresses of the intermediate destination nodes: ")
        counter = 1
        for ttl in sorted(track_routers.keys()):
            print(f"router {counter}: {track_routers[ttl]}")
            counter+= 1
                  
        # Intermediate routers sorted by TTL (hop count)
        print(f"The values in the protocol field of IP headers: ")
        protocol_names = {1: "ICMP",6:"TCP", 17: "UDP"}
        for p in sorted(protocols_seen):
            print(f"    {p}: {protocol_names[p]}")
            


        # Fragmentation info — only print fragmented datagrams (count > 1)
        
        fragmented = False

        for frag_id, frag_info in fragments.items():
            if frag_info["count"] > 1:   # fragmented datagram
                print(f"The number of fragments created from the original datagram is: {frag_info['count']}")
                print(f"The offset of the last fragment is: {frag_info['last_offset']}")
                fragmented = True
                break

        # fallback (ONLY if no fragmentation found)
        if not fragmented:
            print("The number of fragments created from the original datagram is: 1")
            print("The offset of the last fragment is: 0 bytes")


    
        # RTT average and standard deviation per destination IP
        # Using sample standard deviation (divide by N-1)
        for src_ip_val, rtt in rtt_data.items():
            avg = sum(rtt)/len(rtt) 
            std = math.sqrt(sum((x-avg)**2 for x in rtt)/(len(rtt)-1)) if len(rtt)>1 else 0
            avg_ms = avg*1000
            std_ms = std*1000
            print( f"The avg RTT between {src_ip} and {src_ip_val} is: {avg_ms:.2f} ms, the s.d. is: {std_ms:.2f} ms")

        



if __name__ == "__main__":
    main()