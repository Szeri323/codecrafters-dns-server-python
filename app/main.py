import socket


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    # Uncomment this block to pass the first stage
    #
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    #
    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            
            p_id = b"\x04\xd2" # Packet Identifier (ID) 16 bits
            p_qr = b"\x81" # Query/Response Indicator (QR) 1 bit
            p_opcode = b"\x80"
            p_aa = b""
            p_tc = b""
            p_rd = b""
            p_ra = b""
            p_z = b""
            p_rcode = b""
            p_qdcount = b"\x01"
            p_ancount = b""
            p_nscount = b""
            p_arcount = b""
            
            header = p_id + p_qr + p_opcode + b"\x00" + p_qdcount + b"\x00" + b"\x00" + (b"\x00" * 4)
            
            q_domain = b"\x0ccodecrafters\x02io\x00"
            q_type = b"\x00\x01"
            q_class = b"\x00\x01"
            
            questions = q_domain + q_type + q_class
            
            response = header + questions
            
            print(list(response))
            
            print(f"buf: {buf}")
            print(f"source: {source}")
            print(f"response: {response}")
    
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
