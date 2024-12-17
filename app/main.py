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
            
            pid = 1234
            qr = 1
            opcode = 0
            aa = 0
            tc = 0
            rd = 0
            ra = 0
            z = 0
            rcode = 0
            qdcount = 0
            ancount = 0
            nscount = 0
            arcount = 0
            dns_header = f"{pid}{qr}{opcode}{aa}{tc}{rd}{ra}{z}{rcode}{qdcount}{ancount}{nscount}{arcount}"
            

            dns_message = f"{dns_header}"
            
            response = bytes(dns_header, encoding="utf-8")
            
            print(f"buf: {buf}")
            print(f"source: {source}")
            print(f"response: {response}")
    
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
