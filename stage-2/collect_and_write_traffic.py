import socket

with socket.socket(socket.AF_INET, socket.SOCK_RAW) as my_socket:
    my_socket.bind(("127.0.0.1", 5733))
    my_socket.listen()
    client, _ = my_socket.accept()
    with open('local.txt', 'wb') as my_file:
        while True:
            data = client.recv(1000000)
            if len(data) == 0:
                client.close()
                break
            my_file.write(data)
