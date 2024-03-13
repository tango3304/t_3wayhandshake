# t_3wayhandshake
self-made 3way handshake module
自作3ウェイハンドシェイクモジュール

# Argument
◇Send Syn Packet Argument
Argument ([0]:My MACaddress [1]:The OtherPerson MACaddress [2]:My IPaddress [3]:The OtherPerson IPaddress [4]:My Interface [5]:The OtherPerson Port)
Return Value: Syn IntegerID
引数 ([0]:自身のMACアドレス [1]:相手のMACアドレス [2]:自身のIPアドレス [3]:相手のIPアドレス [4]:自身のインターフェース [5]:相手のポート)
戻り値: Syn 整数ID

◇Receive Syn/Ack Packet Argument
Argument ([0]:The OtherPerson MACaddress [1]:The OtherPerson IPaddress [2]:The OtherPerson Port [3]:My Interface)
Return Value: Receive IP/TCP header, Receive Source MACaddress
引数 ([0]:相手のMACアドレス [1]:相手のIPアドレス [2]:相手のポート [3]自身のインターフェース)
戻り値: 受信_IP/TCPヘッダ, 受信_送信元MACアドレス

◇Send Ack Packet Argument
Argument ([0]:Receive IP/TCP header [1]:My MACaddress [2]:Receive Source MACaddress [3]:Syn packet IntegerID [4]:My InterfaceSend)
Return Value: Ack IntegerID
引数 ([0]:受信_IP/TCPヘッダ [1]:自身のMACアドレス [2]:受信_送信元MACアドレス [3]:Synパケットの整数ID [4]:自身のインターフェース)
戻り値: Ack 整数ID
