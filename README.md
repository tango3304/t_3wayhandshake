# Outline
self-made 3way handshake module<br>
Check Execution on Manjaro

# Install
pip install git+https://github.com/tango3304/t_3wayhandshake.git

# Argument
<h3>◆Send Receive Packet Argument</h3>

【Argument】<br>
[0]:My MACaddress<br>
[1]:The OtherPerson MACaddress<br>
[2]:My IPaddress<br>
[3]:The OtherPerson IPaddress<br>
[4]:My Interface<br>
[5]:The OtherPerson Port<br>

【Return Value】<br>
Syn IntegerID, Receive IP/TCP header, The OtherPercon MACaddress<br>

<h3>◆Send Ack Packet Argument</h3>
【Argument】<br>
[0]:Receive IP/TCP header<br>
[1]:My MACaddress<br>
[2]:The OtherPerson MACaddress<br>
[3]:Syn packet IntegerID<br>
[4]:My InterfaceSend)<br>

<br>【Return Value】<br>
Ack IntegerID<br>

# 概要
自作3ウェイハンドシェイクモジュール<br>
Manjaroでの実行を確認<br>

# インストール
pip install git+https://github.com/tango3304/t_3wayhandshake.git

# 引数
<h3>◇送受信パケットの引数</h3>
【引数】<br>
[0]:自身のMACアドレス<br>
[1]:相手のMACアドレス<br>
[2]:自身のIPアドレス<br>
[3]:相手のIPアドレス<br>
[4]:自身のインターフェース<br>
[5]:相手のポート<br>

<br>【戻り値】<br>
Syn 整数ID、受信IP/TCPヘッダ、相手のMACアドレス<br>

<h3>◇送信 Ackパケット引数</h3>
【引数】<br>
[0]:受信_IP/TCPヘッダ<br>
[1]:自身のMACアドレス<br>
[2]:相手のMACアドレス<br>
[3]:Synパケットの整数ID<br>
[4]:自身のインターフェース<br>

<br>【戻り値】<br>
Ack 整数ID<br>
