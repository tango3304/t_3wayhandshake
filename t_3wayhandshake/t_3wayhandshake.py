#Coding UTF-8
from sys import exit, exc_info
from traceback import format_exception_only
from random import randint
import socket
from datetime import datetime
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.inet import TCP
from .module import t_mixmodule
from t_argchecksum.t_argchecksum import MyCheckSum
from itertools import repeat

# Header for each layer
# 各レイヤのヘッダ
class Header:
	try:
		def __init__(self, *args):
			len_args = len(args)
			if len_args == 2:
				self.src_mac  = args[0]
				self.dest_mac = args[1]
			elif len_args == 3:
				self.syn_src_addr  = args[0]
				self.syn_dest_addr = args[1]
				self.syn_dest_port = args[2]
			elif len_args == 8:
				self.ack_src_addr           = args[0]
				self.ack_dest_addr          = args[1]
				self.ack_src_port           = args[2]
				self.ack_dest_port          = args[3]
				self.ack_syn_sequence       = args[4]
				self.ack_syn_acknowledgment = args[5]
				self.syn_id_int             = args[6]
				self.recv_timestamp         = args[7]
			else:
				print(f'Different number of arguments')
				print(f'引数の数が異なります')
				exit(1)

		# EthernetII Field
		# EthernetIIフィールド
		def ethernetII(self):
			smac_addr  = t_mixmodule.HexadecimalConversion(self.src_mac).mac()
			dmac_addr  = t_mixmodule.HexadecimalConversion(self.dest_mac).mac()
			ETHII_TYPE = b'\x08\x00'
			ethernetII_header = dmac_addr + smac_addr + ETHII_TYPE
			return ethernetII_header
		
		# IPv4 & TCP Field
		# IPv4 & TCP フィールド
		def syn_ip_tcp(self):
		# IPv4 Field
		# IPv4フィールド
			VERSION                   = format(4, '04b') # int(Decimal) => str(BinaryNumber) [int型(10進数) => 文字型(2進数)]
			HEADER_LENGTH             = format(5, '04b') # int(Decimal) => str(BinaryNumber) [int型(10進数) => 文字型(2進数)]
			VERSION_AND_HEADER_LENGTH = int(VERSION + HEADER_LENGTH, 2).to_bytes(1, 'big')
			DIFFERENTIATED_SERVICES   = b'\x00'
			total_length              = b'\x00\x00'
			IDENTIFICATION_INT        = randint(30000, 40000)
			IDENTIFICATION            = IDENTIFICATION_INT.to_bytes(2, 'big')
			FLAGS_AND_FLAGMENT_OFFSET = b'\x40\x00'
			TTL                       = b'\x40'
			PROTCOL                   = b'\x06'
			ip_checksum               = b'\x00\x00'
			sip_addr                  = t_mixmodule.HexadecimalConversion(self.syn_src_addr).ip()
			dip_addr                  = t_mixmodule.HexadecimalConversion(self.syn_dest_addr).ip()

		# TCP Field
		# TCPフィールド
			SOURCE_PORT            = randint(1024, 49151).to_bytes(2, 'big')
			destination_port       = self.syn_dest_port.to_bytes(2, 'big')
			SEQUENCE_NUMBER        = randint(0, 4000000000).to_bytes(4, 'big')
			ACKNOWLEDGMENT_NUMBER  = b'\x00\x00\x00\x00'
			HEADER_LENGTH          = b'\xa0'
			FLAGS                  = b'\x02'
			WINDOW                 = b'\x7d\x78'
			tcp_checksum           = b'\x00\x00'
			URGENT_POINTER         = b'\x00\x00'
			# Mazimum amount of data send in one TCP packet
			# 1回のTCPパケットで送信される最大データ量
			MAXIMUM_SEGMENT_SIZE   = 2
			MAXIMUM_LENGTH         = 4
			MSS_VALUE              = 1460
			OPTION_MAXIMUM_SEGMENT = MAXIMUM_SEGMENT_SIZE.to_bytes(1, 'big') + MAXIMUM_LENGTH.to_bytes(1, 'big') + MSS_VALUE.to_bytes(2, 'big')
			# Notify of use Select ACK
			# Selective ACKの利用を通知
			SACK_PERMITTED         = 4
			SACK_LENGTH            = 2
			OPTION_SACK_PERMITTED  = SACK_PERMITTED.to_bytes(1, 'big') + SACK_LENGTH.to_bytes(1, 'big')
			# Calculate RTT values at any time during a connection
			# RTT(Round Trip Time) :Time from sending a packet to the destination until receiving a response
			# コネクション中でいつでも RTT 値を計算する
			# 宛先にパケット送信から応答が返ってくるまでの時間
			TIMESTAMPS_OPTION      = b'\x08'
			TIMESTAMPS_LENHTH      = b'\x0a'
			TIMESTAMPS_VALUE       = int(datetime.timestamp(datetime.now())).to_bytes(4, 'big')
			TIMESTAMPS_ECHO_REPLY  = b'\x00\x00\x00\x00'
			OPTION_TIMESTAMPS      = TIMESTAMPS_OPTION + TIMESTAMPS_LENHTH + TIMESTAMPS_VALUE + TIMESTAMPS_ECHO_REPLY
			# Used as a delimiter between options and arranged in 4-byte units
			# オプション間の区切り文字として利用し、4バイト単位に揃うように配置
			OPTION_NO_OPERATION    = b'\x01'
			# Extending TCP field WINDOW
			# TCPフィールドのWINDOWの拡張
			WINDOW_SCALE           = 3
			WINDOW_LENGTH          = 3
			SHIFT_COUNT            = 7
			OPTION_WINDOW_SCALE    = WINDOW_SCALE.to_bytes(1, 'big') + WINDOW_LENGTH.to_bytes(1, 'big') + SHIFT_COUNT.to_bytes(1, 'big')

		# PseudoIP Field
		# 疑似IPフィールド
			ZERO                   = b'\x00'
			syn_tcp_header_len_tmp = SOURCE_PORT + destination_port + SEQUENCE_NUMBER + ACKNOWLEDGMENT_NUMBER + HEADER_LENGTH + FLAGS + WINDOW + tcp_checksum +\
						 			 URGENT_POINTER + OPTION_MAXIMUM_SEGMENT + OPTION_SACK_PERMITTED + OPTION_TIMESTAMPS + OPTION_NO_OPERATION + OPTION_WINDOW_SCALE
			syn_tcp_header_len     = len(syn_tcp_header_len_tmp)

			# PseudoIP Header
			# 疑似IPヘッダ
			syn_pseudoIP_header = sip_addr + dip_addr + ZERO + PROTCOL + syn_tcp_header_len.to_bytes(2, 'big')

			# TCP header
			# TCPヘッダ
			syn_tcp_header_tmp = syn_pseudoIP_header + syn_tcp_header_len_tmp
			syn_tcp_checksum   = MyCheckSum(syn_tcp_header_tmp).iptcp_header_module().to_bytes(2, 'big')
			syn_tcp_header     = SOURCE_PORT + destination_port + SEQUENCE_NUMBER + ACKNOWLEDGMENT_NUMBER + HEADER_LENGTH + FLAGS + WINDOW + syn_tcp_checksum +\
						 		 URGENT_POINTER + OPTION_MAXIMUM_SEGMENT + OPTION_SACK_PERMITTED + OPTION_TIMESTAMPS + OPTION_NO_OPERATION + OPTION_WINDOW_SCALE

			# IP Header
			# IPヘッダ
			syn_ip_header_tmp = VERSION_AND_HEADER_LENGTH + DIFFERENTIATED_SERVICES + total_length + IDENTIFICATION + FLAGS_AND_FLAGMENT_OFFSET +\
								TTL + PROTCOL + ip_checksum + sip_addr + dip_addr
			ip_header_len     = len(syn_ip_header_tmp)
			syn_total_length  = (ip_header_len + syn_tcp_header_len).to_bytes(2, 'big')
			syn_ip_header_tmp = None
			syn_ip_header_tmp = VERSION_AND_HEADER_LENGTH + DIFFERENTIATED_SERVICES + syn_total_length + IDENTIFICATION + FLAGS_AND_FLAGMENT_OFFSET +\
								TTL + PROTCOL + ip_checksum + sip_addr + dip_addr
			syn_ip_checksum   = MyCheckSum(syn_ip_header_tmp).iptcp_header_module().to_bytes(2, 'big')
			syn_ip_header     = VERSION_AND_HEADER_LENGTH + DIFFERENTIATED_SERVICES + syn_total_length + IDENTIFICATION + FLAGS_AND_FLAGMENT_OFFSET +\
								TTL + PROTCOL + syn_ip_checksum + sip_addr + dip_addr
			syn_iptcp_header  = syn_ip_header + syn_tcp_header
			return syn_iptcp_header, IDENTIFICATION_INT
		

		def ack_ip_tcp(self):
		# IPv4 Field
		# IPv4フィールド
			VERSION                   = format(4, '04b') # int(Decimal) => str(BinaryNumber) [int型(10進数) => 文字型(2進数)]
			HEADER_LENGTH             = format(5, '04b') # int(Decimal) => str(BinaryNumber) [int型(10進数) => 文字型(2進数)]
			VERSION_AND_HEADER_LENGTH = int(VERSION + HEADER_LENGTH, 2).to_bytes(1, 'big')
			DIFFERENTIATED_SERVICES   = b'\x00'
			total_length              = b'\x00\x00'
			IDENTIFICATION_INT        = self.syn_id_int + 1
			IDENTIFICATION            = IDENTIFICATION_INT.to_bytes(2, 'big')
			FLAGS_AND_FLAGMENT_OFFSET = b'\x40\x00'
			TTL                       = b'\x40'
			PROTCOL                   = b'\x06'
			ip_checksum               = b'\x00\x00'
			sip_addr                  = t_mixmodule.HexadecimalConversion(self.ack_src_addr).ip()
			dip_addr                  = t_mixmodule.HexadecimalConversion(self.ack_dest_addr).ip()
		
		# TCP Field
		# TCPフィールド
			SOURCE_PORT            = self.ack_src_port.to_bytes(2, 'big')
			DESTINATION_PORT       = self.ack_dest_port.to_bytes(2, 'big')
			SEQUENCE_NUMBER        = self.ack_syn_acknowledgment.to_bytes(4, 'big')
			ACKNOWLEDGMENT_NUMBER  = (self.ack_syn_sequence + 1).to_bytes(4, 'big')
			HEADER_LENGTH          = b'\x80'
			FLAGS                  = b'\x10'
			WINDOW                 = b'\x00\xfb'
			tcp_checksum           = b'\x00\x00'
			URGENT_POINTER         = b'\x00\x00'
			# Used as a delimiter between options and arranged in 4-byte units
			# オプション間の区切り文字として利用し、4バイト単位に揃うように配置
			OPTION_NO_OPERATION    = b'\x01'
			# Calculate RTT values at any time during a connection
			# RTT(Round Trip Time) :Time from sending a packet to the destination until receiving a response
			# コネクション中でいつでも RTT 値を計算する
			# 宛先にパケット送信から応答が返ってくるまでの時間
			TIMESTAMPS_OPTION      = b'\x08'
			TIMESTAMPS_LENHTH      = b'\x0a'
			TIMESTAMPS_VALUE       = int(datetime.timestamp(datetime.now())).to_bytes(4, 'big')
			TIMESTAMPS_ECHO_REPLY  = self.recv_timestamp.to_bytes(4, 'big')
			OPTION_TIMESTAMPS      = TIMESTAMPS_OPTION + TIMESTAMPS_LENHTH + TIMESTAMPS_VALUE + TIMESTAMPS_ECHO_REPLY

		# PseudoIP Field
		# 疑似IPフィールド
			ZERO                   = b'\x00'
			ack_tcp_header_len_tmp = SOURCE_PORT + DESTINATION_PORT + SEQUENCE_NUMBER + ACKNOWLEDGMENT_NUMBER + HEADER_LENGTH + FLAGS +\
						 			 WINDOW + tcp_checksum + URGENT_POINTER + OPTION_NO_OPERATION + OPTION_NO_OPERATION + OPTION_TIMESTAMPS
			ack_tcp_header_len     = len(ack_tcp_header_len_tmp)

			# PseudoIP Header
			# 疑似IPヘッダ
			ack_pseudoIP_header = sip_addr + dip_addr + ZERO + PROTCOL + ack_tcp_header_len.to_bytes(2, 'big')
			
			# TCP header
			# TCPヘッダ
			ack_tcp_header_tmp = ack_pseudoIP_header + ack_tcp_header_len_tmp
			ack_tcp_checksum   = MyCheckSum(ack_tcp_header_tmp).iptcp_header_module().to_bytes(2, 'big')
			ack_tcp_header     = SOURCE_PORT + DESTINATION_PORT + SEQUENCE_NUMBER + ACKNOWLEDGMENT_NUMBER + HEADER_LENGTH + FLAGS +\
						 		 WINDOW + ack_tcp_checksum + URGENT_POINTER + OPTION_NO_OPERATION + OPTION_NO_OPERATION + OPTION_TIMESTAMPS
			
			# IP Header
			# IPヘッダ
			ack_ip_header_tmp = VERSION_AND_HEADER_LENGTH + DIFFERENTIATED_SERVICES + total_length + IDENTIFICATION +\
								FLAGS_AND_FLAGMENT_OFFSET +TTL + PROTCOL + ip_checksum + sip_addr + dip_addr
			ack_ip_header_len = len(ack_ip_header_tmp)
			ack_total_length  = (ack_ip_header_len + ack_tcp_header_len).to_bytes(2, 'big')
			ack_ip_header_tmp = None
			ack_ip_header_tmp = VERSION_AND_HEADER_LENGTH + DIFFERENTIATED_SERVICES + ack_total_length + IDENTIFICATION +\
								FLAGS_AND_FLAGMENT_OFFSET +TTL + PROTCOL + ip_checksum + sip_addr + dip_addr
			ack_ip_checksum   = MyCheckSum(ack_ip_header_tmp).iptcp_header_module().to_bytes(2, 'big')
			ack_ip_header     = VERSION_AND_HEADER_LENGTH + DIFFERENTIATED_SERVICES + ack_total_length + IDENTIFICATION + FLAGS_AND_FLAGMENT_OFFSET +\
								TTL + PROTCOL + ack_ip_checksum + sip_addr + dip_addr
			ack_iptcp_header  = ack_ip_header + ack_tcp_header
			return ack_iptcp_header, IDENTIFICATION_INT
	except KeyboardInterrupt:
		# (Ctrl + c) Process
		# (Ctrl + c) の処理
		print(f'\nProcess Interrupted')
		print(f'処理を中断しました')
		exit(1)
	except:
		# Get ErrorMessage
		# エラーメッセージ取得
		exc_type, exc_message, _ = exc_info()
		exc_list                 = format_exception_only(exc_type, exc_message)
		error_message            = ''.join(exc_message for exc_message in exc_list)
		print(f'{error_message}')
		exit(1)


# Analysis Header
# ヘッダ解析
class Analysis:
	try:
		def __init__(self, *args):
			self.ip_tcp_header     = args[0]
			self.ip_tcp_header_len = args[1]
			self.src_ip            = t_mixmodule.HexadecimalConversion(args[2]).ip()
			self.dest_ip           = t_mixmodule.HexadecimalConversion(args[3]).ip()
			self.proto             = args[4].to_bytes(1, 'big')

		# Analysis TCP header
		# TCPヘッダー解析
		def tcp_header_analysis(self):
			ZERO          = b'\x00'
			ip_header_len = 20

			for increment in repeat(1, self.ip_tcp_header_len - ip_header_len):
				# Get Receive TCPheader Checksum
				# 受信TCPヘッダのチェックサムを取得
				tcp_header_tmp     = self.ip_tcp_header[ip_header_len:self.ip_tcp_header_len]
				receive_tcp_chksum = TCP(tcp_header_tmp).chksum.to_bytes(2, 'big')

				# Reset Receive TCPheader Checksum
				# 受信 TCPヘッダのチェックサムをリセット
				tcp_header_front    = tcp_header_tmp[0:16]
				tcp_checksum        = b'\x00\x00'
				tcp_header_back     = tcp_header_tmp[18:self.ip_tcp_header_len]
				checksum_tcp_header = tcp_header_front + tcp_checksum + tcp_header_back

				# PseudoIP Field
				# 疑似IPフィールド
				tcp_header_len  = len(checksum_tcp_header)
				pseudoIP_header = self.src_ip + self.dest_ip + ZERO + self.proto + tcp_header_len.to_bytes(2, 'big')
				
				# Checksum Calculation
				# チェックサム計算
				tcp_chksum_tmp   = pseudoIP_header + checksum_tcp_header
				check_tcp_chksum = MyCheckSum(tcp_chksum_tmp).iptcp_header_module().to_bytes(2, 'big')

				if receive_tcp_chksum == check_tcp_chksum:
					recv_sequence       = TCP(tcp_header_tmp).seq
					recv_acknowledgment = TCP(tcp_header_tmp).ack
					recv_option_tmp     = TCP(tcp_header_tmp).options
					
					# Get Timestamp Echo reply
					# タイムスタンプのエコー応答取得
					recv_option_tmp_len = len(recv_option_tmp)
					for option_count in range(recv_option_tmp_len):
						option_menu = recv_option_tmp[option_count][0]
						if option_menu == 'Timestamp':
							recv_timestamp = recv_option_tmp[option_count][1][0]
					return recv_sequence, recv_acknowledgment, recv_timestamp
				elif ip_header_len < 40:
					ip_header_len += increment
				else:
					print(f"Checksum don't match")
					print(f'チェックサムが一致しません')
					exit(1)
	except KeyboardInterrupt:
		# (Ctrl + c) Process
		# (Ctrl + c) 処理
		print(f'\nProcess Interrupted')
		print(f'処理を中断しました')
		exit(1)
	except:
		# Get ErrorMessage
		# エラーメッセージ取得
		exc_type, exc_message, _ = exc_info()
		exc_list                 = format_exception_only(exc_type, exc_message)
		error_message            = ''.join(exc_message for exc_message in exc_list)
		print(f'{error_message}')
		exit(1)

# Send Socket
# 送信ソケット
class HandshakeSend:
	try:
		def __init__(self, *args):
			len_args = len(args)
			if len_args == 6:
				self.source_mac_address      = args[0]
				self.destination_mac_address = args[1]
				self.source_ip_address       = args[2]
				self.destination_ip_address  = args[3]
				self.source_interface        = args[4]
				self.destination_port        = args[5]
			elif len_args == 5:
				self.recv_iptcp_header       = args[0]
				self.source_mac_address      = args[1]
				self.destination_mac_address = args[2]
				self.syn_id_int              = args[3]
				self.source_interface        = args[4]
				self.recv_iptcp_header_len   = IP(self.recv_iptcp_header).len
			else:
				print(f'Different number of arguments')
				print(f'引数の数が異なります')
				exit(1)
				
		# Send Syn Packet
		# Synパケットを送信
		def send_receive_packet(self):
			PROTOCOL_NUMBER         = 6
			conditional_branch_list = [self.destination_mac_address, PROTOCOL_NUMBER, self.destination_port]
			SOCKET_BUFFSIZE         = 4096
			ETH_P_IP                = 0x0800

			# Create Syn packet
			# Synパケット作成
			syn_ethII_header              = Header(self.source_mac_address, self.destination_mac_address).ethernetII()
			syn_ip_tcp_header, syn_id_int = Header(self.source_ip_address, self.destination_ip_address, self.destination_port).syn_ip_tcp()
			send_syn_packet               = syn_ethII_header + syn_ip_tcp_header

			# Socket Connect
			# ソケット接続
			with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP)) as sock:
				sock.bind((self.source_interface, 0))

				# Send Syn packet
				# Synパケット送信
				sock.send(send_syn_packet)

				while True:
					# Receive Packet
					# パケット受信
					receive_packet         = sock.recv(SOCKET_BUFFSIZE)
					receive_src_macaddress = Ether(receive_packet).src
					receive_protocol       = Ether(receive_packet).proto
					receive_sport          = Ether(receive_packet).sport

					# Conditional branch ([0]:The other person MACaddress [1]:Protocol [2]:The other person Port)
					# 条件分岐 ([0]:相手のMACアドレス [1]:プロトコル [2]:相手のポート)
					if receive_src_macaddress in conditional_branch_list and receive_protocol in conditional_branch_list and receive_sport in conditional_branch_list:
						# Get IP/TCP header
						# IP/TCPヘッダを取得
						receive_header_all_len   = len(Ether(receive_packet))
						receive_iptcp_header_len = Ether(receive_packet).len
						receive_header_eth_len   = receive_header_all_len - receive_iptcp_header_len
						receive_iptcp_header     = receive_packet[receive_header_eth_len:(receive_iptcp_header_len + receive_header_eth_len)]
						return syn_id_int, receive_iptcp_header, receive_src_macaddress
	
		# Send Ack Packet
		# Ackパケットを送信
		def send_ack(self):
			src_ip       = IP(self.recv_iptcp_header).dst
			dest_ip      = IP(self.recv_iptcp_header).src
			src_port     = IP(self.recv_iptcp_header).dport
			dest_port    = IP(self.recv_iptcp_header).sport
			ack_protocol = IP(self.recv_iptcp_header).proto

			# Analysis TCP header
			# Argument ([0]:IP TCP header [1]:IP TCP header Len [2]:Source_IPaddress [3]:Destination_IPaddress [4]:Protocol)
			# Return Value: ReceiveSequence and ReceiveAcknowledgment and ReceiveTimestamp
			# TCPヘッダ解析
			# 引数 ([0]:IP TCPヘッダ [1]:IP TCPヘッダの長さ [2]:送信元IPアドレス [3]:宛先IPアドレス [4]:プロトコル)
			# 戻り値: 受信シーケンス と 受信了承 と 受信タイムスタンプ
			recv_sequence, recv_acknowledgment, recv_timestamp = Analysis(self.recv_iptcp_header, self.recv_iptcp_header_len, src_ip, dest_ip, ack_protocol).tcp_header_analysis()
			
			# Create ACK packet
			# Argument ([0]:Send Source MACaddress [1]:Receive Source MACaddress)
			# Return Value: Ack EthernetIIheader
			# ACKパケット作成
			# 引数 ([0]:送信_送信元MACアドレス [1]:受信_送信元MACアドレス)
			# 戻り値: Ack EthernetIIヘッダ
			ack_ethII_header  = Header(self.source_mac_address, self.destination_mac_address).ethernetII()

			# Argument ([0]:Source IPaddress [1]:Destination IPadress [2]:Source Port [3]Destination Port [4]:Receive Sequence [5]:Receive Acknowledgment [6]Syn ID Integer [7]:Receive Timestamp)
			# Return Value: Ack IP/TCPheader and Ack IntegerID
			# 引数 ([0]:送信元IPアドレス [1]:宛先IPアドレス [2]:送信元ポート [3]:宛先ポート [4]:受信 シーケンス [5]:受信 承認 [6]:Syn ID 整数 [7]:受信タイムスタンプ)
			# 戻り値: ACK IP/TCPヘッダ と ACK 整数ID
			ack_ip_tcp_header, ack_id_int = Header(src_ip, dest_ip, src_port, dest_port, recv_sequence, recv_acknowledgment, self.syn_id_int, recv_timestamp).ack_ip_tcp()
			send_ack_packet = ack_ethII_header + ack_ip_tcp_header

			# Send Ack packet
			# Synパケット送信
			with socket.socket(socket.AF_PACKET, socket.SOCK_RAW) as sock:
				sock.bind((self.source_interface, 0))
				sock.send(send_ack_packet)
			return ack_id_int
	except KeyboardInterrupt:
		# (Ctrl + c) Process
		# (Ctrl + c) 処理
		print(f'\nProcess Interrupted')
		print(f'処理を中断しました')
		exit(1)
	except:
		# Get ErrorMessage
		# エラーメッセージ取得
		exc_type, exc_message, _ = exc_info()
		exc_list                 = format_exception_only(exc_type, exc_message)
		error_message            = ''.join(exc_message for exc_message in exc_list)
		print(f'{error_message}')
		exit(1)
