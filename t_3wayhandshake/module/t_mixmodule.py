# Coding: UTF-8
from re import compile
from sys import exc_info
from traceback import format_exception_only

# Syntax check MACaddress or IPaddress
# MACアドレスかIPアドレスの構文確認
class CheckAddress:
	def __init__(self, address):
		self.addr = address
	
	def mac(self):
		# Check MACaddress
		# MACアドレス確認
		# [0-9]: 0,1,2,3,4,5,6,7,8,9
		# [A-F]: A,B,C,D,E,F
		# [a-f]: a,b,c,d,e,f
		check_macaddr = compile(r'^((([0-9]|[A-F]|[a-f]){2}):){5}([0-9]|[A-F]|[a-f]){2}$')
		if check_macaddr.fullmatch(self.addr) == None:
			print(f"\n  Invalid MACaddress: {self.addr}  [無効なMACアドレス: {self.addr}]\n")
			exit(1)
	
	def ip(self):
		# Check IPaddress
		# IPアドレス確認
		#    0-99: [1-9]?[0-9]
		# 100-199: 1[0-9]{2}(1[0-9][0-9])
		# 200-249: 2[0-4][0-9]
		# 250-255: 25[0-5]
		check_ipaddr = compile(r'^(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')
		if check_ipaddr.fullmatch(self.addr) == None:
			print(f"\n  Invalid IPaddress: {self.addr}  [無効なIPアドレス: {self.addr}]\n")
			exit(1)

# MACaddress and IPaddress Convert from ByteType
# MACアドレスとIPアドレスをバイト型に変換
class HexadecimalConversion:
	try:
		def __init__(self, address):
			self.addr = address
			self.byte_value = b''

		def mac(self):
			# Syntax check MACaddress
			# MACアドレスの構文確認
			CheckAddress(self.addr).mac()

			# Extract Each Delimiter from {:} Convert from StringType → IntegerType → ByteType
			# {:}の区切り文字ずつ取り出し、文字列型 → 整数型 → バイト型 に変換
			for position_value in self.addr.split(':'):
				self.byte_value += int(position_value, base=16).to_bytes(1, 'big')
			return self.byte_value

		def ip(self):
			# Syntax check IPaddress
			# IPアドレスの構文確認
			CheckAddress(self.addr).ip()

			# Extract Each Delimiter from {:} Convert from StringType → IntegerType → ByteType
			# {:}の区切り文字ずつ取り出し、文字列型 → 整数型 → バイト型 に変換
			for position_value in self.addr.split('.'):
				self.byte_value += int(position_value).to_bytes(1, 'big')
			return self.byte_value
	except KeyboardInterrupt:
		# (Ctrl + c) Process
		# (Ctrl + c) の処理
		print(f'\nProcess Interrupted [処理を中断しました]')
		exit(1)
	except:
		# Get ErrorMessage
		# エラーメッセージ取得
		exc_type, exc_message, _ = exc_info()
		exc_list                 = format_exception_only(exc_type, exc_message)
		error_message            = ''.join(exc_message for exc_message in exc_list)
		print(f'{error_message}')
		exit(1)