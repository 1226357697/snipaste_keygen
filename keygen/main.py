import base64
import json
import zlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
import os
from device_id import *
import argparse

class Ed25519Helper:
    """Ed25519签名验证工具类，与CryptoPP兼容"""

    @staticmethod
    def generate_keypair():
        """
        生成Ed25519密钥对

        Returns:
            tuple: (private_key_bytes(32字节), public_key_bytes(32字节))
        """
        private_key = ed25519.Ed25519PrivateKey.generate()

        # 获取私钥的32字节原始格式
        private_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )

        # 获取公钥的32字节原始格式
        public_key = private_key.public_key()
        public_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        return private_bytes, public_bytes

    @staticmethod
    def sign_message(private_key_bytes, message):
        """
        使用Ed25519私钥对消息进行签名

        Args:
            private_key_bytes: 32字节私钥
            message: 要签名的消息

        Returns:
            bytes: 64字节签名
        """
        # 从原始字节加载私钥
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)

        # 对消息进行签名
        signature = private_key.sign(message)
        return signature

    @staticmethod
    def verify_signature(public_key_bytes, message, signature):
        """
        使用Ed25519公钥验证签名

        Args:
            public_key_bytes: 32字节公钥
            message: 原始消息
            signature: 64字节签名

        Returns:
            bool: 验证结果
        """
        try:
            # 从原始字节加载公钥
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)

            # 验证签名
            public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    @staticmethod
    def load_public_key_from_file(filename):
        """
        从文件加载公钥（原始32字节格式）

        Args:
            filename: 公钥文件路径

        Returns:
            bytes: 32字节公钥
        """
        with open(filename, 'rb') as f:
            return f.read()

    @staticmethod
    def save_public_key_to_file(public_key_bytes, filename):
        """
        保存公钥到文件（原始32字节格式）

        Args:
            public_key_bytes: 32字节公钥
            filename: 保存路径
        """
        with open(filename, 'wb') as f:
            f.write(public_key_bytes)

    @staticmethod
    def load_private_key_from_file(filename):
        """
        从文件加载私钥（原始32字节格式）

        Args:
            filename: 私钥文件路径

        Returns:
            bytes: 32字节私钥
        """
        with open(filename, 'rb') as f:
            return f.read()

    @staticmethod
    def save_private_key_to_file(private_key_bytes, filename):
        """
        保存私钥到文件（原始32字节格式）

        Args:
            private_key_bytes: 32字节私钥
            filename: 保存路径
        """
        with open(filename, 'wb') as f:
            f.write(private_key_bytes)

# 使用示例和测试


def demo_ed25519_workflow():
    """演示完整的Ed25519工作流程"""
    print("=== Ed25519 签名验证演示 ===\n")

    # 1. 生成密钥对
    print("1. 生成Ed25519密钥对...")
    private_key, public_key = Ed25519Helper.generate_keypair()
    print(f"   私钥长度: {len(private_key)} 字节")
    print(f"   公钥长度: {len(public_key)} 字节")
    print(f"   私钥(hex): {private_key.hex()}")
    print(f"   公钥(hex): {public_key.hex()}")

    # 2. 要签名的消息
    message = b"Hello, this is a test message for Ed25519 signature verification!"
    print(f"\n2. 要签名的消息: {message}")

    # 3. 生成签名
    print("\n3. 生成签名...")
    signature = Ed25519Helper.sign_message(private_key, message)
    print(f"   签名长度: {len(signature)} 字节")
    print(f"   签名(hex): {signature.hex()}")

    # 4. 验证签名（应该成功）
    print("\n4. 验证签名...")
    result1 = Ed25519Helper.verify_signature(public_key, message, signature)
    print(f"   正确签名验证结果: {result1}")

    # 5. 验证错误的签名（应该失败）
    print("\n5. 测试错误签名验证...")
    wrong_signature = bytes([(b + 1) % 256 for b in signature])  # 修改签名
    result2 = Ed25519Helper.verify_signature(public_key, message, wrong_signature)
    print(f"   错误签名验证结果: {result2}")

    # 6. 验证修改后的消息（应该失败）
    print("\n6. 测试修改消息验证...")
    wrong_message = message + b"tampered"
    result3 = Ed25519Helper.verify_signature(public_key, wrong_message, signature)
    print(f"   修改消息验证结果: {result3}")

    # 7. 文件操作演示
    print("\n7. 文件操作演示...")
    Ed25519Helper.save_public_key_to_file(public_key, "public_key.bin")
    Ed25519Helper.save_private_key_to_file(private_key, "private_key.bin")

    loaded_public = Ed25519Helper.load_public_key_from_file("public_key.bin")
    loaded_private = Ed25519Helper.load_private_key_from_file("private_key.bin")

    # 使用从文件加载的密钥验证
    new_signature = Ed25519Helper.sign_message(loaded_private, message)
    result4 = Ed25519Helper.verify_signature(loaded_public, message, new_signature)
    print(f"   文件加载密钥验证结果: {result4}")

    # 清理文件
    import os
    os.remove("public_key.bin")
    os.remove("private_key.bin")

    print("\n=== 演示完成 ===")


def compatibility_test():
    """与C++ CryptoPP兼容性测试"""
    print("\n=== 兼容性测试 ===\n")

    # 使用固定的测试密钥以确保可重复性
    # 这是一个预生成的Ed25519密钥对
    test_private_key_hex = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    test_public_key_hex = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    test_message = b"Test message for CryptoPP compatibility"

    private_key = bytes.fromhex(test_private_key_hex)
    public_key = bytes.fromhex(test_public_key_hex)

    print(f"测试私钥: {test_private_key_hex}")
    print(f"测试公钥: {test_public_key_hex}")
    print(f"测试消息: {test_message}")

    # 生成签名
    signature = Ed25519Helper.sign_message(private_key, test_message)
    print(f"生成的签名: {signature.hex()}")

    # 验证签名
    result = Ed25519Helper.verify_signature(public_key, test_message, signature)
    print(f"签名验证结果: {result}")

    # 预期的标准Ed25519签名（用于交叉验证）
    expected_signature_hex = (
        "e5564300c360ac729086e2cc806e828a"
        "84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46b"
        "d25bf5f0595bbe24655141438e7a100b"
    )
    expected_signature = bytes.fromhex(expected_signature_hex)

    print(f"预期签名: {expected_signature_hex}")
    print(f"签名匹配: {signature == expected_signature}")


def make_json(name:str,eml:str,dom:str,machineid:str):
    iat_string = '2026-06-25 12:01:01'
    time_string = '2099-01-01 11:11:11'
    info = {
        "nam": name,
        "eml": eml,
        "lic": "123",
        "dev": 666,
        "pln": "Personal",  # Personal,Business,Trial
        "dom": dom,  # 工作组,x_Blake2s
        "api": 0,  # api 版本
        "iat": iat_string,
        "exp": time_string,
        "exx": time_string,
        "ref": time_string,
        "hwi": {
            "machineid": machineid,# x_Blake2s
            "platform": 1,
            "domain": "",
        },
    }
   
    s=json.dumps(info)#,indent='    '
    
    return s
    


def gen_dom()->str:
    # way1
    dom:str=get_workgroup()
    # way2
    # dom=x_Blake2s_128_140277030(dom.encode('utf8'),4).hex().upper()
    # print(f'dom:{dom}')
    return dom
def gen_lic_machineid(sz:int,sep:str)->str:
    machine_guid=get_machine_guid()
    # print(f'machine_guid:{machine_guid}')
    lic_machineid=machineid_140276EB0(machine_guid,sz,sep)
    # print(f'machineid:{lic_machineid}')
    return lic_machineid.decode()

    pass
def s_xor(xor_k:bytes,data:bytes):
    out=[]
    xor_k_sz=len(xor_k)
    for i ,x in enumerate(data):
        out.append(x^xor_k[i%xor_k_sz])
    return bytes(out)

def gzip_compress(data:bytes)->bytes:
    """gzip 压缩，对应解码端 inflateInit2(wbits=31) 的 gzip 格式"""
    co=zlib.compressobj(9,zlib.DEFLATED,31)
    return co.compress(data)+co.flush()

def gzip_decompress(data:bytes)->bytes:
    """gzip 解压，wbits=31，与 C++ 端 gunzip 一致"""
    return zlib.decompress(data,31)

def simulate_client(code:str):
    """模拟客户端 setLicenseKey 的完整判定链，定位 license 在哪一步被判空。
    返回解析出的 JSON dict；任一步失败则打印原因并返回 None(对应 fromJson 的 isNull)。"""
    print('=== simulate_client ===')
    # 1. 格式校验: len>3 且 code[2]=='-'  (对应 sub_14024C9C0 入口守卫)
    if not (len(code) > 3 and code[2] == '-'):
        print(f'[X] 格式校验失败: len={len(code)}, code[2]={code[2:3]!r} (需要 > 3 且 code[2]==\'-\')')
        return None
    print(f'[OK] 格式: len={len(code)}, code[0]={code[0]!r} code[1]={code[1]!r} code[2]=\'-\'')

    check_char = code[1]                 # 内嵌校验字符
    body_b64   = code[3:]                 # base64 载荷

    # 2. checksum 校验: code[1] == calculate_adjacent_char_diff_sum(body_b64)
    expected = calculate_adjacent_char_diff_sum(body_b64)
    if check_char != expected:
        print(f'[X] checksum 校验失败: code[1]={check_char!r} 但客户端算出={expected!r}')
        return None
    print(f'[OK] checksum: {check_char!r} == {expected!r}')

    # 3. base64 解码
    try:
        raw = base64.standard_b64decode(body_b64)
    except Exception as e:
        print(f'[X] base64 解码失败: {e}')
        return None
    print(f'[OK] base64 解码: {len(raw)} 字节')

    # 4. postProcess: 不足 65 字节直接透传
    if len(raw) < 65:
        print(f'[X] postProcess: 长度 {len(raw)} < 65,会原样返回 → 验签必败')
        return None
    sig  = raw[:64]                      # 头 64 字节 = 签名
    body = bytearray(raw[64:])

    # postProcess: A) gzip 前 XOR
    for i in range(len(body)):
        body[i] ^= sig[i % 64]
    # postProcess: gunzip
    try:
        body = bytearray(gzip_decompress(bytes(body)))
    except zlib.error as e:
        print(f'[X] gunzip 失败: {e} → postProcess 返回原始数据 → 验签必败')
        return None
    # postProcess: B) gzip 后 XOR
    for i in range(len(body)):
        body[i] ^= sig[i % 64]
    # 此时 body = postProcess 的输出 body 段(+408 = sig + body)

    # 5. 验签 (sub_14024B1D0): C) 验签前再 XOR 一次,然后 Ed25519 verify
    msg = bytearray(body)
    for i in range(len(msg)):
        msg[i] ^= sig[i % 64]
    msg = bytes(msg)
    if not Ed25519Helper.verify_signature(PUBLIC_KEY, msg, sig):
        print('[X] Ed25519 验签失败 → sub_14024B1D0 返回空 → fromJson 走 isNull 分支!')
        print(f'    验签 message 前80字节: {msg[:80]!r}')
        return None
    print('[OK] Ed25519 验签通过')
    json_bytes = msg                     # 验签通过返回的就是 message = JSON

    # 6. JSON 解析
    try:
        info = json.loads(json_bytes.decode('utf-8'))
    except Exception as e:
        print(f'[X] JSON 解析失败 (对应 !isObject): {e}')
        print(f'    前80字节: {json_bytes[:80]!r}')
        return None
    print(f'[OK] JSON 解析成功: {info}')
    return info
'''
1. 生成Ed25519密钥对...
   私钥长度: 32 字节
   公钥长度: 32 字节
   私钥(hex): 951743f1381818ec1af9a32a2eafce42c6261f5089468ef863e7b903c183b3f6
   公钥(hex): 1ebf8f1197d33a99aee6c625e306739eb9bf1c2806324eb7b83a09933062aa04
'''
PRIVATE_KEY =bytes.fromhex('951743f1381818ec1af9a32a2eafce42c6261f5089468ef863e7b903c183b3f6')
PUBLIC_KEY=bytes.fromhex('1ebf8f1197d33a99aee6c625e306739eb9bf1c2806324eb7b83a09933062aa04')


def activation_machine(name:str, dom:str, machineid:str) -> str:

    # print(f'machineid:{machineid}')
    s=make_json(name,'12138@yan.com',dom,machineid).encode()
    # print('[-]license info:',s.decode())
    sig=Ed25519Helper.sign_message(PRIVATE_KEY,s)
    # print(f'sig:{sig.hex()}')
    ok=Ed25519Helper.verify_signature(PUBLIC_KEY,s,sig)
    # print('[-]verify:',ok)

    # 当前版编码流程。客户端解码共 3 次 XOR(都用 sig 当 key):
    #   A: postProcess gzip 前   body ^= sig
    #      postProcess           body = gunzip(body)
    #   B: postProcess gzip 后   body ^= sig
    #   C: 验签前(sub_14024B1D0) body ^= sig
    #   B、C 抵消 → 验签 message = gunzip(raw_body ^ sig),需等于签名时的明文 JSON
    #   故生成端(逆): raw_body = gzip(JSON) ^ sig  —— 只一次 XOR,在 gzip 之后
    body = gzip_compress(s)       # gzip(JSON)
    body = s_xor(sig, body)       # ^ sig
    data = sig + body             # header(sig 64字节) + body

    b64_data=base64.standard_b64encode(data)
    part1=calculate_adjacent_char_diff_sum(b64_data.decode())
    port0='0'
    code=f'{port0}{part1}-{b64_data.decode()}'
    return  code

def activation_host_machine():
    dom=gen_dom()
    machine_guid=get_machine_guid()
    machineid=gen_expected_machineid(machine_guid,9)


    activation_code = activation_machine('ikun', dom, machineid)
    print('-'*50)
    print('The activation code for the host machine is:')
    print(activation_code)
    print('-'*50)
    

# def activation_host_machine():
#     # demo_ed25519_workflow()
#     # compatibility_test()
#     dom=gen_dom()
#     # print(f'dom:{dom}')
#     # hwi.machineid 填明文设备码即可(JSON 层明文,客户端内部自行编解码)
#     # = blake2s('Snipaste 2','1', 本机MachineGuid)[-9:] -> hex大写 -> 4-8分段 + 校验 + '1'
#     machine_guid=get_machine_guid()
#     machineid=gen_expected_machineid(machine_guid,9)
#     print(f'machineid:{machineid}')

#     # print(f'machineid:{machineid}')
#     s=make_json('ikun','ikun@kunkun.com',dom,machineid).encode()
#     print('[-]license info:',s.decode())
#     sig=Ed25519Helper.sign_message(PRIVATE_KEY,s)
#     # print(f'sig:{sig.hex()}')
#     ok=Ed25519Helper.verify_signature(PUBLIC_KEY,s,sig)
#     print('[-]verify:',ok)

#     # 当前版编码流程。客户端解码共 3 次 XOR(都用 sig 当 key):
#     #   A: postProcess gzip 前   body ^= sig
#     #      postProcess           body = gunzip(body)
#     #   B: postProcess gzip 后   body ^= sig
#     #   C: 验签前(sub_14024B1D0) body ^= sig
#     #   B、C 抵消 → 验签 message = gunzip(raw_body ^ sig),需等于签名时的明文 JSON
#     #   故生成端(逆): raw_body = gzip(JSON) ^ sig  —— 只一次 XOR,在 gzip 之后
#     body = gzip_compress(s)       # gzip(JSON)
#     body = s_xor(sig, body)       # ^ sig
#     data = sig + body             # header(sig 64字节) + body

#     b64_data=base64.standard_b64encode(data)
#     part1=calculate_adjacent_char_diff_sum(b64_data.decode())
#     port0='0'
#     code=f'{port0}{part1}-{b64_data.decode()}'
#     print('-------------------------------------------------------------')
#     print(code)
#     simulate_client(code)
#     return code
def gen_k():
    print("1. 生成Ed25519密钥对...")
    while True:
        private_key, public_key = Ed25519Helper.generate_keypair()
        if b'\x00' in public_key:
            continue
        print(f"   私钥长度: {len(private_key)} 字节")
        print(f"   公钥长度: {len(public_key)} 字节")
        print(f"   私钥(hex): {private_key.hex()}")
        print(f"   公钥(hex): {public_key.hex()}")
        break
    
def activation_client_machine(name:str, device_info:str):
    decoded_bytes = base64.b64decode(device_info)
    decompress_bytes = gzip_decompress(decoded_bytes)
    device_info_json = json.loads(decompress_bytes.decode())
    dom = device_info_json['dom']
    machineid = device_info_json['machineid']

    activation_code = activation_machine('ikun', dom, machineid)
    print('-'*50)
    print('The activation code for the client machine is:')
    print(activation_code)
    print('-'*50)

    return

def main():
    parser = argparse.ArgumentParser(description='This is a snipaste keygen')
    parser.add_argument('-d', '--device', default=None, help="The client device information")
    parser.add_argument('-n', '--name', default=None, help="The client device name")

    args = parser.parse_args()

    if args.device and args.name:
        activation_client_machine(args.name, args.device)
    else:
        activation_host_machine()

    return 0

if __name__ == "__main__":
    SystemExit(main())
    # gen_k()
    # test()
    pass

