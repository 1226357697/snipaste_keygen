import hashlib
import ctypes
from ctypes import wintypes
import winreg

class _WKSTA_INFO_100(ctypes.Structure):
    # 与客户端 NetWkstaGetInfo(level=100) 读取的结构一致
    _fields_ = [
        ("wki100_platform_id", wintypes.DWORD),
        ("wki100_computername", wintypes.LPWSTR),
        ("wki100_langroup", wintypes.LPWSTR),     # <- 工作组/域
        ("wki100_ver_major", wintypes.DWORD),
        ("wki100_ver_minor", wintypes.DWORD),
    ]

def get_workgroup():
    """与客户端 sub_1402AC550 一致：NetWkstaGetInfo level 100 的 langroup 字段。
    注意不要用 WMI 的 Workgroup，二者可能不一致(WMI 可能返回 None)。"""
    netapi = ctypes.WinDLL("netapi32.dll")
    netapi.NetWkstaGetInfo.argtypes = [wintypes.LPWSTR, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    netapi.NetWkstaGetInfo.restype = wintypes.DWORD
    buf = ctypes.c_void_p()
    rc = netapi.NetWkstaGetInfo(None, 100, ctypes.byref(buf))
    if rc != 0:
        return None
    try:
        info = ctypes.cast(buf, ctypes.POINTER(_WKSTA_INFO_100)).contents
        return info.wki100_langroup
    finally:
        netapi.NetApiBufferFree(buf)
def get_machine_guid():
    """
    获取注册表中的MachineGuid值
    
    返回:
        MachineGuid字符串，如果获取失败则返回None
    """
    try:
        # 打开注册表键
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography"#r'SOFTWARE\Microsoft\SQMClient'
        )
        
        # 读取MachineGuid值
        machine_guid, _ = winreg.QueryValueEx(key, "MachineGuid")
        
        # 关闭注册表键
        winreg.CloseKey(key)
        
        return machine_guid
        
    except WindowsError as e:
        print(f"获取注册表值失败: {e}")
        return None
def calculate_adjacent_char_diff_sum(input_string: str) -> str:
    """
    计算字符串中相邻字符差值的累积和，并返回模运算后的字符
    
    Args:
        input_string: 输入字符串
        
    Returns:
        str: 根据相邻字符差值累积和取模后索引位置的字符
    """
    if not input_string:
        return '0'
    
    length = len(input_string)
    if length == 1:
        return input_string[0]
    
    total_diff_sum = 0
    
    for i in range(1, length):
        prev_char = ord(input_string[i-1])
        # 获取当前字符的ASCII值（如果>255则设为0）
        curr_char = ord(input_string[i])
        # 计算绝对差值并累加
        abs_diff = abs(curr_char - prev_char)
        total_diff_sum += abs_diff
    
    # 计算模运算后的索引
    index = total_diff_sum % length
    
    return input_string[index]
def x_Blake2s_128_140277030(data:bytes,r_sz:int)->bytes:
    if isinstance(data,str):
        data=data.encode()
    hash_obj = hashlib.blake2s(digest_size=16)
    hash_obj.update(b'Snipaste 2')
    hash_obj.update(b'1')
    hash_obj.update(data)
    out=hash_obj.digest()[-r_sz:]
    # print(out.hex())
    return out
def machineid_140276EB0(machineUniqueId:bytes,r_sz=4,separator='')->bytes:
    out=x_Blake2s_128_140277030(machineUniqueId,r_sz)
    s=out.hex().upper()
    s=format_string_with_separator(s,separator,4,8)
    raw=s.replace(separator,'')
    s+=calculate_adjacent_char_diff_sum(raw)
    s+='1'
    return s.encode()

import ctypes as _ctypes

def gen_expected_machineid(machine_guid:str=None, r_sz:int=9)->str:
    """精确复现客户端 sub_140245B50 现算的"期望设备码"(比较用,非界面展示值)。
    blake2s('Snipaste 2','1',MachineGuid)[-r:] -> hex大写 -> 4-8分段 -> +校验字符 + '1'
    默认 r=9 (客户端用 compute_len(decode(machineid)) 得到,稳定为9)。"""
    if machine_guid is None:
        machine_guid=get_machine_guid()
    out=x_Blake2s_128_140277030(machine_guid.encode(),r_sz)
    s=out.hex().upper()
    s=format_string_with_separator(s,'-',4,8)
    raw=s.replace('-','')
    s+=calculate_adjacent_char_diff_sum(raw)
    s+='1'
    return s

def decode_field_14026DC80(data:bytes)->bytes:
    """复现客户端 sub_14026DC80: 首字节为key, XOR(key^i) 后循环左移 rot 位。"""
    n=len(data)-1
    if n<=0:
        return b''
    key=data[0]
    key_se=_ctypes.c_int8(key).value
    rot=abs(_ctypes.c_int32(n^key_se).value)%n
    body=bytearray(data[1:1+n])
    for i in range(n):
        body[i]^=(key^i)&0xFF
    body=body[rot:]+body[:rot]   # rotate left
    return bytes(body)

def encode_field_14026DC80(plain:bytes,key:int=None)->bytes:
    """decode_field 的逆运算 (= 客户端 sub_14026DB40 编码器)。
    算法: rotate_right(rot) -> XOR(key^i) -> 头部插入 key。
    key 范围 0~250 (客户端用 rand%251), 任意 key 都能被 decode 正确还原。
    key=None 时自动选一个使结果全为可打印 ASCII 的 key, 保证安全通过 JSON/UTF-8。"""
    def _enc(plain,key):
        n=len(plain)
        key_se=_ctypes.c_int8(key).value
        v=n^key_se
        rot=(v if v>0 else -v)%n
        body=bytearray(plain)
        body=body[-rot:]+body[:-rot] if rot else body   # rotate right (逆)
        for i in range(n):
            body[i]^=(key^i)&0xFF
        return bytes([key])+bytes(body)
    if key is not None:
        return _enc(plain,key)
    # 自动选可打印 ASCII 的 key(0~250), 确保 JSON/UTF-8 传输无损
    for k in range(0x20,0x7f):
        enc=_enc(plain,k)
        if all(0x20<=b<0x7f for b in enc) and decode_field_14026DC80(enc)==plain:
            return enc
    return _enc(plain,(plain[0]+1)&0xFF)   # 退而求其次

def gen_machineid_lic_field(machine_guid:str=None)->str:
    """生成 license 里 hwi.machineid 字段应填的值:
    encode(期望设备码),客户端 decode 还原后 == sub_140245B50 现算值,通过门槛3。"""
    expected=gen_expected_machineid(machine_guid,9)
    enc=encode_field_14026DC80(expected.encode())
    return enc.decode('latin1')

def sub_140277190(input_str):
    """
    将输入字符串中的十六进制字符根据自定义映射表进行转换
    """
    # 映射表
    mapping_str = "3679EFHKMNPRTWXY"

    # 将输入字符串转换为大写
    upper_str = input_str.upper()
    
    # 如果输入字符串为空，直接返回
    if len(upper_str) <= 0:
        return upper_str
    
    result_chars = []
    
    # 遍历输入字符串的每个字符
    for char in upper_str:
        # 将十六进制字符转换为数值
        try:
            index = int(char, 16)  # 将十六进制字符转换为0-15的数值
        except ValueError:
            # 如果不是有效的十六进制字符，返回空字符串
            return ""
        
        # 根据索引从映射表中获取对应的字符
        mapped_char = mapping_str[index]
        result_chars.append(mapped_char)
    
    # 构建结果字符串
    return ''.join(result_chars)
def format_string_with_separator(input_str, separator, first_step, subsequent_step):
    """
    格式化字符串：按照指定步长插入分隔符
    
    参数:
        input_str: 输入字符串
        separator: 分隔符
        first_step: 第一段的长度
        subsequent_step: 后续段的长度
        
    返回:
        格式化后的字符串
    """
    if not separator or not input_str:
        return input_str
    
    result = []
    pos = 0
    length = len(input_str)
    step = first_step
    
    while pos < length:
        # 添加分隔符（除了第一个段）
        if pos > 0:
            result.append(separator)
        
        # 计算当前段的实际长度
        actual_step = min(step, length - pos)
        
        # 添加当前段
        result.append(input_str[pos:pos + actual_step])
        
        # 更新位置和步长
        pos += actual_step
        step = subsequent_step
    
    return ''.join(result)
def x_gen_device_id_140219810(MachineId_or_MAC:bytes,r_sz:int):
    out=b'\x01'
    mid=machineid_140276EB0(MachineId_or_MAC,r_sz).decode()
    out+=bytes.fromhex(mid) 
    wkgroup=get_workgroup()
    out+=x_Blake2s_128_140277030(wkgroup,4)
    s=out.hex().upper()
    s+=calculate_adjacent_char_diff_sum(s)
    s=sub_140277190(s)
    s=format_string_with_separator(s,'-',1,5)
    # print(s)
    return s
    
def test():
    machine_guid=get_machine_guid()
    print(f'machine_guid:{machine_guid} type:{type(machine_guid)}')
    net_device_id=x_gen_device_id_140219810(machine_guid,4)
    print(net_device_id)

if __name__=='__main__':
    test()
