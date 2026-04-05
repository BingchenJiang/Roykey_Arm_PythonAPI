import ctypes
import hashlib
import os
import random
import secrets
import sys
import time
from ctypes import *
from typing import NoReturn

# =================================================================
# 核心安全配置：开发者需根据自己的 ROCKEY-ARM 加密锁参数进行填充
# =================================================================

# [配置 A]：加密锁基础状态码与标志位
# DONGLE_SUCCESS 通常为 0x00000000，FLAG_ENCODE 通常为 0
DONGLE_SUCCESS: int = 0x00000000
FLAG_ENCODE: int = 0

# [配置 B]：私钥文件 ID (请在出厂工具中查看你创建的 RSA 私钥文件 ID)
# 示例：如果是 0x00BB，则填入 187 (0xBB 的十进制)
RSA_PRIKEY_FILE_ID: int = 0  # <--- 在此填入你的私钥文件 ID

# [配置 C]：产品 ID (PID)
# 请填入你加密锁对应的 8 位十六进制 PID 转为十进制后的数值
EXPECTED_PID: int = 0  # <--- 在此填入你的 EXPECTED_PID

# [配置 D]：RSA 公钥模数 (Modulus N)
# 请使用 parse_rsapub_file.py 提取出的十六进制字符串填入
# 此处为了防止静态分析，建议在发布时使用 Base64 编码或混淆处理
MODULUS_HEX: str = ""  # <--- 在此填入长达 256/512 位的公钥模数 N

# [配置 E]：RSA 公钥指数 (Exponent E)
# 通常为标准值 "10001" (即十进制 65537)
EXPONENT_HEX: str = "10001"

# [配置 F]：DLL 组件指纹 (SHA256)
# 请运行 _sha256_file 函数计算你本地 'Dynamic/Dongle_d.dll' 的哈希值并填入
# 这是防止黑客替换 DLL 实现劫持攻击的关键防线
EXPECTED_DLL_HASH: str = ""  # <--- 在此填入 64 位 SHA256 字符串

# =================================================================
# 校验逻辑：确保开发者已正确填写配置
# =================================================================

if not MODULUS_HEX or not EXPECTED_DLL_HASH or EXPECTED_PID == 0:
    print("\n" + "!" * 60)
    print("  [CRITICAL ERROR] 安全配置缺失！")
    print("  请开发者在代码配置区填写您的 MODULUS_HEX, EXPECTED_PID 和 DLL_HASH。")
    print("  相关参数可通开发商工具或 parse_rsapub_file.py 脚本获取。")
    print("!" * 60 + "\n")
    sys.exit(1)


# =================================================================
# 状态日志输出 (教学演示专用)
# =================================================================
def _log(stage: str, msg: str, success: bool = True):
    symbol = "[+]" if success else "[!]"
    print(f"{symbol} {stage.ljust(12)} : {msg}")


# =================================================================
# 基础防御模块
# =================================================================

def _anti_debug() -> None:
    """[防御层] 检测调试环境"""
    if sys.gettrace() is not None:
        _log("Anti-Debug", "Python 调试器已拦截 (sys.gettrace)", False)
        raise RuntimeError("TERMINATED: Debugger presence detected.")

    if hasattr(ctypes.windll.kernel32, "IsDebuggerPresent"):
        if ctypes.windll.kernel32.IsDebuggerPresent():
            _log("Anti-Debug", "Win32 内核调试器已拦截", False)
            raise RuntimeError("TERMINATED: Ring3 Debugger detected.")


def _check_dll(path: str) -> bool:
    """[防御层] 检测 DLL 完整性"""
    if not os.path.exists(path):
        _log("Integrity", f"缺少组件: {os.path.basename(path)}", False)
        return False

    sha256_hash = hashlib.sha256()
    with open(path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)

    if sha256_hash.hexdigest() != EXPECTED_DLL_HASH:
        _log("Integrity", "组件哈希校验失败！检测到非法 Patch 或 DLL 劫持。", False)
        return False

    _log("Integrity", "Dynamic/Dongle_d.dll 校验通过", True)
    return True


# =================================================================
# 硬件通讯结构
# =================================================================

class DONGLE_INFO(Structure):
    _fields_ = [
        ("m_Ver", c_ushort), ("m_Type", c_ushort), ("m_BirthDay", c_ubyte * 8),
        ("m_Agent", c_ulong), ("m_PID", c_ulong), ("m_UserID", c_ulong),
        ("m_HID", c_ubyte * 8), ("m_IsMother", c_ulong), ("m_DevType", c_ulong),
    ]


# =================================================================
# 核心验证逻辑
# =================================================================

def _verify_signature_safe(signature: bytes, expected_hash: bytes, n: int, e: int) -> bool:
    """[防御层] 纯数学验签"""
    # 模拟 RSA 计算
    sig_int: int = int.from_bytes(signature, 'big')
    decrypted_int: int = pow(sig_int, e, n)

    k: int = (n.bit_length() + 7) // 8
    decrypted: bytes = decrypted_int.to_bytes(k, 'big')

    # 1. 结构校验
    if decrypted[0] != 0x00:
        _log("RSA-Math", "填充结构错误 (非 0x00 开头)", False)
        return False

    # 2. 内容校验
    if not decrypted.endswith(expected_hash):
        _log("RSA-Math", "签名匹配失败！私钥不正确或签名被伪造。", False)
        return False

    _log("RSA-Math", "硬件私钥签名验证成功", True)
    return True


def _check_once(dll: ctypes.WinDLL) -> bool:
    """单次质询流程"""
    count = c_int(0)
    # 1. 发现设备
    if dll.Dongle_Enum(None, byref(count)) != DONGLE_SUCCESS or count.value == 0:
        _log("Hardware", "未检测到 USB 加密锁", False)
        return False

    # 2. 身份识别
    info = DONGLE_INFO()
    dll.Dongle_Enum(byref(info), byref(count))
    if info.m_PID != EXPECTED_PID:
        _log("Hardware", f"无效设备 (PID: {hex(info.m_PID)})", False)
        return False

    # 3. 动态质询
    hid_bytes: bytes = bytes(info.m_HID)
    challenge: bytes = hashlib.sha256(hid_bytes + secrets.token_bytes(16)).digest()
    _log("Protocol", f"已向 HID:{hid_bytes.hex().upper()} 发起挑战", True)

    # 4. 私钥运算
    h = c_void_p()
    if dll.Dongle_Open(byref(h), 0) != DONGLE_SUCCESS:
        _log("Hardware", "设备占用中或打开失败", False)
        return False

    in_buf = (c_ubyte * len(challenge)).from_buffer_copy(challenge)
    out_buf = (c_ubyte * 256)()
    out_len = c_int(256)

    res: int = dll.Dongle_RsaPri(h, RSA_PRIKEY_FILE_ID, FLAG_ENCODE, in_buf, len(challenge), out_buf, byref(out_len))
    dll.Dongle_Close(h)

    if res != DONGLE_SUCCESS:
        _log("Hardware", f"硬件拒绝签名运算 (错误码: {hex(res)})", False)
        return False

    # 5. 数学对撞
    n_val: int = int(MODULUS_HEX, 16)
    e_val: int = int(EXPONENT_HEX, 16)
    return _verify_signature_safe(bytes(out_buf[:out_len.value]), challenge, n_val, e_val)


# =================================================================
# 对外接口
# =================================================================

def check_dongle_secure() -> bool:
    """主验证入口"""
    print("\n" + "=" * 50)
    print("      ROCKEY-ARM RSA 安全校验系统 v1.0")
    print("=" * 50)

    try:
        # 第一阶段：环境自检
        _anti_debug()

        # 第二阶段：完整性校验
        bundle_dir: str = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
        dll_path: str = os.path.join(bundle_dir, 'Dynamic', 'Dongle_d.dll')
        if not _check_dll(dll_path): return False

        dll = ctypes.WinDLL(dll_path)
        dll.Dongle_Enum.argtypes = [POINTER(DONGLE_INFO), POINTER(c_int)]
        dll.Dongle_Open.argtypes = [POINTER(c_void_p), c_int]
        dll.Dongle_RsaPri.argtypes = [c_void_p, c_ushort, c_int, POINTER(c_ubyte), c_int, POINTER(c_ubyte),
                                      POINTER(c_int)]
        dll.Dongle_Close.argtypes = [c_void_p]

        # 第三阶段：双重握手
        _log("Protocol", "启动双重质询机制...", True)
        if not _check_once(dll): return False

        time.sleep(0.05)
        if not _check_once(dll): return False

        print("=" * 50)
        _log("Summary", "系统授权验证通过！欢迎使用。", True)
        return True

    except Exception as e:
        _log("Fatal", str(e), False)
        return False


def _abort_action() -> NoReturn:
    """执行安全阻断"""
    print("\n[!!!] 安全策略触发：正在清理运行环境...")
    time.sleep(1)
    os._exit(1)


def runtime_guard() -> None:
    """运行时抽检"""
    if random.random() < 0.1:  # 提高抽检概率以便观察演示效果
        if not check_dongle_secure():
            _abort_action()
