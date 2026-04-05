# 飞天诚信 ROCKEY-ARM C SDK for Python

## 1. 项目用途

本仓库展示了如何使用 Python 调用飞天诚信（Feitian）官方提供的 64 位 C 语言接口，并结合 **RSA 非对称加密** 与 **双重动态质询** 机制，构建一个商用级的硬件授权保护方案。

项目在启动 PyQt5 窗口之前，会执行高强度的底层安全自检。通过 `RyRAMNavigation.exe` 管理工具新建匿名 RSA 密钥对，实现“无密码、高强度”的身份验证。


## 2. 自动化测试案例与预期输出

在开发或演示过程中，针对不同的物理与软件环境，程序将提供精确的反馈输出。

### 拦截场景

#### 1. 未插入加密狗 (No Dongle)

* 现象：程序启动后立即拦截，无法进入主界面。

* 控制台预期输出：

  ```plaintext
  [!] Hardware     : 未检测到 USB 加密锁
  ```
  
* 原因：Dongle_Enum 未能在 USB 总线上扫描到对应的硬件设备。

#### 2. 环境完整性受损 (DLL Hijacked)

* 现象：程序检测到 DLL 组件被恶意修改或替换。

* 控制台预期输出：

  ```Plaintext
  [!] Integrity    : 组件哈希校验失败！检测到非法 Patch 或 DLL 劫持。
  ```
  
* 原因：文件夹下的 Dynamic/Dongle_d.dll 与代码预设的 EXPECTED_DLL_HASH 不符。

#### 3. 调试器拦截 (Anti-Debug)

* 现象：在使用 PyCharm Debug 模式或 x64dbg 等工具挂载时触发。

* 控制台预期输出：

    ```Plaintext
    [!] Anti-Debug   : Win32 内核调试器已拦截
    [!] Fatal        : TERMINATED: Ring3 Debugger detected.
    ```
  
* 原因：触发了 IsDebuggerPresent 系统调用检测，程序主动拒绝在调试环境下运行。

#### 4. 插入了非本软件的加密狗 (PID Mismatch)
 
* 现象：虽然有加密狗，但不是该软件对应的授权锁。

* 控制台预期输出：

    ```Plaintext
    [!] Hardware     : 无效设备 (PID: 0xXXXXXXXX)
    ```
  
* 原因：检测到的硬件 PID 与代码中硬编码的 EXPECTED_PID 不匹配。

#### 5. 仿冒狗或私钥不匹配 (RSA Verify Failed)

* 现象：硬件身份验证失败。

* 控制台预期输出：

    ```Plaintext
    [!] Protocol     : 已向 HID:XXXXXXXXXXXXXXXX 发起挑战
    [!] RSA-Math     : 签名匹配失败！私钥不正确或签名被伪造。
    ```
* 原因：加密狗内部没有预置对应的 RSA 私钥，或者私钥与代码中的公钥（Modulus N）不是一对。

### 正常启动 (Success)
* 现象：顺利进入主程序。

* 控制台预期输出：

    ```Plaintext
    [+] Integrity    : Dynamic/Dongle_d.dll 校验通过
    [+] Protocol     : 启动双重质询机制...
    [+] RSA-Math     : 硬件私钥签名验证成功
    [+] Summary      : 系统授权验证通过！欢迎使用。
  ```
  
## 3. 配置指南

若要使验证通过，请在 auth_secure.py 中正确配置以下参数：

* EXPECTED_PID: 您的加密锁产品 ID（十进制）。

* MODULUS_HEX: 您的 RSA 公钥模数（16进制字符串，由 parse_rsapub_file.py 提取）。

* EXPECTED_DLL_HASH: 您本地 Dongle_d.dll 的 SHA256 值。