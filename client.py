import hashlib
import hmac
import socket
import struct
import sys
from getpass import getpass
from struct import pack, unpack, calcsize
from threading import Thread
from os.path import isfile, normpath
from Crypto.Cipher import AES

# 密钥，用于AES加密和HMAC签名
key = b'mysecretkey12345' 
hmac_key = b'mysecretkey12345' 

# 定义整数大小，用于后续数据包长度的打包和解包
intSize = calcsize('i')

# 定义缓冲区大小，用于文件传输
bufferSize = 40960

def hash_data(data):
    """
    使用SHA256算法对数据进行哈希处理
    :param data: 需要哈希处理的数据
    :return: 数据的哈希值
    """
    hash_object = hashlib.sha256()
    hash_object.update(data.encode('utf-8'))
    return hash_object.hexdigest()

def pad_data(data):
    """
    对要加密的数据进行填充，使其长度符合AES加密要求
    :param data: 需要填充的数据
    :return: 填充后的数据
    """
    block_size = AES.block_size
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding

def encrypt_data(data):
    """
    使用AES算法对数据进行加密
    :param data: 需要加密的数据
    :return: 加密后的数据
    """
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_data = cipher.encrypt(pad_data(data))
    return encrypted_data

def create_hmac(message):
    """
    为消息创建HMAC值
    :param message: 需要签名的消息
    :return: HMAC值
    """
    hmac_obj = hmac.new(hmac_key, message, hashlib.sha256)
    return hmac_obj.digest()

def unpad_data(data):
    """
    去除解密后数据的填充部分
    :param data: 解密后的数据
    :return: 去除填充后的原始数据
    """
    padding_length = data[-1]
    return data[:-padding_length]

def decrypt_data(data):
    """
    使用AES算法对接收的数据进行解密
    :param data: 需要解密的数据
    :return: 解密后的数据
    """
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(data)
    return unpad_data(decrypted_data)

def main(serverIP):
    """
    客户端主函数，负责连接服务器、认证用户、处理命令和接收消息
    :param serverIP: 服务器IP地址
    """
    command_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建命令socket
    message_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建消息socket
    try:
        # 连接命令端口
        command_sock.connect((serverIP, 10800))
        # 连接消息端口
        message_sock.connect((serverIP, 10801))
    except Exception as e:
        print(f'连接服务器失败: {e}')
        exit()

    userId = input('请输入用户名：')  # 输入用户名
    userPwd = getpass('请输入密码：')  # 输入密码，使用getpass隐藏密码显示
    # 对密码进行哈希处理
    hashed_userPwd = hash_data(userPwd)
    message = f'{userId},{hashed_userPwd}'.encode()  # 将用户名和密码哈希值组合成消息
    # message = f'{userId},{userPwd}'.encode()  # 原始密码版本，不推荐使用
    command_sock.send(pack('i', len(message)) + message)  # 发送认证消息
    length = unpack('i', command_sock.recv(intSize))[0]  # 接收认证结果长度
    login = command_sock.recv(length)  # 接收认证结果
    if login == b'error':
        print('用户名或密码错误')
        return

    def receive_messages():
        """
        子线程函数，负责接收服务器发送的消息
        """
        while True:
            try:
                length = unpack('i', message_sock.recv(intSize))[0]  # 接收消息长度
                if length < 0:
                    print("接收到的消息长度不合理，可能出现错误")
                    continue
                # 后续接收消息内容等逻辑保持不变
                encrypted_message = message_sock.recv(length)  # 接收加密消息
                decrypted_message = decrypt_data(encrypted_message).decode('utf-8')  # 解密消息
                print(f"收到服务器消息: {decrypted_message}")  # 打印消息
            except struct.error as e:
                print(f"解析消息长度时出错: {e}")
                continue
            except Exception as e:
                print(f"接收消息出错: {e}")
                break

    Thread(target=receive_messages, daemon=True).start()  # 启动消息接收子线程

    while True:
        command = input('##> ').lower().strip()  # 输入命令
        if not command:
            continue
        # 对命令进行加密
        encrypted_command = encrypt_data(command.encode('utf-8'))
        command_sock.sendall(pack('i', len(encrypted_command)) + encrypted_command)  # 发送加密命令
        if command in ('quit', 'q'):
            break  # 如果命令是退出，则跳出循环
        elif command in ('list', 'ls', 'dir', 'pwd', 'cd..'):
            length = unpack('I', command_sock.recv(intSize))[0]  # 接收响应长度
            response = command_sock.recv(length).decode()  # 接收响应
            print(response)  # 打印响应
        elif command.startswith('cd '):
            length = unpack('I', command_sock.recv(intSize))[0]  # 接收响应长度
            response = command_sock.recv(length).decode()  # 接收响应
            print(response)  # 打印响应
        elif command.startswith('get '):
            if command_sock.recv(2) != b'ok':  # 检查文件是否存在
                print('文件不存在。')
            else:
                size = unpack('I', command_sock.recv(intSize))[0]  # 接收文件大小
                fn = command.split()[1]  # 获取文件名
                with open(fn, 'wb') as fp:
                    while size > 0:
                        temp = command_sock.recv(min(size, bufferSize))  # 接收文件内容
                        size -= len(temp)
                        fp.write(temp)  # 写入文件
                print('下载完成。')  # 打印下载完成信息
        elif command.startswith('put '):
            buffer = command_sock.recv(2)  # 检查是否允许上传
            if buffer == b'ok':
                fn = command.split(maxsplit=1)[1]  # 获取文件名
                if isfile(fn) and '\\' not in normpath(fn):  # 检查文件是否存在且路径合法
                    with open(fn, 'rb') as fp:
                        content = fp.read()  # 读取文件内容
                    command_sock.sendall(pack('i', len(content)) + content)  # 发送文件内容
                    if command_sock.recv(2) == b'ok':  # 检查上传结果
                        print('上传成功。')
                    else:
                        print('上传失败，请稍后重试。')
                else:
                    command_sock.sendall(b'nono')  # 发送不允许上传的消息
            else:
                print('服务器拒绝上传，服务端已存在该文件或类型不正确。')  # 打印拒绝上传信息
        elif command.startswith('del '):
            if command_sock.recv(2) == b'ok':  # 检查删除结果
                print('删除成功。')
            else:
                print('删除失败。')  # 打印删除失败信息
        elif command.startswith('mkdir '):
            if command_sock.recv(2) == b'ok':  # 检查创建目录结果
                print('创建成功。')
            else:
                print('创建失败。')  # 打印创建失败信息
        else:
            print('')  # 忽略未知命令

    command_sock.close()  # 关闭命令socket
    message_sock.close()  # 关闭消息socket

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} serverIPAddress')
        exit()
    serverIP = sys.argv[1]  # 获取服务器IP地址
    main(serverIP)  # 启动客户端主函数