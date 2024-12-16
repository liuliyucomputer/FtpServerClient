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
key = b'mysecretkey12345' 
hmac_key = b'mysecretkey12345' 
intSize = calcsize('i')
bufferSize = 40960
def hash_data(data):
    hash_object = hashlib.sha256()
    hash_object.update(data.encode('utf-8'))
    return hash_object.hexdigest()

def pad_data(data):
    """
    对要加密的数据进行填充，使其长度符合AES加密要求
    """
    block_size = AES.block_size
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length]) * padding_length
    return data + padding

def encrypt_data(data):
    """
    使用AES算法对数据进行加密
    """
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_data = cipher.encrypt(pad_data(data))
    return encrypted_data

def create_hmac(message):
    """
    为消息创建HMAC值
    """
    hmac_obj = hmac.new(hmac_key, message, hashlib.sha256)
    return hmac_obj.digest()
def unpad_data(data):
    """
    去除解密后数据的填充部分
    """
    padding_length = data[-1]
    return data[:-padding_length]

def decrypt_data(data):
    """
    使用AES算法对接收的数据进行解密
    """
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = cipher.decrypt(data)
    return unpad_data(decrypted_data)
def main(serverIP):
    command_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    message_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # 连接命令端口
        command_sock.connect((serverIP, 10800))
        # 连接消息端口
        message_sock.connect((serverIP, 10801))
    except Exception as e:
        print(f'连接服务器失败: {e}')
        exit()

    userId = input('请输入用户名：')
    userPwd = getpass('请输入密码：')
     # 对密码进行哈希处理
    hashed_userPwd = hash_data(userPwd)
    message = f'{userId},{hashed_userPwd}'.encode()
    # message = f'{userId},{userPwd}'.encode()
    command_sock.send(pack('i', len(message)) + message)
    length = unpack('i', command_sock.recv(intSize))[0]
    login = command_sock.recv(length)
    if login == b'error':
        print('用户名或密码错误')
        return

    def receive_messages():
        while True:
            try:
                length = unpack('i', message_sock.recv(intSize))[0]
                if length < 0:
                    print("接收到的消息长度不合理，可能出现错误")
                    continue
                # 后续接收消息内容等逻辑保持不变
                encrypted_message = message_sock.recv(length)
                decrypted_message = decrypt_data(encrypted_message).decode('utf-8')
                print(f"收到服务器消息: {decrypted_message}")
            except struct.error as e:
                print(f"解析消息长度时出错: {e}")
                continue
            except Exception as e:
                print(f"接收消息出错: {e}")
                break

    Thread(target=receive_messages, daemon=True).start()

    while True:
        command = input('##> ').lower().strip()
        if not command:
            continue
         # 对命令进行加密
        encrypted_command = encrypt_data(command.encode('utf-8'))
        command_sock.sendall(pack('i', len(encrypted_command)) + encrypted_command)
        if command in ('quit', 'q'):
            break
        elif command in ('list', 'ls', 'dir', 'pwd', 'cd..'):
            length = unpack('I', command_sock.recv(intSize))[0]
            response = command_sock.recv(length).decode()
            print(response)
        elif command.startswith('cd '):
            length = unpack('I', command_sock.recv(intSize))[0]
            response = command_sock.recv(length).decode()
            print(response)
        elif command.startswith('get '):
            if command_sock.recv(2) != b'ok':
                print('文件不存在。')
            else:
                size = unpack('I', command_sock.recv(intSize))[0]
                fn = command.split()[1]
                with open(fn, 'wb') as fp:
                    while size > 0:
                        temp = command_sock.recv(min(size, bufferSize))
                        size -= len(temp)
                        fp.write(temp)
                print('下载完成。')
        elif command.startswith('put '):
            buffer = command_sock.recv(2)
            if buffer == b'ok':
                fn = command.split(maxsplit=1)[1]
                if isfile(fn) and '\\' not in normpath(fn):
                    with open(fn, 'rb') as fp:
                        content = fp.read()
                    command_sock.sendall(pack('i', len(content)) + content)
                    if command_sock.recv(2) == b'ok':
                        print('上传成功。')
                    else:
                        print('上传失败，请稍后重试。')
                else:
                    command_sock.sendall(b'nono')
            else:
                print('服务器拒绝上传，服务端已存在该文件或类型不正确。')
        elif command.startswith('del '):
            if command_sock.recv(2) == b'ok':
                print('删除成功。')
            else:
                print('删除失败。')
        elif command.startswith('mkdir '):
            if command_sock.recv(2) == b'ok':
                print('创建成功。')
            else:
                print('创建失败。')
        else:
            print('')

    command_sock.close()
    message_sock.close()

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f'Usage: {sys.argv[0]} serverIPAddress')
        exit()
    serverIP = sys.argv[1]
    main(serverIP)