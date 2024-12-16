import hashlib
import socket
from multiprocessing import Process, Manager, freeze_support
from struct import pack, unpack, calcsize
from os.path import isfile, isdir, normpath, dirname
from os import getcwd, chdir, makedirs, remove, listdir, mkdir, rmdir
import struct
from threading import Thread
import os
from Crypto.Cipher import AES

from client import create_hmac, decrypt_data

# 定义整数大小，用于后续数据包长度的打包和解包
intSize = calcsize('i')

# 获取当前脚本所在的目录路径
current_dir = os.path.dirname(os.path.abspath(__file__))

# 用户账号、密码（哈希后）、主目录
# 注意：这里的密钥是硬编码的，实际应用中应避免这样做，以提高安全性
key = b'mysecretkey12345'

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

def hash_password(password):
    """
    使用SHA256算法对密码进行哈希处理
    :param password: 原始密码
    :return: 密码的哈希值
    """
    hash_object = hashlib.sha256()
    hash_object.update(password.encode('utf-8'))
    return hash_object.hexdigest()

def unpad_data(data):
    """
    去除解密后数据的填充部分
    :param data: 解密后的数据
    :return: 去除填充后的原始数据
    """
    padding_length = data[-1]
    return data[:-padding_length]

# 用户信息字典，包含用户名、密码哈希值和主目录路径
users = {
    'zhangsan': {
        'pwd': hash_password('0'),  # 密码为'0'的哈希值
        'home': os.path.join(current_dir)  # 用户主目录设置为当前脚本所在目录
    },
    'lisi': {
        'pwd': hash_password('0'),  # 密码为'0'的哈希值
        'home': os.path.join(current_dir)  # 用户主目录设置为当前脚本所在目录
    }
}

def authenticate_user(conn):
    """
    认证用户身份
    :param conn: 与客户端建立的socket连接
    :return: 认证成功返回用户名，否则返回None
    """
    length = unpack('i', conn.recv(intSize))[0]  # 接收用户名和密码哈希值的长度
    user_id, user_pwd_hash = conn.recv(length).decode().split(',')  # 接收用户名和密码哈希值，并拆分
    # 验证密码哈希值是否匹配
    if user_id in users and users[user_id]['pwd'] == user_pwd_hash:
        conn.sendall(pack('i', len(b'ok')) + b'ok')  # 发送认证成功的消息
        print(f"用户 {user_id} 已连接")  # 打印日志
        return user_id
    else:
        conn.sendall(pack('i', len(b'error')) + b'error')  # 发送认证失败的消息
        return None

def handle_client_command(conn, addr, user_id, online_users, connections, message_connections):
    """
    处理客户端发送的命令
    :param conn: 与客户端建立的socket连接
    :param addr: 客户端地址
    :param user_id: 用户名
    :param online_users: 在线用户字典
    :param connections: 用户连接字典
    :param message_connections: 用户消息连接字典
    """
    try:
        connections[user_id] = conn  # 将用户连接存储在字典中
        while True:
            length = unpack('i', conn.recv(intSize))[0]  # 接收命令长度
            # 接收加密后的命令并解密
            encrypted_command = conn.recv(length)
            command = decrypt_data(encrypted_command).decode('utf-8')
            print(f"客户端{addr}发来命令（解密后）: {command}")  # 打印接收到的命令
            if command in ('quit', 'q'):
                break  # 如果命令是退出，则跳出循环
            elif command in ('list', 'ls', 'dir'):
                files = str(listdir(getcwd())).encode()  # 获取当前目录下的文件列表
                conn.sendall(pack('I', len(files)) + files)  # 发送文件列表给客户端
            elif ''.join(command.split()) == 'cd..':
                cwd = getcwd()
                newCwd = dirname(cwd)
                if newCwd[-1] == ':':
                    newCwd += '\\'
                if newCwd.lower().startswith(users[user_id]['home'].lower()):
                    chdir(newCwd)  # 切换到上级目录
                    msg = b'ok'
                    conn.sendall(pack('i', len(msg)) + msg)  # 发送成功消息
                else:
                    msg = b'error'
                    conn.sendall(pack('i', len(msg)) + msg)  # 发送错误消息
            elif command in ('pwd', 'cd'):
                msg = str(getcwd()).encode()  # 获取当前工作目录
                conn.sendall(pack('i', len(msg)) + msg)  # 发送当前工作目录给客户端
            elif command.startswith('cd '):
                command = command.split(maxsplit=1)
                if len(command) == 2 and isdir(command[1]) and ('\\' not in command[1]):
                    chdir(command[1])  # 切换到指定目录
                    msg = b'ok'
                    conn.sendall(pack('i', len(msg)) + msg)  # 发送成功消息
                else:
                    msg = b'error'
                    conn.sendall(pack('i', len(msg)) + msg)  # 发送错误消息
            elif command.startswith('get '):
                command = command.split(maxsplit=1)
                if len(command) == 2 and isfile(command[1]):
                    conn.sendall(b'ok')  # 发送文件存在消息
                    with open(command[1], 'rb') as fp:
                        content = fp.read()  # 读取文件内容
                    conn.sendall(pack('I', len(content)) + content)  # 发送文件内容给客户端
                else:
                    conn.sendall(b'no')  # 发送文件不存在消息
            elif command.startswith('put '):
                fn = command.split(maxsplit=1)[1]
                if (isfile(fn) or fn.endswith(('.exe', '.com')) or ('\\' in normpath(fn))):
                    conn.sendall(b'no')  # 发送不允许上传的消息
                else:
                    conn.sendall(b'ok')  # 发送允许上传的消息
                    buffer = conn.recv(intSize)
                    if buffer != b'nono':
                        rest = unpack('i', buffer)[0]
                        with open(fn, 'wb') as fp:
                            while rest > 0:
                                received = conn.recv(min(rest, 40960))
                                if not received:
                                    break
                                fp.write(received)  # 写入接收到的数据
                                rest = rest - len(received)
                        if rest > 0:
                            remove(fn)  # 删除未完全接收的文件
                            conn.sendall(b'no')  # 发送上传失败消息
                        else:
                            conn.sendall(b'ok')  # 发送上传成功消息
            elif command.startswith('del '):
                fn = command.split(maxsplit=1)[1]
                if '\\' not in normpath(fn) and isfile(fn):
                    try:
                        remove(fn)  # 删除文件
                        conn.sendall(b'ok')  # 发送删除成功消息
                    except:
                        conn.sendall(b'no')  # 发送删除失败消息
                else:
                    conn.sendall(b'no')  # 发送文件不存在或路径非法消息
            elif command.startswith('mkdir '):
                subDir = command.split(maxsplit=1)[1]
                if '\\' not in normpath(subDir) and not isdir(subDir):
                    try:
                        mkdir(subDir)  # 创建目录
                        conn.sendall(b'ok')  # 发送创建成功消息
                    except:
                        conn.sendall(b'no')  # 发送创建失败消息
                else:
                    conn.sendall(b'no')  # 发送目录已存在或路径非法消息
            else:
                pass  # 忽略未知命令
    except Exception as e:
        print(f"处理客户端命令出错: {e}")  # 打印异常信息
    finally:
        del online_users[user_id]  # 从在线用户字典中移除用户
        del connections[user_id]  # 从用户连接字典中移除用户连接
        conn.close()  # 关闭连接
        print(f"{addr} 关闭连接")  # 打印日志

def handle_client_message(conn, addr, user_id, online_users, message_connections):
    """
    处理客户端发送的消息
    :param conn: 与客户端建立的socket连接
    :param addr: 客户端地址
    :param user_id: 用户名
    :param online_users: 在线用户字典
    :param message_connections: 用户消息连接字典
    """
    try:
        message_connections[user_id] = conn  # 将用户消息连接存储在字典中
        while True:
            # 接收消息长度并验证
            length_bytes = conn.recv(struct.calcsize('i'))
            if len(length_bytes) < struct.calcsize('i'):
                print("接收长度信息不完整，关闭连接")
                break
            message_length = struct.unpack('!i', length_bytes)[0]
            # 接收完整消息
            received_data = b''
            while len(received_data) < message_length:
                new_data = conn.recv(message_length - len(received_data))
                if not new_data:
                    print("接收消息中断，关闭连接")
                    break
                received_data += new_data
            received_message = received_data

            encrypted_message = received_message[:-calcsize('sha256')]  # 提取加密消息部分
            received_hmac = received_message[-calcsize('sha256'):]  # 提取接收到的HMAC值

            # 验证HMAC
            calculated_hmac = create_hmac(encrypted_message)
            if calculated_hmac == received_hmac:
                decrypted_message = decrypt_data(encrypted_message).decode('utf-8')
                print(f"收到来自 {user_id} 的消息: {decrypted_message}")
                response = f"服务器已收到消息: {decrypted_message}".encode()
                conn.sendall(pack('i', len(response)) + response)
            else:
                print("消息完整性验证失败，可能被篡改！")
                break

    except Exception as e:
        print(f"处理客户端消息出错: {e}")
    finally:
        del message_connections[user_id]
        conn.close()
        print(f"{addr} 消息连接关闭")

def handle_server_command(online_users, message_connections):
    """
    处理服务器端命令
    :param online_users: 在线用户字典
    :param message_connections: 用户消息连接字典
    """
    while True:
        cmd = input("Server> ").strip()  # 读取服务器端命令
        if cmd == "uls":
            print("在线用户列表：")
            for user_id in online_users.keys():
                print(f"用户: {user_id}")  # 打印在线用户列表
        elif cmd.startswith("send "):
            try:
                _, user, message = cmd.split(" ", 2)  # 拆分命令，获取用户名和消息内容
                if user in message_connections:
                    conn = message_connections[user]
                    try:
                        encrypted_message = encrypt_data(f"Server message: {message}".encode())
                        msg = pack('i', len(encrypted_message)) + encrypted_message
                        conn.sendall(msg)  # 发送加密消息给指定用户
                        print(f"加密消息已发送给 {user}")
                    except ValueError as e:
                        print(f"加密数据时出现值错误: {e}")
                    except OSError as e:
                        print(f"发送加密消息时网络相关错误: {e}")
                    except Exception as e:
                        print(f"加密或发送消息时其他未知错误: {e}")
                else:
                    print(f"用户 {user} 不在线")
            except ValueError:
                print("命令格式错误：send 命令需要按照 <username> <message> 的格式输入")
            except KeyError:
                print("指定的用户名不存在，请检查输入的用户名是否正确")

if __name__ == '__main__':
    freeze_support()  # 支持冻结可执行文件
    manager = Manager()
    online_users = manager.dict()  # 在线用户字典
    connections = manager.dict()  # 用户连接字典
    message_connections = manager.dict()  # 用户消息连接字典

    command_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建命令socket
    command_sock.bind(('', 10800))  # 绑定命令端口
    command_sock.listen(5)  # 开始监听

    message_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # 创建消息socket
    message_sock.bind(('', 10801))  # 绑定消息端口
    message_sock.listen(5)  # 开始监听

    print('服务器已启动。')  # 打印启动信息
    Thread(target=handle_server_command, args=(online_users, message_connections), daemon=True).start()  # 启动服务器命令处理线程

    while True:
        try:
            command_conn, command_addr = command_sock.accept()  # 接受命令连接
            user_id = authenticate_user(command_conn)  # 认证用户
            if user_id:
                online_users[user_id] = command_addr  # 将用户添加到在线用户字典

                msg_conn, msg_addr = message_sock.accept()  # 接受消息连接
                Process(target=handle_client_command, args=(command_conn, command_addr, user_id, online_users, connections, message_connections)).start()  # 启动客户端命令处理进程
                Process(target=handle_client_message, args=(msg_conn, msg_addr, user_id, online_users, message_connections)).start()  # 启动客户端消息处理进程
        except Exception as e:
            print(f"接受连接出错: {e}")  # 打印异常信息
            break  # 出错时退出循环