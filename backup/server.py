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
intSize = calcsize('i')
current_dir = os.path.dirname(os.path.abspath(__file__))
# 用户账号、密码、主目录
key =b'mysecretkey12345' 
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
def hash_password(password):
    """
    使用SHA256算法对密码进行哈希处理
    """
    hash_object = hashlib.sha256()
    hash_object.update(password.encode('utf-8'))
    return hash_object.hexdigest()
def unpad_data(data):
    """
    去除解密后数据的填充部分
    """
    padding_length = data[-1]
    return data[:-padding_length]

users = {
    'zhangsan': {
        'pwd': hash_password('0'),
        'home': os.path.join(current_dir)
    },
    'lisi': {
        'pwd': hash_password('0'),
        'home': os.path.join(current_dir)
    }
}

def authenticate_user(conn):
    length = unpack('i', conn.recv(intSize))[0]
    user_id, user_pwd_hash = conn.recv(length).decode().split(',')
    # 验证密码哈希值是否匹配
    if user_id in users and users[user_id]['pwd'] == user_pwd_hash:
        conn.sendall(pack('i', len(b'ok')) + b'ok')
        print(f"用户 {user_id} 已连接")
        return user_id
    else:
        conn.sendall(pack('i', len(b'error')) + b'error')
        return None
def hash_password(password):
    """
    使用SHA256算法对密码进行哈希处理
    """
    hash_object = hashlib.sha256()
    hash_object.update(password.encode('utf-8'))
    return hash_object.hexdigest()
def handle_client_command(conn, addr, user_id, online_users, connections, message_connections):
    try:
        connections[user_id] = conn
        while True:
            length = unpack('i', conn.recv(intSize))[0]
             # 接收加密后的命令并解密
            encrypted_command = conn.recv(length)
            command = decrypt_data(encrypted_command).decode('utf-8')
            print(f"客户端{addr}发来命令（解密后）: {command}")
            if command in ('quit', 'q'):
                break
            elif command in ('list', 'ls', 'dir'):
                files = str(listdir(getcwd())).encode()
                conn.sendall(pack('I', len(files)) + files)
            elif ''.join(command.split()) == 'cd..':
                cwd = getcwd()
                newCwd = dirname(cwd)
                if newCwd[-1] == ':':
                    newCwd += '\\'
                if newCwd.lower().startswith(users[user_id]['home'].lower()):
                    chdir(newCwd)
                    msg = b'ok'
                    conn.sendall(pack('i', len(msg)) + msg)
                else:
                    msg = b'error'
                    conn.sendall(pack('i', len(msg)) + msg)
            elif command in ('pwd', 'cd'):
                msg = str(getcwd()).encode()
                conn.sendall(pack('i', len(msg)) + msg)
            elif command.startswith('cd '):
                command = command.split(maxsplit=1)
                if len(command) == 2 and isdir(command[1]) and ('\\' not in command[1]):
                    chdir(command[1])
                    msg = b'ok'
                    conn.sendall(pack('i', len(msg)) + msg)
                else:
                    msg = b'error'
                    conn.sendall(pack('i', len(msg)) + msg)
            elif command.startswith('get '):
                command = command.split(maxsplit=1)
                if len(command) == 2 and isfile(command[1]):
                    conn.sendall(b'ok')
                    with open(command[1], 'rb') as fp:
                        content = fp.read()
                    conn.sendall(pack('I', len(content)) + content)
                else:
                    conn.sendall(b'no')
            elif command.startswith('put '):
                fn = command.split(maxsplit=1)[1]
                if (isfile(fn) or fn.endswith(('.exe', '.com')) or ('\\' in normpath(fn))):
                    conn.sendall(b'no')
                else:
                    conn.sendall(b'ok')
                    buffer = conn.recv(intSize)
                    if buffer != b'nono':
                        rest = unpack('i', buffer)[0]
                        with open(fn, 'wb') as fp:
                            while rest > 0:
                                received = conn.recv(min(rest, 40960))
                                if not received:
                                    break
                                fp.write(received)
                                rest = rest - len(received)
                        if rest > 0:
                            remove(fn)
                            conn.sendall(b'no')
                        else:
                            conn.sendall(b'ok')
            elif command.startswith('del '):
                fn = command.split(maxsplit=1)[1]
                if '\\' not in normpath(fn) and isfile(fn):
                    try:
                        remove(fn)
                        conn.sendall(b'ok')
                    except:
                        conn.sendall(b'no')
                else:
                    conn.sendall(b'no')
            elif command.startswith('mkdir '):
                subDir = command.split(maxsplit=1)[1]
                if '\\' not in normpath(subDir) and not isdir(subDir):
                    try:
                        mkdir(subDir)
                        conn.sendall(b'ok')
                    except:
                        conn.sendall(b'no')
                else:
                    conn.sendall(b'no')
            else:
                pass
    except Exception as e:
        print(f"处理客户端命令出错: {e}")
    finally:
        del online_users[user_id]
        del connections[user_id]
        conn.close()
        print(f"{addr} 关闭连接")
def handle_client_message(conn, addr, user_id, online_users, message_connections):
    try:
        message_connections[user_id] = conn
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
    while True:
        cmd = input("Server> ").strip()
        if cmd == "uls":
            print("在线用户列表：")
            for user_id in online_users.keys():
                print(f"用户: {user_id}")
        elif cmd.startswith("send "):
            try:
                _, user, message = cmd.split(" ", 2)
                if user in message_connections:
                    conn = message_connections[user]
                    try:
                        encrypted_message = encrypt_data(f"Server message: {message}".encode())
                        msg = pack('i', len(encrypted_message)) + encrypted_message
                        conn.sendall(msg)
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
    freeze_support()
    manager = Manager()
    online_users = manager.dict()
    connections = manager.dict()
    message_connections = manager.dict()

    command_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    command_sock.bind(('', 10800))
    command_sock.listen(5)

    message_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    message_sock.bind(('', 10801))
    message_sock.listen(5)

    print('服务器已启动。')
    Thread(target=handle_server_command, args=(online_users, message_connections), daemon=True).start()

    while True:
        try:
            command_conn, command_addr = command_sock.accept()
            user_id = authenticate_user(command_conn)
            if user_id:
                online_users[user_id] = command_addr

                msg_conn, msg_addr = message_sock.accept()
                Process(target=handle_client_command, args=(command_conn, command_addr, user_id, online_users, connections, message_connections)).start()
                Process(target=handle_client_message, args=(msg_conn, msg_addr, user_id, online_users, message_connections)).start()
        except Exception as e:
            print(f"接受连接出错: {e}")
            break