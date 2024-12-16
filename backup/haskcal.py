import hashlib

# 原用户信息字典
users = {
    'zhangsan': {'pwd': '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'home': r'D:\ftp_home\zhangsan'},
    'lisi': {'pwd': '8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92', 'home': r'D:\ftp_home\lisi'}
}

def hash_password(password):
    """
    使用SHA256算法计算密码的哈希值
    """
    hash_object = hashlib.sha256()
    hash_object.update(password.encode('utf-8'))
    return hash_object.hexdigest()

# 计算'0'的哈希值
new_password_hash = hash_password('0')

# 更新所有用户的密码哈希值
for user in users:
    users[user]['pwd'] = new_password_hash

print(users)