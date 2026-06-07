# 安装 Python3、OpenSSL、venv（venv 用于 cert-operator 一键部署）
sudo apt install -y python3 python3-pip python3-venv openssh-client openssl

# 安装 cert-operator 服务端依赖（开发/测试用）
pip3 install --break-system-packages -r /workspace/ca_server/requirements.txt

# 安装客户端依赖（开发/测试用）
pip3 install --break-system-packages "requests>=2.31"
