# 安装 uv（Python 包管理器），替代 pip
curl -LsSf https://astral.sh/uv/install.sh | sh

# 将 uv 添加到 PATH
export PATH="$HOME/.local/bin:$PATH"

# 安装 Python 和 OpenSSL（用于服务器和 SSH 测试）
sudo apt install -y python3 python3-pip openssh-client openssl

# 安装服务端依赖
uv pip install --system "flask>=3.0" "pyotp>=2.9" "pyyaml>=6.0"

# 安装客户端依赖
uv pip install --system "requests>=2.31"

# 安装 TOTP 二维码生成（终端显示 + PNG）
uv pip install --system "qrcode[pil]>=7.0"
