#!/bin/bash

# WiFi Auditor 一键打包脚本

# 定义颜色
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== WiFi Auditor 打包向导 ===${NC}"

# 1. 检查目录环境
if [ ! -f "main.py" ]; then
    echo -e "${RED}错误: 请在项目根目录下运行此脚本 (包含 main.py 的目录)${NC}"
    exit 1
fi

# 定义虚拟环境路径
VENV_DIR="./venv"
PYINSTALLER="$VENV_DIR/bin/pyinstaller"
PIP="$VENV_DIR/bin/pip"

if [ ! -d "$VENV_DIR" ]; then
    echo -e "${RED}错误: 未找到虚拟环境 '$VENV_DIR'${NC}"
    exit 1
fi

# 2. 检查 PyInstaller
echo "正在检查依赖..."
if [ ! -f "$PYINSTALLER" ]; then
    echo "未找到 PyInstaller，正在通过 pip 安装..."
    sudo $PIP install pyinstaller
fi

# 3. 自动查找 manuf 数据文件路径
# 之前的路径通常是 venv/lib/pythonX.X/site-packages/manuf/manuf
echo "正在定位 manuf 数据文件..."
MANUF_FILE=$(find "$VENV_DIR" -path "*/site-packages/manuf/manuf" -type f | head -n 1)

if [ -z "$MANUF_FILE" ]; then
    echo -e "${RED}错误: 无法在 venv 中找到 manuf 数据文件。请确认已安装 manuf 库。${NC}"
    exit 1
fi
echo -e "找到数据文件: ${GREEN}$MANUF_FILE${NC}"

# 4. 清理旧文件
echo "正在清理旧的构建文件..."
if [ -d "build" ] || [ -d "dist" ]; then
    sudo rm -rf build dist *.spec
fi

# 5. 执行打包
echo -e "${GREEN}开始打包...${NC}"
echo "执行命令: pyinstaller --onefile --name WiFi-Auditor ..."

# 注意：这里使用了 sudo 来运行 pyinstaller，因为你的开发环境似乎一直依赖 sudo
sudo $PYINSTALLER --onefile \
    --name WiFi-Auditor \
    --clean \
    --hidden-import manuf \
    --add-data "$MANUF_FILE:manuf" \
    main.py

# 6. 检查结果
if [ $? -eq 0 ]; then
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  打包成功！${NC}"
    echo -e "  可执行文件: ${GREEN}dist/WiFi-Auditor${NC}"
    echo -e "  运行命令:   ${GREEN}sudo ./dist/WiFi-Auditor${NC}"
    echo -e "${GREEN}========================================${NC}"
else
    echo -e "${RED}打包失败，请检查上方的错误信息。${NC}"
    exit 1
fi
