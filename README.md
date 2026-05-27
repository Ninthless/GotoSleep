# WiFi Auditor

WiFi Auditor 是一个基于 PyQt6 的无线网络审计图形界面。它通过 `aircrack-ng` 工具链扫描附近 WiFi 接入点和客户端，展示信号强度、加密信息、厂商信息，并提供基于 `mdk4` 的授权测试操作入口。

仅在你拥有或被明确授权测试的无线网络中使用本项目。

## 功能

- 自动发现无线网卡
- 启用 monitor mode
- 扫描 WiFi AP 与关联客户端
- 显示 ESSID、BSSID、厂商、信道、信号强度和加密方式
- 按 AP 过滤客户端列表
- 复制 ESSID/BSSID
- 对选定目标启动 `mdk4` 测试任务
- Hunter Mode：按 ESSID 列表周期扫描并处理匹配目标

## 运行环境

推荐环境：

- Linux
- Python 3.10+
- 支持 monitor mode 的无线网卡
- root 权限
- `aircrack-ng`
- `mdk4`
- `wireless-tools`

Debian/Ubuntu/Kali 系统依赖示例：

```bash
sudo apt update
sudo apt install aircrack-ng mdk4 wireless-tools python3 python3-venv python3-pip
```

## 安装

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 启动

```bash
sudo venv/bin/python main.py
```

应用启动后：

1. 选择无线网卡
2. 点击 `Enable Monitor Mode`
3. 确认界面切换到 monitor 接口
4. 点击 `Start Scan`
5. 选择 AP 后查看客户端或打开右键菜单执行授权测试

## Hunter Mode

Hunter Mode 会按 ESSID 列表周期扫描附近网络，并对匹配目标启动测试流程。

使用步骤：

1. 点击 `Hunter Mode`
2. 添加目标 ESSID
3. 设置攻击速率和扫描间隔
4. 确认启动
5. 再次点击 `Stop Hunter` 停止

## 打包

项目提供 `build.sh` 用于 PyInstaller 单文件打包：

```bash
chmod +x build.sh
./build.sh
```

成功后输出文件位于：

```bash
dist/WiFi-Auditor
```

运行打包结果：

```bash
sudo ./dist/WiFi-Auditor
```

## 项目结构

```text
main.py
src/
  gui.py
  process.py
  utils.py
requirements.txt
build.sh
```

核心职责：

- `main.py`：应用入口
- `src/gui.py`：PyQt6 界面和用户交互
- `src/process.py`：扫描、Hunter、测试任务线程
- `src/utils.py`：权限检查、网卡发现、monitor mode、厂商识别、CSV 解析

## 注意事项

- 必须使用 root 权限运行，否则扫描和测试按钮会被禁用。
- monitor mode 可能会中断当前无线连接。
- 关闭应用时会停止扫描、测试任务、Hunter Mode，并尝试关闭本次启用的 monitor 接口。
- `venv`、`build`、`dist`、`__pycache__` 等生成物不应提交到版本控制。
