# 从仓库拉取 带有 python 3.7 的 Linux 环境
FROM python:3.8

MAINTAINER F4

# 设置 python 环境变量
ENV PYTHONUNBUFFERED 1

# 添加 Debian 清华镜像源
RUN cp /etc/apt/sources.list /etc/apt/sources.list.bak
RUN echo " " > /etc/apt/sources.list
RUN echo \
deb https://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye main contrib non-free\
deb https://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye-updates main contrib non-free\
deb https://mirrors.tuna.tsinghua.edu.cn/debian/ bullseye-backports main contrib non-free\
deb https://mirrors.tuna.tsinghua.edu.cn/debian-security bullseye-security main contrib non-free\
    > /etc/apt/sources.list

# 添加这两行
RUN apt-get update
RUN apt-get install python3-dev default-libmysqlclient-dev -y

# 创建 code 文件夹并将其设置为工作目录
RUN mkdir -p /code
WORKDIR /code
# 更新 pip
RUN pip install pip -U -i https://pypi.tuna.tsinghua.edu.cn/simple
# 将当前目录复制到容器的 code 目录
ADD . /code
# 安装库
RUN pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple