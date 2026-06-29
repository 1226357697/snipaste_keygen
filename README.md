## 说明

本项目对Windows snipaste v2.11.3 的离线授权进行分析，总结。

本项目参考自：[Snipaste-2.10.8-x64 离线激活记录 - DirWangK - 博客园](https://www.cnblogs.com/DirWang/p/19258416) 文章。

## 步骤

- python 第三方库安装命令: `pip install -r requirements.txt`
- 替换 Snipaste_patched.exe 到 Snipaste程序目录中的Snipaste.exe

## 详细步骤

### 本机激活

#### 安装python 第三方库

`pip install -r requirements.txt`

#### 替换pacthed 二进制

替换 Snipaste_patched.exe 到 Snipaste程序目录中的Snipaste.exe

#### 生成序列号

`python keygen\main.py ` 

输出示例：

```
--------------------------------------------------
The activation code for the host machine is:
0w-vKrYmZZXP0Tv0xxxxxxx1FPZccEzL4dao8L7xt6HtDbWOBJfbeGm7U7SHvvUxEpWz6U2TptvaiI88G8yrwAYBaMh0JmWVz9E7dgjZ+RGhuRfXy6xxxxxxxxxkt/mXP28RBIBjS6Y1SD86AATr5dqIxbSm9S0HqNIDl8UDFvVwu1exY7k1nWvR2BoDDRQv4CZ4JOhOTFyCrhSqvJCKQN3SfxxxxxxxxxxG7L3q7x0raWDbrUCx+sJ1lynR6unisNNm0/+DUFbUKu2x72kJ18U91jqmC8APnqs2VhQS9dAA6NrMfKJ2ESJ+pyrNMQbeK0N8Xjmm5MzKIRf10DilnPOrgI++OlVj9E
--------------------------------------------------
```

### 客户端激活

#### 客户端操作

##### 替换pacthed 二进制

替换 Snipaste_patched.exe 到 Snipaste程序目录中的Snipaste.exe

##### 获取客户端设备信息

执行 client.exe， 获取方式可以从 https://github.com/1226357697/snipaste_keygen/releases/download/v1.0/client.exe 下载。

输出示例：

````
The device information is H4sIAAAAAAAA/wE0AMv/eyJkxxxxxxxxxx5TRSIsIm1hY2hpbmVpZCI6IkRFRkItOTExM0Y1OTYtOURENjdxxxxxxxxxxRA0AAAA
````

#### keygen端

##### 安装python 第三方库

`pip install -r requirements.txt`

##### 生成序列号

`python keygen\main.py -n [name] -d  [device_info]`

示例: `python keygen\main.py -nikun -d  H4sIAAAAAAAA/wE0AMv/eyJkxxxxxxxxxx5TRSIsIm1hY2hpbmVpZCI6IkRFRkItOTExM0Y1OTYtOURENjdxxxxxxxxxxRA0AAAA`

输出示例：

```
--------------------------------------------------
The activation code for the host machine is:
0w-vKrYmZZXP0Tv0xxxxxxx1FPZccEzL4dao8L7xt6HtDbWOBJfbeGm7U7SHvvUxEpWz6U2TptvaiI88G8yrwAYBaMh0JmWVz9E7dgjZ+RGhuRfXy6xxxxxxxxxkt/mXP28RBIBjS6Y1SD86AATr5dqIxbSm9S0HqNIDl8UDFvVwu1exY7k1nWvR2BoDDRQv4CZ4JOhOTFyCrhSqvJCKQN3SfxxxxxxxxxxG7L3q7x0raWDbrUCx+sJ1lynR6unisNNm0/+DUFbUKu2x72kJ18U91jqmC8APnqs2VhQS9dAA6NrMfKJ2ESJ+pyrNMQbeK0N8Xjmm5MzKIRf10DilnPOrgI++OlVj9E
--------------------------------------------------
```

## TODO

- [ ] client.exe 自动化patch Snipaste程序目录中的Snipaste.exe

## 效果图

![效果图](./assets/效果图.png)

## 补丁图
仅补丁一个返回值
![效果图](./assets/补丁图.png)