## todesk_get_passwd

## 测试

v4.7.6.3 v4.7.7.0 火绒360暂时没看到杀

 v4.7.7.1 偏移错误 

## 介绍

一款暴力搜索内存找到todesk密码的小工具 - 可以读取临时密码 安全密码 设备代码 手机号

**免责声明：本工具仅供安全研究与学习之用，禁止用于任何非法活动。如用于其他用途，由使用者承担全部法律及连带责任，与工具作者无关。**

## 原理

通过暴力搜索"WinSock 2.0"这个字符串来确定基址,随后搜索0x1000范围内的有效字符串

![QQ_1747999107198](./QQ_1747999107198.png)