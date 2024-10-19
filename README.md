# 一、项目简介<br>
### 该项目实现了S-DES算法，这是一种简化的数据加密标准，项目对一个输入为8-bit的数据，用10-bit的秘钥对其进行加密或解密。<br>
# 二、测试结果<br>
## 1、基本测试  
##### 对输入为11101011，秘钥为1100011110进行解密或加密得到结果如下  
![image](https://github.com/douge999/S-DES/blob/main/image/ba01500e-c780-41df-9f29-ab6e1258cc24.png)  
## 2、交叉测试  
#### 我与另一个小组对00111011，相同秘钥1001100111对其加密  
#### 我的结果  
![image](https://github.com/douge999/S-DES/blob/main/image/5a887829484e6f69972ca41005d6825e.png)
#### 另一个小组结果  
![image](https://github.com/douge999/S-DES/blob/main/image/47274b76fdb30dfaf4cadaad615fac62.png)
#### 结果相同
## 3、扩展功能  
#### 对一个输入ASII编码字符串，对其进行加密或者解密，得到以下结果  
![image](https://github.com/douge999/S-DES/blob/main/image/210db2c3a0d53c9c1fc450b321b092a8.png)  
## 4、暴力测试
#### 对已知的对应的密文和明文，使用暴力破解的方法找到正确的秘钥  
#### 使用多线程方式进行破解，但由于秘钥空间为2`^`56，运行时间过长，无法显示结果
#### 测试结果如下  
![image](https://github.com/douge999/S-DES/blob/main/image/851b9f05fa13688c289535cfa285b268.png)_  
## 5、封闭测试  
#### 由于上面的暴力破解运行时间过长，无法显示结果，这里我也不知道是否会存在不同的密钥得到相同的密文
