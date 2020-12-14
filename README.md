# Aquaman

自动化渗透测试(安全审计)API服务器

# Function
- 资产探测(探测资产信息,Web指纹、IP运营商、GPS、区域、端口、服务等信息)
- 认证爆破(支持ssh、ftp、vnc、cisco、smb、mysql、smtp等数十种服务的认证爆破)
- Web渗透(SQL注入、upload任意文件上传等高危web漏洞)
- 服务漏洞(包含中间件、web服务器、数据库、网站等可定制的Poc检测)
- 自动化作业任务(周期、定时探测)

# Description
(若图片无法显示，可在images文件夹中获得)  
0.login  
![login](https://github.com/jstang9527/aquaman/tree/main/images/login.png)  
1.Dashboard  
![dashboard](https://github.com/jstang9527/aquaman/tree/main/images/dashboard.png)  
2.资产任务  
![dashboard](https://github.com/jstang9527/aquaman/tree/main/images/assets.png)  
3.资产详情  
![dashboard](https://github.com/jstang9527/aquaman/tree/main/images/asset1.png)  
4.资产详情2  
![dashboard](https://github.com/jstang9527/aquaman/tree/main/images/asset2.png)  
5.资产详情3  
![dashboard](https://github.com/jstang9527/aquaman/tree/main/images/asset3.png)  
6.Poc漏洞渗透  
![dashboard](https://github.com/jstang9527/aquaman/tree/main/images/poc.png)  
7.Web漏洞检出  
![dashboard](https://github.com/jstang9527/aquaman/tree/main/images/webs.png)  
8.Web漏洞详情  
![dashboard](https://github.com/jstang9527/aquaman/tree/main/images/web.png)  
9.认证爆破  
![dashboard](https://github.com/jstang9527/aquaman/tree/main/images/authtest.png)  
10.认证任务  
![dashboard](https://github.com/jstang9527/aquaman/tree/main/images/authtest2.png)  
11.系统设定  
![dashboard](https://github.com/jstang9527/aquaman/tree/main/images/sys.png)  


# Require
- Python2.7
- Hydra
- Awvs
- Nmap
- Pocsuite


# Install
- 容器安装  

docker run -d -p 27017:27017 -v /home/aquaman/mongo/config:/data/configdb -v /home/aquaman/mongo/db:/data/db --name mongo mongo --auth  
docker run -it -d -p 23443:3443 --name awvs jstang/awvs:1.0  
docker run -itd -v settings.py:/home/aquaman/application/settings.py -p 9777:9777 --name aquaman jstang/aquaman:1.0  
docker run -itd -v vue.config.js:/opt/vue.config.js -p 9527:9527 --name aquaman-view jstang/aquaman-view:1.0  

# Dockerfile
```shell
FROM prodataninja/ubuntu-python2.7:latest

MAINTAINER jstang <389634070@qq.com>

ADD . /home/aquaman

WORKDIR /home/aquaman

RUN rm -rf mongo && \
    apt-get update && \
    apt-get -y install hydra nmap && \
    pip install --upgrade pip -i https://pypi.doubanio.com/simple/ && \
    pip install -r requirements.txt -i https://pypi.doubanio.com/simple/

EXPOSE 9777

CMD ["python", "main.py"]
```

# 免责声明
本软件仅提供学习测试使用, 不得使用于非法用途, 若触发法律行为, 本人概不负责。
