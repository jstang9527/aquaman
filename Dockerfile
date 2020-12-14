FROM prodataninja/ubuntu-python2.7:latest

MAINTAINER jstang <389634070@qq.com>

# ADD get-pip.py /tmp/
ADD . /home/aquaman

WORKDIR /home/aquaman

RUN rm -rf mongo && \
    apt-get update && \
    apt-get -y install hydra nmap && \
    pip install --upgrade pip -i https://pypi.doubanio.com/simple/ && \
    pip install -r requirements.txt -i https://pypi.doubanio.com/simple/

EXPOSE 9777

CMD ["python", "main.py"]
