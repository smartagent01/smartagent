FROM ubuntu:20.04

RUN apt-get update && apt-get install -y software-properties-common gcc && \
    add-apt-repository -y ppa:deadsnakes/ppa

RUN apt-get update && apt-get install -y python3.9 python3-distutils python3-pip python3-apt
RUN ln -s /usr/bin/python3 /usr/bin/python
RUN mkdir /root/Achecker
WORKDIR /root/Achecker

COPY ./ /root/Achecker
RUN pip3 install -r requirements.txt
RUN chmod +x process_file.sh
ENTRYPOINT ["./process_file.sh"]



