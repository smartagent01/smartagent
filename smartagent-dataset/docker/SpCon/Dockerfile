FROM ubuntu:20.04

RUN apt-get update && apt-get install -y software-properties-common gcc && \
    add-apt-repository -y ppa:deadsnakes/ppa

RUN apt-get update && apt-get install -y python3.8 python3-distutils python3-pip python3-apt

RUN mkdir /home/spcon
WORKDIR /home/spcon

RUN apt-get install -y git
RUN git clone https://github.com/BubaVV/Pyevolve
RUN cd Pyevolve && /usr/bin/python3 setup.py install && cd ..

RUN pip3 install web3==5.29.0
COPY ISSTA2022Result ISSTA2022Result
COPY spcon spcon
COPY README.md README.md
COPY setup.py setup.py
RUN /usr/bin/python3 setup.py install

RUN /usr/bin/pip3 install solc-select
RUN apt-get install z3

CMD ["/usr/bin/spcon"]



