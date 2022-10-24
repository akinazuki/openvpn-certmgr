FROM ubuntu:jammy

RUN apt-get update
RUN apt-get install -y openssl easy-rsa wget python3-pip libssl-dev libffi-dev python3-dev build-essential cargo
RUN wget https://github.com/OpenVPN/easy-rsa/releases/download/v3.1.1/EasyRSA-3.1.1.tgz
RUN tar xzvf EasyRSA-3.1.1.tgz
RUN rm EasyRSA-3.1.1.tgz
RUN chmod +x /EasyRSA-3.1.1/easyrsa
RUN ln -s /EasyRSA-3.1.1/easyrsa /bin/easyrsa
RUN easyrsa init-pki
COPY certmgr.py /bin/certmgr
RUN chmod +x /bin/certmgr
RUN pip3 install tabulate pyopenssl
ENTRYPOINT ["/bin/certmgr"]