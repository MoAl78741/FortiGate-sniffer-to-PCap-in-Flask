# docker build -t sniffer2pcap .
# docker run -p 127.0.0.1:5001:5000/tcp --name sniffer2pcap sniffer2pcap

FROM ubuntu

COPY . /app

WORKDIR /app

RUN apt update
RUN apt install python3-pip -y
RUN apt install perl -y
RUN DEBIAN_FRONTEND=noninteractive apt install wireshark-common -yq
RUN pip3 install -r requirements.txt

EXPOSE 5000
ENTRYPOINT [ "python3" ]
CMD [ "-m", "flask", "run", "--host=0.0.0.0" ]