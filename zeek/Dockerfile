FROM zeek/zeek:8.0.0
# Install your persistent dependencies
RUN apt-get update && apt-get install -y python3-pip git && \
    pip3 install btest --break-system-packages
