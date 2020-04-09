FROM python:3.8.2-slim as build-container
MAINTAINER Danny Grove <danny@drgrovellc.com>
RUN apt update && \
  apt install -y gnupg openssl build-essential make sqlite3
RUN useradd -u 1000 -m mtls
RUN echo "export PATH=/home/mtls/.local/bin:$PATH" >> .bashrc
USER mtls
WORKDIR /home/mtls/
COPY --chown=mtls:mtls requirements.txt /home/mtls/
RUN pip3 install -r requirements.txt --src /usr/local/src --user
COPY --chown=mtls:mtls uwsgi.ini /home/mtls/
COPY --chown=mtls:mtls *.py /home/mtls/
COPY --chown=mtls:mtls LICENSE /home/mtls/
COPY --chown=mtls:mtls VERSION  /home/mtls/
RUN mkdir /home/mtls/secrets
EXPOSE 4000
CMD ["/home/mtls/.local/bin/uwsgi", "--ini", "uwsgi.ini"]
