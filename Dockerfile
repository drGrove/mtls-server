# 3.9.5-slim
ARG PYTHON_DIGEST="sha256:076f9edf940d59446b98c242de0058054240b890a47d1dbed18560d12ec58228"
FROM python@${PYTHON_DIGEST} as build-container
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
COPY --chown=mtls:mtls mtls_server /home/mtls/mtls_server
COPY --chown=mtls:mtls LICENSE /home/mtls/
COPY --chown=mtls:mtls VERSION  /home/mtls/
RUN mkdir -p /home/mtls/secrets
EXPOSE 4000
CMD ["/home/mtls/.local/bin/uwsgi", "--ini", "uwsgi.ini"]
