FROM python:3.7-slim-stretch
MAINTAINER Danny Grove <danny@drgrovellc.com>
RUN apt update && \
  apt install -y gnupg openssl build-essential make
RUN useradd -m mtls
RUN echo "export PATH=/home/mtls/.local/bin:$PATH" >> .bashrc
USER mtls
WORKDIR /home/mtls/
ADD requirements.txt /home/mtls/
RUN pip3 install -r requirements.txt --src /usr/local/src --user
ADD *.py /home/mtls/
ADD uwsgi.ini /home/mtls/
RUN mkdir /home/mtls/secrets && chown -R mtls:mtls /home/mtls/secrets
EXPOSE 4000
CMD ["/home/mtls/.local/bin/uwsgi", "--ini", "uwsgi.ini"]
