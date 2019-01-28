FROM python:3.7-slim-stretch
MAINTAINER Danny Grove <danny@drgrovellc.com>
WORKDIR /srv/
ADD requirements.txt /srv/
RUN apt update && \
  apt install -y gnupg openssl build-essential make && \
  pip3 install -r requirements.txt --src /usr/local/src
ADD *.py /srv/
ADD scripts/start.sh /srv/
ADD uwsgi.ini /srv/
RUN chown -R www-data:www-data /srv/
EXPOSE 4000
CMD ["./start.sh"]
