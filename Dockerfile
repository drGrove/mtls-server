FROM nginx:1.15.8
MAINTAINER Danny Grove <danny@drgrovellc.com>
WORKDIR /srv/
ADD requirements.txt /srv/
RUN apt update && \
  apt install -y gnupg openssl python3-dev python3-pip build-essential make && \
  pip3 install -r requirements.txt --src /usr/local/src
ADD *.py /srv/
ADD nginx/nginx.conf /etc/nginx/
ADD nginx/includes /etc/nginx/includes/
ADD scripts/start.sh /srv/
ADD uwsgi.ini /srv/
RUN chown -R www-data:www-data /srv/
EXPOSE 4000
CMD ["./start.sh"]
