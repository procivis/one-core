FROM nginx:mainline-alpine

COPY docs/docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY target/doc /usr/share/nginx/html

# Make nginx user as owner
RUN chown -R nginx:nginx /etc/nginx/ /var/log/nginx/ /var/cache/nginx /var/run/ /run/ /usr/share/nginx

USER nginx
