#!/bin/bash -eu

# Put the platform-specific definitions here

HTTPD_SYSTEMD_NAME='httpd2.service'
HTTPD_LOGDIR='/var/log/httpd2'
HTTPD_ERRORLOG="${HTTPD_LOGDIR}/error_log"
HTTPD_BASEDIR='/etc/httpd2'
HTTPD_ALIASDIR="${HTTPD_BASEDIR}/conf"
BIND_BASEDIR='/var/lib/bind'
BIND_DATADIR="${BIND_BASEDIR}/data"
