#pragma once

#ifdef WEB_WORD_LIST_HEADER_H
#ifndef APACHE_WORD_LIST_HEADER_H
#define APACHE_WORD_LIST_HEADER_H

const char* wordListApacheFile[] = {
"/.htaccess",
"/.htpasswd",
"/.meta",
"/.web",
"/access_log",
"/cgi",
"/cgi-bin",
"/cgi-pub",
"/cgi-script",
"/dummy",
"/error",
"/error_log",
"/htdocs",
"/httpd",
"/httpd.pid",
"/icons",
"/index.html",
"/phf",
"/printenv",
"/server-info",
"/server-status",
"/status",
"/test-cgi",
"/~bin",
"/~ftp",
"/~nobody",
"/~root",
"/php.ini",
"/mod_cluster-manager",
"/balancer-manager"
};
const char* wordListApacheDir[] = {
"/tmp/",
"/logs/",
"/manual/",
"/server-info/",
"/server-status/"
};

#endif
#endif
