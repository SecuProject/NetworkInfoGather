
/* 
 * NetworkInfoGather
 * Copyright (C) 2023  SecuProject
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
