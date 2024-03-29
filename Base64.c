
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

#include <stdio.h>
#include <string.h>

#pragma warning(disable : 4996)

/* ---- Base64 Encoding/Decoding Table --- */
char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* decodeblock - decode 4 '6-bit' characters into 3 8-bit binary bytes */
void decodeblock(unsigned char in[], char* clrstr) {
    unsigned char out[4];
    out[0] = in[0] << 2 | in[1] >> 4;
    out[1] = in[1] << 4 | in[2] >> 2;
    out[2] = in[2] << 6 | in[3] >> 0;
    out[3] = '\0';
    strncat(clrstr, out, sizeof(out));
}

void Base64Dencode(char* input, char* output) {
    int phase, i;
    unsigned char in[4];
    char* p;

    output[0] = '\0';
    phase = 0; i = 0;
    while (input[i]) {
        int c = (int)input[i];
        if (c == '=') {
            decodeblock(in, output);
            break;
        }
        p = strchr(b64, c);
        if (p) {
            in[phase] = (unsigned char)(p - b64);
            phase = (phase + 1) % 4;
            if (phase == 0) {
                decodeblock(in, output);
                in[0] = in[1] = in[2] = in[3] = 0;
            }
        }
        i++;
    }
}

/* encodeblock - encode 3 8-bit binary bytes as 4 '6-bit' characters */
void encodeblock(unsigned char in[], char b64str[], int len) {
    unsigned char out[5];
    out[0] = b64[in[0] >> 2];
    out[1] = b64[((in[0] & 0x03) << 4) | ((in[1] & 0xf0) >> 4)];
    out[2] = (unsigned char)(len > 1 ? b64[((in[1] & 0x0f) << 2) |
        ((in[2] & 0xc0) >> 6)] : '=');
    out[3] = (unsigned char)(len > 2 ? b64[in[2] & 0x3f] : '=');
    out[4] = '\0';
    strncat(b64str, out, sizeof(out));
}

/* encode - base64 encode a stream, adding padding if needed */
void Base64Encode(char* input, char* output) {
    unsigned char in[3];
    int j = 0;

    output[0] = '\0';
    while (input[j]) {
        int len = 0;
        for (int i = 0; i < 3; i++) {
            in[i] = (unsigned char)input[j];
            if (input[j]) {
                len++; j++;
            } else in[i] = 0;
        }
        if (len) {
            encodeblock(in, output, len);
        }
    }
}