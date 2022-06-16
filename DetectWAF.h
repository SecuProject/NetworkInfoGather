#pragma once

#ifndef DETECT_WAF_HEADER_H
#define DETECT_WAF_HEADER_H

BOOL IsHttpWaf(RequestInfoStruct requestInfoStruct, FILE* pFile);

#endif