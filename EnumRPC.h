#pragma once

#ifndef ENUM_RPC_HEADER_H
#define ENUM_RPC_HEADER_H

// int EnumRPC("DC1","pentest.local", StructWordList structWordList);
int EnumRPC(char* NameDC, char* domainName, StructWordList structWordList);

BOOL RpcAuthBruteForce(BruteforceStruct bruteforceStruct);


#endif