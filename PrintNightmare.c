
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

#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "Rpcrt4.lib")

BOOL CheckPrintNightmare(char* ipAddress,BOOL is2tab){
    RPC_CSTR szStringBinding = NULL;
    RPC_BINDING_HANDLE hRpc;
    RPC_EP_INQ_HANDLE hInq;
    RPC_STATUS rpcErr;

    printf("%s[-] Checking for print nightmare vulnerability\n",is2tab ? "\t" : "" );

    rpcErr = RpcStringBindingComposeA(NULL, "ncacn_ip_tcp", ipAddress, NULL, NULL, &szStringBinding);
    if (rpcErr != RPC_S_OK){
        printf("%s\t[x] RpcStringBindingCompose failed: %d\n", is2tab ? "\t":"", rpcErr);
        return FALSE;
    }

    rpcErr = RpcBindingFromStringBindingA(szStringBinding, &hRpc);
    if (rpcErr != RPC_S_OK){
        printf("%s\t[x] RpcBindingFromStringBinding failed: %d\n", is2tab ? "\t" : "", rpcErr);
        RpcStringFreeA(&szStringBinding);
        return FALSE;
    }

    rpcErr = RpcMgmtEpEltInqBegin(hRpc, RPC_C_EP_ALL_ELTS, NULL, 0, NULL, &hInq);
    if (rpcErr != RPC_S_OK){
        printf("%s\t[x] RpcMgmtEpEltInqBegin failed: %d\n", is2tab ? "\t" : "", rpcErr);
        RpcStringFreeA(&szStringBinding);
        RpcBindingFree(&hRpc);
        return FALSE;
    }

    while (rpcErr != RPC_X_NO_MORE_ENTRIES){
        RPC_IF_ID IfId;
        RPC_BINDING_HANDLE hEnumBind;
        UUID uuid;
        RPC_CSTR szAnnot;

        rpcErr = RpcMgmtEpEltInqNextA(hInq, &IfId, &hEnumBind, &uuid, &szAnnot);
        if (rpcErr == RPC_S_OK){
            RPC_CSTR str = NULL;
            if (UuidToStringA(&(IfId.Uuid), &str) == RPC_S_OK){
                /*
                * Spool File Contents
                [MS-RPRN] 12345678-1234-abcd-ef00-0123456789ab -> https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rprn/e8f9dad8-d114-41cc-9a52-fc927e908cf4
                [MS-PAR] 76F03F96-CDFD-44FC-A22C-64950A001209 -> https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-par/d81865df-838d-4c13-a705-d41ee24890de
                */
                if (strcmp(str, "12345678-1234-abcd-ef00-0123456789ab") == 0
                    || strcmp(str, "76F03F96-CDFD-44FC-A22C-64950A001209") == 0){
                    printf("%s\t[i] The host %s is probably vulnerable !\n", is2tab ? "\t" : "", ipAddress);
                    RpcStringFreeA(&str);
                    RpcStringFreeA(&szStringBinding);
                    RpcBindingFree(&hRpc);
                    return TRUE;
                }
                RpcStringFreeA(&str);
            }
        }
    }
    RpcStringFreeA(&szStringBinding);
    RpcBindingFree(&hRpc);

    return FALSE;
}