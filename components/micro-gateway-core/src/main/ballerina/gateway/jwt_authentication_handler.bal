// Copyright (c) 2019 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
//
// WSO2 Inc. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

import ballerina/http;
import ballerina/log;
import ballerina/auth;
import ballerina/cache;
import ballerina/config;
import ballerina/runtime;
import ballerina/time;
import ballerina/io;

public type JwtAuthenticationHandler object {

    public string name;
    public auth:JWTAuthProviderConfig jwtConfig;
    public auth:JWTAuthProvider jwtAuthProvider;
    public http:HttpJwtAuthnHandler jwtAuthnHandler;

    public function canHandle(http:Request req) returns (boolean);
    public function handle(http:Request req) returns (boolean);
    public function __init(auth:JWTAuthProvider jwtAuthProvider, auth:JWTAuthProviderConfig jwtConfig) {
        self.jwtAuthProvider = jwtAuthProvider;
        self.jwtConfig = jwtConfig;
        self.jwtAuthProvider = new(self.jwtConfig);
        self.jwtAuthnHandler = new(self.jwtAuthProvider);
        self.name = "jwt";
    }
};

public function JwtAuthenticationHandler.canHandle(http:Request req) returns (boolean) {
    return self.jwtAuthnHandler.canHandle(req);
}

public function JwtAuthenticationHandler.handle(http:Request req) returns (boolean) {
    //Start a span attaching to the system span.
    int|error|() spanId_req = startingSpan(JWT_AUTHENHANDLER_HANDLE);
    boolean handleVar;
    //Start a new child span for the span.
    int|error|() spanId_Bal = startingSpan(BALLERINA_JWTAUTHN_HANDLER);
    handleVar = self.jwtAuthnHandler.handle(req);
    //finishing span
    finishingSpan(BALLERINA_JWTAUTHN_HANDLER, spanId_Bal);
    if (handleVar) {
        boolean isBlacklisted = false;
        string? jti = "";
        string jwtToken = runtime:getInvocationContext().authContext.authToken;
        //Start a new child span for the span.
        int|error|() spanId_Cache = startingSpan(JWT_CACHE);
        var cachedJwt = trap <auth:CachedJwt>jwtCache.get(jwtToken);
        //finishing span
        finishingSpan(JWT_CACHE, spanId_Cache);
        if (cachedJwt is auth:CachedJwt) {
            printDebug(KEY_JWT_AUTH_PROVIDER, "jwt found from the jwt cache");
            internal:JwtPayload jwtPayloadFromCache = cachedJwt.jwtPayload;
            jti = jwtPayloadFromCache["jti"];
            if(jti is string) {
                printDebug(KEY_JWT_AUTH_PROVIDER, "jti claim found in the jwt");
                printDebug(KEY_JWT_AUTH_PROVIDER, "Checking for the JTI in the gateway invalid revoked token map.");
                var status = retrieveFromRevokedTokenMap(jti);
                if (status is boolean) {
                    if (status) {
                        printDebug(KEY_JWT_AUTH_PROVIDER, "JTI token found in the invalid token map.");
                        isBlacklisted = true;
                    } else {
                        printDebug(KEY_JWT_AUTH_PROVIDER, "JTI token not found in the invalid token map.");
                        isBlacklisted = false;
                    }
                } else {
                    printDebug(KEY_JWT_AUTH_PROVIDER, "JTI token not found in the invalid token map.");
                    isBlacklisted = false;
                }

                if (isBlacklisted) {
                    printDebug(KEY_JWT_AUTH_PROVIDER, "JWT Authentication Handler returned with value : " + !isBlacklisted);
                    printDebug(KEY_JWT_AUTH_PROVIDER, "JWT Token is revoked");
                    //Finish span.
                    finishingSpan(JWT_AUTHENHANDLER_HANDLE, spanId_req);
                    return false;
                } else {
                    //Finish span.
                    finishingSpan(JWT_AUTHENHANDLER_HANDLE, spanId_req);
                    return true;
                }

            } else {
                printDebug(KEY_JWT_AUTH_PROVIDER, "jti claim not found in the jwt");
                //Finish span.
                finishingSpan(JWT_AUTHENHANDLER_HANDLE, spanId_req);
                return handleVar;
            }

        } else {
            printDebug(KEY_JWT_AUTH_PROVIDER, "jwt not found in the jwt cache");
            //Finish span.
            finishingSpan(JWT_AUTHENHANDLER_HANDLE, spanId_req);
            return handleVar;
        }

    } else {
        //Finish span.
        finishingSpan(JWT_AUTHENHANDLER_HANDLE, spanId_req);
        return handleVar;
    }
}

