import { Request } from "express";

import { TokenExtractor } from "./types";

function headerAsString(header: string, request: Request): string | undefined {
  const value = request.headers[header];
  if (value === undefined) {
    return undefined;
  }

  return typeof value === "string" ? value : value[0];
}

function extractToken(authorization: string): string | undefined {
  const [bearer, token] = authorization.split(" ");
  if (bearer === "Bearer" && token) {
    return token;
  }

  return undefined;
}

export function authorizationFromHeader(request: Request) {
  return headerAsString("authorization", request);
}

export function authorizationFromCookie(
  request: Request,
  cookieName: string = "Authorization"
): string | undefined {
  return cookieName && request.cookies && request.cookies[cookieName];
}

export const authorizationFromHeaderOrCookie = (cookieName?: string): TokenExtractor => (
  request: Request
): string | undefined => {
  const authorization =
    authorizationFromHeader(request) || authorizationFromCookie(request, cookieName);
  return authorization ? extractToken(authorization) : undefined;
};
