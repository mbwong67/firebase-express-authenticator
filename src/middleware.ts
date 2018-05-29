import * as firebase from "firebase-admin";
import { Handler, Request, Response, NextFunction } from "express";

import {
  FirebaseAuthenticatorProperties,
  AuthenticationErrorHandler,
  AuthenticationError,
} from "./types";
import { authorizationFromHeaderOrCookie } from "./tokens";

const defaultErrorHandler: AuthenticationErrorHandler = (
  error: any,
  request: Request,
  response: Response,
  next: NextFunction
) => {
  if (error.name === "AuthenticationError") {
    response.sendStatus(401);
  } else {
    next(error);
  }
};

export const firebaseAuthenticator: (properties?: FirebaseAuthenticatorProperties) => Handler = (
  properties = {}
) => async (request: Request, response: Response, next: NextFunction) => {
  const tokenExtractor = properties.tokenExtractor || authorizationFromHeaderOrCookie();
  const errorHandler = (error: any) =>
    (properties.errorHandler || defaultErrorHandler)(error, request, response, next);

  const token = tokenExtractor(request);
  if (token) {
    const auth = properties.auth || firebase.auth();
    const verificationFunctions = properties.verificationFunctions || [];

    const verify = (claims: firebase.auth.DecodedIdToken) =>
      verificationFunctions.reduce(async (verified, verification) => {
        return (await verified) ? verification(claims) : false;
      }, Promise.resolve(true));

    try {
      const claims = await auth.verifyIdToken(token);
      const verified = await verify(claims);

      if (verified) {
        (request as any).claims = claims;
        next();
      } else {
        errorHandler(new AuthenticationError());
      }
    } catch (error) {
      errorHandler(new AuthenticationError(error.message));
    }
  } else {
    errorHandler(new AuthenticationError());
  }
};
