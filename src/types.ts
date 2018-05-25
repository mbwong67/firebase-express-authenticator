import { auth } from "firebase-admin";
import { Request, Response, NextFunction } from "express";

export type AuthenticationVerificationFunction = (
  claims: auth.DecodedIdToken
) => boolean | Promise<boolean>;

export type AuthenticationErrorHandler = (
  error: any,
  request: Request,
  response: Response,
  next: NextFunction
) => void;

export type TokenExtractor = (request: Request) => string | undefined;

export type FirebaseAuthenticatorProperties = {
  auth?: auth.Auth;
  tokenExtractor?: TokenExtractor;
  errorHandler?: AuthenticationErrorHandler;
  verificationFunctions?: AuthenticationVerificationFunction[];
};

export class AuthenticationError extends Error {
  constructor(message: string = "Unauthorized") {
    super(message);
    Object.setPrototypeOf(this, AuthenticationError.prototype);
    this.name = "AuthenticationError";
  }
}
