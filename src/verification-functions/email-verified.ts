import { auth } from "firebase-admin";

import { AuthenticationVerificationFunction } from "../types";

export const emailVerified: AuthenticationVerificationFunction = (claims: auth.DecodedIdToken) => {
  return claims.email_verified === true;
};
