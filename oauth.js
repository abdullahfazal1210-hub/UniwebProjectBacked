import { Google } from "arctic";
import dotenv from "dotenv";

dotenv.config();

const clientId = process.env.GOOGLE_CLIENT_ID?.trim();
const clientSecret = process.env.GOOGLE_CLIENT_SECRET?.trim();
const redirectUri = `${process.env.BACKEND_URL?.trim()}/auth/google/callback`;

console.log("Google OAuth Config:", {
    clientId: clientId ? "exists" : "MISSING",
    clientSecret: clientSecret ? "exists" : "MISSING",
    redirectUri
});

export const google = new Google(clientId, clientSecret, redirectUri);
