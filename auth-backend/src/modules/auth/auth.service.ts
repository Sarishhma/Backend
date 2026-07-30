
import { randomUUID } from "crypto";
import { env } from "../../config/env.js";
import { sendOtpEmail } from "../../lib/email.js";
import { comparepassword, hashPassword } from "../../lib/password.js";
import { badRequest, conflict, forbidden, notFound, tooManyRequests, unauthorized } from "../../utils/app-error.js";

import { generateOtp, getOtpExpiry, hashOtp, isOtpExpired, verifyOtpHash } from "../../utils/otp.js";
import { signAccessToken, signRefreshToken,  verifyRefreshToken } from "../../utils/token.js";
import { createRefreshToken, createUser, createVerificationOtp, deleteVerificationOtpsForUser, findLatestVerificationOtp, findRefreshTokenById, finduserByEmail, findUserById, incrementOtpAttempts, markEmailAsVerified, revokeAllUserRefreshToken, revokeRefreshToken } from "./auth.repository.js";


const REFRESH_TOKEN_MS = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds

// this is for user registration
export async function  registerUser(email:string,password:string){
    const existingUser =await finduserByEmail(email)
    if(existingUser){
        throw conflict("An account with this email already exists")
    }
 
const passwordHash= await hashPassword(password);
const user =await createUser(email,passwordHash)
await deleteVerificationOtpsForUser(user.id)
const otp = generateOtp();
const otpHash=hashOtp(otp)
const expiresAt=getOtpExpiry()

await createVerificationOtp(user.id,otpHash,expiresAt)
await sendOtpEmail(user.email,otp)

return {
        message: "Registration successful. Please check your email for the verification code.",
    userId: user.id,
}
}

// this is for verifying email
export async function verifyEmail(email:string,otp:string){
const user = await finduserByEmail(email)
if(!user){
    throw notFound("No account with this email");
}
if(user.isEmailVerified){
    throw badRequest("This email is already verified")
}
const otpRecord=await findLatestVerificationOtp(user.id);
if(!otpRecord){
    throw badRequest("No verification vode found .Please request a new one ")
}
  if (otpRecord.attempts >= env.OTP_MAX_ATTEMPTS) {
    throw tooManyRequests("Too many incorrect attempts. Please request a new code");
  }
    if (isOtpExpired(otpRecord.expiresAt)) {
    throw badRequest("This verification code has expired. Please request a new one");
  }
  const isValid= verifyOtpHash(otp,otpRecord.otpHash);
    if (!isValid) {
    await incrementOtpAttempts(otpRecord.id);
    throw badRequest("Incorrect verification code");
  }

  await markEmailAsVerified(user.id);
  await deleteVerificationOtpsForUser(user.id);
    return { message: "Email verified successfully. You can now log in." };

}


// this is for login  or This is where the isEmailVerified gate actually gets enforced, plus real token issuance.
export async function loginUser(email:string,password:string){
    const user = await finduserByEmail(email);
    if(!user){
        throw unauthorized("Invalid email or password")
    }
    const isPasswordvalid= await  comparepassword(password,user.password);
    if(isPasswordvalid){
        throw unauthorized("invalid email or password")
    }
    if(!user.isEmailVerified){
        throw forbidden("Please verify  your email before logging in ")
    }
    const accessToken = signAccessToken({sub:user.id, email:user.email});

    const tokenId = randomUUID();
    const refreshToken=signRefreshToken({sub:user.id,jti:tokenId});
    const refreshTokenHash= hashOtp(refreshToken);// reusing our sha256 hash helper
    const refreshExpiresAt= new Date(Date.now()+REFRESH_TOKEN_MS);

await createRefreshToken(tokenId,user.id,refreshTokenHash,refreshExpiresAt);
return{
    accessToken,
    refreshToken,
    user:{id:user.id,email:user.email}
}

}
//refreshToken access
export async function refreshAccessToken(refreshToken:string){
    let decoded;
    try{
        decoded= verifyRefreshToken(refreshToken)
    }catch{
        throw unauthorized("Invalid or expired refresh Token")
    }
    const tokenrecord= await findRefreshTokenById(decoded.jti)
    if(!tokenrecord){
         throw unauthorized("Invalid or expired refresh Token")
    }
    if(tokenrecord.revoked){
         // This token was already used/revoked once but is being used again —
    // a strong signal it was stolen. Revoke ALL of this user's sessions as a precaution.
        await revokeAllUserRefreshToken(tokenrecord.id)
          throw unauthorized("Session invalid. Please log in again");
    }
    if(isOtpExpired(tokenrecord.expiresAt)){// 1. is the OLD token itself expired?
          throw unauthorized("Invalid or expired refresh token");
    }
    const user = await findUserById(tokenrecord.id)// 2. fetch the user this token belongs to
      if (!user) {
    throw unauthorized("Invalid or expired refresh token");
  }

   // Rotate: revoke the old refresh token, issue a brand new one

await revokeRefreshToken(tokenrecord.id)// 3. kill the OLD token 
const newAccessToken= signAccessToken({sub:user.id,email:user.email})

const newTokenId = randomUUID()
const newRefreshToken= signRefreshToken({sub:user.id,jti:newTokenId})
const newRefreshTokenHash= hashOtp(newRefreshToken)
const newExpireAt = new Date(Date.now()+ REFRESH_TOKEN_MS)

await createRefreshToken(newTokenId,user.id,newRefreshTokenHash,newExpireAt)//save to db
return{
    accessToken:newAccessToken,
    refreshToken:newRefreshToken
}

}

//logoutuser
export async function logoutUser(refreshToken:string){
    let decoded;
    try{
        decoded = verifyRefreshToken(refreshToken)

    }catch{
         return { message: "Logged out" };
    }
    const tokenRecord = await findRefreshTokenById(decoded.jti)
    // Only reached if the token verified successfully above. Now we take the jti (the unique ID we signed into the token back when
    //      it was issued) and use it to look up 
    // the exact matching row in your RefreshToken database table
    if(tokenRecord){
            await revokeRefreshToken(tokenRecord.id);
    }
return{message:"Loged Out"}
}