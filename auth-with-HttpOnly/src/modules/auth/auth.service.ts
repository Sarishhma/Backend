
import { randomUUID } from "crypto";
import { env } from "../../config/env.js";
import { sendOtpEmail } from "../../lib/email.js";
import { comparepassword, hashPassword } from "../../lib/password.js";
import { badRequest, conflict, forbidden, notFound, tooManyRequests, unauthorized } from "../../utils/app-error.js";

import { generateOtp, getOtpExpiry, hashOtp, isOtpExpired, verifyOtpHash } from "../../utils/otp.js";
import { signAccessToken, signRefreshToken,  verifyRefreshToken } from "../../utils/token.js";
import { createPasswordResetOtp, createRefreshToken, createUser, createVerificationOtp, deletePasswordResetOtpsForUser, deleteVerificationOtpsForUser, findActiveSessionsForUser, findLatestPasswordResetOtp, findLatestVerificationOtp, findRefreshTokenById, findRefreshTokenByIdAndUser, finduserByEmail, findUserById, incrementFailedLoginAttempts, incrementOtpAttempts, incrementPasswordResetAttempts, lockUserAccount, markEmailAsVerified, resetLoginAttempts, revokeAllUserRefreshToken, revokeRefreshToken, updateUserPassword } from "./auth.repository.js";




const REFRESH_TOKEN_MS = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds
const MAX_FAILED_ATTEMPTS=5;

function calculateLockoutDuration(failedLoginAttempts:number):number {
     // Number of times they've been locked out before, based on how far past the threshold they are
    const lockoutCount = Math.floor(failedLoginAttempts/MAX_FAILED_ATTEMPTS);
    const baseMinutes =1 ;
    const minutes = baseMinutes* Math.pow(5,lockoutCount-1)// 1min, 5min, 25min, 125min...
    return minutes * 60 * 1000
}
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
export async function loginUser(
    email:string,
    password:string,
    userAgent?:string,
    ipAddress?:string
){
    const user = await finduserByEmail(email);
    if(!user){
        throw unauthorized("Invalid email or password")
    }
  // Check lockout BEFORE checking the password
  if(user.lockedUntil && user.lockedUntil >new Date()){
    const minutesLeft = Math.ceil((user.lockedUntil.getTime()- Date.now())/60000);
    throw forbidden(`Account temporarily locked. Try again in ${minutesLeft} minute(s).`)
  }

    const isPasswordvalid= await  comparepassword(password,user.password);
    if(!isPasswordvalid){
        const newAttempts =user.failedLoginAttempts +1;
        if(newAttempts >= MAX_FAILED_ATTEMPTS && newAttempts% MAX_FAILED_ATTEMPTS===0){
         const lockoutMs = calculateLockoutDuration(newAttempts);
         const lockedUntil= new Date(Date.now()+lockoutMs);
         await lockUserAccount(user.id,lockedUntil)
        }
        await incrementFailedLoginAttempts(user.id);

        throw unauthorized("invalid email or password")
    }
    if(!user.isEmailVerified){
        throw forbidden("Please verify  your email before logging in ")
    }

  // Successful login — wipe the slate clean
    await resetLoginAttempts(user.id)

    const accessToken = signAccessToken({sub:user.id, email:user.email,role:user.role});

    const tokenId = randomUUID();
    const refreshToken=signRefreshToken({sub:user.id,jti:tokenId});
    const refreshTokenHash= hashOtp(refreshToken);// reusing our sha256 hash helper
    const refreshExpiresAt= new Date(Date.now()+REFRESH_TOKEN_MS);

await createRefreshToken(tokenId,user.id,refreshTokenHash,refreshExpiresAt,userAgent,ipAddress);
return{
    accessToken,
    refreshToken,
    user:{id:user.id,email:user.email,role:user.role}
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
        await revokeAllUserRefreshToken(tokenrecord.userId)
          throw unauthorized("Session invalid. Please log in again");
    }
    if(isOtpExpired(tokenrecord.expiresAt)){// 1. is the OLD token itself expired?
          throw unauthorized("Invalid or expired refresh token");
    }
    const user = await findUserById(tokenrecord.userId)// 2. fetch the user this token belongs to
      if (!user) {
    throw unauthorized("Invalid or expired refresh token");
  }

   // Rotate: revoke the old refresh token, issue a brand new one

await revokeRefreshToken(tokenrecord.id)// 3. kill the OLD token 
const newAccessToken= signAccessToken({sub:user.id,email:user.email,role:user.role})

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

export async function resendOtp(email:string){
const user = await finduserByEmail(email)
if(!user){
    throw notFound("NO account with this email")

}
if(user.isEmailVerified){
    throw badRequest("This email is already verified")
}
await deleteVerificationOtpsForUser(user.id)

const otp = generateOtp();
const otpHash=hashOtp(otp);
const expiresAt= getOtpExpiry();

await createVerificationOtp(user.id,otpHash,expiresAt)
await sendOtpEmail(user.email,otp)

 return { message: "A new verification code has been sent to your email." };

}

//forgot password 

export async function forgotPassword(email:string){
    const user = await finduserByEmail(email);
    // Deliberately do NOT throw an error if user doesn't exist — explained below
    if(!user){
        return{message:"If an account with this email exists, a reset code has been sent."}
    }
    await deletePasswordResetOtpsForUser(user.id)

    const otp = generateOtp();
    const otpHash = hashOtp(otp);
    const expireAt=getOtpExpiry();

    await createPasswordResetOtp(user.id,otpHash,expireAt)
    await sendOtpEmail(user.email,otp)
    return { message: "If an account with this email exists, a reset code has been sent." }; 
}

export async function resetPassword(email:string,otp:string,newPassword:string){
    const user = await finduserByEmail(email);
    if(!user){
        throw notFound("No account found with this email")
    }
    const otpRecord =await findLatestPasswordResetOtp(user.id);
    if(!otpRecord){
            throw badRequest("No reset code found. Please request a new one");
    }
      if (otpRecord.attempts >= env.OTP_MAX_ATTEMPTS) {
    throw tooManyRequests("Too many incorrect attempts. Please request a new code");
  }

  if (isOtpExpired(otpRecord.expiresAt)) {
    throw badRequest("This reset code has expired. Please request a new one");
  }
  const isValid =verifyOtpHash(otp,otpRecord.otpHash)
    if (!isValid) {
    await incrementPasswordResetAttempts(otpRecord.id);
    throw badRequest("Incorrect reset code");
  }

  const newPasswordHash =await hashPassword(newPassword);
  await updateUserPassword(user.id,newPasswordHash)


  await deletePasswordResetOtpsForUser(user.id);
  await revokeAllUserRefreshToken(user.id);

  return { message: "Password reset successfully. Please log in with your new password." };


}

export async function getUserSessions(userId: string) {
  const sessions = await findActiveSessionsForUser(userId);

  return sessions.map((session) => ({
    id: session.id,
    userAgent: session.userAgent,
    ipAddress: session.ipAddress,
    createdAt: session.createdAt,
    lastUsedAt: session.lastUsedAt,
  }));
}

export async function revokeSession(sessionId: string, userId: string) {
  const session = await findRefreshTokenByIdAndUser(sessionId, userId);

  if (!session) {
    throw notFound("Session not found");
  }

  await revokeRefreshToken(session.id);

  return { message: "Session revoked successfully" };
}