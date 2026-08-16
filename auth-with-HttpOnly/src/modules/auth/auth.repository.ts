import { prisma } from "../../lib/prisma.js";
// This is the only file in the entire auth module allowed to call prisma directly — 
// everything else (service, controller) goes through these functions instead.

//create user
export  function createUser(email:string,passwordHash:string){
    return prisma.user.create({
        data:{
            email,
            password:passwordHash
        }
    })
}

export function finduserByEmail(email:string){
    return prisma.user.findUnique({
        where:{email}
    })
}
export function findUserById(id:string){
    return prisma.user.findUnique({
        where:{id}
    })
}

export function markEmailAsVerified(userId:string){
    return prisma.user.update({
        where:{id:userId},
        data:{isEmailVerified:true}

})
}
//otp queries
export function createVerificationOtp(
    userId:string,
otpHash:string,
expiresAt:Date,
){
return prisma.verificationOtp.create({
    data:{userId,otpHash,expiresAt}
})
}
export function findLatestVerificationOtp(userId:string){
    return prisma.verificationOtp.findFirst({
        where:{userId},
        orderBy:{createdAt:"desc"}
    })
}
export function incrementOtpAttempts(otpId:string){
    return prisma.verificationOtp.update({
        where:{id:otpId},
        data:{attempts:{increment:1}}
        // instead of your JavaScript code reading a number, doing math, and sending a new number back — this tells Postgres itself: 
        // "whatever the current value is at the exact moment you run this, add 1 to it, in one single indivisible operation." Postgres handles both requests one at
        //  a time internally (databases are built to do this safely),
    })
}
export function deleteVerificationOtpsForUser(userId:string){
    return prisma.verificationOtp.deleteMany({
        where:{userId}
    })
}
// ── Refresh token queries ──────────────────────────────
export function createRefreshToken(
    id:string,
    userId:string,
    tokenHash:string,
    expiresAt:Date,
    userAgent?:string,
    ipAddress?:string
){
    return prisma.refreshToken.create({
        data:{id,userId,tokenHash,expiresAt,userAgent,ipAddress}
    })
}
export function  findRefreshTokenById(id:string){
    return prisma.refreshToken.findUnique({
        where:{id}
    })
}
export function revokeRefreshToken(id:string){
    return prisma.refreshToken.update({
        where:{id},
        data:{revoked:true}
    })
}
export function revokeAllUserRefreshToken(userId:string){
    return prisma.refreshToken.updateMany({
        where:{userId},
        data:{revoked:true}
    })
}
// This layer answers only "how do I read/write this data," never "should this be allowed."

//password reset  Otp queries

export function createPasswordResetOtp(
    userId:string,
    otpHash:string,
    expiresAt:Date
){
    return  prisma.passwordResetOtp.create({
        data:{userId,otpHash,expiresAt}
    })
}
export function findLatestPasswordResetOtp(userId:string){
    return prisma.passwordResetOtp.findFirst({
        where:{userId},
        orderBy:{createdAt:"desc"}
    })
}

export function incrementPasswordResetAttempts(otpId:string){
    return prisma.passwordResetOtp.update({
        where:{id:otpId},
        data:{attempts:{increment:1}}
    })
}

export function deletePasswordResetOtpsForUser(userId:string){
    return prisma.passwordResetOtp.deleteMany({
        where:{userId}
    })
}

export function updateUserPassword(userId:string,passwordHash:string){
    return prisma.user.update({
        where:{id:userId},
        data:{password:passwordHash}
    })

}

export function incrementFailedLoginAttempts(userId:string){
    return prisma.user.update({
        where:{id:userId},
        data:{failedLoginAttempts:{increment:1}}

    })
}

export function lockUserAccount (userId:string,lockedUntil:Date){
    return prisma.user.update({
        where:{id:userId},
        data:{lockedUntil}
    })
}

export function resetLoginAttempts(userId:string){
    return prisma.user.update({
        where :{id:userId},
        data:{failedLoginAttempts:0,lockedUntil:null}
    })
}

export function findActiveSessionsForUser (userId:string){
    return prisma.refreshToken.findMany({
        where:{
            userId,
            revoked:false,
            expiresAt:{gt:new Date()},//gte/lte (greater/less than or equal).


        },
        orderBy:{lastUsedAt:"desc"},
    })
}

export function touchRefreshToken(id:string){
    return prisma.refreshToken.update({
        where:{id},
        data:{lastUsedAt: new Date()}
    })
}

export function findRefreshTokenByIdAndUser(id:string,userId:string){
    return prisma.refreshToken.findFirst({
        where:{id,userId}
    })
}