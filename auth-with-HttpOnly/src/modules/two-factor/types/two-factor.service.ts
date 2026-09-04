// generate secret
// generate OTP URI
// generate QR data
// verify TOTP code

import {
  generateSecret,
  generateURI,
  verify,
} from "otplib";
import { twoFactorRepository } from "../repositories/two-factor.repository.js";
import {
  badRequest,
  conflict,
  notFound,
} from "../../../utils/app-error.js";
import { success } from "zod";

export const twoFactorService={
async generateSetup(userId:string,email:string){
    const user = await twoFactorRepository.findUserById(userId)
    if(!user){
        throw notFound ("user not found")
    }

    if(user.isTwoFactorEnabled){
        throw conflict ("Two factor authentication is already established");
    }
    // Generate a random Base32 secret
    const secret =generateSecret()

     // Save the secret

     await twoFactorRepository.saveTopSecrete(userId,secret)

     // Generate the URI that will be encoded into the QR code
     const otpauthURl =generateURI({
        issuer:"Sarishma's App Name",
        label:"email",
        secret
     });

     return{
        secret,
        otpauthURl
     }


},


async verifySetup(userId:string,code:string){
const user = await twoFactorRepository.findUserById(userId)

if(!user){
     throw notFound ("User not found");
}

if(!user.totpSecret){
      throw badRequest(
        "Two-factor authentication is already enabled"
      );
}
if(user.isTwoFactorEnabled){
    throw conflict("Two factor is already established")
}

const result = await verify({
    secret:user.totpSecret,
    token:code

})

if(!result.valid){
    throw badRequest("Invalid authentication code")
}

await twoFactorRepository.enableTwoFactor(userId)

return{
    success:true,
    message:"Two-factor authentication enabled successfully"
}

}

}