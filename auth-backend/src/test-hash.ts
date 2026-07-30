import { sendOtpEmail } from "./lib/email.js";


async function main() {
  await sendOtpEmail("sarishma242@gmail.com", "123456");
  console.log("Email sent! Check your inbox.");
}

main().catch((err) => {
  console.error("Failed to send email:", err);
});