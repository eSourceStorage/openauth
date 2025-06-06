import { issuer } from "@openauthjs/openauth";
import { CloudflareStorage } from "@openauthjs/openauth/storage/cloudflare";
import { PasswordProvider } from "@openauthjs/openauth/provider/password";
import { PasswordUI } from "@openauthjs/openauth/ui/password";
import { createSubjects } from "@openauthjs/openauth/subject";
import { object, string } from "valibot";

const subjects = createSubjects({
  user: object({
    id: string(),
  }),
});

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const url = new URL(request.url);

    // Handle the callback separately
    if (url.pathname === "/callback") {
      const code = url.searchParams.get('code');
      const headers = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "https://returnedmath.xyz",
        "Access-Control-Allow-Credentials": "true"
      };

      if (!code) {
        return new Response(JSON.stringify({
          error: "invalid_request",
          error_description: "No auth code provided"
        }), { status: 400, headers });
      }

      return new Response(JSON.stringify({
        message: "authcomplete",
        code: code
      }), { headers });
    }

    // Update redirect URI with https
    if (url.pathname === "/") {
      url.searchParams.set("redirect_uri", "https://returnedmath.xyz/auth-callback");
      url.searchParams.set("client_id", "your-client-id");
      url.searchParams.set("response_type", "code");
      url.pathname = "/authorize";
      return Response.redirect(url.toString());
    } 

    return issuer({
      storage: CloudflareStorage({
        namespace: env.AUTH_STORAGE,
      }),
      subjects,
      providers: {
        password: PasswordProvider(
          PasswordUI({
            sendCode: async (email, code) => {
              console.log(`Sending code ${code} to ${email}`);

              const response = await fetch("https://api.resend.com/emails", {
                method: "POST",
                headers: {
                  Authorization: "Bearer re_YiQGaW7d_CWbEzmZZWauFAeqUC92oSpE5",
                  "Content-Type": "application/json",
                },
                body: JSON.stringify({
                  from: "codes@returnedmath.xyz",
                  to: [email],
                  subject: "Your Verification Code",
                  html: `<strong>Your verification code for returnedmath's basement is: ${code}</strong>`,
                }),
              });

              const data = await response.json();
              console.log("Resend API response:", data);
            },
            copy: {
              input_code: "Code (check your email)",
            },
          })
        ),
      },
      cors: {
        origins: ["https://returnedmath.xyz"],
        credentials: true
      },
      domain: "auth.returnedmath.xyz",
      cookies: {
        domain: ".returnedmath.xyz",
        secure: true,
        sameSite: "strict"
      },
      theme: {
        title: "myAuth",
        primary: "#0051c3",
        favicon: "https://workers.cloudflare.com/favicon.ico",
        logo: {
          dark: "https://imagedelivery.net/wSMYJvS3Xw-n339CbDyDIA/db1e5c92-d3a6-4ea9-3e72-155844211f00/public",
          light: "https://imagedelivery.net/wSMYJvS3Xw-n339CbDyDIA/fa5a3023-7da9-466b-98a7-4ce01ee6c700/public",
        },
      },
      success: async (ctx, value) => {
        const headers = new Headers({
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "https://returnedmath.xyz",
          "Access-Control-Allow-Credentials": "true",
          "Location": "https://returnedmath.xyz" // Add redirect header
        });

        const cookie = `user_id=${value.email}; Domain=.returnedmath.xyz; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=604800`;
        headers.append("Set-Cookie", cookie);

        return new Response(JSON.stringify({
          message: "success",
          user: { email: value.email },
          redirect: "https://returnedmath.xyz"
        }), { 
          status: 302, // Add redirect status
          headers 
        });
      }
    }).fetch(request, env, ctx);
  }
};
