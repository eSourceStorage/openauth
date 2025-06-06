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
      try {
        const body = await request.json();
        const code = body.code;
        
        if (!code) {
          throw new Error("No auth code provided");
        }

        // Log for debugging
        console.log("Processing auth callback with code:", code);

        return new Response(JSON.stringify({
          message: "authcomplete",
          user: {
            id: "temp-user-id", // This will be replaced by actual user ID
            email: body.email || "user@example.com"
          }
        }), {
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "https://returnedmath.xyz",
            "Access-Control-Allow-Credentials": "true"
          }
        });
      } catch (err) {
        console.error("Callback error:", err);
        return new Response(JSON.stringify({
          message: "error",
          error: "auth_error",
          description: err.message
        }), { 
          status: 400,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "https://returnedmath.xyz",
            "Access-Control-Allow-Credentials": "true"
          }
        });
      }
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
        try {
          console.log("Processing auth for email:", value.email);
          
          // Try to find existing user first
          const existingUser = await findUser(env, value.email);
          
          let userId;
          if (existingUser) {
            userId = existingUser.id;
            console.log("Found existing user:", userId);
          } else {
            // Only create if user doesn't exist
            userId = await createUser(env, value.email);
            console.log("Created new user:", userId);
          }

          const subjectResponse = ctx.subject("user", { id: userId });

          return new Response(subjectResponse.body, {
            status: 200,
            headers: {
              ...Object.fromEntries(subjectResponse.headers.entries()),
              "Set-Cookie": `user_id=${userId}; Domain=.returnedmath.xyz; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=604800`,
              "Access-Control-Allow-Origin": "https://returnedmath.xyz",
              "Access-Control-Allow-Credentials": "true"
            }
          });
        } catch (err) {
          console.error("Auth error:", err);
          return new Response(JSON.stringify({
            error: "auth_error",
            description: "Failed to authenticate user"
          }), { status: 401 });
        }
      }
    }).fetch(request, env, ctx);
  }
};

async function findUser(env: Env, email: string) {
  const result = await env.AUTH_DB.prepare(
    `SELECT id, email FROM user WHERE email = ?`
  )
    .bind(email)
    .first<{ id: string; email: string }>();
  
  return result || null;
}

async function createUser(env: Env, email: string): Promise<string> {
  const result = await env.AUTH_DB.prepare(
    `INSERT INTO user (email) VALUES (?) RETURNING id`
  )
    .bind(email)
    .first<{ id: string }>();

  if (!result) {
    throw new Error("Failed to create user");
  }

  return result.id;
}
