const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Cache-Control": "no-store"
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" }
  });
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    if (!env.IMAGEKIT_PRIVATE_KEY || !env.IMAGEKIT_PUBLIC_KEY) {
      return json({ error: "Missing ImageKit keys" }, 500);
    }

    const token = crypto.randomUUID();
    const expire = Math.floor(Date.now() / 1000) + 1800;
    const encoder = new TextEncoder();

    const key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(env.IMAGEKIT_PRIVATE_KEY),
      { name: "HMAC", hash: "SHA-1" },
      false,
      ["sign"]
    );

    const signatureBytes = await crypto.subtle.sign(
      "HMAC",
      key,
      encoder.encode(token + expire)
    );

    const signature = [...new Uint8Array(signatureBytes)]
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    return json({
      token,
      expire,
      signature,
      publicKey: env.IMAGEKIT_PUBLIC_KEY
    });
  }
};
