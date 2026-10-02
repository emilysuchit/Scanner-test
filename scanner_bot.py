import asyncio
import re
import ssl
import time
from urllib.parse import urlparse

from telethon import TelegramClient, events
from playwright.async_api import async_playwright, TimeoutError as PWTimeout
import dns.asyncresolver

API_ID = 20351186
API_HASH = 'f86b0b388670f1024e579b43e4eacaed'
BOT_TOKEN = '7804873166:AAGuTs5EoeYTSQZsFW8z2OpOO4t60IQD1PM'
ADMIN_ID = [5544288619]

SCAN_DEADLINE = 45
MAX_CONCURRENT_SCANS = 1

# connect မလုပ်သေးဘူး — object ပဲ ဖန်တီးထားတယ် (loop fix)
bot = TelegramClient('scanner_bot', API_ID, API_HASH)
SEM = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
PW = None
BROWSER = None


# ── access ──────────────────────────────────────────────
def is_premium(uid: int) -> bool:
    if uid in ADMIN_ID:
        return True
    try:
        with open('premium_users.txt') as f:
            return str(uid) in f.read().split()
    except FileNotFoundError:
        return False


# ── signatures ──────────────────────────────────────────
GATEWAY_REQ = {
    "Stripe":        ["js.stripe.com", "api.stripe.com", "m.stripe.network"],
    "PayPal":        ["paypal.com/sdk", "paypalobjects.com", "paypal.com/xoplatform"],
    "Braintree":     ["braintreegateway.com", "braintree-api.com"],
    "Square":        ["squareup.com", "squarecdn.com"],
    "Adyen":         ["checkoutshopper.adyen.com", "adyen.com"],
    "Razorpay":      ["checkout.razorpay.com", "api.razorpay.com", "rzp.io"],
    "Mollie":        ["mollie.com"],
    "Klarna":        ["klarna.com", "klarnacdn.net"],
    "Afterpay":      ["afterpay.com", "clearpay"],
    "MercadoPago":   ["mercadopago.com", "mercadolibre.com"],
    "PagSeguro":     ["pagseguro"],
    "Paddle":        ["paddle.com", "paddle.io"],
    "Authorize.net": ["authorize.net", "secureacceptance"],
    "Worldpay":      ["worldpay.com", "secure.worldpay.com"],
    "Cybersource":   ["cybersource.com"],
    "NMI":           ["secure.nmi.com", "nmi.com"],
}

GATEWAY_HTML = {
    "Stripe":      ["js.stripe.com", "pk_live_", "pk_test_", "stripe.com"],
    "PayPal":      ["paypal.com/sdk", "paypalobjects.com", "data-paypal-button"],
    "Braintree":   ["braintree.dropin", "braintreegateway"],
    "Square":      ["sqpaymentform", "squareup.com"],
    "Adyen":       ["adyen."],
    "Razorpay":    ["razorpay"],
    "Mollie":      ["mollie."],
    "Klarna":      ["klarna."],
    "Afterpay":    ["afterpay", "clearpay"],
    "MercadoPago": ["mercadopago"],
    "PagSeguro":   ["pagseguro"],
    "Paddle":      ["paddle."],
    "WooCommerce": ["wc-ajax", "woocommerce"],
    "Shopify Pay": ["shopify_pay", "shopify-checkout"],
}

CMS_SIGS = {
    "WordPress":   ["/wp-content/", "wp-json", "wp-includes"],
    "Shopify":     ["myshopify.com", "cdn.shopify.com", "shopify.theme", "shopify-features"],
    "WooCommerce": ["woocommerce", "wc-ajax"],
    "Magento":     ["static/version", "mage/", "magento"],
    "Joomla":      ["joomla"],
    "Drupal":      ["drupal.js", "drupal.org", "/sites/default/"],
    "PrestaShop":  ["prestashop"],
    "BigCommerce": ["bigcommerce.com", "bigcommerce"],
    "Wix":         ["wixstatic.com", "wix.com"],
    "Squarespace": ["squarespace.com", "static1.squarespace"],
    "Webflow":     ["webflow", "wf/"],
    "Weebly":      ["weebly.com"],
    "Next.js":     ["__next", "/_next/"],
    "Nuxt":        ["__nuxt", "/_nuxt/"],
    "React":       ["reactroot", "data-reactroot", "__reactcontainer"],
    "Vue":         ["__vue__", "data-v-"],
}

ANALYTICS_SIGS = {
    "Google Analytics": ["google-analytics.com", "googletagmanager.com", "gtag(", "ga("],
    "Facebook Pixel":   ["connect.facebook.net", "fbq("],
    "Hotjar":           ["hotjar.com"],
    "TikTok Pixel":     ["analytics.tiktok.com"],
    "Clarity":          ["clarity.ms"],
    "Yandex Metrika":   ["mc.yandex.ru"],
}

CDN_REQ = {
    "Cloudflare":     ["cdn-cgi/"],
    "Fastly":         ["fastly.net", "fastly.com"],
    "Akamai":         ["akamai", "akamaized.net", "akamaitechnologies"],
    "AWS CloudFront": ["cloudfront.net"],
    "Cloudinary":     ["res.cloudinary.com"],
}

KEY_PATTERNS = {
    "Stripe pk":        re.compile(r'pk_(?:live|test)_[A-Za-z0-9_-]{10,}'),
    "Stripe sk":        re.compile(r'sk_(?:live|test)_[A-Za-z0-9_-]{10,}'),
    "PayPal client-id": re.compile(r'client-id[="\':\s]+([A-Za-z0-9_-]{30,})', re.I),
    "Razorpay":         re.compile(r'rzp_(?:test|live)_[A-Za-z0-9]{8,}'),
    "Square":           re.compile(r'sq0atp-[A-Za-z0-9_-]{10,}'),
    "Adyen pub":        re.compile(r'pub_key_[A-Za-z0-9]{10,}'),
    "Braintree auth":   re.compile(r'authorizationFingerprint["\s:]+([A-Za-z0-9._-]{20,})'),
    "reCAPTCHA":        re.compile(r'data-sitekey=["\'](6[A-Za-z0-9_-]{39})'),
    "hCaptcha":         re.compile(r'data-sitekey=["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'),
    "Turnstile":        re.compile(r'data-sitekey=["\'](0x[A-Za-z0-9]{20,})'),
}

CARD_DOM_SELECTORS = [
    'input[autocomplete="cc-number"]',
    'input[name*="card" i][name*="number" i]',
    'input[id*="cardnumber" i]',
    'input[placeholder*="card number" i]',
    'input[data-stripe="number"]',
    'iframe[src*="stripe.com"]',
    'iframe[src*="braintreegateway"]',
    'iframe[src*="paypal.com"]',
    'iframe[src*="adyen.com"]',
]

SECURE_3D_SIGS = ["3d_secure", "3dsecure", "requires_action", "cardinalcommerce",
                  "cavv", "3ds2", "three_d_secure"]


# ── detection layer ─────────────────────────────────────
def _find(blob: dict, table: dict) -> list:
    out = []
    for name, sigs in table.items():
        if any(s in blob["req"] for s in sigs):
            out.append((name, True))
        elif any(s in blob["html"] for s in sigs):
            out.append((name, False))
    return out


def extract_keys(html: str) -> dict:
    found = {}
    for name, rx in KEY_PATTERNS.items():
        hits = list(dict.fromkeys(rx.findall(html)))
        if hits:
            found[name] = hits
    return found


# ── host probe: DNS + TLS ───────────────────────────────
async def probe_host(host: str) -> dict:
    out = {"ns": [], "issuer": "N/A", "valid": "N/A", "san": []}
    try:
        ans = await asyncio.wait_for(dns.asyncresolver.resolve(host, 'NS'), 8)
        out["ns"] = [str(r).rstrip('.') for r in ans]
    except Exception:
        pass
    try:
        ctx = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, 443, ssl=ctx), 10)
        cert = writer.get_extra_info('ssl_object').getpeercert()
        writer.close()
        issuer = dict(x[0] for x in cert.get('issuer', ()))
        out["issuer"] = issuer.get('organizationName', 'N/A')
        out["valid"] = cert.get('notAfter', 'N/A')
        out["san"] = [v for t, v in cert.get('subjectAltName', ())][:4]
    except Exception:
        pass
    return out


# ── the scanner ─────────────────────────────────────────
async def scan_site(url: str) -> str:
    async with SEM:
        context = await BROWSER.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1366, "height": 768},
            ignore_https_errors=True,
        )
        page = await context.new_page()

        async def slim_route(route):
            if route.request.resource_type in ("image", "media", "font"):
                await route.abort()
            else:
                await route.continue_()
        await page.route("**/*", slim_route)

        reqs = []
        page.on("request", lambda r: reqs.append(r.url))
        t0 = time.monotonic()
        try:
            resp = await page.goto(url, wait_until="domcontentloaded", timeout=35000)
            try:
                await page.wait_for_load_state("networkidle", timeout=10000)
            except PWTimeout:
                pass

            status = resp.status if resp else 0
            headers = await resp.all_headers() if resp else {}
            final_url = page.url
            html = await page.content()
            cookies = await context.cookies()

            card_form = any(await page.query_selector(s) for s in CARD_DOM_SELECTORS)

            runtime_blob = await page.evaluate(
                """() => {
                    let s = '';
                    try { s += JSON.stringify(window.Shopify || {}); } catch(e) {}
                    try {
                        for (const k of Object.keys(window)) {
                            if (/stripe|paypal|braintree|checkout|config/i.test(k)) {
                                try { s += k + JSON.stringify(window[k]); } catch(e) {}
                            }
                        }
                    } catch(e) {}
                    return s + performance.getEntriesByType('resource')
                                 .map(e => e.name).join('\\n');
                }"""
            )
        finally:
            await context.close()
        elapsed = int((time.monotonic() - t0) * 1000)

    # ── analysis ──
    host = urlparse(final_url).hostname or ""
    h_low = html.lower()
    blob = {
        "html": h_low + "\n" + runtime_blob.lower(),
        "req": "\n".join(reqs).lower(),
    }

    gateways = _find(blob, {**GATEWAY_REQ, **GATEWAY_HTML})
    cms = _find(blob, CMS_SIGS)
    analytics = _find(blob, ANALYTICS_SIGS)
    cdn = _find(blob, CDN_REQ)

    keys = extract_keys(html + "\n" + runtime_blob)
    keys_str = "\n".join(
        f"{p}: <code>{hits[0][:32]}</code>" + (f" +{len(hits)-1}" if len(hits) > 1 else "")
        for p, hits in keys.items()) or "  ❌ Nᴏɴᴇ ғᴏᴜɴᴅ"

    captcha = next((n for n in ["reCAPTCHA", "hCaptcha", "Turnstile"]
                    if n.lower() in blob["req"] or n.lower() in h_low), "None")
    cloudflare = "Cloudflare" if (
        any(s in blob["req"] for s in ["cdn-cgi/", "__cf_bm"]) or
        headers.get("cf-ray") or
        "cloudflare" in headers.get("server", "").lower()) else "None"
    sec_3d = ("3D Secure Found ✅" if any(s in blob["html"] for s in SECURE_3D_SIGS)
              else "2D (No 3D Secure Found ❌)")
    graphql = ("GraphQL Found ✅" if any("/graphql" in r for r in reqs) or "graphql" in h_low
               else "No GraphQL Found ❌")
    cookies_str = ", ".join(dict.fromkeys(c["name"] for c in cookies))[:120] or "N/A"

    probe = await probe_host(host)

    gw_str = "\n".join(
        f"  {n} {'⚡ net' if net else '· html'}" for n, net in gateways) or "  ❌ Nᴏɴᴇ"

    return f"""∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼
   Sɪᴛᴇ Sᴄᴀɴɴᴇʀ  ·  ᴅᴇᴇᴘ ᴍᴏᴅᴇ
∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼
🌐 <b>URL:</b> <code>{host}</code>
📡 <b>Sᴛᴀᴛᴜs:</b> <code>{status}</code>  ·  ⏱️ <code>{elapsed}ms</code>
📦 <b>Rᴇǫᴜᴇsᴛs:</b> <code>{len(reqs)}</code>
🔌 <b>Gᴀᴛᴇᴡᴀʏs:</b>
{gw_str}
💡️ <b>CMS:</b> {', '.join(n for n, _ in cms)}
💳 <b>Cᴀʀᴅ Fᴏʀᴍ:</b> {'✅ Yᴇs' if card_form else '❌ Nᴏ'}
∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼
🔑 <b>Kᴇʏs:</b>
{keys_str}
🛡️ <b>Sᴇʀᴠᴇʀ:</b> <code>{headers.get('server', 'N/A')}</code>
🛡️ <b>Cʟᴏᴜᴅғʟᴀʀᴇ:</b> {cloudflare}
💡 <b>Cᴀᴘᴛᴄʜᴀ:</b> {captcha}
🔐 <b>3D Sᴇᴄᴜʀᴇ:</b> {sec_3d}
📊 <b>GʀᴀᴘʜQL:</b> {graphql}
📈 <b>Aɴᴀʟʏᴛɪᴄs:</b> {', '.join(n for n, _ in analytics) or 'None'}
🌍 <b>CDN:</b> {', '.join(n for n, _ in cdn) or 'N/A'}
🍪 <b>Cᴏᴏᴋɪᴇs:</b> {cookies_str}
∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼
🏦 <b>NS:</b> {', '.join(probe['ns']) or 'N/A'}
🔏 <b>Cᴇʀᴛ:</b> <code>{probe['issuer']}</code>
📆 <b>Vᴀʟɪᴅ:</b> <code>{probe['valid']}</code>
📍 <b>SAN:</b> {', '.join(probe['san']) or 'N/A'}
∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼
💡 Mᴀᴅᴇ ʙʏ @AFUONA_V"""


# ── telegram handlers ───────────────────────────────────
@bot.on(events.NewMessage(pattern=r'^/scg'))
async def scg(event):
    if not is_premium(event.sender_id):
        await event.reply("❌ Aᴄᴄᴇss Dᴇɴɪᴇᴅ\n\nOɴʟʏ ᴘʀᴇᴍɪᴜᴍ ᴜsᴇʀs ᴄᴀɴ ᴜsᴇ ᴛʜɪs.", parse_mode='html')
        return

    parts = event.raw_text.split()
    if len(parts) != 2:
        await event.reply("📝 Usᴀɢᴇ: <code>/scg &lt;URL&gt;</code>\n\n"
                          "<code>/scg example.com</code>", parse_mode='html')
        return

    url = parts[1].strip()
    if not url.startswith('http'):
        url = f'https://{url}'

    if SEM.locked():
        await event.reply("⏳ Sᴄᴀɴ ɪɴ ᴘʀᴏɢʀᴇss — ᴡᴀɪᴛ ғᴏʀ ɪᴛ ᴛᴏ ғɪɴɪsʜ ғɪʀsᴛ.", parse_mode='html')
        return

    status_msg = await event.reply(f"🔍 Dᴇᴇᴘ sᴄᴀɴɴɪɴɢ <code>{url}</code>...", parse_mode='html')
    try:
        result = await asyncio.wait_for(scan_site(url), SCAN_DEADLINE)
        await status_msg.edit(result, parse_mode='html')
    except asyncio.TimeoutError:
        await status_msg.edit(f"❌ Sᴄᴀɴ ᴅᴇᴀᴅʟɪɴᴇ ᴇxᴄᴇᴇᴅᴇᴅ ({SCAN_DEADLINE}s)", parse_mode='html')
    except Exception as e:
        await status_msg.edit(f"❌ Eʀʀᴏʀ: {type(e).__name__}: {e}", parse_mode='html')


@bot.on(events.NewMessage(pattern=r'^/start'))
async def start(event):
    await event.reply("👋 <b>Deep Site Scanner</b>\n\n"
                      "├─ <code>/scg &lt;URL&gt;</code> → ʀᴇɴᴅᴇʀ + ɴᴇᴛᴡᴏʀᴋ + ᴛʟs sᴄᴀɴ\n"
                      "└─ sᴇʀᴠᴇᴅ ғʀᴏᴍ ʀᴀɪʟᴡᴀʏ · ᴘᴏᴡᴇʀᴇᴅ ʙʏ ᴘʟᴀʏᴡʀɪɢʜᴛ",
                      parse_mode='html')


async def main():
    global PW, BROWSER

    # loop fix — connect ကို ဒီထဲမှာပဲ လုပ်တယ်
    await bot.start(bot_token=BOT_TOKEN)

    PW = await async_playwright().start()
    BROWSER = await PW.chromium.launch(
        headless=True,
        args=[
            "--no-sandbox",
            "--disable-dev-shm-usage",
            "--disable-gpu",
            "--disable-extensions",
            "--disable-background-networking",
            "--disable-features=site-per-process,TranslateUI",
            "--renderer-process-limit=2",
            "--js-flags=--max-old-space-size=256",
        ],
    )
    await bot.run_until_disconnected()


if __name__ == '__main__':
    asyncio.run(main())
