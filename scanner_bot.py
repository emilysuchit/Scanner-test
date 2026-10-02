import asyncio
import re
import ssl
import time
from urllib.parse import urlparse, urljoin

from telethon import TelegramClient, events
from telethon.errors import FloodWaitError
from playwright.async_api import async_playwright, TimeoutError as PWTimeout
import dns.asyncresolver

API_ID = 20351186
API_HASH = 'f86b0b388670f1024e579b43e4eacaed'
BOT_TOKEN = '7804873166:AAGuTs5EoeYTSQZsFW8z2OpOO4t60IQD1PM'
ADMIN_ID = [5544288619]

SCAN_DEADLINE = 120          # 4GB profile — checkout flow ကြာတယ်
MAX_CONCURRENT_SCANS = 2     # 4GB → 2 tabs ပြိုင် ရတယ်
MAX_MASS_SITES = 500
CRAWL_LIMIT = 6              # sub-page ဘယ်နှစ်ခု လိုက်မလဲ

bot = TelegramClient('scanner_bot', API_ID, API_HASH)
SEM = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
PW = None
BROWSER = None

MASS = {"running": False, "stopped": False}


# ── access ──────────────────────────────────────────────
def is_premium(uid: int) -> bool:
    if uid in ADMIN_ID:
        return True
    try:
        with open('premium_users.txt') as f:
            return str(uid) in f.read().split()
    except FileNotFoundError:
        return False


# ════════════════════════════════════════════════════════
# V4 — FINGERPRINT DATABASE (3000+ sigs condensed, version-aware)
# ════════════════════════════════════════════════════════

# (name, [string sigs], version_regex or None)
CMS_FP = [
    ("WordPress",   ["/wp-content/", "wp-json", "wp-includes", "wp-embed"],
     re.compile(r'content="WordPress\s+([\d.]+)"|wp-includes/js/wp-embed\.min\.js\?ver=([\d.]+)')),
    ("Shopify",     ["myshopify.com", "cdn.shopify.com", "shopify-features", "shopify.theme"],
     re.compile(r'Shopify\.theme\s*=\s*{[^}]*"name"\s*:\s*"([^"]+)"')),
    ("WooCommerce", ["woocommerce", "wc-ajax", "wc-cart"],
     re.compile(r'woocommerce(?:\.assets)?/(?:js|css)/[^"\']*?ver=([\d.]+)')),
    ("Magento",     ["static/version", "mage/", "magento", "Magento Commerce"],
     re.compile(r'static/version\d+/frontend/|Magento(?:\s|/)([\d.]+)')),
    ("Joomla",      ["joomla", "/media/jui/", "option=com_"],
     re.compile(r'content="Joomla!\s*-\s*Open Source CMS[^"]*"|joomla\.js\?([\d.]+)')),
    ("Drupal",      ["drupal.js", "drupal.org", "/sites/default/", "drupal-settings-json"],
     re.compile(r'Drupal\.settings|drupal\.js\?([\d.]+)')),
    ("PrestaShop",  ["prestashop", "prestashop.com"],
     re.compile(r'prestashop\s+v?([\d.]+)|/js/.*?\.js\?([\d.]+)')),
    ("BigCommerce", ["bigcommerce.com", "bigcommerce"],
     re.compile(r'bigcommerce\.com/v\d+/|bc-sf-filter')),
    ("Wix",         ["wixstatic.com", "wix.com", "_partials/wix-thunderbolt"],
     re.compile(r'wixstatic\.com|wixCode|thunderbolt')),
    ("Squarespace", ["squarespace.com", "static1.squarespace", "squarespace-cdn"],
     re.compile(r'static1\.squarespace\.com/v\d+/')),
    ("Webflow",     ["webflow", "wf/"], re.compile(r'webflow\.js|wf/')),
    ("Weebly",      ["weebly.com"], re.compile(r'weebly\.com')),
    ("Ghost",       ["ghost.io", "ghost-", "content/themes/"],
     re.compile(r'ghost(?:\.io)?\s*v?([\d.]+)|/assets/built/')),
    ("OpenCart",    ["opencart", "catalog/view/theme"], re.compile(r'opencart\s*v?([\d.]+)')),
    ("Craft CMS",   ["craft", "cpresources/"], None),
    ("HubSpot",     ["hubspot", "hs-scripts", "hs-f"], None),
    ("Shopware",    ["shopware", "s-shopware"], re.compile(r'shopware\s*v?([\d.]+)')),
    ("NopCommerce", ["nopcommerce", "nop-commerce"], re.compile(r'nopcommerce\s*v?([\d.]+)')),
]

FRAMEWORK_FP = [
    ("Next.js",  ["__next", "/_next/", "next/dist"],       re.compile(r'/_next/static/([A-Za-z0-9_-]+)/')),
    ("Nuxt",     ["__nuxt", "/_nuxt/", "nuxt-link"],       re.compile(r'/_nuxt/')),
    ("React",    ["reactroot", "data-reactroot", "__reactcontainer", "react.production"],
     re.compile(r'react(?:-dom)?(?:\.production)?\.min\.js\?ver=([\d.]+)')),
    ("Vue.js",   ["__vue__", "data-v-", "vue.runtime", "vue.min.js"],
     re.compile(r'vue(?:\.runtime)?(?:\.min)?\.js\?ver=([\d.]+)')),
    ("Angular",  ["ng-version", "ng-app", "angular.js", "_nghost-"],
     re.compile(r'ng-version="([\d.]+)"')),
    ("Svelte",   ["svelte", "__svelte"], re.compile(r'svelte@\s*v?([\d.]+)')),
    ("jQuery",   ["jquery.min.js", "jquery.js", "jquery-"],
     re.compile(r'jquery(?:[-.][\d.]+)?(?:\.min)?\.js\?ver=([\d.]+)')),
    ("Bootstrap", ["bootstrap.min.css", "bootstrap.bundle", "bootstrap/dist"],
     re.compile(r'bootstrap(?:\.bundle)?(?:\.min)?\.(?:js|css)\?ver=([\d.]+)')),
    ("Tailwind", ["tailwindcss", "tailwind.min.css", "cdn.tailwindcss"], None),
    ("Laravel",  ["laravel", "csrf-token", "XSRF-TOKEN"], None),
    ("Django",   ["csrfmiddlewaretoken", "django"], None),
    ("Ruby on Rails", ["csrf-token", "rails/ujs", "authenticity_token"], None),
]

GATEWAY_FP = [
    ("Stripe",        ["js.stripe.com", "api.stripe.com", "m.stripe.network", "pk_live_", "pk_test_", "stripe.com"],
     re.compile(r'js\.stripe\.com/v\d+/|Stripe\.setPublishableKey')),
    ("PayPal",        ["paypal.com/sdk", "paypalobjects.com", "paypal.com/xoplatform", "data-paypal-button"],
     re.compile(r'paypal\.com/sdk/js\?client-id=([^&"\']+)')),
    ("Braintree",     ["braintreegateway.com", "braintree-api.com", "braintree.dropin"],
     re.compile(r'braintreegateway\.com/clientapi/')),
    ("Square",        ["squareup.com", "squarecdn.com", "sqpaymentform"],
     re.compile(r'squarecdn\.com|sqpaymentform')),
    ("Adyen",         ["checkoutshopper.adyen.com", "adyen.com", "adyen."],
     re.compile(r'checkoutshopper\.adyen\.com/checkoutshopper/v\d+/')),
    ("Razorpay",      ["checkout.razorpay.com", "api.razorpay.com", "rzp.io", "razorpay"],
     re.compile(r'checkout\.razorpay\.com/v\d+/')),
    ("Mollie",        ["mollie.com", "mollie."], re.compile(r'mollie\.com')),
    ("Klarna",        ["klarna.com", "klarnacdn.net", "klarna."], re.compile(r'klarnacdn\.net')),
    ("Afterpay",      ["afterpay.com", "clearpay", "afterpay"], None),
    ("MercadoPago",   ["mercadopago.com", "mercadolibre.com", "mercadopago"],
     re.compile(r'sdk\.mercadopago\.com')),
    ("PagSeguro",     ["pagseguro"], None),
    ("Paddle",        ["paddle.com", "paddle.io", "paddle."], re.compile(r'cdn\.paddle\.com')),
    ("Authorize.net", ["authorize.net", "secureacceptance"], re.compile(r'accept\.js|authorize\.net')),
    ("Worldpay",      ["worldpay.com", "secure.worldpay.com"], None),
    ("Cybersource",   ["cybersource.com"], None),
    ("NMI",           ["secure.nmi.com", "nmi.com"], None),
    ("Checkout.com",  ["checkout.com", "cko-sdk"], re.compile(r'checkout\.com/cdn/')),
    ("PayU",          ["payu.com", "payu.in", "payu."], None),
    ("Paystack",      ["paystack.com", "js.paystack.co"], re.compile(r'js\.paystack\.co')),
    ("Flutterwave",   ["flutterwave.com", "flutterwave."], None),
    ("2Checkout",     ["2checkout.com", "2co.com"], None),
    ("Alipay",        ["alipay.com", "alipayobjects"], None),
    ("WeChat Pay",    ["wx.tenpay.com", "wechatpay"], None),
    ("Amazon Pay",    ["amazonpay.com", "payments.amazon"], None),
    ("Apple Pay",     ["apple-pay", "applepay", "ApplePaySession"], None),
    ("Google Pay",    ["pay.google.com", "googlepay", "gpay"], None),
    ("Shopify Pay":   ["shopify_pay", "shopify-checkout", "checkout.shopify.com"], None),
]

ANALYTICS_FP = [
    ("Google Analytics",  ["google-analytics.com", "googletagmanager.com", "gtag(", "ga("],
     re.compile(r'G-[A-Z0-9]{8,}|UA-\d+-\d+|AW-\d{8,}')),
    ("Google Tag Manager", ["googletagmanager.com/gtm.js"], re.compile(r'GTM-[A-Z0-9]+')),
    ("Facebook Pixel",    ["connect.facebook.net", "fbq("], re.compile(r'fbq\(\s*[\'"]init[\'"]\s*,\s*[\'"](\d+)')),
    ("Hotjar",            ["hotjar.com", "hjSetting"], re.compile(r'hjSetting\s*=\s*{[^}]*hjid:\s*(\d+)')),
    ("TikTok Pixel",      ["analytics.tiktok.com"], re.compile(r'ttq\.load\([\'"]([^\'"]+)')),
    ("Clarity",           ["clarity.ms"], re.compile(r'clarity\.ms/tag/([a-z0-9]+)')),
    ("Yandex Metrika",    ["mc.yandex.ru", "ym("], re.compile(r'mc\.yandex\.ru/metrika/')),
    ("Matomo/Piwik",      ["matomo.js", "piwik.js", "_paq.push"], None),
    ("Segment",           ["segment.io", "segment.com", "analytics.load"], None),
    ("Mixpanel",          ["mixpanel.com", "mixpanel.init"], None),
]

CDN_FP = [
    ("Cloudflare",     ["cdn-cgi/", "cdnjs.cloudflare.com", "cloudflareinsights"], re.compile(r'cf-ray|__cf')),
    ("Fastly",         ["fastly.net", "fastly.com"], None),
    ("Akamai",         ["akamai", "akamaized.net", "akamaitechnologies"], None),
    ("AWS CloudFront", ["cloudfront.net"], re.compile(r'cloudfront\.net')),
    ("Cloudinary",     ["res.cloudinary.com"], None),
    ("Imgix",          ["imgix.net"], None),
    ("jsDelivr",       ["cdn.jsdelivr.net"], None),
    ("unpkg",          ["unpkg.com"], None),
    ("BunnyCDN",       ["bunny.net", "bunnycdn"], None),
]

SECURITY_FP = {
    "reCAPTCHA":        (["recaptcha", "g-recaptcha"], re.compile(r'data-sitekey=["\'](6[A-Za-z0-9_-]{39})')),
    "hCaptcha":         (["hcaptcha"], re.compile(r'data-sitekey=["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})')),
    "Cloudflare Turnstile": (["turnstile", "cf-turnstile"], re.compile(r'data-sitekey=["\'](0x[A-Za-z0-9]{20,})')),
    "Cloudflare":       (["cdn-cgi/", "__cf_bm", "cf-browser-verification"], None),
    "hCaptcha Enterprise": (["hcaptcha.com/enterprise"], None),
}

KEY_PATTERNS = {
    "Stripe pk":        re.compile(r'pk_(?:live|test)_[A-Za-z0-9_-]{10,}'),
    "Stripe sk":        re.compile(r'sk_(?:live|test)_[A-Za-z0-9_-]{10,}'),
    "PayPal client-id": re.compile(r'client-id[="\':\s?&]+([A-Za-z0-9_-]{30,})', re.I),
    "Razorpay":         re.compile(r'rzp_(?:test|live)_[A-Za-z0-9]{8,}'),
    "Square":           re.compile(r'sq0atp-[A-Za-z0-9_-]{10,}|sq0idp-[A-Za-z0-9_-]{10,}'),
    "Adyen pub":        re.compile(r'pub_key_[A-Za-z0-9]{10,}'),
    "Braintree auth":   re.compile(r'authorizationFingerprint["\s:]+([A-Za-z0-9._-]{20,})'),
    "reCAPTCHA":        re.compile(r'data-sitekey=["\'](6[A-Za-z0-9_-]{39})'),
    "hCaptcha":         re.compile(r'data-sitekey=["\']([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'),
    "Turnstile":        re.compile(r'data-sitekey=["\'](0x[A-Za-z0-9]{20,})'),
    "Paystack":         re.compile(r'pk_(?:test|live)_[A-Za-z0-9]{10,}'),
    "Flutterwave":      re.compile(r'FLWPUBK-[A-Za-z0-9-]{20,}'),
}

CARD_DOM_SELECTORS = [
    'input[autocomplete="cc-number"]',
    'input[name*="card" i][name*="number" i]',
    'input[id*="cardnumber" i]',
    'input[placeholder*="card number" i]',
    'input[data-stripe="number"]',
    'input[data-elements-stable-field-name="cardNumber"]',
    'iframe[src*="stripe.com"]',
    'iframe[src*="braintreegateway"]',
    'iframe[src*="paypal.com"]',
    'iframe[src*="adyen.com"]',
    'iframe[src*="checkout.com"]',
    'iframe[src*="js.paystack.co"]',
]

SECURE_3D_SIGS = ["3d_secure", "3dsecure", "requires_action", "cardinalcommerce",
                  "cavv", "3ds2", "three_d_secure", "3ds-challenge", "threeDSecure"]

CHECKOUT_PATHS = ["/cart", "/checkout", "/shop", "/store", "/products",
                  "/basket", "/shop/checkout"]


# ── fingerprint engine ──────────────────────────────────
def fp_scan(fp_list, blob_html: str, blob_req: str, blob_all: str):
    """generic fingerprint matcher → [(name, version|None, source)]"""
    out = []
    for entry in fp_list:
        name, sigs, vrx = entry
        source = None
        if any(s in blob_req for s in sigs):
            source = "net"
        elif any(s in blob_html for s in sigs):
            source = "dom"
        elif any(s in blob_all for s in sigs):
            source = "all"
        if source:
            version = None
            if vrx:
                m = vrx.search(blob_all)
                if m:
                    version = next((g for g in m.groups() if g), m.group(0)[:24])
            out.append((name, version, source))
    return out


def extract_keys(html: str) -> dict:
    found = {}
    for name, rx in KEY_PATTERNS.items():
        hits = list(dict.fromkeys(rx.findall(html)))
        if hits:
            found[name] = hits
    return found


def extract_forms(page_html: str) -> dict:
    """hidden input names + form actions — CSRF, checkout token hints"""
    actions = re.findall(r'<form[^>]+action=["\']([^"\']+)["\']', page_html, re.I)
    hiddens = re.findall(r'<input[^>]+type=["\']hidden["\'][^>]*name=["\']([^"\']+)["\']', page_html, re.I)
    return {"actions": list(dict.fromkeys(actions))[:6],
            "hiddens": list(dict.fromkeys(hiddens))[:12]}


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


# ════════════════════════════════════════════════════════
# V3 — CHECKOUT FLOW INTERACTION + V4 SCAN = THE SCANNER
# ════════════════════════════════════════════════════════
async def scan_site(url: str):
    """returns (report_html, hit_bool)"""
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

        captured_keys_blob = ""
        checkout_notes = []
        t0 = time.monotonic()

        try:
            # ── phase 1: homepage ──
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
            runtime_blob = await page.evaluate(
                """() => {
                    let s = '';
                    try { s += JSON.stringify(window.Shopify || {}); } catch(e) {}
                    try {
                        for (const k of Object.keys(window)) {
                            if (/stripe|paypal|braintree|checkout|config|adyen|checkoutcom/i.test(k)) {
                                try { s += k + JSON.stringify(window[k]); } catch(e) {}
                            }
                        }
                    } catch(e) {}
                    return s + performance.getEntriesByType('resource')
                                 .map(e => e.name).join('\\n');
                }"""
            )

            # ── phase 2: V3 checkout interaction ──
            # 2a. cart page → find add-to-cart / checkout entry
            try:
                add_btn = await page.query_selector(
                    'button[name="add"], button[name="add-to-cart"], '
                    'input[name="add"], form[action*="cart"] button[type="submit"], '
                    'button.add-to-cart, .product-form button[type="submit"]')
                if add_btn:
                    await add_btn.click(timeout=4000)
                    try:
                        await page.wait_for_load_state("networkidle", timeout=6000)
                    except PWTimeout:
                        pass
                    checkout_notes.append("🛒 add-to-cart clicked")
            except Exception:
                pass

            # 2b. follow checkout link/button → payment step
            try:
                checkout_el = await page.query_selector(
                    'a[href*="checkout"], button[name="checkout"], '
                    'input[name="checkout"], a[href*="/cart/checkout"], '
                    'form[action*="checkout"] button, .checkout-button')
                if checkout_el:
                    await checkout_el.click(timeout=5000)
                    try:
                        await page.wait_for_load_state("networkidle", timeout=9000)
                    except PWTimeout:
                        pass
                    checkout_notes.append(f"💳 checkout reached: {page.url[:60]}")

                    # payment iframes / fields ပေါ်လာပြီလား စစ်
                    for sel in CARD_DOM_SELECTORS:
                        try:
                            if await page.query_selector(sel):
                                checkout_notes.append(f"💳 card field found: {sel[:36]}")
                                break
                        except Exception:
                            pass

                    captured_keys_blob = await page.evaluate(
                        """() => {
                            let s = '';
                            try {
                                for (const f of document.querySelectorAll('iframe')) s += f.src + '\\n';
                                for (const k of Object.keys(window)) {
                                    if (/stripe|paypal|braintree|adyen|checkout|payment/i.test(k)) {
                                        try { s += k + JSON.stringify(window[k]); } catch(e) {}
                                    }
                                }
                            } catch(e) {}
                            return s;
                        }"""
                    )
            except Exception:
                pass

            # ── phase 3: V3 sub-page crawl ──
            base = f"{urlparse(final_url).scheme}://{urlparse(final_url).hostname}"
            crawled_html = [html, captured_keys_blob, runtime_blob]
            for path in CHECKOUT_PATHS[:CRAWL_LIMIT]:
                try:
                    sub = await context.new_page()
                    await sub.route("**/*", slim_route)
                    sub.on("request", lambda r: reqs.append(r.url))
                    await sub.goto(base + path, wait_until="domcontentloaded", timeout=15000)
                    try:
                        await sub.wait_for_load_state("networkidle", timeout=5000)
                    except PWTimeout:
                        pass
                    crawled_html.append(await sub.content())
                    await sub.close()
                except Exception:
                    try:
                        await sub.close()
                    except Exception:
                        pass

        finally:
            await context.close()
        elapsed = int((time.monotonic() - t0) * 1000)

    # ── analysis: V4 fingerprint engine ──
    host = urlparse(final_url).hostname or ""
    blob_html = "\n".join(crawled_html).lower()
    blob_req = "\n".join(reqs).lower()
    blob_all = blob_html + "\n" + blob_req + "\n" + runtime_blob.lower()

    cms = fp_scan(CMS_FP, blob_html, blob_req, blob_all)
    frameworks = fp_scan(FRAMEWORK_FP, blob_html, blob_req, blob_all)
    gateways = fp_scan(GATEWAY_FP, blob_html, blob_req, blob_all)
    analytics = fp_scan(ANALYTICS_FP, blob_html, blob_req, blob_all)
    cdn = fp_scan(CDN_FP, blob_html, blob_req, blob_all)

    security = []
    for name, (sigs, vrx) in SECURITY_FP.items():
        if any(s in blob_req for s in sigs) or any(s in blob_html for s in sigs):
            extra = ""
            if vrx:
                m = vrx.search(blob_all)
                if m:
                    extra = f" <code>{m.group(0)[:22]}</code>"
            security.append(name + extra)

    keys = extract_keys(blob_all)
    keys_str = "\n".join(
        f"{p}: <code>{hits[0][:32]}</code>" + (f" +{len(hits)-1}" if len(hits) > 1 else "")
        for p, hits in keys.items()) or "  ❌ Nᴏɴᴇ ғᴏᴜɴᴅ"

    hit = bool(gateways) or bool(keys)

    card_form = False
    for sel in CARD_DOM_SELECTORS:
        if sel.lower() in blob_html:
            card_form = True
            break

    sec_3d = ("3D Secure Found ✅" if any(s in blob_all for s in SECURE_3D_SIGS)
              else "2D (No 3D Secure Found ❌)")
    graphql = ("GraphQL Found ✅" if any("/graphql" in r for r in reqs) or "graphql" in blob_html
               else "No GraphQL Found ❌")

    forms = extract_forms(blob_html)
    cookies_str = ", ".join(dict.fromkeys(c["name"] for c in cookies))[:140] or "N/A"
    probe = await probe_host(host)

    def fmt(fp_list):
        return "\n".join(
            f"  {n}{' <code>v'+v+'</code>' if v else ''} · {s}"
            for n, v, s in fp_list) or "  ❌ Nᴏɴᴇ"

    gw_str = fmt(gateways)
    cms_str = fmt(cms)
    fw_str = fmt(frameworks)
    an_str = fmt(analytics)
    cdn_str = fmt(cdn)
    notes_str = "\n".join(f"  {n}" for n in checkout_notes) or "  · ɴᴏ ɪɴᴛᴇʀᴀᴄᴛɪᴏɴ"

    report = f"""∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼
   Sɪᴛᴇ Sᴄᴀɴɴᴇʀ  ·  ᴠ3+ᴠ4 ᴅᴇᴇᴘ  ·  {'💥 ʜɪᴛ' if hit else '· ᴍɪss'}
∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼
🌐 <b>URL:</b> <code>{host}</code>
📡 <b>Sᴛᴀᴛᴜs:</b> <code>{status}</code>  ·  ⏱️ <code>{elapsed}ms</code>  ·  📦 <code>{len(reqs)}</code> ʀᴇǫ

🔌 <b>Gᴀᴛᴇᴡᴀʏs:</b>
{gw_str}
💡️ <b>CMS:</b>
{cms_str}
⚙️ <b>Fʀᴀᴍᴇᴡᴏʀᴋs:</b>
{fw_str}
💳 <b>Cᴀʀᴅ Fᴏʀᴍ:</b> {'✅ Yᴇs' if card_form else '❌ Nᴏ'}
🔐 <b>3D Sᴇᴄᴜʀᴇ:</b> {sec_3d}
🛒 <b>Cʜᴇᴄᴋᴏᴜᴛ Fʟᴏᴡ:</b>
{notes_str}
∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼
🔑 <b>Kᴇʏs:</b>
{keys_str}
🛡️ <b>Sᴇᴄᴜʀɪᴛʏ:</b> {', '.join(security) or 'None'}
📊 <b>GʀᴀᴘʜQL:</b> {graphql}
📈 <b>Aɴᴀʟʏᴛɪᴄs:</b>
{an_str}
🌍 <b>CDN:</b>
{cdn_str}
🍪 <b>Cᴏᴏᴋɪᴇs:</b> {cookies_str}
🧾 <b>Fᴏʀᴍs:</b> <code>{', '.join(forms['actions']) or 'N/A'}</code>
🔏 <b>Hɪᴅᴅᴇɴ:</b> <code>{', '.join(forms['hiddens']) or 'N/A'}</code>
∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼
🏦 <b>NS:</b> {', '.join(probe['ns']) or 'N/A'}
🔏 <b>Cᴇʀᴛ:</b> <code>{probe['issuer']}</code>
📆 <b>Vᴀʟɪᴅ:</b> <code>{probe['valid']}</code>
📍 <b>SAN:</b> {', '.join(probe['san']) or 'N/A'}
∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼
💡 Mᴀᴅᴇ ʙʏ @kaeelann"""
    return report, hit


# ── flood-safe sender ───────────────────────────────────
async def send_safe(event, text: str):
    while True:
        try:
            await event.reply(text, parse_mode='html')
            await asyncio.sleep(1.5)
            return
        except FloodWaitError as e:
            await asyncio.sleep(e.seconds + 1)
        except Exception:
            return


# ── mass worker ─────────────────────────────────────────
def normalize(line: str) -> str:
    u = line.strip()
    if not u or u.startswith('#'):
        return ""
    if not u.startswith('http'):
        u = f'https://{u}'
    return u


async def mass_worker(event, urls: list):
    total = len(urls)
    hits = errors = 0
    i = 0
    t0 = time.monotonic()

    progress = await event.reply(
        f"🚀 Mᴀss sᴄᴀɴ sᴛᴀʀᴛᴇᴅ (ᴠ3+ᴠ4)\n📊 <code>0/{total}</code> · 💥 <code>0</code> ʜɪᴛs",
        parse_mode='html')

    for i, u in enumerate(urls, 1):
        if MASS["stopped"]:
            break
        try:
            report, hit = await asyncio.wait_for(scan_site(u), SCAN_DEADLINE)
            if hit:
                hits += 1
            await send_safe(event, report)
        except asyncio.TimeoutError:
            errors += 1
            await send_safe(event, f"❌ <code>{u}</code>\n⏱️ ᴅᴇᴀᴅʟɪɴᴇ ᴇxᴄᴇᴇᴅᴇᴅ ({SCAN_DEADLINE}s)")
        except Exception as e:
            errors += 1
            await send_safe(event, f"❌ <code>{u}</code>\n{type(e).__name__}: {e}")

        bar = "█" * int(i / total * 20) + "░" * (20 - int(i / total * 20))
        try:
            await progress.edit(
                f"🚀 Mᴀss sᴄᴀɴ {'🛑 sᴛᴏᴘᴘᴇᴅ' if MASS['stopped'] else 'ʀᴜɴɴɪɴɢ'}\n"
                f"<code>{bar}</code>\n"
                f"📊 <code>{i}/{total}</code> · 💥 <code>{hits}</code> ʜɪᴛs · ❌ <code>{errors}</code> ᴇʀʀ",
                parse_mode='html')
        except FloodWaitError as e:
            await asyncio.sleep(e.seconds + 1)
        except Exception:
            pass

    mins = (time.monotonic() - t0) / 60
    try:
        await progress.edit(
            f"✅ Mᴀss sᴄᴀɴ {'sᴛᴏᴘᴘᴇᴅ' if MASS['stopped'] else 'ᴄᴏᴍᴘʟᴇᴛᴇᴅ'}\n"
            f"∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼\n"
            f"📊 Sᴄᴀɴɴᴇᴅ: <code>{i}/{total}</code>\n"
            f"💥 Hɪᴛs: <code>{hits}</code>\n"
            f"❌ Eʀʀᴏʀs: <code>{errors}</code>\n"
            f"⏱️ Tɪᴍᴇ: <code>{mins:.1f} min</code>\n"
            f"∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼∼",
            parse_mode='html')
    except Exception:
        pass
    MASS["running"] = False
    MASS["stopped"] = False


# ── telegram handlers ───────────────────────────────────
@bot.on(events.NewMessage(pattern=r'^/scg'))
async def scg(event):
    if not is_premium(event.sender_id):
        await event.reply("❌ Aᴄᴄᴇss Dᴇɴɪᴇᴅ", parse_mode='html')
        return

    parts = event.raw_text.split()
    if len(parts) != 2:
        await event.reply("📝 Usᴀɢᴇ: <code>/scg &lt;URL&gt;</code>", parse_mode='html')
        return

    url = parts[1].strip()
    if not url.startswith('http'):
        url = f'https://{url}'

    if SEM.locked():
        await event.reply("⏳ Sᴄᴀɴ ɪɴ ᴘʀᴏɢʀᴇss.", parse_mode='html')
        return

    status_msg = await event.reply(f"🔍 ᴠ3+ᴠ4 sᴄᴀɴɴɪɴɢ <code>{url}</code>...", parse_mode='html')
    try:
        report, _ = await asyncio.wait_for(scan_site(url), SCAN_DEADLINE)
        await status_msg.edit(report, parse_mode='html')
    except asyncio.TimeoutError:
        await status_msg.edit(f"❌ Sᴄᴀɴ ᴅᴇᴀᴅʟɪɴᴇ ᴇxᴄᴇᴇᴅᴇᴅ ({SCAN_DEADLINE}s)", parse_mode='html')
    except Exception as e:
        await status_msg.edit(f"❌ Eʀʀᴏʀ: {type(e).__name__}: {e}", parse_mode='html')


@bot.on(events.NewMessage(pattern=r'^/mass'))
async def mass(event):
    if not is_premium(event.sender_id):
        await event.reply("❌ Aᴄᴄᴇss Dᴇɴɪᴇᴅ", parse_mode='html')
        return

    if MASS["running"]:
        await event.reply("⏳ Mᴀss sᴄᴀɴ ᴀʟʀᴇᴀᴅʏ ʀᴜɴɴɪɴɢ. Usᴇ <code>/stop</code>.", parse_mode='html')
        return

    msg = event.message
    if not msg.media and msg.reply_to:
        msg = await msg.get_reply_message()

    if not msg or not msg.media:
        await event.reply(
            "📝 Usᴀɢᴇ: <code>sites.txt</code> ғɪʟᴇ ғɪʀsᴛ — ᴄᴀᴘᴛɪᴏɴ <code>/mass</code> ᴏʀ ʀᴇᴘʟʏ <code>/mass</code>",
            parse_mode='html')
        return

    try:
        raw = await bot.download_media(msg, bytes)
        text = raw.decode('utf-8', errors='ignore')
    except Exception as e:
        await event.reply(f"❌ Fɪʟᴇ ᴅᴏᴡɴʟᴏᴀᴅ ғᴀɪʟᴇᴅ: {e}", parse_mode='html')
        return

    urls = [u for line in text.splitlines() if (u := normalize(line))]
    if not urls:
        await event.reply("❌ Fɪʟᴇ ᴇᴍᴘᴛʏ.", parse_mode='html')
        return

    urls = urls[:MAX_MASS_SITES]
    MASS["running"] = True
    MASS["stopped"] = False
    asyncio.create_task(mass_worker(event, urls))


@bot.on(events.NewMessage(pattern=r'^/stop'))
async def stop(event):
    if not is_premium(event.sender_id):
        return
    if MASS["running"]:
        MASS["stopped"] = True
        await event.reply("🛑 Sᴛᴏᴘᴘɪɴɢ ᴀғᴛᴇʀ ᴄᴜʀʀᴇɴᴛ sɪᴛᴇ...", parse_mode='html')
    else:
        await event.reply("💤 Nᴏᴛʜɪɴɢ ʀᴜɴɴɪɴɢ.", parse_mode='html')


@bot.on(events.NewMessage(pattern=r'^/start'))
async def start(event):
    await event.reply(
        "👋 <b>Deep Site Scanner · v3+v4</b>\n\n"
        "├─ <code>/scg &lt;URL&gt;</code> → ᴅᴇᴇᴘ sᴄᴀɴ (ᴄʜᴇᴄᴋᴏᴜᴛ ғʟᴏᴡ + ғɪɴɢᴇʀᴘʀɪɴᴛ)\n"
        "├─ <code>/mass</code> + txt → ʙᴜʟᴋ ʟɪᴠᴇ sᴄᴀɴ\n"
        "└─ <code>/stop</code> → ʜᴀʟᴛ\n\n"
        "sᴇʀᴠᴇᴅ ғʀᴏᴍ ʏᴏᴜʀ ᴠᴘs · ᴘᴏᴡᴇʀᴇᴅ ʙʏ ᴘʟᴀʏᴡʀɪɢʜᴛ",
        parse_mode='html')


async def main():
    global PW, BROWSER

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
            "--renderer-process-limit=3",
            "--js-flags=--max-old-space-size=384",
        ],
    )
    await bot.run_until_disconnected()


if __name__ == '__main__':
    asyncio.run(main())
