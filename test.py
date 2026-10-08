"""
Omni Key System - Discord Bot + REST API (v8.2 - Signed + Secure)
================================================================================
Features:
  - Premium keys only (permanent, HWID-locked)
  - Self-service HWID reset (configurable limit per 24h, PERSISTENT in DB)
  - Premium panel with buttons
  - Full admin toolkit + audit log + auto-prune
  - Ed25519 signed API responses (anti fake-server / MITM)
  - Atomic HWID bind (race-safe)
  - Compatible with Omni client license_verify.cpp

Environment variables (.env):
  DISCORD_TOKEN       - bot token
  SERVER_PORT         - API port (default: 10750)
  SIGN_PRIVATE_KEY    - Ed25519 private key (64 hex char) untuk signing
                        Generate: python server_signing.py --genkey
                        JANGAN commit / share / taruh di client.
  AUDIT_LOG_CHANNEL   - (opsional) channel ID untuk audit log
  TRUST_PROXY         - (opsional) "true" kalau di belakang reverse proxy
                        dengan whitelist IP (lihat PROXY_WHITELIST)

  PROXY_WHITELIST     - (opsional) comma-separated IP yang boleh kirim
                        X-Forwarded-For. Default: 127.0.0.1,::1

Deployment:
  - Untuk Pterodactyl panel: expose port 10750, client pakai HTTP.
  - Untuk production dengan HTTPS: pakai Cloudflare Tunnel atau VPS biasa.
"""
import discord
from discord import app_commands
from discord.ext import commands, tasks
from aiohttp import web
import sqlite3, secrets, time, asyncio, logging, json, os, sys
from contextlib import contextmanager

from server_signing import build_signed_validate_response

# ====================== ENV ======================
def load_env(path=".env"):
    if not os.path.isfile(path):
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))

load_env()

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("omni")

# ======================= CONFIG =======================
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
GUILD_ID = 1542261096877137922

API_HOST = "0.0.0.0"
API_PORT = int(os.getenv("SERVER_PORT", "10750"))
DB_PATH  = "keys.db"

TRUST_PROXY = os.getenv("TRUST_PROXY", "false").lower() in ("1", "true", "yes")

PROXY_WHITELIST = os.getenv("PROXY_WHITELIST", "127.0.0.1,::1").split(",")
PROXY_WHITELIST = {ip.strip() for ip in PROXY_WHITELIST if ip.strip()}

AUDIT_LOG_CHANNEL = int(os.getenv("AUDIT_LOG_CHANNEL", "0"))
PRUNE_AFTER_DAYS = 7

# ==================== BRAND ====================
BRAND_NAME   = "Omni Key System"
BRAND_FOOTER = "Omni Key System"
BRAND_ICON   = None

COLOR_PRIMARY  = 0x5865F2
COLOR_SUCCESS  = 0x57F287
COLOR_WARNING  = 0xFEE75C
COLOR_DANGER   = 0xED4245
COLOR_PREMIUM  = 0xF1C40F
COLOR_INFO     = 0x00B0F4
COLOR_DARK     = 0x23272A

DIVIDER = "─────────────────────"

# ==================== SPINNER ====================
SPINNER_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

class Spinner:
    def __init__(self, message: discord.Message, text: str = "Processing",
                 interval: float = 0.6):
        self.message = message
        self.text = text
        self.interval = interval
        self.idx = 0
        self._task = None

    async def _run(self):
        try:
            while True:
                frame = SPINNER_FRAMES[self.idx % len(SPINNER_FRAMES)]
                self.idx += 1
                try:
                    await self.message.edit(content=f"{frame}  {self.text}...")
                except asyncio.CancelledError:
                    raise
                except discord.HTTPException:
                    pass
                except discord.NotFound:
                    return
                except Exception:
                    return
                await asyncio.sleep(self.interval)
        except asyncio.CancelledError:
            pass

    def start(self):
        self._task = asyncio.create_task(self._run())

    async def stop(self):
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        self._task = None

# ==================== DEFAULTS ====================
DEFAULT_SETTINGS = {
    "premium_role_id":   1543935190533939281,
    "admin_role_ids":    [1542261604312420382],
    "panel_channel_id":  0,
    "panel_message_id":  0,
    "hwid_reset_limit":  2,
}

# ============ HWID RESET (rolling 24h window) ============
HWID_RESET_WINDOW = 24 * 60 * 60

# ============ PANEL BUTTON RATE LIMIT ============
_panel_rate_limit = {}
PANEL_BUTTON_COOLDOWN = 3

# ===================== DATABASE =====================
@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH, timeout=10.0)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    with db() as c:
        c.executescript("""
            CREATE TABLE IF NOT EXISTS keys (
                token        TEXT PRIMARY KEY,
                discord_id   INTEGER NOT NULL,
                created_at   INTEGER NOT NULL,
                expires_at   INTEGER NOT NULL,
                is_permanent INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS users (
                discord_id INTEGER PRIMARY KEY,
                last_claim INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS hwid_resets (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                discord_id INTEGER NOT NULL,
                reset_at   INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_keys_user ON keys(discord_id);
            CREATE INDEX IF NOT EXISTS idx_hwid_resets_user
                ON hwid_resets(discord_id, reset_at);
        """)
        cols = [r["name"] for r in c.execute("PRAGMA table_info(keys)")]
        if "bound_ip" not in cols:
            c.execute("ALTER TABLE keys ADD COLUMN bound_ip TEXT DEFAULT NULL")
            log.info("Migration: added bound_ip column")

        for k, v in DEFAULT_SETTINGS.items():
            c.execute("INSERT OR IGNORE INTO settings(key, value) VALUES(?, ?)",
                      (k, json.dumps(v)))
    log.info("DB ready: %s", DB_PATH)

def prune_expired_keys():
    cutoff = int(time.time()) - (PRUNE_AFTER_DAYS * 86400)
    with db() as c:
        cur = c.execute("""DELETE FROM keys
                           WHERE is_permanent=0 AND expires_at < ?""", (cutoff,))
        removed = cur.rowcount
    if removed:
        log.info("Pruned %d expired keys", removed)
    return removed

def get_setting(key: str):
    with db() as c:
        row = c.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    if not row:
        return DEFAULT_SETTINGS.get(key)
    try:
        return json.loads(row["value"])
    except Exception:
        return row["value"]

def set_setting(key: str, value):
    with db() as c:
        c.execute("""INSERT INTO settings(key, value) VALUES(?, ?)
                     ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                  (key, json.dumps(value)))
    log.info("Setting: %s = %r", key, value)

def premium_role_id():  return int(get_setting("premium_role_id") or 0)
def admin_role_ids():   return list(get_setting("admin_role_ids") or [])
def hwid_reset_limit(): return int(get_setting("hwid_reset_limit") or 2)

# ===================== KEY / USER DB =====================
def gen_token() -> str:
    return "OM-" + secrets.token_urlsafe(24)

def get_active_key(uid: int):
    now = int(time.time())
    with db() as c:
        return c.execute("""SELECT * FROM keys
                            WHERE discord_id=? AND (is_permanent=1 OR expires_at>?)
                            ORDER BY is_permanent DESC, created_at DESC LIMIT 1""",
                         (uid, now)).fetchone()

def get_all_keys(uid: int):
    with db() as c:
        return c.execute("""SELECT * FROM keys WHERE discord_id=?
                            ORDER BY created_at DESC""", (uid,)).fetchall()

def create_key(uid: int, duration: int, permanent: bool=False):
    now = int(time.time())
    tok = gen_token()
    exp = 0 if permanent else now + duration
    with db() as c:
        c.execute("INSERT INTO keys(token,discord_id,created_at,expires_at,is_permanent) VALUES(?,?,?,?,?)",
                  (tok, uid, now, exp, 1 if permanent else 0))
    return tok, exp

def find_key(tok: str):
    with db() as c:
        return c.execute("SELECT * FROM keys WHERE token=?", (tok,)).fetchone()

def try_bind_key_hwid(tok: str, hwid: str) -> bool:
    """
    Atomic bind: hanya bind jika `bound_ip` masih NULL.
    Return True kalau binding berhasil (kita yang menang).
    """
    with db() as c:
        cur = c.execute(
            "UPDATE keys SET bound_ip=? WHERE token=? AND bound_ip IS NULL",
            (hwid, tok))
        return cur.rowcount > 0

def count_active_keys() -> int:
    now = int(time.time())
    with db() as c:
        row = c.execute("""SELECT COUNT(*) AS n FROM keys
                           WHERE is_permanent=1 OR expires_at>?""", (now,)).fetchone()
    return row["n"] if row else 0

def count_total_users() -> int:
    with db() as c:
        row = c.execute("SELECT COUNT(*) AS n FROM users").fetchone()
    return row["n"] if row else 0

# ============= HWID RESET (persistent, DB-backed) =============
def get_hwid_reset_state(uid: int):
    """
    Return (uses_left, next_ready_ts, uses_used, last_reset_ts).
    """
    now = int(time.time())
    cutoff = now - HWID_RESET_WINDOW

    with db() as c:
        c.execute("DELETE FROM hwid_resets WHERE discord_id=? AND reset_at<?",
                  (uid, cutoff))
        rows = c.execute(
            "SELECT reset_at FROM hwid_resets WHERE discord_id=? ORDER BY reset_at ASC",
            (uid,)).fetchall()

    history = [r["reset_at"] for r in rows]
    limit = hwid_reset_limit()
    uses_left = limit - len(history)
    next_ready_ts = int(history[0] + HWID_RESET_WINDOW) if (uses_left <= 0 and history) else 0
    last_reset_ts = int(history[-1]) if history else 0

    return uses_left, next_ready_ts, len(history), last_reset_ts

def record_hwid_reset(uid: int):
    with db() as c:
        c.execute("INSERT INTO hwid_resets(discord_id, reset_at) VALUES(?, ?)",
                  (uid, int(time.time())))

def clear_hwid_reset_history(uid: int):
    with db() as c:
        c.execute("DELETE FROM hwid_resets WHERE discord_id=?", (uid,))

# ==================== UI HELPERS =====================
def bar(fraction: float, length: int = 12) -> str:
    fraction = max(0.0, min(1.0, fraction))
    filled = int(round(fraction * length))
    return "▰" * filled + "▱" * (length - filled)

def fmt_remaining(secs: int) -> str:
    if secs <= 0:
        return "0s"
    d, r = divmod(secs, 86400)
    h, r = divmod(r, 3600)
    m, s = divmod(r, 60)
    parts = []
    if d: parts.append(f"{d}d")
    if h: parts.append(f"{h}h")
    if m: parts.append(f"{m}m")
    if not parts: parts.append(f"{s}s")
    return " ".join(parts)

def mask_hwid(hwid: str) -> str:
    if not hwid:
        return "unbound (will bind on first use)"
    if len(hwid) <= 10:
        return hwid
    return f"{hwid[:4]}...{hwid[-4:]}"

def apply_footer(e: discord.Embed, extra: str = None):
    text = BRAND_FOOTER if not extra else f"{BRAND_FOOTER} - {extra}"
    if BRAND_ICON:
        e.set_footer(text=text, icon_url=BRAND_ICON)
    else:
        e.set_footer(text=text)
    e.timestamp = discord.utils.utcnow()
    return e

def set_author(e: discord.Embed, user: discord.abc.User, prefix: str = ""):
    name = f"{prefix}{user.display_name}" if prefix else user.display_name
    try:
        e.set_author(name=name, icon_url=user.display_avatar.url)
    except Exception:
        e.set_author(name=name)
    return e

def key_embed(title, token, *, color, description=None, fields=None, user=None):
    e = discord.Embed(title=title, color=color, description=description)
    if user:
        set_author(e, user)
    e.add_field(name="Your Key", value=f"```\n{token}\n```", inline=False)
    if fields:
        for name, value, inline in fields:
            e.add_field(name=name, value=value, inline=inline)
    return apply_footer(e)

def get_client_hwid(req: web.Request) -> str:
    hwid = (req.rel_url.query.get("hwid") or "").strip()
    if hwid and 8 <= len(hwid) <= 64:
        return hwid
    return get_client_ip(req)

def get_client_ip(req: web.Request) -> str:
    remote = req.remote or "unknown"
    if TRUST_PROXY and remote in PROXY_WHITELIST:
        fwd = req.headers.get("X-Forwarded-For")
        if fwd:
            return fwd.split(",")[0].strip()
        real = req.headers.get("X-Real-IP")
        if real:
            return real.strip()
    return remote

async def resolve_username(uid: int) -> str:
    try:
        u = await bot.fetch_user(uid)
        return u.name
    except Exception:
        return f"user_{uid}"

async def log_audit(guild: discord.Guild, action: str, admin: discord.User,
                    details: str = "", color: int = COLOR_INFO):
    if not AUDIT_LOG_CHANNEL or not guild:
        return
    ch = guild.get_channel(AUDIT_LOG_CHANNEL)
    if not ch:
        return
    e = discord.Embed(title=f"Audit: {action}", color=color,
                      description=details, timestamp=discord.utils.utcnow())
    e.set_author(name=str(admin), icon_url=admin.display_avatar.url)
    try:
        await ch.send(embed=e)
    except Exception as ex:
        log.warning("Audit log failed: %s", ex)

def check_panel_cooldown(interaction: discord.Interaction) -> tuple:
    uid = interaction.user.id
    now_ts = time.time()
    if uid in _panel_rate_limit:
        elapsed = now_ts - _panel_rate_limit[uid]
        if elapsed < PANEL_BUTTON_COOLDOWN:
            return False, int(PANEL_BUTTON_COOLDOWN - elapsed) + 1
    _panel_rate_limit[uid] = now_ts
    return True, 0

async def safe_followup(interaction: discord.Interaction, **kwargs):
    try:
        await interaction.followup.send(**kwargs)
    except discord.HTTPException as ex:
        log.warning("Followup failed: %s", ex)

# ======================== API =========================
async def api_validate(req: web.Request):
    token = req.match_info["token"]
    row = find_key(token)
    if not row:
        return web.json_response(
            {"valid": False, "reason": "not_found"}, status=404)

    now = int(time.time())
    if not row["is_permanent"] and row["expires_at"] <= now:
        return web.json_response(
            {"valid": False, "reason": "expired"}, status=403)

    keys = row.keys()
    client_hwid = get_client_hwid(req)
    nonce = (req.rel_url.query.get("nonce") or "").strip()

    if row["is_permanent"]:
        bound_hwid = row["bound_ip"] if "bound_ip" in keys else None

        if bound_hwid is None:
            if try_bind_key_hwid(token, client_hwid):
                bound_hwid = client_hwid
                log.info("Premium %s bound to HWID %s",
                         token[-8:], bound_hwid)
            else:
                row2 = find_key(token)
                bound_hwid = row2["bound_ip"] if (row2 and "bound_ip" in row2.keys()) else None
                if bound_hwid is None:
                    return web.json_response(
                        {"valid": False, "reason": "bind_failed"}, status=500)

        if bound_hwid != client_hwid:
            return web.json_response({
                "valid": False,
                "reason": "hwid_mismatch",
                "hint": "This premium key is locked to another device. Use the panel to reset."
            }, status=403)

        return build_signed_validate_response(
            token,
            valid=True,
            permanent=True,
            giveaway=False,
            expires_after=0,
            owner=str(row["discord_id"]),
            hwid=bound_hwid,
            tier="premium",
            nonce=nonce,
        )

    return build_signed_validate_response(
        token,
        valid=True,
        permanent=False,
        giveaway=False,
        expires_after=row["expires_at"] * 1000,
        owner=str(row["discord_id"]),
        hwid=client_hwid if client_hwid else "",
        tier="premium",
        nonce=nonce,
    )

async def api_health(_):
    return web.json_response({
        "status": "ok",
        "brand": BRAND_NAME,
        "active_keys": count_active_keys()
    })

async def start_api():
    app = web.Application()
    app.router.add_get("/", api_health)
    app.router.add_get("/api/validate/{token}", api_validate)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, API_HOST, API_PORT)
    await site.start()
    log.info("API listening on http://%s:%d", API_HOST, API_PORT)

# ==================== DISCORD BOT =====================
intents = discord.Intents.default()
intents.members = True
bot = commands.Bot(command_prefix="!", intents=intents)

def is_premium(member: discord.Member) -> bool:
    pr = premium_role_id()
    if pr == 0 or not isinstance(member, discord.Member):
        return False
    return any(r.id == pr for r in member.roles)

def is_admin(member: discord.Member) -> bool:
    if not isinstance(member, discord.Member):
        return False
    if member.guild_permissions.administrator:
        return True
    allowed = set(admin_role_ids())
    if allowed and ({r.id for r in member.roles} & allowed):
        return True
    return False

async def send_dm(user: discord.User, embed: discord.Embed) -> bool:
    try:
        await user.send(embed=embed)
        return True
    except discord.Forbidden:
        return False
    except Exception as e:
        log.exception("DM failed for %s: %s", user, e)
        return False

def admin_only():
    async def predicate(interaction: discord.Interaction) -> bool:
        if not is_admin(interaction.user):
            await interaction.response.send_message(
                "You don't have permission to use this command.",
                ephemeral=True)
            return False
        return True
    return app_commands.check(predicate)

# ============= PREMIUM PANEL VIEW =============
def premium_only_callback(func):
    async def wrapper(self, interaction: discord.Interaction):
        if not isinstance(interaction.user, discord.Member):
            await interaction.response.send_message(
                "This only works inside the server.", ephemeral=True)
            return
        if not is_premium(interaction.user):
            await interaction.response.send_message(
                "This panel is for **Premium Members** only.",
                ephemeral=True)
            return
        return await func(self, interaction)
    return wrapper

class OmniPanelView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=None)

        btn_get = discord.ui.Button(
            label="Get Key", emoji="🔑",
            style=discord.ButtonStyle.success,
            custom_id="omni_panel_getkey")
        btn_get.callback = self.get_key_cb
        self.add_item(btn_get)

        btn_reset = discord.ui.Button(
            label="Reset HWID", emoji="🔒",
            style=discord.ButtonStyle.primary,
            custom_id="omni_panel_resethwid")
        btn_reset.callback = self.reset_hwid_cb
        self.add_item(btn_reset)

        btn_status = discord.ui.Button(
            label="Key Status", emoji="📊",
            style=discord.ButtonStyle.secondary,
            custom_id="omni_panel_status")
        btn_status.callback = self.status_cb
        self.add_item(btn_status)

    @premium_only_callback
    async def get_key_cb(self, interaction: discord.Interaction):
        allowed, remaining = check_panel_cooldown(interaction)
        if not allowed:
            await interaction.response.send_message(
                f"⏳ Slow down! Wait **{remaining}s** before clicking again.",
                ephemeral=True)
            return

        await interaction.response.defer(ephemeral=True)
        uid = interaction.user.id

        existing = get_active_key(uid)
        if existing and existing["is_permanent"]:
            tok = existing["token"]
            keys = existing.keys()
            hwid = existing["bound_ip"] if "bound_ip" in keys else None
            desc = "Here's your existing premium key."
        else:
            tok, _ = create_key(uid, 0, permanent=True)
            hwid = None
            desc = "Here's your new permanent key."

        e = key_embed("Premium Key", tok, color=COLOR_PREMIUM,
                      description=desc, user=interaction.user)
        e.add_field(name="Tier", value="PERMANENT", inline=True)
        e.add_field(name="HWID", value=f"`{mask_hwid(hwid)}`", inline=True)
        e.add_field(name="Note",
                    value="This key locks to the first device that uses it.\n"
                          "Keep it private — never share your key or HWID file.",
                    inline=False)

        await asyncio.sleep(0.3)
        ok = await send_dm(interaction.user, e)
        if ok:
            await safe_followup(interaction,
                content="Your key has been sent to your DM.", ephemeral=True)
        else:
            await safe_followup(interaction,
                embed=e,
                content="Could not DM you (DMs closed). Key below — save it:",
                ephemeral=True)

    @premium_only_callback
    async def reset_hwid_cb(self, interaction: discord.Interaction):
        allowed, remaining = check_panel_cooldown(interaction)
        if not allowed:
            await interaction.response.send_message(
                f"⏳ Slow down! Wait **{remaining}s** before clicking again.",
                ephemeral=True)
            return

        await interaction.response.defer(ephemeral=True)
        uid = interaction.user.id
        now = int(time.time())
        limit = hwid_reset_limit()

        uses_left, next_ready_ts, uses_used, _last = get_hwid_reset_state(uid)

        if uses_left <= 0:
            ready_at = next_ready_ts
            remaining_s = max(0, int(ready_at - now))

            e = discord.Embed(
                title="HWID Reset Limit Reached",
                color=COLOR_WARNING,
                description=(f"You've used **{uses_used}/{limit}** "
                             f"resets in the last 24 hours."))
            set_author(e, interaction.user)
            e.add_field(name="Time Remaining",
                        value=f"**{fmt_remaining(remaining_s)}**", inline=True)
            e.add_field(name="Next Reset Available",
                        value=f"<t:{ready_at}:R>", inline=True)
            e.add_field(name="Uses Remaining",
                        value=f"**0/{limit}**", inline=True)
            e.add_field(name="How it works",
                        value="Each use clears 24h after it was made.",
                        inline=False)
            await safe_followup(interaction, embed=apply_footer(e), ephemeral=True)
            return

        with db() as c:
            rows = c.execute("""SELECT token, bound_ip FROM keys
                                WHERE discord_id=? AND is_permanent=1""",
                             (uid,)).fetchall()

        if not rows:
            e = discord.Embed(title="No Premium Key", color=COLOR_DANGER,
                              description="You don't have a permanent key.\n"
                                          "Click **Get Key** first.")
            set_author(e, interaction.user)
            await safe_followup(interaction, embed=apply_footer(e), ephemeral=True)
            return

        with db() as c:
            c.execute("""UPDATE keys SET bound_ip=NULL
                         WHERE discord_id=? AND is_permanent=1""", (uid,))

        record_hwid_reset(uid)

        uses_remaining, _, uses_used_after, _ = get_hwid_reset_state(uid)

        old_hwids = [r["bound_ip"] or "unbound" for r in rows]
        old_display = ", ".join(f"`{mask_hwid(ip)}`" for ip in old_hwids[:3])
        if len(old_hwids) > 3:
            old_display += f" (+{len(old_hwids)-3} more)"

        e = discord.Embed(
            title="HWID Reset Successful",
            color=COLOR_SUCCESS,
            description="Your key is now unbound.\n"
                        "It will lock to the **next device** that uses it.")
        set_author(e, interaction.user)
        e.add_field(name="Keys Reset", value=str(len(rows)), inline=True)
        e.add_field(name="Uses Remaining",
                    value=f"**{uses_remaining}/{limit}**", inline=True)
        e.add_field(name="Previous HWID", value=old_display, inline=False)

        if uses_remaining > 0:
            e.add_field(name="Next Reset",
                        value="Available now (uses left)", inline=False)
        else:
            _, next_ready_after, _, _ = get_hwid_reset_state(uid)
            next_ready_after = next_ready_after or (now + HWID_RESET_WINDOW)
            e.add_field(name="Next Reset",
                        value=f"Available <t:{next_ready_after}:R> (oldest reset expires in 24h)",
                        inline=False)

        await safe_followup(interaction, embed=apply_footer(e), ephemeral=True)
        await log_audit(interaction.guild, "Self HWID Reset", interaction.user,
                        f"By user ({len(rows)} key(s), uses: {uses_used_after}/{limit})",
                        COLOR_WARNING)

    @premium_only_callback
    async def status_cb(self, interaction: discord.Interaction):
        allowed, remaining = check_panel_cooldown(interaction)
        if not allowed:
            await interaction.response.send_message(
                f"⏳ Slow down! Wait **{remaining}s** before clicking again.",
                ephemeral=True)
            return

        await interaction.response.defer(ephemeral=True)
        uid = interaction.user.id
        active = get_active_key(uid)
        limit = hwid_reset_limit()

        e = discord.Embed(title="Your Premium Key Status", color=COLOR_PREMIUM,
                          description=DIVIDER)
        set_author(e, interaction.user)
        e.add_field(name="Tier", value="Premium", inline=True)

        if active and active["is_permanent"]:
            keys = active.keys()
            hwid = active["bound_ip"] if "bound_ip" in keys else None
            e.add_field(name="Key",
                        value=f"```\n{active['token']}\n```", inline=False)
            e.add_field(name="HWID", value=f"`{mask_hwid(hwid)}`", inline=True)
            e.add_field(name="Created",
                        value=f"<t:{active['created_at']}:R>", inline=True)

            uses_left, next_ready_ts, uses_used, last_reset = get_hwid_reset_state(uid)

            if last_reset:
                e.add_field(name="Last Reset",
                            value=f"<t:{last_reset}:R>", inline=True)
            else:
                e.add_field(name="Last Reset", value="Never", inline=True)

            if uses_left > 0:
                e.add_field(
                    name="HWID Reset",
                    value=f"Available now — **{uses_left}/{limit}** uses left",
                    inline=False)
            else:
                remaining_s = max(0, int(next_ready_ts - time.time()))
                e.add_field(
                    name="HWID Reset",
                    value=(f"**Limit reached** ({uses_used}/{limit})\n"
                           f"Next: <t:{next_ready_ts}:R> ({fmt_remaining(remaining_s)})"),
                    inline=False)
        else:
            e.add_field(name="Key", value="None — click **Get Key** to receive one",
                        inline=False)

        await safe_followup(interaction, embed=apply_footer(e), ephemeral=True)

# ============= OMNI PANEL MANAGEMENT =============
omni_group = app_commands.Group(name="omni",
                                description="Manage the Omni panel")

@omni_group.command(name="set",
                    description="[Admin] Send the premium panel to a channel")
@app_commands.describe(channel="Channel where the premium panel will be posted")
@admin_only()
async def omni_set(interaction: discord.Interaction, channel: discord.TextChannel):
    await interaction.response.defer(ephemeral=True)

    perms = channel.permissions_for(interaction.guild.me)
    if not (perms.send_messages and perms.embed_links):
        await interaction.followup.send(
            f"I can't post in {channel.mention}.\nMissing permissions: "
            f"`Send Messages` and/or `Embed Links`.", ephemeral=True)
        return

    old_ch = get_setting("panel_channel_id")
    old_msg = get_setting("panel_message_id")
    if old_ch and old_msg:
        try:
            old_ch_obj = bot.get_channel(int(old_ch))
            if old_ch_obj:
                old_msg_obj = await old_ch_obj.fetch_message(int(old_msg))
                await old_msg_obj.delete()
                log.info("Deleted old premium panel")
        except Exception as ex:
            log.warning("Failed to delete old premium panel: %s", ex)

    e = discord.Embed(
        title=BRAND_NAME,
        color=COLOR_PREMIUM,
        description=(
            f"{DIVIDER}\n"
            "**Premium Members Only**\n"
            "Use the buttons below to manage your key.\n"
            "All responses are private — only you can see them."
        ),
    )
    e.add_field(name="🔑 Get Key",
                value="Receive your permanent key via DM.", inline=False)
    e.add_field(name="🔒 Reset HWID",
                value=f"Unbind your key from its current device.\n"
                      f"Use when you switch PCs. ({hwid_reset_limit()}x per 24h)",
                inline=False)
    e.add_field(name="📊 Key Status",
                value="View your key, HWID, and reset availability.",
                inline=False)
    e.set_footer(text=BRAND_FOOTER)
    e.timestamp = discord.utils.utcnow()

    try:
        msg = await channel.send(embed=e, view=OmniPanelView())
    except Exception as ex:
        await interaction.followup.send(f"Failed to send panel: {ex}", ephemeral=True)
        return

    set_setting("panel_channel_id", channel.id)
    set_setting("panel_message_id", msg.id)

    confirm = discord.Embed(title="Premium Panel Sent", color=COLOR_SUCCESS,
                            description=f"Premium panel posted in {channel.mention}.")
    set_author(confirm, interaction.user)
    confirm.add_field(name="Message ID", value=f"`{msg.id}`", inline=True)
    await interaction.followup.send(embed=apply_footer(confirm), ephemeral=True)
    await log_audit(interaction.guild, "Premium Panel Deployed", interaction.user,
                    f"Channel: {channel.mention}", COLOR_INFO)

@omni_group.command(name="remove",
                    description="[Admin] Remove the premium panel")
@admin_only()
async def omni_remove(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)

    ch_id = get_setting("panel_channel_id")
    msg_id = get_setting("panel_message_id")
    if not ch_id or not msg_id:
        await interaction.followup.send("No premium panel is currently set.", ephemeral=True)
        return

    try:
        ch = bot.get_channel(int(ch_id))
        if ch:
            msg = await ch.fetch_message(int(msg_id))
            await msg.delete()
    except Exception as ex:
        log.warning("Remove premium panel failed: %s", ex)

    set_setting("panel_channel_id", 0)
    set_setting("panel_message_id", 0)

    e = discord.Embed(title="Premium Panel Removed", color=COLOR_WARNING,
                      description="The premium panel has been deleted.")
    set_author(e, interaction.user)
    await interaction.followup.send(embed=apply_footer(e), ephemeral=True)

# ======================== EVENTS ========================
@bot.event
async def on_ready():
    log.info("=" * 55)
    log.info("%s online: %s (ID: %s)", BRAND_NAME, bot.user, bot.user.id)
    for g in bot.guilds:
        log.info("   - %s (ID: %s)", g.name, g.id)

    bot.add_view(OmniPanelView())
    log.info("Persistent premium panel view registered")

    try:
        bot.tree.add_command(omni_group)
        log.info("Command group /omni registered")
    except Exception as e:
        log.exception("Failed to add omni_group: %s", e)

    try:
        if GUILD_ID and any(g.id == GUILD_ID for g in bot.guilds):
            guild_obj = discord.Object(id=GUILD_ID)
            bot.tree.clear_commands(guild=guild_obj)
            bot.tree.copy_global_to(guild=guild_obj)
            synced = await bot.tree.sync(guild=guild_obj)
            log.info("Synced %d commands to guild %d", len(synced), GUILD_ID)
            for cmd in synced:
                log.info("   /%s", cmd.name)
        else:
            synced = await bot.tree.sync()
            log.info("Synced %d commands globally", len(synced))
    except Exception as e:
        log.exception("Sync failed: %s", e)

    if not prune_task.is_running():
        prune_task.start()
    log.info("=" * 55)

@tasks.loop(hours=24)
async def prune_task():
    try:
        prune_expired_keys()
    except Exception as e:
        log.exception("Prune task failed: %s", e)

# ======================== USER COMMANDS ========================
@bot.tree.command(name="status", description="Check your premium key status")
async def status(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    uid = interaction.user.id
    active = get_active_key(uid)

    e = discord.Embed(title="Account Status", color=COLOR_PREMIUM,
                      description=DIVIDER)
    set_author(e, interaction.user)
    e.add_field(name="Tier",
                value="Premium" if is_premium(interaction.user) else "None",
                inline=True)

    if active:
        if active["is_permanent"]:
            e.add_field(name="Key", value="Permanent", inline=True)
            keys = active.keys()
            hwid = active["bound_ip"] if "bound_ip" in keys else None
            e.add_field(name="HWID", value=f"`{mask_hwid(hwid)}`", inline=True)
        else:
            e.add_field(name="Key",
                        value=f"Expires <t:{active['expires_at']}:R>",
                        inline=True)
    else:
        e.add_field(name="Key", value="None", inline=True)

    e.add_field(name="How to get a key",
                value="Use the **premium panel** in the designated channel.",
                inline=False)

    await interaction.followup.send(embed=apply_footer(e), ephemeral=True)

@bot.tree.command(name="mykey", description="View your current active key (via DM)")
async def mykey(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)
    row = get_active_key(interaction.user.id)
    if not row:
        e = discord.Embed(title="No Active Key", color=COLOR_DANGER,
                          description="You don't have an active key.\n"
                                      "Use the premium panel to get one.")
        set_author(e, interaction.user)
        await interaction.followup.send(embed=apply_footer(e), ephemeral=True)
        return

    if row["is_permanent"]:
        keys = row.keys()
        hwid = row["bound_ip"] if "bound_ip" in keys else None
        e = key_embed("Your Permanent Key", row["token"], color=COLOR_PREMIUM,
                      description="Premium Member — this key never expires.",
                      user=interaction.user,
                      fields=[("Tier", "PERMANENT", True),
                              ("HWID", f"`{mask_hwid(hwid)}`", True)])
    else:
        remaining = row["expires_at"] - int(time.time())
        e = key_embed("Your Active Key", row["token"], color=COLOR_PRIMARY,
                      description="Here's your current key.",
                      user=interaction.user,
                      fields=[("Expires In", f"**{fmt_remaining(remaining)}**", True),
                              ("Expires", f"<t:{row['expires_at']}:R>", True)])

    ok = await send_dm(interaction.user, e)
    await interaction.followup.send(
        "Sent to your DM." if ok else
        "Could not DM you. Enable Direct Messages from server members.",
        ephemeral=True)

@bot.tree.command(name="help", description="Show available commands")
async def help_cmd(interaction: discord.Interaction):
    e = discord.Embed(
        title=BRAND_NAME,
        color=COLOR_PREMIUM,
        description=f"{DIVIDER}\nWelcome to Omni Key System.",
    )
    set_author(e, interaction.user)
    e.add_field(
        name="User Commands",
        value=("**`/status`** — Check your account and key status\n"
               "**`/mykey`** — Retrieve your current active key via DM\n"
               "**`/help`** — Show this menu"),
        inline=False)
    e.add_field(
        name="Premium Panel",
        value=(f"{DIVIDER}\n"
               "Check the designated channel for the panel.\n"
               "Use **Get Key**, **Reset HWID**, and **Key Status** buttons."),
        inline=False)
    e.add_field(
        name="HWID Lock",
        value=("Your key locks to the first device that uses it.\n"
               f"You can self-reset **{hwid_reset_limit()}x per 24h** via the panel."),
        inline=False)
    await interaction.response.send_message(embed=apply_footer(e), ephemeral=True)

# ==================== ADMIN COMMANDS ====================
@bot.tree.command(name="premium", description="[Admin] Grant premium role and permanent key")
@app_commands.describe(user="User to upgrade")
@admin_only()
async def premium(interaction: discord.Interaction, user: discord.Member):
    await interaction.response.defer(ephemeral=True)
    pr = premium_role_id()
    if pr == 0:
        await interaction.followup.send("Premium role not configured.", ephemeral=True)
        return
    role = interaction.guild.get_role(pr)
    if not role:
        await interaction.followup.send("Premium role not found in this server.", ephemeral=True)
        return
    try:
        if role not in user.roles:
            await user.add_roles(role, reason=f"Premium granted by {interaction.user}")
    except discord.Forbidden:
        await interaction.followup.send("Bot can't assign that role. Move bot role above premium role.", ephemeral=True)
        return
    except Exception as ex:
        await interaction.followup.send(f"Failed: {ex}", ephemeral=True)
        return

    existing = get_active_key(user.id)
    if existing and existing["is_permanent"]:
        tok = existing["token"]
    else:
        tok, _ = create_key(user.id, 0, permanent=True)

    dm_e = key_embed("Premium Activated", tok, color=COLOR_PREMIUM,
                     description="An admin granted you Premium. Your key is permanent.",
                     user=user,
                     fields=[("Tier", "PERMANENT", True),
                             ("Note", "This key locks to your first device.", False)])
    dm_ok = await send_dm(user, dm_e)

    confirm = discord.Embed(title="Premium Granted", color=COLOR_SUCCESS,
                            description=f"{user.mention} now has {role.mention} and a permanent key.")
    set_author(confirm, interaction.user)
    confirm.add_field(name="Role", value=role.mention, inline=True)
    confirm.add_field(name="DM", value="Sent" if dm_ok else "Failed", inline=True)
    confirm.add_field(name="Key", value=f"```\n{tok}\n```", inline=False)
    await interaction.followup.send(embed=apply_footer(confirm), ephemeral=True)
    await log_audit(interaction.guild, "Premium Granted", interaction.user,
                    f"To {user.mention}", COLOR_PREMIUM)

@bot.tree.command(name="unpremium", description="[Admin] Remove premium role and permanent key")
@app_commands.describe(user="User to downgrade",
                       delete_key="Delete their permanent key (default: True)")
@admin_only()
async def unpremium(interaction: discord.Interaction, user: discord.Member,
                    delete_key: bool = True):
    await interaction.response.defer(ephemeral=True)
    pr = premium_role_id()
    role = interaction.guild.get_role(pr) if pr else None

    removed_role = False
    if role and role in user.roles:
        try:
            await user.remove_roles(role, reason=f"Revoked by {interaction.user}")
            removed_role = True
        except discord.Forbidden:
            await interaction.followup.send("Bot can't remove that role.", ephemeral=True)
            return

    deleted = 0
    if delete_key:
        with db() as c:
            cur = c.execute("DELETE FROM keys WHERE discord_id=? AND is_permanent=1", (user.id,))
            deleted = cur.rowcount

    e = discord.Embed(title="Premium Revoked", color=COLOR_WARNING,
                      description=f"Premium access removed from {user.mention}.")
    set_author(e, interaction.user)
    e.add_field(name="Role Removed", value="Yes" if removed_role else "Not present", inline=True)
    e.add_field(name="Keys Deleted", value=str(deleted), inline=True)
    await interaction.followup.send(embed=apply_footer(e), ephemeral=True)
    await log_audit(interaction.guild, "Premium Revoked", interaction.user,
                    f"From {user.mention}", COLOR_WARNING)

@bot.tree.command(name="resethwid",
                  description="[Admin] Reset HWID binding of a user's premium key")
@app_commands.describe(user="User whose premium key binding should be reset")
@admin_only()
async def resethwid(interaction: discord.Interaction, user: discord.Member):
    await interaction.response.defer(ephemeral=True)

    with db() as c:
        rows = c.execute("""SELECT token, bound_ip FROM keys
                            WHERE discord_id=? AND is_permanent=1""",
                         (user.id,)).fetchall()

    if not rows:
        e = discord.Embed(title="No Premium Key", color=COLOR_DANGER,
                          description=f"{user.mention} doesn't have a permanent key.")
        set_author(e, interaction.user)
        await interaction.followup.send(embed=apply_footer(e), ephemeral=True)
        return

    with db() as c:
        c.execute("""UPDATE keys SET bound_ip=NULL
                     WHERE discord_id=? AND is_permanent=1""", (user.id,))

    clear_hwid_reset_history(user.id)

    old_hwids = [r["bound_ip"] or "unbound" for r in rows]
    old_display = ", ".join(f"`{mask_hwid(ip)}`" for ip in old_hwids[:3])
    if len(old_hwids) > 3:
        old_display += f" (+{len(old_hwids)-3} more)"

    e = discord.Embed(
        title="HWID Reset",
        color=COLOR_SUCCESS,
        description=f"HWID binding reset for {user.mention}'s premium key(s).\n"
                    f"{DIVIDER}\n"
                    f"The key will bind to the next device that uses it."
    )
    set_author(e, interaction.user)
    e.add_field(name="Keys Reset", value=str(len(rows)), inline=True)
    e.add_field(name="Previous HWID", value=old_display, inline=False)
    e.add_field(name="Self-Reset History", value="Cleared (fresh quota)", inline=False)

    try:
        dm = discord.Embed(
            title="Premium Key Reset",
            color=COLOR_INFO,
            description="An admin has reset your premium key's HWID binding.\n"
                        "Next time you use the key, it will bind to that device."
        )
        dm.set_footer(text=BRAND_FOOTER)
        await user.send(embed=dm)
    except Exception:
        pass

    await interaction.followup.send(embed=apply_footer(e), ephemeral=True)
    await log_audit(interaction.guild, "HWID Reset (Admin)", interaction.user,
                    f"User: {user.mention} ({len(rows)} key(s))", COLOR_WARNING)

@bot.tree.command(name="checkkey", description="[Admin] Inspect a user's keys")
@app_commands.describe(user="User to inspect", show_all="Include expired keys")
@admin_only()
async def checkkey(interaction: discord.Interaction, user: discord.User,
                   show_all: bool = False):
    await interaction.response.defer(ephemeral=True)
    active = get_active_key(user.id)

    e = discord.Embed(title=f"Key Inspection — {user.name}", color=COLOR_INFO,
                      description=f"{user.mention}  |  `{user.id}`")
    set_author(e, interaction.user, prefix="Inspect by ")
    e.add_field(name="Tier",
                value="Premium" if is_premium(user) else "None", inline=True)

    if active:
        if active["is_permanent"]:
            keys = active.keys()
            hwid = active["bound_ip"] if "bound_ip" in keys else None
            e.add_field(name="Key",
                        value=f"```\n{active['token']}\n```Permanent\n"
                              f"HWID: `{mask_hwid(hwid)}`",
                        inline=False)
        else:
            remaining_key = active["expires_at"] - int(time.time())
            e.add_field(name="Key",
                        value=f"```\n{active['token']}\n```"
                              f"Expires **{fmt_remaining(remaining_key)}** "
                              f"(<t:{active['expires_at']}:R>)",
                        inline=False)
    else:
        e.add_field(name="Key", value="None", inline=False)

    if show_all:
        rows = get_all_keys(user.id)
        if rows:
            lines = []
            now = int(time.time())
            for r in rows[:15]:
                st = "PERM" if r["is_permanent"] else (
                    "ACTIVE" if r["expires_at"] > now else "EXPIRED")
                lines.append(f"`{r['token']}` — {st}")
            more = "" if len(rows) <= 15 else f"\n...and {len(rows)-15} more"
            e.add_field(name=f"History ({len(rows)})",
                        value="\n".join(lines) + more, inline=False)

    await interaction.followup.send(embed=apply_footer(e), ephemeral=True)

@bot.tree.command(name="listkeys", description="[Admin] List all active keys")
@admin_only()
async def listkeys(interaction: discord.Interaction):
    await interaction.response.defer(ephemeral=True)

    msg = await interaction.followup.send("⠋  Fetching keys...")
    spinner = Spinner(msg, "Fetching keys")
    spinner.start()

    e = None
    try:
        now = int(time.time())
        with db() as c:
            rows = c.execute("""SELECT * FROM keys
                                WHERE is_permanent=1 OR expires_at>?
                                ORDER BY is_permanent DESC, created_at DESC
                                LIMIT 25""", (now,)).fetchall()

        e = discord.Embed(title="Active Keys", color=COLOR_PRIMARY,
                          description=f"{DIVIDER}\nShowing {len(rows)} key(s).")
        set_author(e, interaction.user)

        if not rows:
            e.description = "No active keys found."
        else:
            for r in rows:
                keys = r.keys()
                if r["is_permanent"]:
                    name = await resolve_username(r["discord_id"])
                    bound = r["bound_ip"] if "bound_ip" in keys and r["bound_ip"] else "unbound"
                    tag = f"Premium — {name} ({mask_hwid(bound)})"
                else:
                    name = await resolve_username(r["discord_id"])
                    tag = f"User — {name}"
                exp_str = "Permanent" if r["is_permanent"] else f"<t:{r['expires_at']}:R>"
                e.add_field(name=tag, value=f"```\n{r['token']}\n```{exp_str}", inline=False)
    finally:
        await spinner.stop()

    await asyncio.sleep(0.3)

    if e is None:
        try:
            await msg.edit(content="Failed to build key list.")
        except Exception:
            pass
        return

    try:
        await msg.edit(content=None, embed=apply_footer(e))
    except discord.HTTPException as ex:
        log.error("listkeys final edit failed: %s", ex)
        try:
            await msg.delete()
            await interaction.followup.send(embed=apply_footer(e), ephemeral=True)
        except Exception as ex2:
            log.exception("listkeys fallback failed: %s", ex2)

@bot.tree.command(name="whois", description="[Admin] Look up a key's owner")
@app_commands.describe(token="Key token (e.g. OM-xxxxxxxxxxxx)")
@admin_only()
async def whois(interaction: discord.Interaction, token: str):
    await interaction.response.defer(ephemeral=True)
    row = find_key(token.strip())
    if not row:
        e = discord.Embed(title="Key Not Found", color=COLOR_DANGER,
                          description="No key matches that token.")
        await interaction.followup.send(embed=apply_footer(e), ephemeral=True)
        return

    keys = row.keys()
    try:
        o = await bot.fetch_user(row["discord_id"])
        owner_str = f"{o.mention} (`{o.name}` — `{o.id}`)"
    except Exception:
        owner_str = f"`{row['discord_id']}`"

    status_txt = "Permanent" if row["is_permanent"] else (
        f"Active until <t:{row['expires_at']}:R>"
        if row["expires_at"] > int(time.time()) else "Expired")

    e = discord.Embed(title="Key Lookup", color=COLOR_INFO, description=DIVIDER)
    set_author(e, interaction.user)
    e.add_field(name="Token", value=f"```\n{row['token']}\n```", inline=False)
    e.add_field(name="Owner", value=owner_str, inline=False)
    e.add_field(name="Status", value=status_txt, inline=False)
    if row["is_permanent"]:
        hwid = row["bound_ip"] if "bound_ip" in keys else None
        e.add_field(name="HWID", value=f"`{mask_hwid(hwid)}`", inline=True)
    e.add_field(name="Created", value=f"<t:{row['created_at']}:R>", inline=True)
    if not row["is_permanent"]:
        e.add_field(name="Expires", value=f"<t:{row['expires_at']}:R>", inline=True)
    await interaction.followup.send(embed=apply_footer(e), ephemeral=True)

@bot.tree.command(name="grant", description="[Admin] Grant a permanent key (no role)")
@app_commands.describe(user="Recipient", dm="Send via DM (default: True)")
@admin_only()
async def grant(interaction: discord.Interaction, user: discord.User, dm: bool = True):
    await interaction.response.defer(ephemeral=True)
    existing = get_active_key(user.id)
    if existing and existing["is_permanent"]:
        e = key_embed("Already Permanent", existing["token"], color=COLOR_INFO,
                      description=f"{user.mention} already has a permanent key.",
                      user=interaction.user)
        await interaction.followup.send(embed=e, ephemeral=True)
        return

    tok, _ = create_key(user.id, 0, permanent=True)
    dm_e = key_embed("Permanent Key Granted", tok, color=COLOR_PREMIUM,
                     description="An admin granted you a permanent key.",
                     user=user,
                     fields=[("Tier", "PERMANENT", True),
                             ("Note", "This key locks to your first device.", False)])

    if dm:
        ok = await send_dm(user, dm_e)
        if ok:
            await interaction.followup.send(
                f"Permanent key sent to {user.mention}'s DM.", ephemeral=True)
        else:
            await interaction.followup.send(
                content=f"Could not DM {user.mention} — key below:",
                embed=dm_e, ephemeral=True)
    else:
        await interaction.followup.send(embed=dm_e, ephemeral=True)
    await log_audit(interaction.guild, "Permanent Key Granted", interaction.user,
                    f"To {user.mention}", COLOR_PREMIUM)

# ---------- Revoke with confirmation ----------
class RevokeConfirmView(discord.ui.View):
    def __init__(self, target: discord.User, admin: discord.User):
        super().__init__(timeout=30)
        self.target = target
        self.admin = admin

    @discord.ui.button(label="Confirm Revoke", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.admin.id:
            await interaction.response.send_message(
                "Only the original admin can confirm.", ephemeral=True)
            return
        with db() as c:
            cur = c.execute("DELETE FROM keys WHERE discord_id=?", (self.target.id,))
            removed = cur.rowcount
        e = discord.Embed(title="Keys Revoked", color=COLOR_DANGER,
                          description=f"Removed **{removed}** key(s) from {self.target.mention}.")
        await interaction.response.edit_message(embed=apply_footer(e), view=None)
        await log_audit(interaction.guild, "Keys Revoked", interaction.user,
                        f"From {self.target.mention} ({removed} keys)", COLOR_DANGER)

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.admin.id:
            await interaction.response.send_message("Not your button.", ephemeral=True)
            return
        e = discord.Embed(title="Cancelled", color=COLOR_INFO,
                          description="Revoke operation cancelled.")
        await interaction.response.edit_message(embed=apply_footer(e), view=None)

@bot.tree.command(name="revoke", description="[Admin] Delete all keys of a user")
@app_commands.describe(user="Target user")
@admin_only()
async def revoke(interaction: discord.Interaction, user: discord.User):
    e = discord.Embed(title="Confirm Revoke", color=COLOR_WARNING,
                      description=f"This will delete **all keys** for {user.mention}.\n"
                                  f"{DIVIDER}\nThis action cannot be undone.")
    set_author(e, interaction.user)
    view = RevokeConfirmView(user, interaction.user)
    await interaction.response.send_message(embed=apply_footer(e),
                                            view=view, ephemeral=True)

# ---------- Delete key with confirmation ----------
class DeleteKeyConfirmView(discord.ui.View):
    def __init__(self, token: str, owner_info: str, admin: discord.User):
        super().__init__(timeout=30)
        self.token = token
        self.owner_info = owner_info
        self.admin = admin

    @discord.ui.button(label="Delete Key", style=discord.ButtonStyle.danger)
    async def confirm(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.admin.id:
            await interaction.response.send_message(
                "Only the original admin can confirm.", ephemeral=True)
            return

        with db() as c:
            cur = c.execute("DELETE FROM keys WHERE token=?", (self.token,))
            removed = cur.rowcount

        if removed:
            e = discord.Embed(title="Key Deleted", color=COLOR_SUCCESS,
                              description="Key has been permanently removed.")
            e.add_field(name="Token", value=f"```\n{self.token}\n```", inline=False)
            e.add_field(name="Owner", value=self.owner_info, inline=True)
            await interaction.response.edit_message(embed=apply_footer(e), view=None)
            await log_audit(interaction.guild, "Key Deleted", interaction.user,
                            f"Token: `{self.token[:16]}...`", COLOR_DANGER)
        else:
            e = discord.Embed(title="Key Not Found", color=COLOR_DANGER,
                              description="The key was already deleted.")
            await interaction.response.edit_message(embed=apply_footer(e), view=None)

    @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
    async def cancel(self, interaction: discord.Interaction, button: discord.ui.Button):
        if interaction.user.id != self.admin.id:
            await interaction.response.send_message("Not your button.", ephemeral=True)
            return
        e = discord.Embed(title="Cancelled", color=COLOR_INFO,
                          description="Delete operation cancelled.")
        await interaction.response.edit_message(embed=apply_footer(e), view=None)

@bot.tree.command(name="deletekey",
                  description="[Admin] Permanently delete a single key by token")
@app_commands.describe(token="The full key token (e.g. OM-xxxxxxxxxxxx)")
@admin_only()
async def deletekey(interaction: discord.Interaction, token: str):
    await interaction.response.defer(ephemeral=True)
    token = token.strip()

    row = find_key(token)
    if not row:
        e = discord.Embed(title="Key Not Found", color=COLOR_DANGER,
                          description="No key matches that token.")
        set_author(e, interaction.user)
        await interaction.followup.send(embed=apply_footer(e), ephemeral=True)
        return

    owner_info = f"<@{row['discord_id']}> (`{row['discord_id']}`)"

    now = int(time.time())
    if row["is_permanent"]:
        status_txt = "Permanent"
    elif row["expires_at"] > now:
        status_txt = f"Active (expires <t:{row['expires_at']}:R>)"
    else:
        status_txt = "Expired"

    e = discord.Embed(
        title="Confirm Key Deletion",
        color=COLOR_WARNING,
        description=f"Delete this key permanently?\n{DIVIDER}\nThis action cannot be undone.",
    )
    set_author(e, interaction.user)
    e.add_field(name="Token", value=f"```\n{row['token']}\n```", inline=False)
    e.add_field(name="Owner", value=owner_info, inline=False)
    e.add_field(name="Status", value=status_txt, inline=True)
    e.add_field(name="Created", value=f"<t:{row['created_at']}:R>", inline=True)

    view = DeleteKeyConfirmView(token, owner_info, interaction.user)
    await interaction.followup.send(embed=apply_footer(e), view=view, ephemeral=True)

# ================= SETTINGS =================
SETTING_KEYS = {
    "premium_role_id":  ("Premium Role ID",   "int"),
    "admin_role_ids":   ("Admin Role IDs",    "id_list"),
    "hwid_reset_limit": ("HWID Reset Limit",  "int_range:1:10"),
}

def format_setting_value(key: str) -> str:
    v = get_setting(key)
    if key == "hwid_reset_limit": return f"`{int(v)}x per 24h`"
    if key == "premium_role_id":  return f"<@&{v}>" if int(v or 0) else "Not set"
    if key == "admin_role_ids":
        ids = list(v or [])
        return ", ".join(f"<@&{i}>" for i in ids) if ids else "None"
    return f"`{v}`"

def parse_ids(s: str) -> list:
    parts = [p.strip() for p in s.replace(",", " ").split() if p.strip()]
    out = []
    for p in parts:
        p = p.strip("<@&!>")
        if p.isdigit():
            out.append(int(p))
    return out

@bot.tree.command(name="settings", description="[Admin] View live bot settings")
@admin_only()
async def settings_panel(interaction: discord.Interaction):
    e = discord.Embed(title="Bot Settings", color=COLOR_PRIMARY,
                      description=f"{DIVIDER}\nChange with `/settings_set`. Restore with `/settings_reset`.")
    set_author(e, interaction.user)
    for key, (label, _) in SETTING_KEYS.items():
        e.add_field(name=label, value=f"{format_setting_value(key)}\n`{key}`", inline=False)
    await interaction.response.send_message(embed=apply_footer(e), ephemeral=True)

@bot.tree.command(name="settings_set", description="[Admin] Change a bot setting")
@app_commands.describe(key="Setting", value="New value")
@admin_only()
@app_commands.choices(key=[
    app_commands.Choice(name="premium_role_id",  value="premium_role_id"),
    app_commands.Choice(name="admin_role_ids",   value="admin_role_ids"),
    app_commands.Choice(name="hwid_reset_limit", value="hwid_reset_limit"),
])
async def settings_set(interaction: discord.Interaction, key: app_commands.Choice[str],
                       value: str):
    await interaction.response.defer(ephemeral=True)
    k = key.value
    _, kind = SETTING_KEYS[k]
    try:
        if kind.startswith("int_range"):
            lo, hi = map(int, kind.split(":")[1:])
            new = int(value.strip())
            if not (lo <= new <= hi):
                raise ValueError(f"Must be between {lo} and {hi}")
        elif kind == "int":
            new = int(value.strip().strip("<@&!>"))
        elif kind == "id_list":
            new = parse_ids(value)
        else:
            new = value
    except Exception as ex:
        await interaction.followup.send(f"Invalid value: {ex}", ephemeral=True)
        return

    set_setting(k, new)
    e = discord.Embed(title="Setting Updated", color=COLOR_SUCCESS,
                      description=f"**{SETTING_KEYS[k][0]}** changed.")
    set_author(e, interaction.user)
    e.add_field(name="Key", value=f"`{k}`", inline=True)
    e.add_field(name="Value", value=format_setting_value(k), inline=True)
    await interaction.followup.send(embed=apply_footer(e), ephemeral=True)
    await log_audit(interaction.guild, "Setting Updated", interaction.user,
                    f"`{k}` = `{new}`", COLOR_INFO)

@bot.tree.command(name="settings_reset", description="[Admin] Restore default settings")
@admin_only()
async def settings_reset(interaction: discord.Interaction):
    with db() as c:
        c.execute("DELETE FROM settings")
    for k, v in DEFAULT_SETTINGS.items():
        set_setting(k, v)
    e = discord.Embed(title="Settings Reset", color=COLOR_WARNING,
                      description="All settings restored to defaults.")
    set_author(e, interaction.user)
    await interaction.response.send_message(embed=apply_footer(e), ephemeral=True)
    await log_audit(interaction.guild, "Settings Reset", interaction.user,
                    "All settings restored to defaults", COLOR_WARNING)

@bot.tree.command(name="prunekeys", description="[Admin] Manually prune expired keys")
@admin_only()
async def prunekeys(interaction: discord.Interaction):
    removed = prune_expired_keys()
    e = discord.Embed(title="Prune Complete", color=COLOR_SUCCESS,
                      description=f"Removed **{removed}** expired key(s) older than {PRUNE_AFTER_DAYS} days.")
    set_author(e, interaction.user)
    await interaction.response.send_message(embed=apply_footer(e), ephemeral=True)
    await log_audit(interaction.guild, "Prune Keys", interaction.user,
                    f"Removed {removed} keys", COLOR_INFO)

# ===================== ADMIN HELP =====================
@bot.tree.command(name="ahelp", description="Admin command reference")
async def ahelp(interaction: discord.Interaction):
    if not is_admin(interaction.user):
        try:
            await interaction.response.defer(ephemeral=True)
        except Exception:
            pass
        return

    await interaction.response.defer(ephemeral=True)
    e = discord.Embed(
        title="Admin Command Reference",
        color=COLOR_DARK,
        description=f"{DIVIDER}\nRestricted to staff members with admin role.",
    )
    set_author(e, interaction.user, prefix="Admin: ")

    e.add_field(
        name="Panel",
        value=("**`/omni set #channel`** — Post the premium panel\n"
               "**`/omni remove`** — Remove the premium panel"),
        inline=False)
    e.add_field(
        name="Premium",
        value=("**`/premium @user`** — Grant premium role + permanent key\n"
               "**`/unpremium @user [delete_key]`** — Revoke premium\n"
               "**`/grant @user [dm]`** — Issue permanent key without a role\n"
               "**`/resethwid @user`** — Reset HWID binding"),
        inline=False)
    e.add_field(
        name="Inspection",
        value=("**`/checkkey @user [show_all]`** — Inspect a user's keys\n"
               "**`/listkeys`** — List all active keys\n"
               "**`/whois <token>`** — Find who owns a key"),
        inline=False)
    e.add_field(
        name="Key Management",
        value=("**`/revoke @user`** — Delete all keys of a user\n"
               "**`/deletekey <token>`** — Delete a single key by token\n"
               "**`/prunekeys`** — Prune expired keys"),
        inline=False)
    e.add_field(
        name="System",
        value=("**`/settings`** — View current config\n"
               "**`/settings_set <key> <value>`** — Modify a setting\n"
               "**`/settings_reset`** — Restore defaults"),
        inline=False)
    e.add_field(
        name="Tips",
        value=(f"{DIVIDER}\n"
               f"Premium keys lock to the first HWID that uses them.\n"
               f"Users can self-reset HWID **{hwid_reset_limit()}x per 24h** via the panel.\n"
               f"The rolling window means each use expires 24h after it was made.\n"
               f"Self-reset quota is stored in DB and survives bot restart."),
        inline=False)

    await interaction.followup.send(embed=apply_footer(e), ephemeral=True)

# ========================= RUN =========================
async def main():
    if not DISCORD_TOKEN:
        log.error("DISCORD_TOKEN is empty. Check your .env file.")
        sys.exit(1)

    try:
        from server_signing import _load_signing_key
        _load_signing_key()
        log.info("Signing key loaded (Ed25519)")
    except Exception as ex:
        log.error("Failed to load signing key: %s", ex)
        log.error("Set SIGN_PRIVATE_KEY in .env. Generate with:")
        log.error("    python server_signing.py --genkey")
        sys.exit(1)

    init_db()
    await start_api()
    try:
        await bot.start(DISCORD_TOKEN)
    except KeyboardInterrupt:
        log.info("Shutting down...")
    finally:
        await bot.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Shutdown requested.")
    except Exception as e:
        log.exception("Fatal: %s", e)
