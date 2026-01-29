import logging
import sqlite3
import asyncio
import os
import datetime
import re
import dns.resolver  # Masih menggunakan dnspython untuk DNS
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    MessageHandler,
    ContextTypes,
    ConversationHandler,
    filters,
)

# ==========================================
# 1. CONFIGURATION
# ==========================================
TOKEN = "TELEGRAM_TOKEN_TOKEN"
DB_NAME = "recon_bot.db"
RESULTS_DIR = "results"

# Logging Setup
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

# State Definitions
SELECT_TOOL, GET_TARGET, CONFIRM_SCAN = range(3)

# Pastikan folder results ada
if not os.path.exists(RESULTS_DIR):
    os.makedirs(RESULTS_DIR)

# ==========================================
# 2. DATABASE LAYER
# ==========================================
class DatabaseManager:
    def __init__(self, db_name):
        self.db_name = db_name
        self.init_db()

    def init_db(self):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    telegram_id INTEGER UNIQUE NOT NULL,
                    username TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    tool TEXT NOT NULL,
                    target TEXT NOT NULL,
                    status TEXT DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    result_file TEXT,
                    FOREIGN KEY (user_id) REFERENCES users(telegram_id)
                )
            """)
            conn.commit()

    def add_user(self, user_id, username):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR IGNORE INTO users (telegram_id, username) VALUES (?, ?)",
                (user_id, username),
            )
            conn.commit()

    def create_scan(self, user_id, tool, target):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO scans (user_id, tool, target, status) VALUES (?, ?, ?, 'pending')",
                (user_id, tool, target),
            )
            scan_id = cursor.lastrowid
            conn.commit()
            return scan_id

    def update_scan_status(self, scan_id, status, result_file=None):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            if result_file:
                cursor.execute(
                    "UPDATE scans SET status = ?, result_file = ? WHERE id = ?",
                    (status, result_file, scan_id),
                )
            else:
                cursor.execute(
                    "UPDATE scans SET status = ? WHERE id = ?", (status, scan_id)
                )
            conn.commit()

db = DatabaseManager(DB_NAME)

# ==========================================
# 3. TOOL WRAPPERS & SCAN MANAGER
# ==========================================
class ScanManager:
    @staticmethod
    def sanitize_target(target, tool_type):
        """Membersihkan target sesuai kebutuhan tool"""
        target = target.strip()
        
        def strip_protocol(t):
            # Hapus http://, https://, www.
            t = re.sub(r'^https?://', '', t)
            t = re.sub(r'^www\.', '', t)
            return t.split('/')[0]

        def ensure_protocol(t):
            if not t.startswith(('http://', 'https://')):
                return f'https://{t}'
            return t

        # Nmap, Subfinder, Whois (CLI), DNS butuh domain polos
        if tool_type in ['nmap', 'subfinder', 'whois', 'dns']:
            return strip_protocol(target)
        # Dirsearch butuh URL lengkap
        elif tool_type == 'dirsearch':
            return ensure_protocol(target)
        return target

    @staticmethod
    async def _run_command(cmd):
        """Menjalankan perintah shell secara async"""
        try:
            # Menggunakan shell=True agar fitur redirection (>) berfungsi
            process = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return True, stdout.decode()
            else:
                # Beberapa tools mungkin mengirim output non-error ke stderr, 
                # tapi biasanya returncode != 0 berarti error.
                return False, stderr.decode()
        except Exception as e:
            return False, str(e)

    # --- CLI TOOLS ---
    @staticmethod
    async def run_nmap(target, output_file):
        clean_target = ScanManager.sanitize_target(target, 'nmap')
        cmd = f"nmap -sV -sC -T4 {clean_target} -oN {output_file}"
        return await ScanManager._run_command(cmd)

    @staticmethod
    async def run_subfinder(target, output_file):
        clean_target = ScanManager.sanitize_target(target, 'subfinder')
        cmd = f"subfinder -d {clean_target} -o {output_file}"
        return await ScanManager._run_command(cmd)

    @staticmethod
    async def run_dirsearch(target, output_file):
        clean_target = ScanManager.sanitize_target(target, 'dirsearch')
        cmd = f"dirsearch -u {clean_target} -o {output_file} --format=plain"
        return await ScanManager._run_command(cmd)

    @staticmethod
    async def run_whois(target, output_file):
        """Menjalankan System Command WHOIS"""
        clean_target = ScanManager.sanitize_target(target, 'whois')
        # Menggunakan redirection '>' linux untuk menyimpan output ke file
        cmd = f"whois {clean_target} > {output_file}"
        return await ScanManager._run_command(cmd)

    # --- PYTHON LIBRARY TOOLS (DNS ONLY) ---
    @staticmethod
    def _dns_worker(target):
        results = [f"DNS Reconnaissance for: {target}\n" + "="*30 + "\n"]
        resolver = dns.resolver.Resolver()
        record_types = ['A', 'MX', 'NS', 'TXT']
        
        for r_type in record_types:
            try:
                answers = resolver.resolve(target, r_type)
                results.append(f"\n[{r_type} RECORDS]")
                for rdata in answers:
                    results.append(f"- {rdata.to_text()}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                results.append(f"\n[{r_type} RECORDS]: None found")
            except Exception as e:
                results.append(f"\n[{r_type} RECORDS]: Error ({str(e)})")
        
        return "\n".join(results)

    @staticmethod
    async def run_dns(target, output_file):
        try:
            clean_target = ScanManager.sanitize_target(target, 'dns')
            output_text = await asyncio.to_thread(ScanManager._dns_worker, clean_target)
            
            with open(output_file, 'w') as f:
                f.write(output_text)
            return True, ""
        except Exception as e:
            return False, str(e)

# ==========================================
# 4. BOT HANDLERS
# ==========================================

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    db.add_user(user.id, user.username)
    
    welcome_text = (
        f"🤖 Selamat Datang, {user.first_name}!\n\n"
        "Saya adalah ReconOps Bot - Asisten keamanan siber otomatis Anda.\n"
        "Gunakan tombol di bawah untuk memulai pengintaian (reconnaissance).\n\n"
        "📋 Fitur Tersedia:\n"
        "👤 Whois: Info domain (System CLI)\n"
        "📡 DNS Recon: Analisis record A, MX, NS, TXT\n"
        "🔍 Nmap: Port scanning & service detection\n"
        "🌐 Subfinder: Menemukan subdomain tersembunyi\n"
        "📂 Dirsearch: Bruteforce direktori website\n"
        "🚀 All-in-One: Jalankan SEMUA tools sekaligus!"
    )
    
    keyboard = [
        [
            InlineKeyboardButton("👤 Whois", callback_data="whois"),
            InlineKeyboardButton("📡 DNS Recon", callback_data="dns"),
        ],
        [
            InlineKeyboardButton("🔍 Nmap", callback_data="nmap"),
            InlineKeyboardButton("🌐 Subfinder", callback_data="subfinder"),
        ],
        [InlineKeyboardButton("📂 Dirsearch", callback_data="dirsearch")],
        [InlineKeyboardButton("🚀 All-in-One Scan", callback_data="all")],
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(welcome_text, reply_markup=reply_markup, parse_mode="Markdown")
    return SELECT_TOOL

async def select_tool(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    tool = query.data
    context.user_data["tool"] = tool
    
    tool_names = {
        "nmap": "🔍 Nmap Scan",
        "subfinder": "🌐 Subfinder",
        "dirsearch": "📂 Dirsearch",
        "dns": "📡 DNS Recon",
        "whois": "👤 Whois (CLI)",
        "all": "🚀 Full Recon Suite"
    }
    
    await query.edit_message_text(
        f"✅ Mode Terpilih: {tool_names[tool]}\n\n"
        "Silakan masukkan Target (IP atau Domain):\n"
        "_Contoh: example.com_",
        parse_mode="Markdown"
    )
    return GET_TARGET

async def get_target(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target = update.message.text
    context.user_data["target"] = target
    tool = context.user_data["tool"]
    
    preview_text = ""
    # Preview command/action
    if tool == "all":
        preview_text = "Urutan: Whois ➔ DNS ➔ Subfinder ➔ Nmap ➔ Dirsearch"
    elif tool == "nmap":
        preview_text = f"nmap -sV -sC {ScanManager.sanitize_target(target, 'nmap')}"
    elif tool == "subfinder":
        preview_text = f"subfinder -d {ScanManager.sanitize_target(target, 'subfinder')}"
    elif tool == "whois":
        preview_text = f"whois {ScanManager.sanitize_target(target, 'whois')}"
    elif tool == "dirsearch":
        preview_text = f"dirsearch -u {ScanManager.sanitize_target(target, 'dirsearch')}"
    elif tool == "dns":
        preview_text = "DNS Queries (A, MX, NS, TXT)"

    keyboard = [[
        InlineKeyboardButton("✅ START", callback_data="confirm"),
        InlineKeyboardButton("❌ BATAL", callback_data="cancel"),
    ]]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        "Konfirmasi Target\n\n"
        f"🔧 Tool: `{tool.upper()}`\n"
        f"🎯 Target: `{target}`\n"
        f"⚙️ Command/Info: `{preview_text}`\n\n"
        "Apakah data sudah benar?",
        reply_markup=reply_markup,
        parse_mode="Markdown"
    )
    return CONFIRM_SCAN

async def cancel_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    await query.edit_message_text("🚫 Dibatalkan. Ketik /start untuk kembali ke menu.")
    return ConversationHandler.END

async def execute_scan_logic(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    tool = context.user_data["tool"]
    target = context.user_data["target"]
    user_id = update.effective_user.id
    
    scan_id = db.create_scan(user_id, tool, target)
    
    await query.edit_message_text(
        f"🚀 Scan #{scan_id} Dimulai!\n"
        f"Target: `{target}`\n"
        "Hasil akan dikirim secara bertahap.",
        parse_mode="Markdown"
    )
    
    # Jalankan background task
    asyncio.create_task(
        process_scan_request(context.application, user_id, scan_id, tool, target)
    )
    
    return ConversationHandler.END

async def process_scan_request(app, user_id, scan_id, tool, target):
    """Menangani logika eksekusi tool"""
    
    # Tentukan urutan tools
    tasks = []
    if tool == "all":
        # Urutan logis: Info Gathering -> Discovery -> Active Scan
        tasks = ["whois", "dns", "subfinder", "nmap", "dirsearch"]
    else:
        tasks = [tool]
        
    db.update_scan_status(scan_id, "running")

    for current_tool in tasks:
        # Notifikasi progress (hanya jika mode All)
        if tool == "all":
            await app.bot.send_message(
                chat_id=user_id,
                text=f"⏳ Menjalankan: {current_tool.upper()}...",
                parse_mode="Markdown"
            )

        filename = f"{current_tool}_{scan_id}_{int(datetime.datetime.now().timestamp())}.txt"
        filepath = os.path.join(RESULTS_DIR, filename)
        
        success = False
        error_msg = ""
        
        try:
            # Routing logika tool
            if current_tool == "nmap":
                success, error_msg = await ScanManager.run_nmap(target, filepath)
            elif current_tool == "subfinder":
                success, error_msg = await ScanManager.run_subfinder(target, filepath)
            elif current_tool == "dirsearch":
                success, error_msg = await ScanManager.run_dirsearch(target, filepath)
            elif current_tool == "dns":
                success, error_msg = await ScanManager.run_dns(target, filepath)
            elif current_tool == "whois":
                # SEKARANG MENGGUNAKAN CLI
                success, error_msg = await ScanManager.run_whois(target, filepath)
                
            if success:
                # Baca preview hasil
                snippet = "Result is empty."
                if os.path.exists(filepath):
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        snippet = content[:800] + "..." if len(content) > 800 else content

                await app.bot.send_message(
                    chat_id=user_id,
                    text=f"✅ {current_tool.upper()} Selesai!\n\nPreview:\n```{snippet}```",
                    parse_mode="Markdown"
                )
                if os.path.exists(filepath):
                    await app.bot.send_document(chat_id=user_id, document=open(filepath, 'rb'))
            else:
                await app.bot.send_message(
                    chat_id=user_id, 
                    text=f"❌ {current_tool.upper()} Gagal.\nError: {error_msg}"
                )

        except Exception as e:
            logger.error(f"Error executing {current_tool}: {e}")
            await app.bot.send_message(chat_id=user_id, text=f"⚠️ Error internal pada {current_tool}.")

    db.update_scan_status(scan_id, "completed")
    await app.bot.send_message(chat_id=user_id, text=f"🏁 Sesi Scan #{scan_id} Selesai.")

# ==========================================
# 5. MAIN ENTRY POINT
# ==========================================
def main():
    application = Application.builder().token(TOKEN).build()

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("start", start)],
        states={
            SELECT_TOOL: [CallbackQueryHandler(select_tool)],
            GET_TARGET: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_target)],
            CONFIRM_SCAN: [
                CallbackQueryHandler(execute_scan_logic, pattern="^confirm$"),
                CallbackQueryHandler(cancel_scan, pattern="^cancel$"),
            ],
        },
        fallbacks=[CommandHandler("start", start)],
        per_message=False # <--- FIX UNTUK MENGHILANGKAN WARNING
    )

    application.add_handler(conv_handler)

    print("🤖 Bot is running with CLI Whois...")
    application.run_polling()

if __name__ == "__main__":
    main()
