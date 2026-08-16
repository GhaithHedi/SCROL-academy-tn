# -*- coding: utf-8 -*-
"""
أكاديمية SCROL — SCROL Academy
Local demo e-learning platform (Math & Physics, 7ème de base → Bac, Tunisia).
Run:  pip install flask   →   python app.py   →   http://localhost:5000
"""
import os
import re
import secrets
import sqlite3
import datetime as dt
import threading
import time
from functools import wraps

from flask import (Flask, g, render_template, request, redirect,
                   url_for, session, flash, abort, jsonify, Response)
from werkzeug.security import generate_password_hash, check_password_hash

try:
    import anthropic
except ImportError:
    anthropic = None

try:
    import requests
except ImportError:
    requests = None

try:
    from fpdf import FPDF
    import arabic_reshaper
    from bidi.algorithm import get_display
except ImportError:
    FPDF = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ARABIC_FONT_PATH = os.path.join(BASE_DIR, "static", "fonts", "NotoNaskhArabic-Regular.ttf")


def load_dotenv(path):
    """Tiny .env loader (KEY=VALUE per line) — avoids adding a dependency
    just to keep secrets out of source control."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


load_dotenv(os.path.join(BASE_DIR, ".env"))

DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "academy.db"))

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "scrol-local-demo-change-me")

# ----------------------------------------------------------------------------
# AI tutor (Anthropic API) — set ANTHROPIC_API_KEY in .env (see .env, kept out
# of version control) to enable it. Without a key the chat widget still
# renders but replies with a friendly "not configured yet" message.
# ----------------------------------------------------------------------------
AI_MODEL = "claude-sonnet-5"
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
ai_client = (anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
             if anthropic and ANTHROPIC_API_KEY else None)

# ----------------------------------------------------------------------------
# Email verification (Brevo) + bot protection (Cloudflare Turnstile) —
# set BREVO_API_KEY / TURNSTILE_SECRET_KEY in .env. TURNSTILE_SITE_KEY is
# public (embedded in the registration page HTML), not a secret.
# ----------------------------------------------------------------------------
BREVO_API_KEY = os.environ.get("BREVO_API_KEY")
BREVO_SENDER_EMAIL = os.environ.get("BREVO_SENDER_EMAIL", "scrolacademy@gmail.com")
BREVO_SENDER_NAME = os.environ.get("BREVO_SENDER_NAME", "SCROL Academy")
TURNSTILE_SITE_KEY = os.environ.get("TURNSTILE_SITE_KEY", "")
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY")
VERIFY_CODE_TTL_MIN = 15
VERIFY_RESEND_COOLDOWN_SEC = 60


def generate_verify_code():
    return f"{secrets.randbelow(1_000_000):06d}"


def _send_code_email(to_email, to_name, code, subject, intro_html, log_label):
    """Send a 6-digit-code email via the Brevo transactional API.
    Returns True on success; failures are logged but never raised, so a
    down email provider doesn't break registration/login/reset."""
    if not BREVO_API_KEY or not requests:
        print(f" * [email disabled] {log_label} for {to_email}: {code}")
        return False
    try:
        resp = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={"api-key": BREVO_API_KEY, "Content-Type": "application/json"},
            json={
                "sender": {"name": BREVO_SENDER_NAME, "email": BREVO_SENDER_EMAIL},
                "to": [{"email": to_email, "name": to_name}],
                "subject": subject,
                "htmlContent": (
                    f"<div dir='rtl' style='font-family:sans-serif;font-size:16px;line-height:1.7'>"
                    f"<p>مرحبًا {to_name}،</p>"
                    f"<p>{intro_html}</p>"
                    f"<p style='font-size:32px;font-weight:bold;letter-spacing:6px'>{code}</p>"
                    f"<p>هذا الرمز صالح لمدة {VERIFY_CODE_TTL_MIN} دقيقة. "
                    f"إن لم تطلب هذا الرمز يمكنك تجاهل هذه الرسالة.</p></div>"
                ),
            },
            timeout=10,
        )
        if resp.status_code >= 300:
            print(f" * [email error] Brevo {resp.status_code}: {resp.text[:300]}")
            return False
        return True
    except requests.RequestException as e:
        print(f" * [email error] {e}")
        return False


def send_verification_email(to_email, to_name, code):
    return _send_code_email(
        to_email, to_name, code,
        subject=f"{code} — رمز التحقق من بريدك | أكاديمية SCROL",
        intro_html="رمز التحقق من بريدك الإلكتروني في أكاديمية SCROL هو:",
        log_label="verification code")


def send_reset_email(to_email, to_name, code):
    return _send_code_email(
        to_email, to_name, code,
        subject=f"{code} — رمز استعادة كلمة المرور | أكاديمية SCROL",
        intro_html="رمز استعادة كلمة المرور لحسابك في أكاديمية SCROL هو:",
        log_label="password reset code")


def verify_turnstile(token, remote_ip=None):
    """Validate a Cloudflare Turnstile response token server-side.
    Fails closed (rejects) if misconfigured or unreachable — a broken
    CAPTCHA should never silently let registrations through unchecked."""
    if not TURNSTILE_SECRET_KEY or not requests:
        return False
    if not token:
        return False
    try:
        payload = {"secret": TURNSTILE_SECRET_KEY, "response": token}
        if remote_ip:
            payload["remoteip"] = remote_ip
        resp = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data=payload, timeout=10)
        return bool(resp.json().get("success"))
    except requests.RequestException as e:
        print(f" * [turnstile error] {e}")
        return False

# ----------------------------------------------------------------------------
# Static configuration
# ----------------------------------------------------------------------------
LEVEL_NAMES = {
    "7b":  {"ar": "السابعة أساسي",   "fr": "7ème année de base"},
    "8b":  {"ar": "الثامنة أساسي",   "fr": "8ème année de base"},
    "9b":  {"ar": "التاسعة أساسي",   "fr": "9ème année de base"},
    "1s":  {"ar": "الأولى ثانوي",    "fr": "1ère année secondaire"},
    "2s":  {"ar": "الثانية ثانوي",   "fr": "2ème année secondaire"},
    "3s":  {"ar": "الثالثة ثانوي",   "fr": "3ème année secondaire"},
    "bac": {"ar": "البكالوريا",      "fr": "Baccalauréat"},
}
LEVEL_CODES = list(LEVEL_NAMES)

SUBJECT_NAMES = {
    "math": {"ar": "رياضيات", "fr": "Mathématiques"},
    "phys": {"ar": "فيزياء",  "fr": "Physique"},
}
SUBJECT_CODES = list(SUBJECT_NAMES)

PLAN_INFO = {
    "monthly": {"price_subject": 29, "price_all": 45, "months": 1,
                "name": {"ar": "العرض الشهري", "fr": "Offre mensuelle"},
                "desc": {"ar": "اشتراك مرن يتجدّد شهريًا",
                         "fr": "Abonnement flexible, renouvelé chaque mois"},
                "features": {
                    "ar": ["دروس فيديو حسب باقتك", "الحصص المباشرة الأسبوعية",
                           "ملخصات وتمارين قابلة للتحميل", "إلغاء في أي وقت"],
                    "fr": ["Cours vidéo selon votre pack",
                           "Sessions en direct hebdomadaires",
                           "Résumés et exercices téléchargeables",
                           "Annulation à tout moment"]}},
    "term":    {"price_subject": 69, "price_all": 109, "months": 3,
                "name": {"ar": "العرض الثلاثي", "fr": "Offre trimestrielle"},
                "desc": {"ar": "ثلاثة أشهر كاملة لكل ثلاثي دراسي",
                         "fr": "Trois mois complets pour chaque trimestre scolaire"},
                "features": {
                    "ar": ["كل مزايا العرض الشهري", "توفير مقارنة بالاشتراك الشهري",
                           "مراجعة مركّزة قبل الامتحانات", "أولوية في أسئلة الحصص المباشرة"],
                    "fr": ["Tous les avantages de l'offre mensuelle",
                           "Économie par rapport au mensuel",
                           "Révision intensive avant les examens",
                           "Priorité pour les questions en direct"]}},
    "year":    {"price_subject": 179, "price_all": 259, "months": 9,
                "name": {"ar": "السنوي (السنة الدراسية)", "fr": "Annuel (année scolaire)"},
                "desc": {"ar": "تسعة أشهر دراسية كاملة… براحة بال",
                         "fr": "Neuf mois d'école complets… en toute tranquillité"},
                "features": {
                    "ar": ["كل مزايا العرض الثلاثي", "أفضل توفير على المدى الطويل",
                           "مرافقة حتى ليلة الامتحان", "شهادة إتمام في آخر السنة"],
                    "fr": ["Tous les avantages de l'offre trimestrielle",
                           "La meilleure économie sur la durée",
                           "Accompagnement jusqu'à la veille de l'examen",
                           "Certificat de fin d'année"]}},
}

PAY_METHOD_NAMES = {
    "d17":      {"ar": "D17 — البريد التونسي", "fr": "D17 — La Poste Tunisienne"},
    "flouci":   {"ar": "تطبيق Flouci",          "fr": "Application Flouci"},
    "virement": {"ar": "تحويل بنكي",            "fr": "Virement bancaire"},
    "mandat":   {"ar": "حوالة بريدية",          "fr": "Mandat postal"},
}
PAY_METHOD_CODES = list(PAY_METHOD_NAMES)

# ----------------------------------------------------------------------------
# Database helpers
# ----------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA journal_mode = WAL")
        g.db.execute("PRAGMA synchronous = NORMAL")
        g.db.execute("PRAGMA busy_timeout = 5000")
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query(sql, args=(), one=False):
    cur = get_db().execute(sql, args)
    rows = cur.fetchall()
    cur.close()
    return (rows[0] if rows else None) if one else rows


def execute(sql, args=()):
    db = get_db()
    cur = db.execute(sql, args)
    db.commit()
    lid = cur.lastrowid
    cur.close()
    return lid


SCHEMA = """
CREATE TABLE IF NOT EXISTS levels (
    code       TEXT PRIMARY KEY,
    name_ar    TEXT NOT NULL,
    name_fr    TEXT NOT NULL,
    sort_order INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS subjects (
    code       TEXT PRIMARY KEY,
    name_ar    TEXT NOT NULL,
    name_fr    TEXT NOT NULL,
    color      TEXT NOT NULL DEFAULT '#2350D8',
    glyph      TEXT NOT NULL DEFAULT '📘',
    sort_order INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    phone         TEXT,
    password_hash TEXT NOT NULL,
    level_code    TEXT,
    role          TEXT NOT NULL DEFAULT 'student',
    sub_plan      TEXT,
    sub_until     TEXT,
    sub_subject   TEXT,
    email_verified INTEGER NOT NULL DEFAULT 1,
    verify_code    TEXT,
    verify_expires TEXT,
    verify_sent_at TEXT,
    reset_code     TEXT,
    reset_expires  TEXT,
    reset_sent_at  TEXT,
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS courses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    level_code  TEXT NOT NULL,
    subject     TEXT NOT NULL,
    title       TEXT NOT NULL,
    description TEXT,
    position    INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS lessons (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id    INTEGER NOT NULL REFERENCES courses(id) ON DELETE CASCADE,
    title        TEXT NOT NULL,
    description  TEXT,
    youtube_id   TEXT NOT NULL,
    duration_min INTEGER DEFAULT 20,
    is_free      INTEGER DEFAULT 0,
    position     INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS live_sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    title        TEXT NOT NULL,
    subject      TEXT NOT NULL,
    level_code   TEXT NOT NULL,
    teacher      TEXT,
    starts_at    TEXT NOT NULL,
    duration_min INTEGER DEFAULT 60,
    meet_url     TEXT,
    reminded_at  TEXT
);
CREATE TABLE IF NOT EXISTS block_reminders (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    block_id   INTEGER NOT NULL REFERENCES study_blocks(id) ON DELETE CASCADE,
    the_date   TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(block_id, the_date)
);
CREATE TABLE IF NOT EXISTS payments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    plan       TEXT NOT NULL,
    subject    TEXT,
    amount     INTEGER NOT NULL,
    method     TEXT NOT NULL,
    reference  TEXT,
    status     TEXT NOT NULL DEFAULT 'pending',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS lesson_progress (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    lesson_id    INTEGER NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,
    completed_at TEXT NOT NULL,
    UNIQUE(user_id, lesson_id)
);
CREATE TABLE IF NOT EXISTS lesson_views (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    lesson_id  INTEGER NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,
    viewed_at  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS lesson_watch (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    lesson_id       INTEGER NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,
    watched_seconds INTEGER NOT NULL DEFAULT 0,
    updated_at      TEXT NOT NULL,
    UNIQUE(user_id, lesson_id)
);
CREATE TABLE IF NOT EXISTS lesson_notes (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    lesson_id     INTEGER NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,
    timestamp_sec INTEGER NOT NULL DEFAULT 0,
    body          TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS study_blocks (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    the_date   TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time   TEXT NOT NULL,
    subject    TEXT,
    note       TEXT,
    repeat     TEXT NOT NULL DEFAULT 'none',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS notifications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title      TEXT NOT NULL,
    body       TEXT NOT NULL,
    created_at TEXT NOT NULL,
    read_at    TEXT
);
CREATE TABLE IF NOT EXISTS chat_messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    level_code TEXT NOT NULL,
    channel    TEXT NOT NULL DEFAULT 'general',
    author_id  INTEGER NOT NULL REFERENCES users(id),
    body       TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chat_reactions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL REFERENCES chat_messages(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    emoji      TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(message_id, user_id)
);
CREATE TABLE IF NOT EXISTS ai_usage (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    the_day TEXT NOT NULL,
    count   INTEGER NOT NULL DEFAULT 0,
    UNIQUE(user_id, the_day)
);
CREATE TABLE IF NOT EXISTS lesson_resources (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    lesson_id INTEGER NOT NULL REFERENCES lessons(id) ON DELETE CASCADE,
    title     TEXT NOT NULL,
    url       TEXT NOT NULL,
    position  INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS quizzes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    course_id  INTEGER NOT NULL UNIQUE REFERENCES courses(id) ON DELETE CASCADE,
    title      TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS quiz_questions (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    quiz_id  INTEGER NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
    question TEXT NOT NULL,
    position INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS quiz_options (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    question_id INTEGER NOT NULL REFERENCES quiz_questions(id) ON DELETE CASCADE,
    option_text TEXT NOT NULL,
    is_correct  INTEGER NOT NULL DEFAULT 0,
    position    INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS quiz_attempts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    quiz_id    INTEGER NOT NULL REFERENCES quizzes(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    score      INTEGER NOT NULL,
    total      INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
"""

REACTION_EMOJIS = ["👍", "❤️", "🎉", "🔥"]
AI_DAILY_LIMIT = 30

# ----------------------------------------------------------------------------
# Seed data — chapter titles follow the spirit of the Tunisian official
# programme. Placeholder video: YouTube's public API demo clip (M7lc1UVf-VE);
# replace every youtube_id with your own lesson videos from the admin panel.
# ----------------------------------------------------------------------------
PLACEHOLDER_VIDEO = "M7lc1UVf-VE"

def _ch(ar, fr):
    return {"ar": ar, "fr": fr}


MATH_CHAPTERS = {
    "7b":  [_ch("الأعداد الطبيعية والعمليات عليها", "Les nombres naturels et leurs opérations"),
            _ch("الكسور", "Les fractions"),
            _ch("الأعداد النسبية", "Les nombres relatifs"),
            _ch("الزوايا والمستقيمات", "Les angles et les droites"),
            _ch("التناظر المحوري", "La symétrie axiale")],
    "8b":  [_ch("القوى", "Les puissances"),
            _ch("الحساب الحرفي والنشر", "Le calcul littéral et le développement"),
            _ch("المعادلات ذات مجهول واحد", "Les équations à une inconnue"),
            _ch("مبرهنة فيثاغرس", "Le théorème de Pythagore"),
            _ch("المستقيمات الهامة في المثلث", "Les droites remarquables du triangle")],
    "9b":  [_ch("الجذور المربعة", "Les racines carrées"),
            _ch("النشر والتفكيك", "Développement et factorisation"),
            _ch("المعادلات والمتراجحات", "Équations et inéquations"),
            _ch("مبرهنة طالس", "Le théorème de Thalès"),
            _ch("حساب المثلثات في المثلث القائم", "Trigonométrie dans le triangle rectangle"),
            _ch("الدوال الخطية", "Les fonctions linéaires")],
    "1s":  [_ch("الأنشطة العددية", "Activités numériques"),
            _ch("الأنشطة الجبرية", "Activités algébriques"),
            _ch("الدوال والتمثيل البياني", "Fonctions et représentation graphique"),
            _ch("الهندسة التحليلية", "Géométrie analytique"),
            _ch("الإحصاء", "Statistiques")],
    "2s":  [_ch("الدوال المرجعية", "Fonctions de référence"),
            _ch("المعادلات والمتراجحات من الدرجة الثانية", "Équations et inéquations du second degré"),
            _ch("الحساب المتجهي", "Calcul vectoriel"),
            _ch("الهندسة في الفضاء", "Géométrie dans l'espace"),
            _ch("المتتاليات العددية", "Suites numériques")],
    "3s":  [_ch("الاشتقاق وتطبيقاته", "La dérivation et ses applications"),
            _ch("دراسة الدوال", "Étude de fonctions"),
            _ch("المتتاليات", "Les suites"),
            _ch("الحساب المثلثي", "Le calcul trigonométrique"),
            _ch("الجداء السلمي", "Le produit scalaire"),
            _ch("الإحصاء والاحتمالات", "Statistiques et probabilités")],
    "bac": [_ch("النهايات والاتصال", "Limites et continuité"),
            _ch("الاشتقاق ودراسة الدوال", "Dérivation et étude de fonctions"),
            _ch("الدوال الأسية واللوغاريتمية", "Fonctions exponentielles et logarithmiques"),
            _ch("الأعداد العقدية", "Les nombres complexes"),
            _ch("الاحتمالات", "Les probabilités"),
            _ch("الحساب التكاملي", "Le calcul intégral")],
}

PHYS_CHAPTERS = {
    "7b":  [_ch("المادة وحالاتها", "La matière et ses états"),
            _ch("قياس الحجم والكتلة", "Mesure du volume et de la masse"),
            _ch("الحرارة ودرجة الحرارة", "La chaleur et la température"),
            _ch("الدارة الكهربائية البسيطة", "Le circuit électrique simple")],
    "8b":  [_ch("التيار والتوتر الكهربائي", "Le courant et la tension électrique"),
            _ch("الضوء وانتشاره", "La lumière et sa propagation"),
            _ch("القوى والتأثيرات", "Les forces et leurs effets"),
            _ch("الضغط", "La pression")],
    "9b":  [_ch("الكتلة الحجمية", "La masse volumique"),
            _ch("الحركة والسكون", "Le mouvement et le repos"),
            _ch("التركيب والتفكيك الكيميائي", "Synthèse et décomposition chimique"),
            _ch("الدارات الكهربائية: التوالي والتوازي", "Circuits électriques : série et dérivation")],
    "1s":  [_ch("بنية المادة والذرة", "Structure de la matière et de l'atome"),
            _ch("التيار الكهربائي المستمر", "Le courant électrique continu"),
            _ch("الضوء والعدسات", "La lumière et les lentilles"),
            _ch("المحاليل المائية", "Les solutions aqueuses")],
    "2s":  [_ch("كمية المادة والمول", "Quantité de matière et la mole"),
            _ch("التفاعل الكيميائي والمعادلة", "Réaction chimique et équation"),
            _ch("القوى والتوازن", "Forces et équilibre"),
            _ch("الطاقة وأشكالها", "L'énergie et ses formes"),
            _ch("الضغط في السوائل والغازات", "Pression dans les liquides et les gaz")],
    "3s":  [_ch("الحركة: السرعة والتسارع", "Le mouvement : vitesse et accélération"),
            _ch("قوانين نيوتن", "Les lois de Newton"),
            _ch("الشغل والطاقة الحركية", "Le travail et l'énergie cinétique"),
            _ch("التكهرب والتيار المستمر", "Électrisation et courant continu"),
            _ch("المحاليل الحمضية والقاعدية", "Solutions acides et basiques")],
    "bac": [_ch("الحركية الكيميائية", "Cinétique chimique"),
            _ch("الأحماض والقواعد", "Acides et bases"),
            _ch("ثنائي القطب RC", "Dipôle RC"),
            _ch("ثنائي القطب RL", "Dipôle RL"),
            _ch("الذبذبات الكهربائية", "Oscillations électriques"),
            _ch("الموجات", "Les ondes"),
            _ch("الفيزياء النووية", "Physique nucléaire")],
}

FIRST_NAMES_NOTE = {
    "ar": "أوّل درس في كل محور مجاني — شاهده قبل الاشتراك.",
    "fr": "Le premier cours de chaque chapitre est gratuit — regardez-le avant de vous abonner.",
}


def seed_db(db):
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    # --- accounts -----------------------------------------------------------
    db.execute(
        "INSERT INTO users(name,email,phone,password_hash,level_code,role,created_at)"
        " VALUES(?,?,?,?,?,?,?)",
        ("مدير المنصة", "admin@scrol.tn", "+216 00 000 000",
         generate_password_hash("admin123"), "bac", "admin", now))
    db.execute(
        "INSERT INTO users(name,email,phone,password_hash,level_code,role,created_at)"
        " VALUES(?,?,?,?,?,?,?)",
        ("أحمد التجريبي", "ahmed@test.tn", "+216 11 111 111",
         generate_password_hash("123456"), "9b", "student", now))
    sub_until = (dt.date.today() + dt.timedelta(days=90)).isoformat()
    db.execute(
        "INSERT INTO users(name,email,phone,password_hash,level_code,role,"
        "sub_plan,sub_until,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
        ("مريم المشتركة", "mariem@test.tn", "+216 22 222 222",
         generate_password_hash("123456"), "bac", "student",
         "term", sub_until, now))
    for name, email, level in (
        ("سامي التجريبي", "prof1@scrol.tn", "9b"),
        ("ليلى التجريبية", "prof2@scrol.tn", "1s"),
        ("كريم التجريبي", "prof3@scrol.tn", "bac"),
    ):
        db.execute(
            "INSERT INTO users(name,email,password_hash,level_code,role,created_at)"
            " VALUES(?,?,?,?,?,?)",
            (name, email, generate_password_hash("prof123"), level, "prof", now))

    # --- courses & lessons --------------------------------------------------
    # Stored titles/descriptions are Arabic (source data); the French display
    # is computed live from level/subject/chapter position (see course_title,
    # course_description, lesson_title, lesson_description below), so this
    # seed data never needs to carry a French copy itself.
    def add_course(level, subject, chapters):
        subj_name = SUBJECT_NAMES[subject]["ar"]
        lvl_name = LEVEL_NAMES[level]["ar"]
        cur = db.execute(
            "INSERT INTO courses(level_code,subject,title,description,position)"
            " VALUES(?,?,?,?,?)",
            (level, subject,
             f"{subj_name} — {lvl_name}",
             f"محاور {subj_name} لمستوى {lvl_name} وفق البرنامج الرسمي التونسي، "
             f"بشرح مبسّط وتمارين تطبيقية. {FIRST_NAMES_NOTE['ar']}",
             0))
        cid = cur.lastrowid
        for i, chap in enumerate(chapters):
            db.execute(
                "INSERT INTO lessons(course_id,title,description,youtube_id,"
                "duration_min,is_free,position) VALUES(?,?,?,?,?,?,?)",
                (cid, chap["ar"],
                 f"شرح مفصّل لمحور «{chap['ar']}» مع أمثلة وتمارين مصحّحة.",
                 PLACEHOLDER_VIDEO, 18 + (i * 4) % 21,
                 1 if i == 0 else 0, i))

    for level in LEVEL_CODES:
        add_course(level, "math", MATH_CHAPTERS[level])
        add_course(level, "phys", PHYS_CHAPTERS[level])

    # --- upcoming live sessions --------------------------------------------
    base = dt.datetime.now().replace(minute=0, second=0, microsecond=0)
    lives = [
        ("مراجعة عامة: الدوال",            "math", "bac", "أ. سامي بن عمر",
         base + dt.timedelta(days=1, hours=3), 90),
        ("حصة تمارين: قوانين نيوتن",       "phys", "3s",  "أ. رانية القاسمي",
         base + dt.timedelta(days=2, hours=5), 60),
        ("تصحيح فرض مراقبة: المعادلات",     "math", "9b",  "أ. سامي بن عمر",
         base + dt.timedelta(days=4, hours=2), 60),
        ("تجارب مباشرة: الدارة الكهربائية", "phys", "7b",  "أ. رانية القاسمي",
         base + dt.timedelta(days=6, hours=4), 45),
        ("ليلة الامتحان: أعداد عقدية",      "math", "bac", "أ. سامي بن عمر",
         base + dt.timedelta(days=9, hours=6), 120),
    ]
    for title, subj, lvl, teacher, when, dur in lives:
        db.execute(
            "INSERT INTO live_sessions(title,subject,level_code,teacher,"
            "starts_at,duration_min,meet_url) VALUES(?,?,?,?,?,?,?)",
            (title, subj, lvl, teacher, when.strftime("%Y-%m-%d %H:%M"),
             dur, "https://meet.google.com/xxx-demo-link"))
    db.commit()


def init_db():
    first_time = not os.path.exists(DB_PATH)
    db = sqlite3.connect(DB_PATH)
    db.executescript(SCHEMA)
    sb_cols = [r[1] for r in db.execute("PRAGMA table_info(study_blocks)")]
    if "repeat" not in sb_cols:
        db.execute("ALTER TABLE study_blocks ADD COLUMN repeat TEXT NOT NULL DEFAULT 'none'")
        db.commit()
    cm_cols = [r[1] for r in db.execute("PRAGMA table_info(chat_messages)")]
    if "channel" not in cm_cols:
        db.execute("ALTER TABLE chat_messages ADD COLUMN channel TEXT NOT NULL DEFAULT 'general'")
        db.commit()
    ls_cols = [r[1] for r in db.execute("PRAGMA table_info(live_sessions)")]
    if "reminded_at" not in ls_cols:
        db.execute("ALTER TABLE live_sessions ADD COLUMN reminded_at TEXT")
        db.commit()
    u_cols = [r[1] for r in db.execute("PRAGMA table_info(users)")]
    if "sub_subject" not in u_cols:
        db.execute("ALTER TABLE users ADD COLUMN sub_subject TEXT")
        db.commit()
    pm_cols = [r[1] for r in db.execute("PRAGMA table_info(payments)")]
    if "subject" not in pm_cols:
        db.execute("ALTER TABLE payments ADD COLUMN subject TEXT")
        db.commit()
    if "email_verified" not in u_cols:
        db.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1")
        db.execute("ALTER TABLE users ADD COLUMN verify_code TEXT")
        db.execute("ALTER TABLE users ADD COLUMN verify_expires TEXT")
        db.execute("ALTER TABLE users ADD COLUMN verify_sent_at TEXT")
        db.commit()
    if "reset_code" not in u_cols:
        db.execute("ALTER TABLE users ADD COLUMN reset_code TEXT")
        db.execute("ALTER TABLE users ADD COLUMN reset_expires TEXT")
        db.execute("ALTER TABLE users ADD COLUMN reset_sent_at TEXT")
        db.commit()
    if db.execute("SELECT COUNT(*) FROM levels").fetchone()[0] == 0:
        for i, code in enumerate(LEVEL_CODES):
            names = LEVEL_NAMES[code]
            db.execute("INSERT INTO levels(code,name_ar,name_fr,sort_order) VALUES(?,?,?,?)",
                      (code, names["ar"], names["fr"], i))
        db.commit()
    if db.execute("SELECT COUNT(*) FROM subjects").fetchone()[0] == 0:
        db.execute("INSERT INTO subjects(code,name_ar,name_fr,color,glyph,sort_order) "
                   "VALUES('math','رياضيات','Mathématiques','#2350D8','ƒ(x)',0)")
        db.execute("INSERT INTO subjects(code,name_ar,name_fr,color,glyph,sort_order) "
                   "VALUES('phys','فيزياء','Physique','#E23D3A','⚡',1)")
        db.commit()
    if first_time:
        seed_db(db)
        print(" * Database created and seeded → academy.db")
    db.close()


# ----------------------------------------------------------------------------
# Auth helpers
# ----------------------------------------------------------------------------
@app.before_request
def load_user():
    g.user = None
    uid = session.get("uid")
    if uid:
        g.user = query("SELECT * FROM users WHERE id=?", (uid,), one=True)
        if g.user is None:
            session.clear()


def is_subscribed(user=None):
    user = user if user is not None else g.user
    if not user:
        return False
    if user["role"] in ("admin", "prof"):
        return True
    if not user["sub_until"]:
        return False
    try:
        return dt.date.fromisoformat(user["sub_until"]) >= dt.date.today()
    except ValueError:
        return False


def has_subject_access(subject, user=None):
    """Like is_subscribed(), but also checks the plan's subject scope —
    a single-subject pack (users.sub_subject set) only unlocks that one
    subject; an all-subjects pack (sub_subject NULL) unlocks everything."""
    user = user if user is not None else g.user
    if not user:
        return False
    if user["role"] in ("admin", "prof"):
        return True
    if not user["sub_until"]:
        return False
    try:
        if dt.date.fromisoformat(user["sub_until"]) < dt.date.today():
            return False
    except ValueError:
        return False
    return not user["sub_subject"] or user["sub_subject"] == subject


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if g.user is None:
            flash(t("flash.login_required"), "warn")
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if g.user is None or g.user["role"] != "admin":
            abort(403)
        return view(*a, **kw)
    return wrapped


def staff_required(view):
    """Admin or teacher (prof) — used for the content/live-sessions/chat routes
    a teacher is allowed to reach, scoped to their own level by the view itself."""
    @wraps(view)
    def wrapped(*a, **kw):
        if g.user is None or g.user["role"] not in ("admin", "prof"):
            abort(403)
        return view(*a, **kw)
    return wrapped


def enforce_prof_scope(course_id):
    """Abort 403 if the current user is a teacher and this course isn't in
    their assigned level. Admins are never restricted."""
    if g.user["role"] != "prof":
        return
    course = query("SELECT level_code FROM courses WHERE id=?", (course_id,), one=True)
    if not course or course["level_code"] != g.user["level_code"]:
        abort(403)


# ----------------------------------------------------------------------------
# i18n — Arabic (default) / French. No JS framework or build step, so
# translation is a plain dict keyed by short strings, looked up per-request
# from the session language. Official (seeded) course/lesson titles are
# computed live from level+subject+chapter position rather than stored in
# French, since the DB only ever holds the Arabic seed text.
# ----------------------------------------------------------------------------
def get_lang():
    lang = session.get("lang", "ar")
    return lang if lang in ("ar", "fr") else "ar"


def get_theme():
    theme = session.get("theme", "light")
    return theme if theme in ("light", "dark") else "light"


def _levels_dict():
    if not hasattr(g, "_levels_cache"):
        g._levels_cache = {r["code"]: r for r in query("SELECT * FROM levels ORDER BY sort_order")}
    return g._levels_cache


def _subjects_dict():
    if not hasattr(g, "_subjects_cache"):
        g._subjects_cache = {r["code"]: r for r in query("SELECT * FROM subjects ORDER BY sort_order")}
    return g._subjects_cache


def all_level_codes():
    return list(_levels_dict().keys())


def all_subject_codes():
    return list(_subjects_dict().keys())


def level_name(code):
    row = _levels_dict().get(code)
    return (row["name_ar"] if get_lang() == "ar" else row["name_fr"]) if row else code


def subject_name(code):
    row = _subjects_dict().get(code)
    return (row["name_ar"] if get_lang() == "ar" else row["name_fr"]) if row else code


def pay_method_name(code):
    return PAY_METHOD_NAMES.get(code, {}).get(get_lang(), code)


def plan_info(code, subject=None):
    p = PLAN_INFO.get(code)
    if not p:
        return None
    lang = get_lang()
    price = p["price_subject"] if subject else p["price_all"]
    return {"name": p["name"][lang], "price": price, "months": p["months"],
            "desc": p["desc"][lang], "features": p["features"][lang],
            "subject": subject}


def chapter_entry(level, subject, position):
    src = MATH_CHAPTERS if subject == "math" else (PHYS_CHAPTERS if subject == "phys" else {})
    lst = src.get(level, [])
    return lst[position] if 0 <= position < len(lst) else None


def course_title(level, subject, stored_title):
    """French display title for the 14 official seeded courses; anything
    else (admin-added custom courses) falls back to whatever was stored."""
    if get_lang() == "fr":
        return f"{subject_name(subject)} — {level_name(level)}"
    return stored_title


def course_description(level, subject, stored_desc):
    if get_lang() == "fr":
        return (f"Chapitres de {subject_name(subject)} pour le niveau "
                f"{level_name(level)}, selon le programme officiel tunisien, "
                f"avec des explications simples et des exercices pratiques. "
                f"{FIRST_NAMES_NOTE['fr']}")
    return stored_desc


def lesson_title(level, subject, position, stored_title):
    if get_lang() == "fr":
        entry = chapter_entry(level, subject, position)
        if entry:
            return entry["fr"]
    return stored_title


def lesson_description(level, subject, position, stored_desc):
    if get_lang() == "fr":
        entry = chapter_entry(level, subject, position)
        if entry:
            return (f"Explication détaillée du chapitre « {entry['fr']} », "
                     "avec exemples et exercices corrigés.")
    return stored_desc


TR = {
    # nav / shared
    "nav.home": {"ar": "الرئيسية", "fr": "Accueil"},
    "nav.courses": {"ar": "الدروس", "fr": "Cours"},
    "nav.live": {"ar": "الحصص المباشرة", "fr": "Sessions en direct"},
    "nav.pricing": {"ar": "العروض", "fr": "Offres"},
    "nav.faq": {"ar": "الأسئلة الشائعة", "fr": "FAQ"},
    "nav.contact": {"ar": "تواصل معنا", "fr": "Contact"},
    "nav.login": {"ar": "تسجيل الدخول", "fr": "Connexion"},
    "nav.register": {"ar": "إنشاء حساب", "fr": "Créer un compte"},
    "nav.logout": {"ar": "خروج", "fr": "Déconnexion"},
    "nav.admin_panel": {"ar": "لوحة الإدارة", "fr": "Panneau admin"},

    # base.html — sidebar (student)
    "side.student_space": {"ar": "فضاء الطالب", "fr": "Espace élève"},
    "side.teacher_space": {"ar": "فضاء الأستاذ", "fr": "Espace enseignant"},
    "side.dashboard": {"ar": "لوحة القيادة", "fr": "Tableau de bord"},
    "side.plans": {"ar": "الباقات", "fr": "Offres"},
    "side.my_courses": {"ar": "دوراتي", "fr": "Mes cours"},
    "side.live_rooms": {"ar": "غرف البث المباشر", "fr": "Salles en direct"},
    "side.subscribers_only": {"ar": "متاح للمشتركين", "fr": "Réservé aux abonnés"},
    "side.portfolio": {"ar": "المحفظة", "fr": "Mon espace"},
    "side.group_chat": {"ar": "الدردشة", "fr": "Chat"},
    "side.schedule": {"ar": "الجدول", "fr": "Planning"},
    "side.leaderboard": {"ar": "لوحة الصدارة", "fr": "Classement"},
    "side.analytics": {"ar": "التحليلات ورادار الباك", "fr": "Analyses et radar du Bac"},
    "side.coming_soon": {"ar": "قريبًا", "fr": "Bientôt"},
    "side.support": {"ar": "الدعم", "fr": "Support"},
    "side.profile": {"ar": "ملفي الشخصي", "fr": "Mon profil"},
    "side.settings": {"ar": "الإعدادات", "fr": "Paramètres"},

    # settings.html
    "st.title": {"ar": "الإعدادات", "fr": "Paramètres"},
    "st.eyebrow": {"ar": "حسابي", "fr": "Mon compte"},
    "st.h1": {"ar": "⚙️ الإعدادات", "fr": "⚙️ Paramètres"},
    "st.sub": {"ar": "خصّص شكل المنصّة وتحكّم في حسابك.", "fr": "Personnalisez l'apparence et gérez votre compte."},
    "st.appearance": {"ar": "المظهر", "fr": "Apparence"},
    "st.appearance_sub": {"ar": "اختر بين الوضع الفاتح والوضع الداكن لكامل المنصّة.",
                           "fr": "Choisissez entre le mode clair et le mode sombre pour toute la plateforme."},
    "st.theme_light": {"ar": "☀️ فاتح", "fr": "☀️ Clair"},
    "st.theme_dark": {"ar": "🌙 داكن", "fr": "🌙 Sombre"},
    "st.language": {"ar": "اللغة", "fr": "Langue"},
    "st.language_sub": {"ar": "لغة عرض المنصّة.", "fr": "Langue d'affichage de la plateforme."},
    "st.account": {"ar": "الحساب", "fr": "Compte"},
    "st.account_sub": {"ar": "أنهِ جلستك الحالية على هذا الجهاز.", "fr": "Terminez votre session actuelle sur cet appareil."},

    # base.html — sidebar (admin)
    "side.admin_panel_label": {"ar": "لوحة الإدارة", "fr": "Panneau admin"},
    "side.overview": {"ar": "نظرة عامة", "fr": "Vue d'ensemble"},
    "side.levels": {"ar": "المستويات", "fr": "Niveaux"},
    "side.taxonomy": {"ar": "الفئات", "fr": "Catégories"},
    "side.payments": {"ar": "المدفوعات", "fr": "Paiements"},
    "side.users": {"ar": "المستخدمون", "fr": "Utilisateurs"},
    "side.teachers": {"ar": "الأساتذة", "fr": "Enseignants"},
    "side.content": {"ar": "المحتوى", "fr": "Contenu"},
    "side.lives": {"ar": "الحصص المباشرة", "fr": "Sessions en direct"},
    "side.community": {"ar": "المجتمع", "fr": "Communauté"},
    "side.chat": {"ar": "الدردشة", "fr": "Chat"},
    "side.notifications": {"ar": "الإشعارات", "fr": "Notifications"},

    # base.html — topbar
    "top.open_menu": {"ar": "فتح القائمة", "fr": "Ouvrir le menu"},
    "top.admin_short": {"ar": "الإدارة", "fr": "Admin"},
    "top.student_prefix": {"ar": "فضاء", "fr": "Espace de"},
    "top.teacher_prefix": {"ar": "أ.", "fr": "Prof."},
    "top.notifications": {"ar": "الإشعارات", "fr": "Notifications"},
    "top.logout": {"ar": "خروج", "fr": "Déconnexion"},

    # base.html — guest header
    "guest.admin_panel": {"ar": "لوحة الإدارة", "fr": "Panneau admin"},

    # base.html — footer
    "footer.tagline": {"ar": "منصة تونسية لتعليم الرياضيات والفيزياء، من السابعة أساسي إلى "
                             "البكالوريا. درسٌ يُفهَم، وتمرينٌ يُحَل، وثقةٌ تُبنى.",
                        "fr": "Plateforme tunisienne d'enseignement des mathématiques et de "
                              "la physique, de la 7ème de base au Baccalauréat. Un cours "
                              "compris, un exercice résolu, une confiance qui se construit."},
    "footer.platform": {"ar": "المنصة", "fr": "Plateforme"},
    "footer.all_courses": {"ar": "كل الدروس", "fr": "Tous les cours"},
    "footer.pricing": {"ar": "العروض والأسعار", "fr": "Offres et tarifs"},
    "footer.account": {"ar": "حسابي", "fr": "Mon compte"},
    "footer.my_space": {"ar": "فضائي الشخصي", "fr": "Mon espace"},
    "footer.legal": {"ar": "قانوني", "fr": "Mentions légales"},
    "footer.terms": {"ar": "شروط الاستخدام", "fr": "Conditions d'utilisation"},
    "footer.privacy": {"ar": "سياسة الخصوصية", "fr": "Politique de confidentialité"},
    "footer.tag_line2": {"ar": "🇹🇳 منصة تونسية — من التلميذ وإلى التلميذ",
                          "fr": "🇹🇳 Plateforme tunisienne — d'un élève à un autre"},
    "footer.copyright": {"ar": "© 2026 أكاديمية SCROL — نسخة تجريبية للتشغيل المحلي",
                          "fr": "© 2026 SCROL Academy — version de démonstration locale"},

    # AI chat widget
    "ai.widget_title": {"ar": "المساعد الذكي", "fr": "Assistant IA"},
    "ai.close": {"ar": "إغلاق", "fr": "Fermer"},
    "ai.greeting": {"ar": "أهلًا {name} 👋 أنا مساعدك الذكي — اسألني عن أي جزء من الدرس تحتاج شرحه.",
                     "fr": "Bonjour {name} 👋 Je suis votre assistant IA — posez-moi vos "
                           "questions sur n'importe quelle partie du cours."},
    "ai.placeholder": {"ar": "اكتب سؤالك...", "fr": "Écrivez votre question..."},
    "ai.send": {"ar": "إرسال", "fr": "Envoyer"},

    # flash messages
    "flash.login_required": {"ar": "سجّل دخولك أولًا للوصول إلى هذه الصفحة.",
                              "fr": "Connectez-vous d'abord pour accéder à cette page."},
    "flash.register_required_fields": {"ar": "الاسم والبريد ورقم الهاتف وكلمة المرور حقول إجبارية.",
                                        "fr": "Le nom, l'email, le téléphone et le mot de passe sont obligatoires."},
    "flash.password_too_short": {"ar": "كلمة المرور يجب أن تتكوّن من 6 رموز على الأقل.",
                                  "fr": "Le mot de passe doit contenir au moins 6 caractères."},
    "flash.choose_level": {"ar": "اختر مستواك الدراسي.",
                            "fr": "Choisissez votre niveau scolaire."},
    "flash.email_taken": {"ar": "هذا البريد مسجّل من قبل — جرّب تسجيل الدخول.",
                           "fr": "Cet email est déjà enregistré — essayez de vous connecter."},
    "flash.welcome_new": {"ar": "مرحبًا بك يا {name}! حسابك جاهز — أوّل درس في كل محور مجاني.",
                           "fr": "Bienvenue {name} ! Votre compte est prêt — le premier "
                                 "cours de chaque chapitre est gratuit."},
    "flash.welcome_back": {"ar": "أهلًا بعودتك يا {name} 👋",
                            "fr": "Content de vous revoir, {name} 👋"},
    "flash.bad_credentials": {"ar": "البريد أو كلمة المرور غير صحيحة.",
                               "fr": "Email ou mot de passe incorrect."},
    "flash.captcha_failed": {"ar": "لم نتمكن من التحقق أنك لست روبوتًا — أعد المحاولة.",
                              "fr": "Impossible de vérifier que vous n'êtes pas un robot — réessayez."},
    "flash.verify_needed": {"ar": "تحقق من بريدك أولًا — أرسلنا لك رمزًا.",
                             "fr": "Vérifiez d'abord votre email — nous vous avons envoyé un code."},
    "flash.verify_code_wrong": {"ar": "الرمز غير صحيح.", "fr": "Le code est incorrect."},
    "flash.verify_code_expired": {"ar": "انتهت صلاحية الرمز — اطلب رمزًا جديدًا.",
                                   "fr": "Le code a expiré — demandez-en un nouveau."},
    "flash.verify_resend_wait": {"ar": "انتظر قليلًا قبل طلب رمز جديد.",
                                  "fr": "Attendez un instant avant de redemander un code."},
    "flash.verify_resend_ok": {"ar": "أرسلنا لك رمزًا جديدًا. 📩",
                                "fr": "Un nouveau code vous a été envoyé. 📩"},
    "flash.reset_sent": {"ar": "إن كان بريدك مسجّلًا لدينا، أرسلنا إليه رمز استعادة. 📩",
                          "fr": "Si cet email est enregistré chez nous, un code de "
                                "récupération vient de lui être envoyé. 📩"},
    "flash.reset_code_wrong": {"ar": "الرمز غير صحيح أو منتهي الصلاحية — اطلب رمزًا جديدًا.",
                                "fr": "Le code est incorrect ou a expiré — demandez-en un nouveau."},
    "flash.reset_password_mismatch": {"ar": "كلمتا المرور غير متطابقتين.",
                                       "fr": "Les deux mots de passe ne correspondent pas."},
    "flash.reset_success": {"ar": "تم تغيير كلمة المرور بنجاح — سجّل الدخول بها الآن.",
                             "fr": "Mot de passe changé avec succès — connectez-vous avec."},
    "flash.logged_out": {"ar": "خرجت من حسابك. إلى اللقاء!",
                          "fr": "Vous êtes déconnecté(e). À bientôt !"},
    "flash.subscribers_only": {"ar": "هذا الدرس متاح للمشتركين فقط — الدرس الأول من كل محور مجاني.",
                                "fr": "Ce cours est réservé aux abonnés — le premier cours "
                                      "de chaque chapitre est gratuit."},
    "flash.note_invalid": {"ar": "اكتب نص الملاحظة أولًا.", "fr": "Écrivez d'abord le texte de la note."},
    "flash.payment_pending": {"ar": "سجّلنا إشعار الدفع الخاص بك — سيُفعَّل اشتراكك بعد مراجعة الإدارة.",
                               "fr": "Nous avons enregistré votre paiement — votre abonnement "
                                     "sera activé après vérification par l'administration."},
    "flash.students_only": {"ar": "هذه الصفحة متاحة للتلاميذ فقط.",
                             "fr": "Cette page est réservée aux élèves."},
    "flash.staff_tab_restricted": {"ar": "هذا القسم متاح للإدارة فقط.",
                                    "fr": "Cette section est réservée à l'administration."},
    "flash.schedule_added": {"ar": "أُضيفت فترة المراجعة إلى جدولك. 🗓️",
                              "fr": "La période de révision a été ajoutée à votre planning. 🗓️"},
    "flash.schedule_invalid": {"ar": "تحقق من التاريخ ووقتيّ البداية والنهاية.",
                                "fr": "Vérifiez la date et les heures de début/fin."},
    "flash.schedule_deleted": {"ar": "حُذفت الفترة من جدولك.",
                                "fr": "La période a été supprimée de votre planning."},
    "flash.schedule_updated": {"ar": "تم تحديث الفترة.",
                                "fr": "Le créneau a été mis à jour."},
    "flash.payment_approved": {"ar": "تم قبول الدفع وتفعيل الاشتراك.",
                                "fr": "Paiement accepté et abonnement activé."},
    "flash.payment_rejected": {"ar": "تم رفض عملية الدفع.",
                                "fr": "Le paiement a été refusé."},
    "flash.sub_activated": {"ar": "تم تفعيل/تمديد الاشتراك يدويًا.",
                             "fr": "Abonnement activé/prolongé manuellement."},
    "flash.sub_revoked": {"ar": "تم إيقاف الاشتراك.",
                           "fr": "L'abonnement a été suspendu."},
    "flash.course_added": {"ar": "أُضيف المحور الجديد.",
                            "fr": "Le nouveau chapitre a été ajouté."},
    "flash.course_invalid": {"ar": "تحقق من الحقول: المستوى، المادة، والعنوان إجبارية.",
                              "fr": "Vérifiez les champs : niveau, matière et titre sont obligatoires."},
    "ad.add_level_title": {"ar": "＋ أضف مستوى", "fr": "＋ Ajouter un niveau"},
    "ad.add_subject_title": {"ar": "＋ أضف مادة", "fr": "＋ Ajouter une matière"},
    "ad.code_field": {"ar": "الرمز", "fr": "Code"},
    "ad.name_ar_field": {"ar": "الاسم بالعربية", "fr": "Nom en arabe"},
    "ad.name_fr_field": {"ar": "الاسم بالفرنسية", "fr": "Nom en français"},
    "ad.color_field": {"ar": "اللون", "fr": "Couleur"},
    "ad.glyph_field": {"ar": "الرمز التعبيري", "fr": "Glyphe/emoji"},
    "ad.add_level_btn": {"ar": "إضافة المستوى", "fr": "Ajouter le niveau"},
    "ad.add_subject_btn": {"ar": "إضافة المادة", "fr": "Ajouter la matière"},
    "ad.usage_col": {"ar": "الاستخدام", "fr": "Utilisation"},
    "ad.subjects_title": {"ar": "المواد", "fr": "Matières"},
    "ad.taxonomy_in_use_note": {"ar": "مستعمل في {n} عنصرًا — لا يمكن حذفه.",
                                 "fr": "Utilisé par {n} élément(s) — suppression impossible."},
    "ad.delete_confirm": {"ar": "هل أنت متأكد من الحذف؟", "fr": "Confirmer la suppression ?"},
    "ad.add_teacher_title": {"ar": "＋ أضف أستاذًا", "fr": "＋ Ajouter un enseignant"},
    "ad.password_field": {"ar": "كلمة المرور", "fr": "Mot de passe"},
    "ad.add_teacher_btn": {"ar": "إضافة الأستاذ", "fr": "Ajouter l'enseignant"},
    "ad.teacher_courses_col": {"ar": "المحاور", "fr": "Chapitres"},
    "ad.teacher_students_col": {"ar": "التلاميذ", "fr": "Élèves"},
    "ad.no_teachers_title": {"ar": "لا يوجد أساتذة بعد", "fr": "Aucun enseignant pour le moment"},
    "ad.no_teachers_p": {"ar": "أضف أول حساب أستاذ من النموذج أعلاه.", "fr": "Ajoutez le premier compte enseignant depuis le formulaire ci-dessus."},
    "flash.taxonomy_invalid": {"ar": "تحقق من الحقول: الرمز (حروف/أرقام لاتينية فقط) والاسمان إجباريون.",
                                "fr": "Vérifiez les champs : le code (lettres/chiffres latins uniquement) et les deux noms sont obligatoires."},
    "flash.taxonomy_code_taken": {"ar": "هذا الرمز مستعمل من قبل.", "fr": "Ce code est déjà utilisé."},
    "flash.taxonomy_in_use": {"ar": "لا يمكن الحذف: يوجد محتوى أو تلاميذ مرتبطون بهذا العنصر.",
                               "fr": "Suppression impossible : du contenu ou des élèves y sont encore associés."},
    "flash.level_added": {"ar": "أُضيف المستوى الجديد.", "fr": "Le nouveau niveau a été ajouté."},
    "flash.level_updated": {"ar": "تم تحديث المستوى.", "fr": "Le niveau a été mis à jour."},
    "flash.level_deleted": {"ar": "حُذف المستوى.", "fr": "Le niveau a été supprimé."},
    "flash.subject_added": {"ar": "أُضيفت المادة الجديدة.", "fr": "La nouvelle matière a été ajoutée."},
    "flash.subject_updated": {"ar": "تم تحديث المادة.", "fr": "La matière a été mise à jour."},
    "flash.subject_deleted": {"ar": "حُذفت المادة.", "fr": "La matière a été supprimée."},
    "flash.teacher_invalid": {"ar": "تحقق من الحقول: الاسم، البريد، كلمة المرور (6 خانات على الأقل)، والمستوى إجبارية.",
                               "fr": "Vérifiez les champs : nom, email, mot de passe (6 caractères min.) et niveau sont obligatoires."},
    "flash.teacher_added": {"ar": "أُضيف حساب الأستاذ.", "fr": "Le compte enseignant a été créé."},
    "flash.teacher_updated": {"ar": "تم تحديث حساب الأستاذ.", "fr": "Le compte enseignant a été mis à jour."},
    "flash.teacher_deleted": {"ar": "حُذف حساب الأستاذ.", "fr": "Le compte enseignant a été supprimé."},
    "flash.lesson_added": {"ar": "أُضيف الدرس.",
                            "fr": "Le cours a été ajouté."},
    "flash.lesson_invalid": {"ar": "تحقق من الحقول: المحور، العنوان، ورمز الفيديو إجبارية.",
                              "fr": "Vérifiez les champs : chapitre, titre et code vidéo sont obligatoires."},
    "flash.lesson_deleted": {"ar": "حُذف الدرس.",
                              "fr": "Le cours a été supprimé."},
    "flash.live_added": {"ar": "أُضيفت الحصة المباشرة.",
                          "fr": "La session en direct a été ajoutée."},
    "flash.live_invalid": {"ar": "تحقق من الحقول قبل إضافة الحصة.",
                            "fr": "Vérifiez les champs avant d'ajouter la session."},
    "flash.live_deleted": {"ar": "حُذفت الحصة.",
                            "fr": "La session a été supprimée."},
    "flash.chat_sent": {"ar": "أُرسلت الرسالة إلى دردشة المستوى.",
                         "fr": "Le message a été envoyé au chat du niveau."},
    "flash.chat_invalid": {"ar": "اختر المستوى واكتب نص الرسالة.",
                            "fr": "Choisissez le niveau et écrivez le message."},
    "flash.notify_invalid": {"ar": "العنوان والنص إجباريان.",
                              "fr": "Le titre et le texte sont obligatoires."},
    "flash.notify_sent": {"ar": "أُرسل الإشعار إلى {n} تلميذًا. 🔔",
                           "fr": "La notification a été envoyée à {n} élève(s). 🔔"},
    "flash.ai_disabled": {"ar": "المساعد الذكي غير مفعّل حاليًا — يجب على إدارة المنصة إعداد مفتاح API أولًا.",
                           "fr": "L'assistant IA n'est pas encore activé — l'administration "
                                 "doit d'abord configurer une clé API."},
    "flash.ai_no_sub": {"ar": "المساعد الذكي متاح فقط للمشتركين — فعّل اشتراكك للاستفادة منه. 🔒",
                         "fr": "L'assistant IA est réservé aux abonnés — active ton abonnement "
                               "pour en profiter. 🔒"},
    "flash.ai_no_question": {"ar": "لم يصلنا أي سؤال.", "fr": "Nous n'avons reçu aucune question."},
    "flash.ai_daily_limit": {"ar": "لقد استعملت الحد الأقصى ({n} سؤالًا) لهذا اليوم — عاود المحاولة غدًا 🙏",
                              "fr": "Vous avez atteint la limite quotidienne ({n} questions) "
                                    "— réessayez demain 🙏"},
    "flash.ai_error": {"ar": "تعذّر الاتصال بالمساعد الذكي، حاول مجددًا بعد قليل.",
                        "fr": "Impossible de contacter l'assistant IA, réessayez dans un instant."},
    "flash.ai_empty_reply": {"ar": "عذرًا، لم أفهم السؤال — أعد صياغته من فضلك.",
                              "fr": "Désolé, je n'ai pas compris la question — reformulez-la s'il vous plaît."},

    # index.html
    "idx.title": {"ar": "الرياضيات والفيزياء لتلاميذ تونس",
                  "fr": "Maths et physique pour les élèves tunisiens"},
    "idx.eyebrow": {"ar": "🇹🇳 من السابعة أساسي إلى البكالوريا",
                     "fr": "🇹🇳 De la 7ème de base au Baccalauréat"},
    "idx.h1_line1": {"ar": "الرياضيات والفيزياء…", "fr": "Les mathématiques et la physique…"},
    "idx.h1_line2": {"ar": "بالطريقة اللي تفهمها", "fr": "d'une façon que tu comprends"},
    "idx.lead": {"ar": "دروس فيديو مرتّبة حسب البرنامج الرسمي التونسي، حصص مباشرة أسبوعية، "
                       "وتمارين مصحّحة خطوة بخطوة. أوّل درس في كل محور {free} — جرّب قبل ما تشترك.",
                 "fr": "Des cours vidéo organisés selon le programme officiel tunisien, des "
                       "sessions en direct hebdomadaires, et des exercices corrigés étape par "
                       "étape. Le premier cours de chaque chapitre est {free} — essayez avant "
                       "de vous abonner."},
    "idx.free": {"ar": "مجاني", "fr": "gratuit"},
    "idx.cta_register": {"ar": "أنشئ حسابك مجانًا", "fr": "Créer un compte gratuit"},
    "idx.cta_browse": {"ar": "تصفّح الدروس", "fr": "Parcourir les cours"},
    "idx.note1": {"ar": "✓ تسجيل مجاني بدون بطاقة بنكية", "fr": "✓ Inscription gratuite, sans carte bancaire"},
    "idx.note2": {"ar": "✓ محتوى مطابق للبرنامج الرسمي", "fr": "✓ Contenu conforme au programme officiel"},
    "idx.note3": {"ar": "✓ درس مجاني في كل محور", "fr": "✓ Un cours gratuit par chapitre"},
    "idx.notebook_session": {"ar": "الحصة 12 — دراسة دالة", "fr": "Séance 12 — Étude de fonction"},
    "idx.notebook_alt": {"ar": "رسم بياني لدالة على ورقة دفتر", "fr": "Graphique d'une fonction sur un cahier"},
    "idx.notebook_local_max": {"ar": "أقصى محلي !", "fr": "Maximum local !"},
    "idx.notebook_note": {"ar": "✎ لا تنسَ جدول التغيّرات", "fr": "✎ N'oublie pas le tableau de variations"},
    "idx.stat_students": {"ar": "تلميذ مسجّل", "fr": "élèves inscrits"},
    "idx.stat_lessons": {"ar": "درس فيديو", "fr": "cours vidéo"},
    "idx.stat_levels": {"ar": "مستويات دراسية", "fr": "niveaux scolaires"},
    "idx.stat_subjects": {"ar": "مادّتان: رياضيات وفيزياء", "fr": "2 matières : maths et physique"},
    "idx.next_live": {"ar": "أقرب حصة مباشرة:", "fr": "Prochaine session en direct :"},
    "idx.live_program": {"ar": "برنامج الحصص", "fr": "Programme des sessions"},
    "idx.how_eyebrow": {"ar": "ثلاث خطوات لا غير", "fr": "Seulement trois étapes"},
    "idx.how_title": {"ar": "كيف تبدأ رحلتك؟", "fr": "Comment commencer ?"},
    "idx.step1_title": {"ar": "أنشئ حسابك", "fr": "Créez votre compte"},
    "idx.step1_desc": {"ar": "سجّل مجانًا باسمك وبريدك واختر مستواك الدراسي — من السابعة أساسي إلى البكالوريا.",
                        "fr": "Inscrivez-vous gratuitement avec votre nom et email, et choisissez "
                              "votre niveau scolaire — de la 7ème de base au Baccalauréat."},
    "idx.step2_title": {"ar": "جرّب درسًا مجانيًا", "fr": "Essayez un cours gratuit"},
    "idx.step2_desc": {"ar": "أوّل فيديو في كل محور متاح مجانًا لكل الحسابات، لتتأكد من طريقة الشرح قبل أي التزام.",
                        "fr": "La première vidéo de chaque chapitre est gratuite pour tous les "
                              "comptes, pour vérifier la méthode d'explication avant tout engagement."},
    "idx.step3_title": {"ar": "اشترك وافتح كل شيء", "fr": "Abonnez-vous et débloquez tout"},
    "idx.step3_desc": {"ar": "اختر العرض المناسب لتفتح كل الدروس والحصص المباشرة والملخصات، بأسعار في متناول الجميع.",
                        "fr": "Choisissez l'offre adaptée pour débloquer tous les cours, les "
                              "sessions en direct et les résumés, à des prix accessibles à tous."},
    "idx.levels_eyebrow": {"ar": "اختر مستواك", "fr": "Choisissez votre niveau"},
    "idx.levels_title": {"ar": "كل مستوى… له مساره", "fr": "Chaque niveau… a son parcours"},
    "idx.levels_sub": {"ar": "رياضيات وفيزياء لكل مستوى، محاور مرتّبة كما في القسم تمامًا.",
                        "fr": "Maths et physique pour chaque niveau, des chapitres organisés "
                              "exactement comme en classe."},
    "idx.levels_subjects": {"ar": "رياضيات · فيزياء", "fr": "Maths · Physique"},
    "idx.levels_bac_badge": {"ar": "سنة الحسم ★", "fr": "L'année décisive ★"},
    "idx.samples_eyebrow": {"ar": "بدون حساب مدفوع", "fr": "Sans compte payant"},
    "idx.samples_title1": {"ar": "دروس مجانية", "fr": "Cours gratuits"},
    "idx.samples_title2": {"ar": "للتجربة", "fr": "à l'essai"},
    "idx.samples_sub": {"ar": "هذه عيّنة من الدروس المفتوحة — أنشئ حسابًا مجانيًا وشاهدها كاملة.",
                         "fr": "Voici un échantillon des cours ouverts — créez un compte "
                               "gratuit pour les regarder en entier."},
    "idx.free_chip": {"ar": "مجاني", "fr": "Gratuit"},
    "idx.minutes": {"ar": "دقيقة", "fr": "min"},
    "idx.features_eyebrow": {"ar": "لماذا أكاديمية SCROL؟", "fr": "Pourquoi SCROL Academy ?"},
    "idx.features_title": {"ar": "منصة كاملة، لا مجرد فيديوهات", "fr": "Une plateforme complète, pas juste des vidéos"},
    "idx.feat1_title": {"ar": "دروس فيديو مرتّبة", "fr": "Cours vidéo organisés"},
    "idx.feat1_desc": {"ar": "كل محور مقسّم إلى دروس قصيرة واضحة، تبدأ من الأساس وتصل إلى تمارين الامتحانات.",
                        "fr": "Chaque chapitre est divisé en cours courts et clairs, des bases "
                              "jusqu'aux exercices d'examen."},
    "idx.feat2_title": {"ar": "حصص مباشرة أسبوعية", "fr": "Sessions en direct hebdomadaires"},
    "idx.feat2_desc": {"ar": "مراجعات وتصحيح فروض على المباشر، مع إمكانية طرح أسئلتك والإجابة عليها فورًا.",
                        "fr": "Révisions et corrections de devoirs en direct, avec la "
                              "possibilité de poser vos questions et d'obtenir une réponse immédiate."},
    "idx.feat3_title": {"ar": "تمارين مصحّحة", "fr": "Exercices corrigés"},
    "idx.feat3_desc": {"ar": "سلاسل تمارين وفروض مراقبة وتأليفية بحلول مفصّلة، على طريقة الإصلاح الرسمي.",
                        "fr": "Des séries d'exercices et de devoirs corrigés en détail, selon "
                              "la méthode de correction officielle."},
    "idx.feat4_title": {"ar": "مطابق للبرنامج التونسي", "fr": "Conforme au programme tunisien"},
    "idx.feat4_desc": {"ar": "نفس ترتيب المحاور التي تدرسها في القسم، فلا تضيع وقتك في محتوى خارج البرنامج.",
                        "fr": "Le même ordre de chapitres que vous étudiez en classe, pour ne "
                              "pas perdre de temps sur du contenu hors programme."},
    "idx.feat5_title": {"ar": "مرافقة وإجابة عن الأسئلة", "fr": "Accompagnement et réponses à vos questions"},
    "idx.feat5_desc": {"ar": "فريق بيداغوجي يرافقك ويجيب عن استفساراتك حتى لا تبقى أي نقطة غامضة.",
                        "fr": "Une équipe pédagogique vous accompagne et répond à vos questions "
                              "pour qu'aucun point ne reste flou."},
    "idx.feat6_title": {"ar": "أسعار تناسب العائلة التونسية", "fr": "Des prix adaptés à la famille tunisienne"},
    "idx.feat6_desc": {"ar": "اشتراك واحد يفتح المادّتين معًا لكل المستويات، بعروض شهرية وثلاثية وسنوية.",
                        "fr": "Un seul abonnement débloque les deux matières pour tous les "
                              "niveaux, avec des offres mensuelles, trimestrielles et annuelles."},
    "idx.pricing_eyebrow": {"ar": "عروض بسيطة وواضحة", "fr": "Des offres simples et claires"},
    "idx.pricing_title": {"ar": "باقتك… بمقاسك", "fr": "Votre pack… à votre mesure"},
    "idx.most_chosen": {"ar": "الأكثر اختيارًا", "fr": "Le plus choisi"},
    "idx.choose_plan": {"ar": "اختر هذا العرض", "fr": "Choisir cette offre"},
    "idx.plans_note": {"ar": "التسجيل في المنصة مجاني دائمًا — الدفع فقط عند فتح كامل المحتوى.",
                        "fr": "L'inscription sur la plateforme est toujours gratuite — le "
                              "paiement n'intervient que pour débloquer tout le contenu."},
    "idx.plans_details": {"ar": "تفاصيل العروض كاملة ←", "fr": "Voir tous les détails des offres ←"},
    "idx.faq_eyebrow": {"ar": "أسئلة التلاميذ والأولياء", "fr": "Questions des élèves et des parents"},
    "idx.faq_title": {"ar": "الأسئلة الشائعة", "fr": "Questions fréquentes"},
    "idx.cta_title": {"ar": "مستعد ترفع معدّلك في الرياضيات والفيزياء؟",
                       "fr": "Prêt à améliorer votre moyenne en maths et en physique ?"},
    "idx.cta_sub": {"ar": "سجّل الآن مجانًا، شاهد أول درس في محورك، وقرّر بنفسك.",
                     "fr": "Inscrivez-vous gratuitement maintenant, regardez le premier cours "
                           "de votre chapitre, et décidez par vous-même."},
    "idx.cta_register2": {"ar": "إنشاء حساب مجاني", "fr": "Créer un compte gratuit"},
    "idx.cta_discover": {"ar": "اكتشف العروض", "fr": "Découvrir les offres"},

    # register.html
    "reg.title": {"ar": "إنشاء حساب", "fr": "Créer un compte"},
    "reg.hero": {"ar": "خطوتك الأولى نحو {excellence}", "fr": "Votre premier pas vers {excellence}"},
    "reg.excellence": {"ar": "التفوّق", "fr": "l'excellence"},
    "reg.perk1": {"ar": "✓ حساب مجاني بالكامل، بدون بطاقة بنكية", "fr": "✓ Compte entièrement gratuit, sans carte bancaire"},
    "reg.perk2": {"ar": "✓ أوّل درس فيديو مجاني في كل محور", "fr": "✓ Premier cours vidéo gratuit par chapitre"},
    "reg.perk3": {"ar": "✓ رياضيات وفيزياء لكل المستويات", "fr": "✓ Maths et physique pour tous les niveaux"},
    "reg.perk4": {"ar": "✓ اشترك لاحقًا متى شئت لفتح كل شيء", "fr": "✓ Abonnez-vous plus tard, quand vous voulez, pour tout débloquer"},
    "reg.quip": {"ar": "✎ «النجاح عادة… نتمرّن عليها كل يوم.»", "fr": "✎ « La réussite est une habitude… qu'on pratique chaque jour. »"},
    "reg.form_title": {"ar": "إنشاء حساب جديد", "fr": "Créer un nouveau compte"},
    "reg.name": {"ar": "الاسم واللقب *", "fr": "Nom et prénom *"},
    "reg.name_ph": {"ar": "مثال: أمين بن صالح", "fr": "Exemple : Amine Ben Salah"},
    "reg.email": {"ar": "البريد الإلكتروني *", "fr": "Email *"},
    "reg.phone": {"ar": "رقم الهاتف *", "fr": "Numéro de téléphone *"},
    "reg.level": {"ar": "المستوى الدراسي *", "fr": "Niveau scolaire *"},
    "reg.level_choose": {"ar": "اختر مستواك…", "fr": "Choisissez votre niveau…"},
    "reg.password": {"ar": "كلمة المرور *", "fr": "Mot de passe *"},
    "reg.password_hint": {"ar": "(6 رموز على الأقل)", "fr": "(6 caractères minimum)"},
    "reg.submit": {"ar": "أنشئ حسابي المجاني", "fr": "Créer mon compte gratuit"},
    "reg.have_account": {"ar": "عندك حساب؟", "fr": "Vous avez déjà un compte ?"},
    "reg.login_link": {"ar": "سجّل الدخول", "fr": "Connectez-vous"},

    # verify_email.html
    "ver.title": {"ar": "تحقق من بريدك", "fr": "Vérifiez votre email"},
    "ver.heading": {"ar": "خطوة أخيرة", "fr": "Dernière étape"},
    "ver.sent_to": {"ar": "أرسلنا رمزًا من 6 أرقام إلى", "fr": "Nous avons envoyé un code à 6 chiffres à"},
    "ver.code_label": {"ar": "رمز التحقق", "fr": "Code de vérification"},
    "ver.submit": {"ar": "تأكيد", "fr": "Confirmer"},
    "ver.no_code": {"ar": "ما وصلكش الرمز؟", "fr": "Vous n'avez pas reçu le code ?"},
    "ver.resend": {"ar": "أعد الإرسال", "fr": "Renvoyer"},
    "ver.back": {"ar": "← الرجوع لإنشاء الحساب", "fr": "← Retour à l'inscription"},

    # login.html
    "log.title": {"ar": "تسجيل الدخول", "fr": "Connexion"},
    "log.welcome": {"ar": "أهلًا", "fr": "Bienvenue"},
    "log.welcome_back": {"ar": "بعودتك", "fr": "de retour"},
    "log.perk1": {"ar": "✓ واصل من حيث توقفت", "fr": "✓ Reprenez là où vous vous êtes arrêté"},
    "log.perk2": {"ar": "✓ برنامج حصصك المباشرة", "fr": "✓ Le programme de vos sessions en direct"},
    "log.perk3": {"ar": "✓ متابعة اشتراكك ومدفوعاتك", "fr": "✓ Suivez votre abonnement et vos paiements"},
    "log.form_title": {"ar": "تسجيل الدخول", "fr": "Connexion"},
    "log.email": {"ar": "البريد الإلكتروني", "fr": "Email"},
    "log.password": {"ar": "كلمة المرور", "fr": "Mot de passe"},
    "log.submit": {"ar": "دخول", "fr": "Se connecter"},
    "log.no_account": {"ar": "ما عندكش حساب؟", "fr": "Vous n'avez pas de compte ?"},
    "log.register_link": {"ar": "أنشئ حسابًا مجانيًا", "fr": "Créez un compte gratuit"},
    "log.forgot_link": {"ar": "نسيت كلمة المرور؟", "fr": "Mot de passe oublié ?"},

    # forgot_password.html
    "fp.title": {"ar": "استعادة كلمة المرور", "fr": "Récupération du mot de passe"},
    "fp.heading": {"ar": "نسيت كلمة المرور؟", "fr": "Mot de passe oublié ?"},
    "fp.intro": {"ar": "أدخل بريدك الإلكتروني وسنرسل لك رمزًا لاستعادة حسابك.",
                 "fr": "Entrez votre email, nous vous enverrons un code pour récupérer votre compte."},
    "fp.email_label": {"ar": "البريد الإلكتروني", "fr": "Email"},
    "fp.submit": {"ar": "أرسل رمز الاستعادة", "fr": "Envoyer le code de récupération"},
    "fp.back_to_login": {"ar": "← الرجوع لتسجيل الدخول", "fr": "← Retour à la connexion"},

    # reset_password.html
    "rp.title": {"ar": "كلمة مرور جديدة", "fr": "Nouveau mot de passe"},
    "rp.heading": {"ar": "خطوة أخيرة", "fr": "Dernière étape"},
    "rp.intro": {"ar": "أدخل الرمز الذي وصلك بالبريد، ثم كلمة المرور الجديدة.",
                 "fr": "Entrez le code reçu par email, puis votre nouveau mot de passe."},
    "rp.code_label": {"ar": "رمز الاستعادة", "fr": "Code de récupération"},
    "rp.new_password_label": {"ar": "كلمة المرور الجديدة", "fr": "Nouveau mot de passe"},
    "rp.confirm_password_label": {"ar": "تأكيد كلمة المرور", "fr": "Confirmer le mot de passe"},
    "rp.submit": {"ar": "تغيير كلمة المرور", "fr": "Changer le mot de passe"},
    "rp.no_code": {"ar": "ما وصلكش الرمز؟", "fr": "Vous n'avez pas reçu le code ?"},
    "rp.resend": {"ar": "أعد الإرسال", "fr": "Renvoyer"},

    # legal.html
    "legal.terms_title": {"ar": "شروط الاستخدام", "fr": "Conditions d'utilisation"},
    "legal.privacy_title": {"ar": "سياسة الخصوصية", "fr": "Politique de confidentialité"},
    "legal.demo_note": {"ar": "نسخة تجريبية للتشغيل المحلي — عدّل هذا النص بما يناسب مشروعك قبل النشر.",
                         "fr": "Version de démonstration locale — adaptez ce texte à votre "
                               "projet avant toute publication."},

    # error.html
    "error.back_home": {"ar": "العودة للرئيسية", "fr": "Retour à l'accueil"},

    # legal.html — terms
    "legal.t1_h": {"ar": "1. الحساب", "fr": "1. Le compte"},
    "legal.t1_p": {"ar": "التسجيل في المنصة مجاني ومخصّص للاستعمال الشخصي للتلميذ. أنت مسؤول عن سرية بيانات دخولك.",
                   "fr": "L'inscription sur la plateforme est gratuite et réservée à l'usage "
                         "personnel de l'élève. Vous êtes responsable de la confidentialité "
                         "de vos identifiants."},
    "legal.t2_h": {"ar": "2. المحتوى", "fr": "2. Le contenu"},
    "legal.t2_p": {"ar": "الدروس والفيديوهات والملخصات مخصّصة للمشاهدة داخل المنصة، ولا يجوز إعادة نشرها أو بيعها.",
                   "fr": "Les cours, vidéos et résumés sont destinés à être consultés sur la "
                         "plateforme uniquement, et ne peuvent être republiés ou revendus."},
    "legal.t3_h": {"ar": "3. الاشتراكات", "fr": "3. Les abonnements"},
    "legal.t3_p": {"ar": "يفتح الاشتراك المدفوع كامل المحتوى طيلة مدة العرض المختار، ويُفعَّل بعد تأكيد الدفع من الإدارة.",
                   "fr": "L'abonnement payant débloque tout le contenu pendant la durée de "
                         "l'offre choisie, et est activé après confirmation du paiement par "
                         "l'administration."},
    "legal.t4_h": {"ar": "4. الحصص المباشرة", "fr": "4. Les sessions en direct"},
    "legal.t4_p": {"ar": "روابط البث خاصة بالمشتركين، ومشاركة الرابط خارج المنصة قد تؤدي إلى إيقاف الحساب.",
                   "fr": "Les liens de diffusion sont réservés aux abonnés ; les partager en "
                         "dehors de la plateforme peut entraîner la suspension du compte."},
    # legal.html — privacy
    "legal.p1_h": {"ar": "1. البيانات التي نجمعها", "fr": "1. Les données que nous collectons"},
    "legal.p1_p": {"ar": "الاسم، البريد الإلكتروني، رقم الهاتف (اختياري)، والمستوى الدراسي — لغرض تشغيل حسابك لا غير.",
                   "fr": "Nom, email, numéro de téléphone (facultatif) et niveau scolaire — "
                         "uniquement pour faire fonctionner votre compte."},
    "legal.p2_h": {"ar": "2. كيف نستعملها", "fr": "2. Comment nous les utilisons"},
    "legal.p2_p": {"ar": "لتمكينك من الدخول، متابعة اشتراكك، وإعلامك بالحصص المباشرة. لا نبيع بياناتك لأي طرف ثالث.",
                   "fr": "Pour vous permettre de vous connecter, suivre votre abonnement, et "
                         "vous informer des sessions en direct. Nous ne vendons vos données à "
                         "aucun tiers."},
    "legal.p3_h": {"ar": "3. التخزين", "fr": "3. Le stockage"},
    "legal.p3_p": {"ar": "في هذه النسخة المحلية تُخزَّن البيانات في ملف academy.db على جهازك، وكلمات المرور مشفّرة.",
                   "fr": "Dans cette version locale, les données sont stockées dans le fichier "
                         "academy.db sur votre machine, et les mots de passe sont chiffrés."},
    "legal.p4_h": {"ar": "4. حقوقك", "fr": "4. Vos droits"},
    "legal.p4_p": {"ar": "يمكنك طلب حذف حسابك وبياناتك في أي وقت عبر التواصل مع إدارة المنصة.",
                   "fr": "Vous pouvez demander la suppression de votre compte et de vos "
                         "données à tout moment en contactant l'administration."},

    # error.html
    "error.title": {"ar": "خطأ {code}", "fr": "Erreur {code}"},
    "error.sorry": {"ar": "عذرًا…", "fr": "Désolé…"},
    "error.404": {"ar": "الصفحة التي تبحث عنها غير موجودة.", "fr": "La page que vous cherchez n'existe pas."},
    "error.403": {"ar": "ليست لديك صلاحية الوصول إلى هذه الصفحة.", "fr": "Vous n'avez pas la permission d'accéder à cette page."},

    # courses.html
    "crs.eyebrow": {"ar": "رياضيات · فيزياء", "fr": "Mathématiques · Physique"},
    "crs.title": {"ar": "كل المحاور، مرتّبة كما في القسم", "fr": "Tous les chapitres, organisés comme en classe"},
    "crs.sub": {"ar": "اختر مستواك ومادّتك — أوّل درس في كل محور مجاني لكل الحسابات.",
                "fr": "Choisissez votre niveau et votre matière — le premier cours de chaque "
                      "chapitre est gratuit pour tous les comptes."},
    "crs.hint": {"ar": "📍 نعرض دروس مستواك: {level} تلقائيًا", "fr": "📍 Nous affichons automatiquement les cours de votre niveau : {level}"},
    "crs.show_all_levels": {"ar": "عرض كل المستويات ←", "fr": "Voir tous les niveaux ←"},
    "crs.level_label": {"ar": "المستوى:", "fr": "Niveau :"},
    "crs.subject_label": {"ar": "المادة:", "fr": "Matière :"},
    "crs.all": {"ar": "الكل", "fr": "Tous"},
    "crs.free_lesson_n": {"ar": "{n} درس مجاني", "fr": "{n} cours gratuit"},
    "crs.n_lessons": {"ar": "{n} درسًا", "fr": "{n} cours"},
    "crs.duration": {"ar": "⏱ ≈ {h} س {m} د", "fr": "⏱ ≈ {h} h {m} min"},
    "crs.empty_title": {"ar": "لا توجد محاور بهذا التصفية بعد", "fr": "Aucun chapitre pour ce filtre pour le moment"},
    "crs.empty_p": {"ar": "جرّب مستوى أو مادّة أخرى، أو عد إلى", "fr": "Essayez un autre niveau ou une autre matière, ou revenez à"},
    "crs.all_courses": {"ar": "كل الدروس", "fr": "tous les cours"},

    # course.html
    "co.free_first": {"ar": "🆓 الدرس الأول مجاني", "fr": "🆓 Le premier cours est gratuit"},
    "co.rest_subscribers": {"ar": "🔒 البقية للمشتركين", "fr": "🔒 Le reste est réservé aux abonnés"},
    "co.minutes": {"ar": "دقيقة", "fr": "min"},
    "co.free": {"ar": "مجاني", "fr": "Gratuit"},
    "co.watch": {"ar": "▶ شاهد", "fr": "▶ Regarder"},
    "co.subscribe": {"ar": "🔒 اشترك", "fr": "🔒 S'abonner"},
    "co.login": {"ar": "🔒 دخول", "fr": "🔒 Connexion"},
    "co.subscribers_only_title": {"ar": "متاح للمشتركين", "fr": "Réservé aux abonnés"},
    "co.login_title": {"ar": "سجّل الدخول", "fr": "Connectez-vous"},
    "co.unlock_title": {"ar": "افتح هذا المحور", "fr": "Débloquez ce chapitre"},
    "co.unlock_p": {"ar": "اشترك في هذه المادة فقط، أو افتح كل المواد بباقة الوصول الكامل.",
                     "fr": "Abonnez-vous à cette seule matière, ou débloquez toutes les matières avec le pack accès complet."},
    "co.discover_offers": {"ar": "اكتشف العروض", "fr": "Découvrir les offres"},

    # watch.html
    "wa.mark_undo": {"ar": "↺ إلغاء تحديد \"تمت المشاهدة\"", "fr": "↺ Annuler « vu »"},
    "wa.mark_done": {"ar": "✓ تحديد الدرس كمكتمل", "fr": "✓ Marquer comme terminé"},
    "wa.like_it": {"ar": "أعجبك الشرح؟", "fr": "Vous avez aimé l'explication ?"},
    "wa.unlock_rest": {"ar": "اشترك في هذه المادة، أو افتح كل المواد بباقة الوصول الكامل.",
                        "fr": "Abonnez-vous à cette matière, ou débloquez toutes les matières "
                              "avec le pack accès complet."},
    "wa.offers": {"ar": "العروض", "fr": "Les offres"},
    "wa.chapter_lessons": {"ar": "دروس المحور", "fr": "Cours du chapitre"},
    "wa.play": {"ar": "تشغيل", "fr": "Lecture"},
    "wa.pause": {"ar": "إيقاف مؤقت", "fr": "Pause"},
    "wa.mute": {"ar": "كتم الصوت", "fr": "Couper le son"},
    "wa.seek": {"ar": "شريط التقدّم", "fr": "Barre de progression"},
    "wa.volume": {"ar": "مستوى الصوت", "fr": "Volume"},
    "wa.fullscreen": {"ar": "ملء الشاشة", "fr": "Plein écran"},
    "wa.quality": {"ar": "جودة الفيديو", "fr": "Qualité vidéo"},
    "wa.quality_auto": {"ar": "تلقائي", "fr": "Auto"},

    # pricing.html
    "pr.eyebrow": {"ar": "بلا مفاجآت وبلا رموز صغيرة", "fr": "Sans surprise et sans petits caractères"},
    "pr.title": {"ar": "اختر باقتك… مادة واحدة أو الوصول الكامل", "fr": "Choisissez votre pack… une matière ou l'accès complet"},
    "pr.sub": {"ar": "مادة واحدة تختارها، أو كل المواد — أنت من يقرر. حصص مباشرة وملخصات ومتابعة أسبوعية في الحالتين.",
               "fr": "Une matière de votre choix, ou toutes les matières — c'est vous qui "
                     "décidez. Sessions en direct, résumés et suivi hebdomadaire dans les deux cas."},
    "pr.most_chosen": {"ar": "الأكثر اختيارًا", "fr": "Le plus choisi"},
    "pr.for_duration": {"ar": "لمدة", "fr": "Pour"},
    "pr.month_1": {"ar": "شهر", "fr": "mois"},
    "pr.month_few": {"ar": "أشهر", "fr": "mois"},
    "pr.month_many": {"ar": "شهرًا", "fr": "mois"},
    "pr.already_subscribed": {"ar": "أنت مشترك بالفعل ✓", "fr": "Vous êtes déjà abonné ✓"},
    "pr.choose_offer": {"ar": "اختر هذا العرض", "fr": "Choisir cette offre"},
    "pr.register_then_subscribe": {"ar": "أنشئ حسابًا ثم اشترك", "fr": "Créez un compte puis abonnez-vous"},
    "pr.all_title": {"ar": "🏆 الوصول الكامل", "fr": "🏆 Accès complet"},
    "pr.all_desc": {"ar": "كل المواد الدراسية ({n} مادة حاليًا) بلا استثناء — الخيار الأشمل والأوفر على المدى الطويل.",
                     "fr": "Toutes les matières ({n} actuellement) sans exception — le choix le plus complet et le plus économique sur la durée."},
    "pr.subject_title": {"ar": "🎯 مادة واحدة على كيفك", "fr": "🎯 Une seule matière, à votre choix"},
    "pr.subject_desc": {"ar": "ركّز على مادة واحدة تختارها بنفسك، بنفس المزايا الكاملة، بسعر أقل.",
                         "fr": "Concentrez-vous sur une seule matière de votre choix, avec tous les avantages, à prix réduit."},
    "pr.choose_subject_hint": {"ar": "اختر مادتك:", "fr": "Choisissez votre matière :"},
    "pr.dur_monthly": {"ar": "شهري", "fr": "Mensuel"},
    "pr.dur_term": {"ar": "ثلاثي", "fr": "Trimestriel"},
    "pr.dur_year": {"ar": "سنوي", "fr": "Annuel"},
    "pr.all_subjects_label": {"ar": "كل المواد", "fr": "Toutes les matières"},
    "pr.scope_label": {"ar": "المادة", "fr": "Matière"},
    "ad.scope_col": {"ar": "النطاق", "fr": "Portée"},
    "pr.pay_methods_title": {"ar": "طرق الدفع المقبولة 🇹🇳", "fr": "Moyens de paiement acceptés 🇹🇳"},
    "pr.pay_note": {"ar": "بعد إرسال المبلغ، أكّد الدفع من صفحة الاشتراك وسيفعَّل حسابك بعد مراجعة الإدارة.",
                     "fr": "Après avoir envoyé le montant, confirmez le paiement depuis la page "
                           "d'abonnement — votre compte sera activé après vérification par "
                           "l'administration."},

    # checkout.html
    "ch.title": {"ar": "إتمام الاشتراك — {plan}", "fr": "Finaliser l'abonnement — {plan}"},
    "ch.last_step": {"ar": "خطوة أخيرة", "fr": "Dernière étape"},
    "ch.complete_sub": {"ar": "إتمام الاشتراك", "fr": "Finaliser l'abonnement"},
    "ch.summary": {"ar": "ملخص طلبك", "fr": "Résumé de votre commande"},
    "ch.offer": {"ar": "العرض", "fr": "Offre"},
    "ch.duration": {"ar": "المدة", "fr": "Durée"},
    "ch.amount": {"ar": "المبلغ", "fr": "Montant"},
    "ch.change_offer": {"ar": "← تغيير العرض", "fr": "← Changer d'offre"},
    "ch.step1": {"ar": "1) أرسل المبلغ بإحدى الطرق", "fr": "1) Envoyez le montant par l'un des moyens suivants"},
    "ch.bank_transfer": {"ar": "تحويل بنكي (RIB):", "fr": "Virement bancaire (RIB) :"},
    "ch.mandat_to": {"ar": "حوالة بريدية باسم:", "fr": "Mandat postal au nom de :"},
    "ch.mandat_country": {"ar": "أكاديمية SCROL — تونس", "fr": "SCROL Academy — Tunisie"},
    "ch.demo_warning": {"ar": "⚠ أرقام رمزية للنسخة التجريبية — عوّضها بحساباتك الحقيقية قبل النشر.",
                         "fr": "⚠ Numéros fictifs pour la version de démonstration — "
                               "remplacez-les par vos vrais comptes avant publication."},
    "ch.step2": {"ar": "2) أكّد عملية الدفع", "fr": "2) Confirmez le paiement"},
    "ch.method_used": {"ar": "الطريقة التي استعملتها", "fr": "Le moyen que vous avez utilisé"},
    "ch.reference": {"ar": "مرجع العملية / رقم الهاتف المرسِل (اختياري)",
                      "fr": "Référence de l'opération / numéro de l'expéditeur (facultatif)"},
    "ch.reference_ph": {"ar": "مثال: TX-2026-0142 أو 00 000 000", "fr": "Exemple : TX-2026-0142 ou 00 000 000"},
    "ch.confirm_btn": {"ar": "أرسلتُ المبلغ — تأكيد الدفع", "fr": "J'ai envoyé le montant — confirmer le paiement"},
    "ch.review_note": {"ar": "سيراجع فريقنا الإشعار ويفعّل اشتراكك، ويظهر ذلك في فضائك الشخصي.",
                        "fr": "Notre équipe examinera votre paiement et activera votre "
                              "abonnement, visible dans votre espace personnel."},

    # live.html
    "lv.on_air": {"ar": "على المباشر", "fr": "En direct"},
    "lv.title": {"ar": "برنامج الحصص المباشرة", "fr": "Programme des sessions en direct"},
    "lv.sub": {"ar": "مراجعات، تصحيح فروض، وإجابة عن أسئلتكم — رابط البث يظهر للمشتركين قبل الموعد.",
               "fr": "Révisions, corrections de devoirs, réponses à vos questions — le lien "
                     "de diffusion apparaît pour les abonnés avant l'heure."},
    "lv.upcoming": {"ar": "الحصص القادمة", "fr": "Sessions à venir"},
    "lv.minutes": {"ar": "دقيقة", "fr": "min"},
    "lv.live_link": {"ar": "🔴 رابط الحصة", "fr": "🔴 Lien de la session"},
    "lv.subscribers_only": {"ar": "🔒 للمشتركين", "fr": "🔒 Réservé aux abonnés"},
    "lv.login_btn": {"ar": "🔒 سجّل الدخول", "fr": "🔒 Connectez-vous"},
    "lv.empty_title": {"ar": "لا توجد حصص مبرمجة حاليًا", "fr": "Aucune session programmée pour le moment"},
    "lv.empty_p": {"ar": "يُنشر البرنامج الجديد هنا كل أسبوع — تابعنا.",
                    "fr": "Le nouveau programme est publié ici chaque semaine — restez à l'écoute."},
    "lv.past": {"ar": "حصص سابقة", "fr": "Sessions passées"},
    "lv.ended": {"ar": "انتهت", "fr": "Terminée"},

    # dashboard.html
    "db.title": {"ar": "فضائي الشخصي", "fr": "Mon espace"},
    "db.student_space": {"ar": "فضاء التلميذ", "fr": "Espace élève"},
    "db.hello": {"ar": "مرحبًا، {name} 👋", "fr": "Bonjour, {name} 👋"},
    "db.your_level": {"ar": "مستواك:", "fr": "Votre niveau :"},
    "db.sub_active": {"ar": "✓ اشتراكك مفعّل", "fr": "✓ Votre abonnement est actif"},
    "db.until": {"ar": "حتى", "fr": "jusqu'au"},
    "db.subscription_word": {"ar": "اشتراك", "fr": "Abonnement"},
    "db.free_account": {"ar": "حساب مجاني", "fr": "Compte gratuit"},
    "db.free_one_lesson": {"ar": "درس واحد مجاني في كل محور", "fr": "Un cours gratuit par chapitre"},
    "db.activate_sub": {"ar": "فعّل اشتراكك", "fr": "Activer votre abonnement"},
    "db.progress_title": {"ar": "تقدّمك الدراسي", "fr": "Votre progression"},
    "db.finished_n_of": {"ar": "أنهيت {done} من {total} درسًا", "fr": "Terminé {done} sur {total} cours"},
    "db.next_lesson": {"ar": "الدرس القادم: {title} ←", "fr": "Prochain cours : {title} ←"},
    "db.all_done": {"ar": "🎉 أنهيت كل دروس {subject} لمستواك!", "fr": "🎉 Vous avez terminé tous les cours de {subject} pour votre niveau !"},
    "db.no_lessons_yet": {"ar": "لا توجد دروس بعد لهذه المادة في مستواك.", "fr": "Pas encore de cours pour cette matière à votre niveau."},
    "db.your_level_courses": {"ar": "دروس مستواك", "fr": "Les cours de votre niveau"},
    "db.explore_other_levels": {"ar": "استكشف بقيّة المستويات ←", "fr": "Explorer les autres niveaux ←"},
    "db.nearest_lives": {"ar": "🔴 أقرب الحصص المباشرة لمستواك", "fr": "🔴 Prochaines sessions en direct pour votre niveau"},
    "db.full_program": {"ar": "كامل البرنامج ←", "fr": "Programme complet ←"},
    "db.no_lives_for_level": {"ar": "لا توجد حصص مبرمجة حاليًا لمستوى {level}.", "fr": "Aucune session programmée pour le niveau {level}."},
    "db.watch_full_program": {"ar": "شاهد كامل البرنامج ←", "fr": "Voir le programme complet ←"},
    "db.my_payments": {"ar": "💳 مدفوعاتي", "fr": "💳 Mes paiements"},
    "db.status_approved": {"ar": "مقبول", "fr": "Accepté"},
    "db.status_pending": {"ar": "قيد المراجعة", "fr": "En cours de vérification"},
    "db.status_rejected": {"ar": "مرفوض", "fr": "Refusé"},
    "db.no_payments": {"ar": "لا توجد عمليات دفع بعد.", "fr": "Aucun paiement pour le moment."},
    "db.discover_offers": {"ar": "اكتشف العروض ←", "fr": "Découvrir les offres ←"},

    # profile.html
    "pf.title": {"ar": "ملفي الشخصي", "fr": "Mon profil"},
    "pf.my_account": {"ar": "حسابي", "fr": "Mon compte"},
    "pf.account_info": {"ar": "معلومات حسابك في أكاديمية SCROL.", "fr": "Les informations de votre compte sur SCROL Academy."},
    "pf.personal_info": {"ar": "👤 المعلومات الشخصية", "fr": "👤 Informations personnelles"},
    "pf.full_name": {"ar": "الاسم الكامل", "fr": "Nom complet"},
    "pf.email": {"ar": "البريد الإلكتروني", "fr": "Email"},
    "pf.phone": {"ar": "الهاتف", "fr": "Téléphone"},
    "pf.level": {"ar": "المستوى الدراسي", "fr": "Niveau scolaire"},
    "pf.member_since": {"ar": "عضو منذ", "fr": "Membre depuis"},
    "pf.my_activity": {"ar": "📈 نشاطي", "fr": "📈 Mon activité"},
    "pf.completed_lessons": {"ar": "الدروس المكتملة", "fr": "Cours terminés"},
    "pf.n_lessons": {"ar": "{n} درسًا", "fr": "{n} cours"},
    "pf.watch_minutes": {"ar": "دقائق المشاهدة", "fr": "Minutes visionnées"},
    "pf.n_minutes": {"ar": "{n} دقيقة", "fr": "{n} min"},
    "pf.sub_status": {"ar": "حالة الاشتراك", "fr": "Statut de l'abonnement"},
    "pf.active_until": {"ar": "مفعّل حتى {date}", "fr": "Actif jusqu'au {date}"},
    "pf.settings_soon": {"ar": "تعديل كلمة المرور وإعدادات الحساب قريبًا 🔒", "fr": "Modification du mot de passe et des paramètres bientôt disponible 🔒"},

    # schedule.html
    "sc.title": {"ar": "جدولي", "fr": "Mon planning"},
    "sc.eyebrow": {"ar": "تنظيم وقتي", "fr": "Organiser mon temps"},
    "sc.h1": {"ar": "🗓️ جدولي الأسبوعي", "fr": "🗓️ Mon planning hebdomadaire"},
    "sc.sub": {"ar": "خصّص فترات مراجعة لنفسك — مثلًا ساعتان من 18:00 إلى 20:00 يوم الاثنين.",
               "fr": "Réservez-vous des créneaux de révision — par exemple 2 heures de "
                     "18h00 à 20h00 le lundi."},
    "sc.add_block": {"ar": "＋ أضف فترة مراجعة", "fr": "＋ Ajouter un créneau de révision"},
    "sc.day": {"ar": "اليوم", "fr": "Jour"},
    "sc.from_time": {"ar": "من الساعة", "fr": "De"},
    "sc.to_time": {"ar": "إلى الساعة", "fr": "À"},
    "sc.subject_optional": {"ar": "المادة (اختياري)", "fr": "Matière (facultatif)"},
    "sc.no_selection": {"ar": "— بدون تحديد —", "fr": "— Aucune sélection —"},
    "sc.note_optional": {"ar": "ملاحظة (اختياري)", "fr": "Note (facultatif)"},
    "sc.note_ph": {"ar": "مثال: مراجعة الجذور المربعة", "fr": "Exemple : révision des racines carrées"},
    "sc.add_to_schedule": {"ar": "إضافة إلى الجدول", "fr": "Ajouter au planning"},
    "sc.delete": {"ar": "حذف", "fr": "Supprimer"},
    "sc.study_block": {"ar": "فترة مراجعة", "fr": "Créneau de révision"},
    "sc.agenda_title": {"ar": "🗓️ أجندة الأسبوع", "fr": "🗓️ Agenda de la semaine"},
    "sc.agenda_sub": {"ar": "فتراتك الشخصية والحصص المباشرة لمستواك، في نفس الأجندة.",
                       "fr": "Vos créneaux personnels et les sessions en direct de votre "
                             "niveau, dans le même agenda."},
    "sc.today": {"ar": "اليوم", "fr": "Aujourd'hui"},
    "sc.live_badge": {"ar": "مباشر", "fr": "Direct"},
    "sc.legend_mine": {"ar": "فتراتي", "fr": "Mes créneaux"},
    "sc.legend_live": {"ar": "حصص مباشرة", "fr": "Sessions en direct"},
    "sc.prev_week": {"ar": "الأسبوع السابق", "fr": "Semaine précédente"},
    "sc.next_week": {"ar": "الأسبوع التالي", "fr": "Semaine suivante"},
    "sc.back_today": {"ar": "الرجوع إلى هذا الأسبوع", "fr": "Revenir à cette semaine"},
    "sc.no_items_day": {"ar": "لا توجد فترات مبرمجة", "fr": "Aucun créneau"},
    "sc.repeat_label": {"ar": "التكرار", "fr": "Répétition"},
    "sc.repeat_none": {"ar": "لا يتكرر", "fr": "Ne se répète pas"},
    "sc.repeat_daily": {"ar": "كل يوم", "fr": "Chaque jour"},
    "sc.repeat_weekly": {"ar": "كل أسبوع", "fr": "Chaque semaine"},
    "sc.edit_block": {"ar": "تعديل الفترة", "fr": "Modifier le créneau"},

    # pomodoro (schedule.html card + global floating widget in base.html)
    "pomo.widget_title": {"ar": "بومودورو", "fr": "Pomodoro"},
    "pomo.card_title": {"ar": "🍅 تقنية بومودورو", "fr": "🍅 Technique Pomodoro"},
    "pomo.card_sub": {"ar": "قسّم وقت مراجعتك إلى فترات تركيز وفترات راحة قصيرة.",
                       "fr": "Découpez votre temps de révision en périodes de concentration et de courtes pauses."},
    "pomo.quick_start_hint": {"ar": "اختر مدة وابدأ فترة تركيز.", "fr": "Choisissez une durée et démarrez une session."},
    "pomo.preset_label": {"ar": "{work} / {rest} د", "fr": "{work} / {rest} min"},
    "pomo.custom": {"ar": "⚙️ مخصص", "fr": "⚙️ Personnalisé"},
    "pomo.work_duration": {"ar": "مدة التركيز", "fr": "Durée de concentration"},
    "pomo.break_duration": {"ar": "مدة الراحة", "fr": "Durée de pause"},
    "pomo.minutes_short": {"ar": "د", "fr": "min"},
    "pomo.start": {"ar": "ابدأ", "fr": "Démarrer"},
    "pomo.pause": {"ar": "إيقاف مؤقت", "fr": "Pause"},
    "pomo.resume": {"ar": "استئناف", "fr": "Reprendre"},
    "pomo.stop": {"ar": "إنهاء", "fr": "Arrêter"},
    "pomo.phase_work": {"ar": "⏳ وقت التركيز", "fr": "⏳ Temps de concentration"},
    "pomo.phase_break": {"ar": "☕ وقت الراحة", "fr": "☕ Temps de pause"},
    "pomo.notif_work_done": {"ar": "انتهت فترة التركيز! حان وقت الراحة 🎉",
                              "fr": "Session de concentration terminée ! C'est l'heure de la pause 🎉"},
    "pomo.notif_break_done": {"ar": "انتهت الراحة! عد للتركيز 💪",
                               "fr": "Pause terminée ! Retour à la concentration 💪"},
    "pomo.customize_link": {"ar": "تخصيص المدة في الجدول ←", "fr": "Personnaliser dans le planning ←"},

    # first-visit onboarding tour (base.html modal, student-only)
    "tour.step1_title": {"ar": "👋 أهلًا بك في أكاديمية SCROL", "fr": "👋 Bienvenue sur SCROL Academy"},
    "tour.step1_body": {"ar": "منصّتك لتعلّم الرياضيات والفيزياء خطوة بخطوة، بمستواك الدراسي ولغتك المفضّلة. خلّينا نتعرّف سريعًا على أهم الأقسام.",
                         "fr": "Votre plateforme pour apprendre les maths et la physique étape par étape, selon votre niveau et dans la langue de votre choix. Faisons un tour rapide des sections principales."},
    "tour.step2_title": {"ar": "📖 دروسك", "fr": "📖 Vos cours"},
    "tour.step2_body": {"ar": "من «دروسي» تصل مباشرة إلى محاور مستواك الدراسي — أول درس في كل محور مجاني للجميع، والباقي متاح للمشتركين.",
                         "fr": "Depuis « Mes cours », accédez directement aux chapitres de votre niveau — le premier cours de chaque chapitre est gratuit pour tous, le reste est réservé aux abonnés."},
    "tour.step3_title": {"ar": "🔴 الحصص المباشرة والدردشة", "fr": "🔴 Sessions en direct et chat"},
    "tour.step3_body": {"ar": "تابع الحصص المباشرة لمستواك، وتواصل مع أستاذك وزملائك في قسم الدردشة — قسم عام مع الأستاذ وقسم آخر بين الطلاب فقط.",
                         "fr": "Suivez les sessions en direct de votre niveau, et échangez avec votre professeur et vos camarades dans le chat — un canal général avec le professeur, et un autre entre élèves seulement."},
    "tour.step4_title": {"ar": "🗓️ خطّط وقتك", "fr": "🗓️ Planifiez votre temps"},
    "tour.step4_body": {"ar": "في «الجدول» نظّم فترات مراجعتك، وجرّب تقنية بومودورو 🍅 لتقسيم وقتك إلى فترات تركيز وراحة قصيرة.",
                         "fr": "Dans « Planning », organisez vos périodes de révision, et essayez la technique Pomodoro 🍅 pour alterner concentration et courtes pauses."},
    "tour.step5_title": {"ar": "📈 تتبّع تقدّمك", "fr": "📈 Suivez votre progression"},
    "tour.step5_body": {"ar": "لوحة التحكم تعرض تقدّمك في كل مادة، ولوحة الصدارة ترتيبك بين زملائك. ولأي سؤال، المساعد الذكي 🤖 دائمًا في خدمتك!",
                         "fr": "Le tableau de bord affiche votre progression par matière, et le classement votre rang parmi vos camarades. Pour toute question, l'assistant IA 🤖 est toujours disponible !"},
    "tour.step_of": {"ar": "الخطوة {n} من {total}", "fr": "Étape {n} sur {total}"},
    "tour.next": {"ar": "التالي ←", "fr": "Suivant →"},
    "tour.prev": {"ar": "→ السابق", "fr": "← Précédent"},
    "tour.skip": {"ar": "تخطّي", "fr": "Passer"},
    "tour.finish": {"ar": "ابدأ الآن 🚀", "fr": "Commencer 🚀"},
    "tour.replay_title": {"ar": "الجولة التعريفية", "fr": "Visite guidée"},
    "tour.replay_sub": {"ar": "أعد مشاهدة جولة التعريف بالمنصّة في أي وقت.", "fr": "Revoyez à tout moment la visite guidée de la plateforme."},
    "tour.replay_btn": {"ar": "🎯 إعادة عرض الجولة", "fr": "🎯 Revoir la visite"},

    # first-visit welcome tour for logged-out guests (base.html, homepage only)
    "gtour.step1_title": {"ar": "🎓 مرحبًا بك في أكاديمية SCROL", "fr": "🎓 Bienvenue sur SCROL Academy"},
    "gtour.step1_body": {"ar": "منصّة تونسية لتعلّم الرياضيات والفيزياء، من السابعة أساسي إلى البكالوريا، بدروس فيديو ومتابعة أسبوعية.",
                          "fr": "Une plateforme tunisienne pour apprendre les maths et la physique, de la 7ème année de base au Bac, avec des cours vidéo et un suivi hebdomadaire."},
    "gtour.step2_title": {"ar": "🎁 أول درس مجاني في كل محور", "fr": "🎁 Le premier cours de chaque chapitre est gratuit"},
    "gtour.step2_body": {"ar": "جرّب المنصّة بدون التزام — أول درس من كل محور متاح مجانًا لكل الزوار، حتى قبل إنشاء حساب.",
                          "fr": "Essayez la plateforme sans engagement — le premier cours de chaque chapitre est accessible gratuitement, même avant de créer un compte."},
    "gtour.step3_title": {"ar": "🔴 حصص مباشرة ومجتمع تفاعلي", "fr": "🔴 Sessions en direct et communauté active"},
    "gtour.step3_body": {"ar": "احضر حصصًا مباشرة أسبوعية، وتواصل مع أستاذك وزملائك في دردشة كل مستوى.",
                          "fr": "Assistez à des sessions en direct chaque semaine, et échangez avec votre professeur et vos camarades dans le chat de votre niveau."},
    "gtour.step4_title": {"ar": "🚀 ابدأ رحلتك الآن", "fr": "🚀 Commencez votre parcours dès maintenant"},
    "gtour.step4_body": {"ar": "أنشئ حسابك المجاني في أقل من دقيقة، واختر مستواك الدراسي لتصل مباشرة إلى محتواك.",
                          "fr": "Créez votre compte gratuit en moins d'une minute, choisissez votre niveau, et accédez directement à votre contenu."},
    "gtour.cta_btn": {"ar": "إنشاء حساب مجاني", "fr": "Créer un compte gratuit"},

    # chat.html
    "ct.title": {"ar": "الدردشة", "fr": "Chat"},
    "ct.level_eyebrow": {"ar": "مستوى {level}", "fr": "Niveau {level}"},
    "ct.h1": {"ar": "💬 الدردشة", "fr": "💬 Chat"},
    "ct.sub": {"ar": "تواصل مع أستاذك وزملائك في نفس المستوى.",
               "fr": "Échangez avec votre professeur et vos camarades du même niveau."},
    "ct.empty_title": {"ar": "لا توجد رسائل بعد", "fr": "Aucun message pour le moment"},
    "ct.empty_p": {"ar": "كن أول من يكتب رسالة هنا.", "fr": "Soyez le premier à écrire un message ici."},
    "ct.tab_general": {"ar": "🎓 عام (مع الأستاذ)", "fr": "🎓 Général (avec le professeur)"},
    "ct.tab_students": {"ar": "🧑‍🤝‍🧑 بين الطلاب", "fr": "🧑‍🤝‍🧑 Entre élèves"},
    "ct.placeholder": {"ar": "اكتب رسالتك…", "fr": "Écrivez votre message…"},
    "ct.send": {"ar": "إرسال", "fr": "Envoyer"},
    "ct.admin_badge": {"ar": "الأستاذ", "fr": "Professeur"},

    # leaderboard.html
    "lb.title": {"ar": "لوحة الصدارة", "fr": "Classement"},
    "lb.live": {"ar": "مباشر", "fr": "En direct"},
    "lb.h1": {"ar": "🏆 لوحة الصدارة", "fr": "🏆 Classement"},
    "lb.sub": {"ar": "ترتيب تلاميذ مستوى {level} حسب عدد الدروس المكتملة — تتحدّث تلقائيًا.",
               "fr": "Classement des élèves du niveau {level} selon le nombre de cours "
                     "terminés — mis à jour automatiquement."},
    "lb.level_label": {"ar": "المستوى:", "fr": "Niveau :"},
    "lb.rank": {"ar": "#", "fr": "#"},
    "lb.student": {"ar": "التلميذ", "fr": "Élève"},
    "lb.completed_lessons": {"ar": "الدروس المكتملة", "fr": "Cours terminés"},
    "lb.you": {"ar": "(أنت)", "fr": "(vous)"},
    "lb.empty": {"ar": "لا يوجد تلاميذ في هذا المستوى بعد.", "fr": "Aucun élève dans ce niveau pour le moment."},

    # notifications.html
    "nt.title": {"ar": "الإشعارات", "fr": "Notifications"},
    "nt.new_badge": {"ar": "جديد", "fr": "Nouveau"},
    "nt.empty_title": {"ar": "لا توجد إشعارات بعد", "fr": "Aucune notification pour le moment"},
    "nt.empty_p": {"ar": "ستظهر هنا الإشعارات التي تُرسلها إدارة المنصة.", "fr": "Les notifications envoyées par l'administration apparaîtront ici."},

    # notification content (generated server-side)
    "notif.chat_title": {"ar": "💬 رسالة جديدة في الدردشة", "fr": "💬 Nouveau message dans le chat"},
    "notif.chat_body": {"ar": "{name}: {msg}", "fr": "{name} : {msg}"},

    # admin/panel.html
    "ad.title": {"ar": "لوحة الإدارة", "fr": "Panneau admin"},
    "ad.platform_mgmt": {"ar": "إدارة المنصة", "fr": "Gestion de la plateforme"},
    "ad.control_panel": {"ar": "لوحة التحكم", "fr": "Tableau de bord"},
    "ad.stat_students": {"ar": "تلميذ مسجّل", "fr": "élèves inscrits"},
    "ad.stat_subs": {"ar": "اشتراك مفعّل", "fr": "abonnements actifs"},
    "ad.stat_pending": {"ar": "دفع بانتظار المراجعة", "fr": "paiement(s) en attente"},
    "ad.stat_revenue": {"ar": "د.ت مداخيل مقبولة", "fr": "DT de revenus acceptés"},
    "ad.welcome_title": {"ar": "مرحبًا بك في نسخة التشغيل المحلي", "fr": "Bienvenue dans la version locale"},
    "ad.welcome_p": {"ar": "من هنا يمكنك قبول إشعارات الدفع، تفعيل الاشتراكات يدويًا، إضافة محاور "
                           "ودروس (برمز فيديو يوتيوب)، وبرمجة الحصص المباشرة. كل التعديلات تُحفَظ "
                           "في قاعدة البيانات academy.db — احذف الملف لإعادة البذر من الصفر.",
                      "fr": "Vous pouvez ici accepter les notifications de paiement, activer "
                            "manuellement des abonnements, ajouter des chapitres et des cours "
                            "(via un code vidéo YouTube), et programmer des sessions en "
                            "direct. Toutes les modifications sont enregistrées dans la base "
                            "de données academy.db — supprimez le fichier pour tout réinitialiser."},
    "ad.level": {"ar": "المستوى", "fr": "Niveau"},
    "ad.students_col": {"ar": "التلاميذ", "fr": "Élèves"},
    "ad.subscribers_col": {"ar": "المشتركون", "fr": "Abonnés"},
    "ad.lesson_views": {"ar": "مشاهدات الدروس", "fr": "Vues des cours"},
    "ad.completed_lessons_col": {"ar": "دروس مكتملة", "fr": "Cours terminés"},
    "ad.details": {"ar": "التفاصيل ←", "fr": "Détails ←"},
    "ad.level_details": {"ar": "تفاصيل مستوى {level}", "fr": "Détails du niveau {level}"},
    "ad.chapter": {"ar": "المحور", "fr": "Chapitre"},
    "ad.subject_col": {"ar": "المادة", "fr": "Matière"},
    "ad.lessons_col": {"ar": "الدروس", "fr": "Cours"},
    "ad.views_col": {"ar": "المشاهدات", "fr": "Vues"},
    "ad.completions_col": {"ar": "الإكمالات", "fr": "Complétions"},
    "ad.no_chapters_level": {"ar": "لا توجد محاور بعد لهذا المستوى.", "fr": "Aucun chapitre pour ce niveau pour le moment."},
    "ad.student_col": {"ar": "التلميذ", "fr": "Élève"},
    "ad.offer_col": {"ar": "العرض", "fr": "Offre"},
    "ad.amount_col": {"ar": "المبلغ", "fr": "Montant"},
    "ad.method_col": {"ar": "الطريقة", "fr": "Moyen"},
    "ad.reference_col": {"ar": "المرجع", "fr": "Référence"},
    "ad.date_col": {"ar": "التاريخ", "fr": "Date"},
    "ad.status_col": {"ar": "الحالة", "fr": "Statut"},
    "ad.action_col": {"ar": "إجراء", "fr": "Action"},
    "ad.accept": {"ar": "قبول ✓", "fr": "Accepter ✓"},
    "ad.reject": {"ar": "رفض ✕", "fr": "Refuser ✕"},
    "ad.no_payments_yet": {"ar": "لا توجد عمليات دفع بعد.", "fr": "Aucun paiement pour le moment."},
    "ad.name_col": {"ar": "الاسم", "fr": "Nom"},
    "ad.email_col": {"ar": "البريد", "fr": "Email"},
    "ad.role_col": {"ar": "الدور", "fr": "Rôle"},
    "ad.watch_col": {"ar": "دقائق المشاهدة", "fr": "Minutes visionnées"},
    "ad.watch_stat": {"ar": "{n} متابع، {pct}٪ بالمتوسط", "fr": "{n} spectateur(s), {pct}% en moyenne"},
    "ad.watch_stat_title": {"ar": "عدد التلاميذ الذين شاهدوا هذا الدرس ونسبة المشاهدة المتوسطة",
                             "fr": "Nombre d'élèves ayant regardé cette leçon et le pourcentage moyen visionné"},
    "ad.subscription_col": {"ar": "الاشتراك", "fr": "Abonnement"},
    "ad.role_admin": {"ar": "إدارة", "fr": "Admin"},
    "ad.role_student": {"ar": "تلميذ", "fr": "Élève"},
    "ad.active_until": {"ar": "مفعّل حتى {date}", "fr": "Actif jusqu'au {date}"},
    "ad.not_subscribed": {"ar": "غير مشترك", "fr": "Non abonné"},
    "ad.activate_extend": {"ar": "تفعيل/تمديد", "fr": "Activer/Prolonger"},
    "ad.stop": {"ar": "إيقاف", "fr": "Arrêter"},
    "ad.add_course_title": {"ar": "＋ إضافة محور جديد", "fr": "＋ Ajouter un nouveau chapitre"},
    "ad.level_field": {"ar": "المستوى", "fr": "Niveau"},
    "ad.subject_field": {"ar": "المادة", "fr": "Matière"},
    "ad.course_title_field": {"ar": "عنوان المحور", "fr": "Titre du chapitre"},
    "ad.course_title_ph": {"ar": "مثال: رياضيات — البكالوريا (دورة مراجعة)", "fr": "Exemple : Mathématiques — Baccalauréat (révision)"},
    "ad.short_desc": {"ar": "وصف قصير", "fr": "Description courte"},
    "ad.add_course_btn": {"ar": "إضافة المحور", "fr": "Ajouter le chapitre"},
    "ad.add_lesson_title": {"ar": "＋ إضافة درس فيديو", "fr": "＋ Ajouter un cours vidéo"},
    "ad.chapter_field": {"ar": "المحور", "fr": "Chapitre"},
    "ad.lesson_title_field": {"ar": "عنوان الدرس", "fr": "Titre du cours"},
    "ad.lesson_title_ph": {"ar": "مثال: تمارين حول النهايات — ج1", "fr": "Exemple : Exercices sur les limites — partie 1"},
    "ad.youtube_field": {"ar": "رابط يوتيوب أو رمز الفيديو", "fr": "Lien YouTube ou code de la vidéo"},
    "ad.duration_min_field": {"ar": "المدة (دقائق)", "fr": "Durée (minutes)"},
    "ad.is_free_check": {"ar": "درس مجاني", "fr": "Cours gratuit"},
    "ad.add_lesson_btn": {"ar": "إضافة الدرس", "fr": "Ajouter le cours"},
    "ad.current_content": {"ar": "المحاور والدروس الحالية", "fr": "Chapitres et cours actuels"},
    "ad.open_course_page": {"ar": "فتح صفحة المحور لعرض الدروس ←", "fr": "Ouvrir la page du chapitre pour voir les cours ←"},
    "ad.schedule_live_title": {"ar": "＋ برمجة حصة مباشرة", "fr": "＋ Programmer une session en direct"},
    "ad.session_title_field": {"ar": "العنوان", "fr": "Titre"},
    "ad.session_title_ph": {"ar": "مثال: مراجعة عامة — الاحتمالات", "fr": "Exemple : Révision générale — Probabilités"},
    "ad.datetime_field": {"ar": "التاريخ والساعة", "fr": "Date et heure"},
    "ad.teacher_field": {"ar": "الأستاذ(ة)", "fr": "Enseignant(e)"},
    "ad.teacher_ph": {"ar": "مثال: أ. سامي بن عمر", "fr": "Exemple : M. Sami Ben Omar"},
    "ad.stream_link_field": {"ar": "رابط البث (Meet/Zoom/YouTube)", "fr": "Lien de diffusion (Meet/Zoom/YouTube)"},
    "ad.add_session_btn": {"ar": "إضافة الحصة", "fr": "Ajouter la session"},
    "ad.session_col": {"ar": "الحصة", "fr": "Session"},
    "ad.subject_level_col": {"ar": "المادة/المستوى", "fr": "Matière/Niveau"},
    "ad.appointment_col": {"ar": "الموعد", "fr": "Rendez-vous"},
    "ad.delete": {"ar": "حذف", "fr": "Supprimer"},
    "ad.no_sessions": {"ar": "لا توجد حصص.", "fr": "Aucune session."},
    "ad.level_label": {"ar": "المستوى:", "fr": "Niveau :"},
    "ad.message_to_chat": {"ar": "＋ رسالة إلى دردشة {level}", "fr": "＋ Message pour le chat de {level}"},
    "ad.message_text": {"ar": "نص الرسالة", "fr": "Texte du message"},
    "ad.message_ph": {"ar": "اكتب رسالة للتلاميذ...", "fr": "Écrivez un message pour les élèves..."},
    "ad.send_btn": {"ar": "إرسال 💬", "fr": "Envoyer 💬"},
    "ad.message_log": {"ar": "سجل الرسائل — {level}", "fr": "Historique des messages — {level}"},
    "ad.message_col": {"ar": "الرسالة", "fr": "Message"},
    "ad.reactions_col": {"ar": "التفاعلات", "fr": "Réactions"},
    "ad.no_messages_level": {"ar": "لا توجد رسائل بعد لهذا المستوى.", "fr": "Aucun message pour ce niveau pour le moment."},
    "ad.send_notif_title": {"ar": "＋ إرسال إشعار", "fr": "＋ Envoyer une notification"},
    "ad.notif_title_field": {"ar": "العنوان", "fr": "Titre"},
    "ad.notif_title_ph": {"ar": "مثال: حصة مراجعة غدًا", "fr": "Exemple : Session de révision demain"},
    "ad.notif_text_field": {"ar": "النص", "fr": "Texte"},
    "ad.notif_text_ph": {"ar": "تفاصيل الإشعار...", "fr": "Détails de la notification..."},
    "ad.destination": {"ar": "الوجهة", "fr": "Destination"},
    "ad.all_students": {"ar": "كل التلاميذ", "fr": "Tous les élèves"},
    "ad.level_prefix": {"ar": "مستوى: {level}", "fr": "Niveau : {level}"},
    "ad.send_notif_btn": {"ar": "إرسال الإشعار 🔔", "fr": "Envoyer la notification 🔔"},
    "ad.recent_notifs": {"ar": "آخر الإشعارات المُرسَلة", "fr": "Dernières notifications envoyées"},
    "ad.recipients_col": {"ar": "المستلمون", "fr": "Destinataires"},
    "ad.no_notifs_sent": {"ar": "لم يُرسَل أي إشعار بعد.", "fr": "Aucune notification envoyée pour le moment."},

    # flash — content management additions
    "flash.course_updated": {"ar": "تم تحديث المحور.", "fr": "Le chapitre a été mis à jour."},
    "flash.course_deleted": {"ar": "حُذف المحور وكل دروسه.", "fr": "Le chapitre et tous ses cours ont été supprimés."},
    "flash.lesson_updated": {"ar": "تم تحديث الدرس.", "fr": "Le cours a été mis à jour."},
    "flash.resource_added": {"ar": "أُضيف المرفق.", "fr": "La ressource a été ajoutée."},
    "flash.resource_invalid": {"ar": "العنوان والرابط إجباريان.", "fr": "Le titre et le lien sont obligatoires."},
    "flash.resource_deleted": {"ar": "حُذف المرفق.", "fr": "La ressource a été supprimée."},
    "flash.quiz_question_added": {"ar": "أُضيف السؤال.", "fr": "La question a été ajoutée."},
    "flash.quiz_question_invalid": {"ar": "اكتب السؤال وأربعة اختيارات، وحدّد الإجابة الصحيحة.",
                                     "fr": "Rédigez la question et quatre choix, et indiquez la bonne réponse."},
    "flash.quiz_question_deleted": {"ar": "حُذف السؤال.", "fr": "La question a été supprimée."},
    "flash.quiz_no_questions": {"ar": "لا توجد أسئلة في هذا الاختبار بعد.", "fr": "Ce quiz n'a pas encore de questions."},
    "flash.quiz_submitted": {"ar": "أجبت عن {score} من {total}. 🎉", "fr": "Vous avez obtenu {score} sur {total}. 🎉"},

    # admin content — course/lesson management
    "ad.edit": {"ar": "تعديل", "fr": "Modifier"},
    "ad.save": {"ar": "حفظ", "fr": "Enregistrer"},
    "ad.delete_course_confirm_note": {"ar": "سيحذف هذا المحور وكل دروسه نهائيًا.", "fr": "Ceci supprimera définitivement ce chapitre et tous ses cours."},
    "ad.move_up": {"ar": "↑", "fr": "↑"},
    "ad.move_down": {"ar": "↓", "fr": "↓"},
    "ad.lesson_number": {"ar": "الدرس {n}", "fr": "Cours {n}"},
    "ad.resources_title": {"ar": "📎 المرفقات", "fr": "📎 Ressources"},
    "ad.resource_title_field": {"ar": "عنوان المرفق", "fr": "Titre de la ressource"},
    "ad.resource_title_ph": {"ar": "مثال: ملخص الدرس (PDF)", "fr": "Exemple : Résumé du cours (PDF)"},
    "ad.resource_url_field": {"ar": "الرابط", "fr": "Lien"},
    "ad.resource_url_ph": {"ar": "https://drive.google.com/...", "fr": "https://drive.google.com/..."},
    "ad.add_resource_btn": {"ar": "＋ إضافة", "fr": "＋ Ajouter"},
    "ad.no_resources": {"ar": "لا توجد مرفقات لهذا الدرس بعد.", "fr": "Aucune ressource pour ce cours pour le moment."},
    "ad.quiz_title": {"ar": "📝 اختبار المحور", "fr": "📝 Quiz du chapitre"},
    "ad.quiz_sub": {"ar": "اختبار قصير من اختيارات متعددة يظهر للتلميذ بعد قائمة الدروس.",
                     "fr": "Un court quiz à choix multiples affiché au élève après la liste des cours."},
    "ad.add_question": {"ar": "＋ إضافة سؤال", "fr": "＋ Ajouter une question"},
    "ad.question_field": {"ar": "نص السؤال", "fr": "Texte de la question"},
    "ad.option_n": {"ar": "الاختيار {n}", "fr": "Choix {n}"},
    "ad.correct_answer": {"ar": "الإجابة الصحيحة", "fr": "Bonne réponse"},
    "ad.add_question_btn": {"ar": "إضافة السؤال", "fr": "Ajouter la question"},
    "ad.existing_questions": {"ar": "الأسئلة الحالية ({n})", "fr": "Questions actuelles ({n})"},
    "ad.no_questions_yet": {"ar": "لا توجد أسئلة بعد.", "fr": "Aucune question pour le moment."},
    "ad.correct_mark": {"ar": "✓ صحيح", "fr": "✓ Correct"},

    # course.html — quiz (student side)
    "qz.title": {"ar": "📝 اختبار المحور", "fr": "📝 Quiz du chapitre"},
    "qz.intro": {"ar": "اختبر فهمك لهذا المحور بأسئلة سريعة من اختيارات متعددة.",
                 "fr": "Testez votre compréhension de ce chapitre avec des questions rapides à choix multiples."},
    "qz.n_questions": {"ar": "{n} سؤالًا", "fr": "{n} questions"},
    "qz.start_quiz": {"ar": "ابدأ الاختبار ←", "fr": "Commencer le quiz ←"},
    "qz.subscribers_only": {"ar": "الاختبار متاح للمشتركين فقط.", "fr": "Le quiz est réservé aux abonnés."},
    "qz.not_ready": {"ar": "لم يُضِف الأستاذ اختبارًا لهذا المحور بعد.", "fr": "L'enseignant n'a pas encore ajouté de quiz pour ce chapitre."},
    "qz.your_attempts": {"ar": "محاولاتك السابقة", "fr": "Vos tentatives précédentes"},
    "qz.submit": {"ar": "تصحيح الإجابات", "fr": "Corriger les réponses"},
    "qz.result_title": {"ar": "نتيجتك", "fr": "Votre résultat"},
    "qz.result_score": {"ar": "{score} من {total}", "fr": "{score} sur {total}"},
    "qz.retake": {"ar": "أعد المحاولة", "fr": "Retenter"},
    "qz.back_to_course": {"ar": "← العودة إلى المحور", "fr": "← Retour au chapitre"},
    "qz.your_answer_correct": {"ar": "✓ إجابة صحيحة", "fr": "✓ Bonne réponse"},
    "qz.your_answer_wrong": {"ar": "✕ إجابة خاطئة — الصحيحة:", "fr": "✕ Réponse incorrecte — la bonne réponse :"},

    # profile.html — quiz history
    "pf.quiz_history": {"ar": "📝 نتائج اختباراتي", "fr": "📝 Mes résultats de quiz"},
    "pf.no_quiz_attempts": {"ar": "لم تخض أي اختبار بعد.", "fr": "Vous n'avez encore passé aucun quiz."},

    # watch.html — resources
    "wa.resources_title": {"ar": "📎 مرفقات الدرس", "fr": "📎 Ressources du cours"},

    # watch.html — notes
    "notes.title": {"ar": "📝 ملاحظاتي", "fr": "📝 Mes notes"},
    "notes.add_at": {"ar": "أضف ملاحظة عند", "fr": "Ajouter une note à"},
    "notes.placeholder": {"ar": "اكتب ملاحظتك هنا…", "fr": "Écrivez votre note ici…"},
    "notes.add_btn": {"ar": "إضافة", "fr": "Ajouter"},
    "notes.export_pdf": {"ar": "⬇️ تصدير PDF", "fr": "⬇️ Exporter en PDF"},
    "notes.empty": {"ar": "لا توجد ملاحظات بعد لهذا الدرس.", "fr": "Aucune note pour ce cours pour l'instant."},
    "notes.delete": {"ar": "حذف", "fr": "Supprimer"},
}


FAQ_ITEMS = [
    {"ar": ("هل المحتوى مطابق للبرنامج الرسمي التونسي؟",
            "نعم، كل المحاور مرتّبة حسب البرامج الرسمية لوزارة التربية، من السابعة أساسي "
            "إلى البكالوريا، وتُحدَّث كل سنة دراسية."),
     "fr": ("Le contenu suit-il le programme officiel tunisien ?",
            "Oui, tous les chapitres sont organisés selon les programmes officiels du "
            "ministère de l'Éducation, de la 7ème de base au Baccalauréat, et mis à jour "
            "chaque année scolaire.")},
    {"ar": ("هل يمكنني تجربة المنصة قبل الدفع؟",
            "بالتأكيد. أنشئ حسابًا مجانيًا وشاهد أول درس فيديو في كل محور دون أي التزام، "
            "ثم اشترك متى اقتنعت."),
     "fr": ("Puis-je essayer la plateforme avant de payer ?",
            "Bien sûr. Créez un compte gratuit et regardez la première vidéo de chaque "
            "chapitre sans engagement, puis abonnez-vous quand vous êtes convaincu.")},
    {"ar": ("كيف تجري الحصص المباشرة؟",
            "حصص أسبوعية عبر رابط بث مباشر يظهر للمشتركين قبل الموعد، مع إمكانية طرح "
            "الأسئلة والإجابة عليها مباشرة."),
     "fr": ("Comment se déroulent les sessions en direct ?",
            "Des sessions hebdomadaires via un lien de diffusion visible par les abonnés "
            "avant l'heure, avec la possibilité de poser des questions en direct.")},
    {"ar": ("ما هي طرق الدفع المتاحة؟",
            "D17، تطبيق Flouci، تحويل بنكي أو حوالة بريدية. بعد تأكيد الدفع يُفعَّل حسابك "
            "ويصلك إشعار داخل المنصة."),
     "fr": ("Quels sont les moyens de paiement disponibles ?",
            "D17, l'application Flouci, virement bancaire ou mandat postal. Après "
            "confirmation du paiement, votre compte est activé et vous recevez une "
            "notification sur la plateforme.")},
    {"ar": ("نسيت كلمة المرور، ماذا أفعل؟",
            "في هذه النسخة التجريبية تواصل مع إدارة المنصة عبر الواتساب أو البريد "
            "لإعادة تعيينها."),
     "fr": ("J'ai oublié mon mot de passe, que faire ?",
            "Dans cette version de démonstration, contactez l'administration par "
            "WhatsApp ou email pour le réinitialiser.")},
    {"ar": ("هل يمكنني الاشتراك في مادة واحدة فقط؟",
            "نعم — يمكنك اختيار باقة مادة واحدة (رياضيات أو فيزياء أو غيرها) بسعر أقل، "
            "أو باقة الوصول الكامل لكل المواد دفعة واحدة."),
     "fr": ("Puis-je m'abonner à une seule matière ?",
            "Oui — vous pouvez choisir un pack pour une seule matière (maths, physique, "
            "ou autre) à prix réduit, ou le pack accès complet pour toutes les matières.")},
]


def t(key, **kwargs):
    entry = TR.get(key)
    text = entry.get(get_lang(), entry.get("ar", key)) if entry else key
    return text.format(**kwargs) if kwargs else text


app.jinja_env.globals.update(
    t=t, level_name=level_name, subject_name=subject_name,
    pay_method_name=pay_method_name, course_title=course_title,
    course_description=course_description, lesson_title=lesson_title,
    lesson_description=lesson_description, has_subject_access=has_subject_access,
)


@app.route("/lang/<code>")
def set_lang(code):
    if code in ("ar", "fr"):
        session["lang"] = code
    return redirect(request.referrer or url_for("index"))


@app.route("/theme/<mode>")
def set_theme(mode):
    if mode in ("light", "dark"):
        session["theme"] = mode
    return redirect(request.referrer or url_for("index"))


def unread_notifications_count():
    if not g.user or g.user["role"] != "student":
        return 0
    return query("SELECT COUNT(*) c FROM notifications WHERE user_id=? "
                 "AND read_at IS NULL", (g.user["id"],), one=True)["c"]


def pending_payments_count():
    if not g.user or g.user["role"] != "admin":
        return 0
    return query("SELECT COUNT(*) c FROM payments WHERE status='pending'",
                 one=True)["c"]


@app.context_processor
def inject_globals():
    lang = get_lang()
    levels_rows = _levels_dict()
    subjects_rows = _subjects_dict()
    levels = [(c, r["name_ar"] if lang == "ar" else r["name_fr"]) for c, r in levels_rows.items()]
    subjects = [(c, r["name_ar"] if lang == "ar" else r["name_fr"]) for c, r in subjects_rows.items()]
    subject_meta = {c: {"name": (r["name_ar"] if lang == "ar" else r["name_fr"]),
                        "color": r["color"], "glyph": r["glyph"]}
                    for c, r in subjects_rows.items()}
    pay_methods = [(c, PAY_METHOD_NAMES[c][lang]) for c in PAY_METHOD_CODES]
    plans = {c: plan_info(c) for c in PLAN_INFO}
    return dict(LEVELS=levels, LEVEL_MAP=dict(levels),
                SUBJECTS=subjects, SUBJECT_MAP=dict(subjects),
                SUBJECT_META=subject_meta,
                PAY_METHODS=pay_methods, PAY_METHOD_MAP=dict(pay_methods),
                PLANS=plans, subscribed=is_subscribed(),
                today=dt.date.today().isoformat(),
                unread_count=unread_notifications_count(),
                pending_payments=pending_payments_count(),
                lang=lang, text_dir="rtl" if lang == "ar" else "ltr",
                theme=get_theme(), TURNSTILE_SITE_KEY=TURNSTILE_SITE_KEY)


# ----------------------------------------------------------------------------
# Template filters
# ----------------------------------------------------------------------------
DAY_NAMES = {
    0: {"ar": "الاثنين", "fr": "lundi"}, 1: {"ar": "الثلاثاء", "fr": "mardi"},
    2: {"ar": "الأربعاء", "fr": "mercredi"}, 3: {"ar": "الخميس", "fr": "jeudi"},
    4: {"ar": "الجمعة", "fr": "vendredi"}, 5: {"ar": "السبت", "fr": "samedi"},
    6: {"ar": "الأحد", "fr": "dimanche"},
}
MONTH_NAMES = {
    1: {"ar": "جانفي", "fr": "janvier"}, 2: {"ar": "فيفري", "fr": "février"},
    3: {"ar": "مارس", "fr": "mars"}, 4: {"ar": "أفريل", "fr": "avril"},
    5: {"ar": "ماي", "fr": "mai"}, 6: {"ar": "جوان", "fr": "juin"},
    7: {"ar": "جويلية", "fr": "juillet"}, 8: {"ar": "أوت", "fr": "août"},
    9: {"ar": "سبتمبر", "fr": "septembre"}, 10: {"ar": "أكتوبر", "fr": "octobre"},
    11: {"ar": "نوفمبر", "fr": "novembre"}, 12: {"ar": "ديسمبر", "fr": "décembre"},
}


@app.template_filter("ardate")
def ardate(value):
    """'2026-08-07 18:00' → 'الجمعة 07 أوت — 18:00' (or French equivalent)"""
    try:
        d = dt.datetime.strptime(value, "%Y-%m-%d %H:%M")
        lang = get_lang()
        day, month = DAY_NAMES[d.weekday()][lang], MONTH_NAMES[d.month][lang]
        return f"{day} {d.day:02d} {month} — {d.strftime('%H:%M')}"
    except Exception:
        return value


@app.template_filter("ardateshort")
def ardateshort(value):
    try:
        d = dt.date.fromisoformat(value[:10])
        return f"{d.day:02d} {MONTH_NAMES[d.month][get_lang()]} {d.year}"
    except Exception:
        return value


@app.template_filter("hms")
def fmt_hms(total_seconds):
    """1800 → '30:00', 4025 → '1:07:05' — used for note/video timestamps."""
    total_seconds = max(0, int(total_seconds or 0))
    h, rem = divmod(total_seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


# ----------------------------------------------------------------------------
# Public pages
# ----------------------------------------------------------------------------
@app.route("/")
def index():
    stats = {
        "students": query("SELECT COUNT(*) c FROM users WHERE role='student'",
                          one=True)["c"],
        "lessons": query("SELECT COUNT(*) c FROM lessons", one=True)["c"],
        "lives": query("SELECT COUNT(*) c FROM live_sessions", one=True)["c"],
    }
    free_samples = query(
        """SELECT l.id, l.title, l.position, l.duration_min, c.subject, c.level_code
           FROM lessons l JOIN courses c ON c.id = l.course_id
           WHERE l.is_free = 1 AND c.level_code IN ('9b','bac')
           ORDER BY c.subject, c.level_code LIMIT 4""")
    next_live = query(
        "SELECT * FROM live_sessions WHERE starts_at >= ? ORDER BY starts_at LIMIT 1",
        (dt.datetime.now().strftime("%Y-%m-%d %H:%M"),), one=True)
    faqs = [f[get_lang()] for f in FAQ_ITEMS]
    return render_template("index.html", stats=stats, faqs=faqs,
                           free_samples=free_samples, next_live=next_live)


@app.route("/legal/<page>")
def legal(page):
    if page not in ("terms", "privacy"):
        abort(404)
    return render_template("legal.html", page=page)


# ----------------------------------------------------------------------------
# Auth
# ----------------------------------------------------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        level = request.form.get("level", "")
        pw = request.form.get("password", "")
        captcha_token = request.form.get("cf-turnstile-response", "")
        if not name or not email or not phone or not pw:
            flash(t("flash.register_required_fields"), "error")
        elif len(pw) < 6:
            flash(t("flash.password_too_short"), "error")
        elif level not in all_level_codes():
            flash(t("flash.choose_level"), "error")
        elif query("SELECT id FROM users WHERE email=?", (email,), one=True):
            flash(t("flash.email_taken"), "error")
        elif not verify_turnstile(captcha_token, request.remote_addr):
            flash(t("flash.captcha_failed"), "error")
        else:
            now = dt.datetime.now()
            code = generate_verify_code()
            uid = execute(
                "INSERT INTO users(name,email,phone,password_hash,level_code,"
                "email_verified,verify_code,verify_expires,verify_sent_at,created_at) "
                "VALUES(?,?,?,?,?,0,?,?,?,?)",
                (name, email, phone, generate_password_hash(pw), level, code,
                 (now + dt.timedelta(minutes=VERIFY_CODE_TTL_MIN)).strftime("%Y-%m-%d %H:%M:%S"),
                 now.strftime("%Y-%m-%d %H:%M:%S"),
                 now.strftime("%Y-%m-%d %H:%M")))
            send_verification_email(email, name, code)
            session["pending_uid"] = uid
            return redirect(url_for("verify_email"))
    return render_template("register.html")


@app.route("/verify-email", methods=["GET", "POST"])
def verify_email():
    pending_uid = session.get("pending_uid")
    if not pending_uid:
        return redirect(url_for("register"))
    user = query("SELECT * FROM users WHERE id=?", (pending_uid,), one=True)
    if not user or user["email_verified"]:
        session.pop("pending_uid", None)
        return redirect(url_for("register"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        try:
            expired = dt.datetime.strptime(
                user["verify_expires"], "%Y-%m-%d %H:%M:%S") < dt.datetime.now()
        except (TypeError, ValueError):
            expired = True
        if not code or not user["verify_code"] or code != user["verify_code"]:
            flash(t("flash.verify_code_wrong"), "error")
        elif expired:
            flash(t("flash.verify_code_expired"), "error")
        else:
            execute("UPDATE users SET email_verified=1, verify_code=NULL, "
                    "verify_expires=NULL, verify_sent_at=NULL WHERE id=?", (user["id"],))
            session.pop("pending_uid", None)
            session["uid"] = user["id"]
            flash(t("flash.welcome_new", name=user["name"]), "ok")
            return redirect(url_for("courses"))
    return render_template("verify_email.html", pending_email=user["email"])


@app.route("/verify-email/resend", methods=["POST"])
def verify_email_resend():
    pending_uid = session.get("pending_uid")
    if not pending_uid:
        return redirect(url_for("register"))
    user = query("SELECT * FROM users WHERE id=?", (pending_uid,), one=True)
    if not user or user["email_verified"]:
        session.pop("pending_uid", None)
        return redirect(url_for("register"))

    now = dt.datetime.now()
    if user["verify_sent_at"]:
        try:
            last_sent = dt.datetime.strptime(user["verify_sent_at"], "%Y-%m-%d %H:%M:%S")
            if (now - last_sent).total_seconds() < VERIFY_RESEND_COOLDOWN_SEC:
                flash(t("flash.verify_resend_wait"), "warn")
                return redirect(url_for("verify_email"))
        except ValueError:
            pass
    code = generate_verify_code()
    execute("UPDATE users SET verify_code=?, verify_expires=?, verify_sent_at=? WHERE id=?",
            (code, (now + dt.timedelta(minutes=VERIFY_CODE_TTL_MIN)).strftime("%Y-%m-%d %H:%M:%S"),
             now.strftime("%Y-%m-%d %H:%M:%S"), user["id"]))
    send_verification_email(user["email"], user["name"], code)
    flash(t("flash.verify_resend_ok"), "ok")
    return redirect(url_for("verify_email"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("admin_panel") if g.user["role"] in ("admin", "prof") else url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        user = query("SELECT * FROM users WHERE email=?", (email,), one=True)
        if user and check_password_hash(user["password_hash"], pw):
            if not user["email_verified"]:
                session["pending_uid"] = user["id"]
                flash(t("flash.verify_needed"), "warn")
                return redirect(url_for("verify_email"))
            session["uid"] = user["id"]
            flash(t("flash.welcome_back", name=user["name"].split()[0]), "ok")
            nxt = request.args.get("next")
            if user["role"] in ("admin", "prof"):
                return redirect(nxt or url_for("admin_panel"))
            return redirect(nxt or url_for("dashboard"))
        flash(t("flash.bad_credentials"), "error")
    return render_template("login.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        user = query("SELECT * FROM users WHERE email=?", (email,), one=True)
        if user:
            now = dt.datetime.now()
            code = generate_verify_code()
            execute("UPDATE users SET reset_code=?, reset_expires=?, reset_sent_at=? WHERE id=?",
                    (code, (now + dt.timedelta(minutes=VERIFY_CODE_TTL_MIN)).strftime("%Y-%m-%d %H:%M:%S"),
                     now.strftime("%Y-%m-%d %H:%M:%S"), user["id"]))
            send_reset_email(user["email"], user["name"], code)
            session["reset_uid"] = user["id"]
        flash(t("flash.reset_sent"), "ok")
        return redirect(url_for("reset_password"))
    return render_template("forgot_password.html")


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        new_pw = request.form.get("password", "")
        confirm_pw = request.form.get("confirm_password", "")
        reset_uid = session.get("reset_uid")
        user = query("SELECT * FROM users WHERE id=?", (reset_uid,), one=True) if reset_uid else None
        try:
            expired = (not user or not user["reset_expires"] or
                       dt.datetime.strptime(user["reset_expires"], "%Y-%m-%d %H:%M:%S") < dt.datetime.now())
        except ValueError:
            expired = True
        if not user or not code or not user["reset_code"] or code != user["reset_code"] or expired:
            flash(t("flash.reset_code_wrong"), "error")
        elif len(new_pw) < 6:
            flash(t("flash.password_too_short"), "error")
        elif new_pw != confirm_pw:
            flash(t("flash.reset_password_mismatch"), "error")
        else:
            execute("UPDATE users SET password_hash=?, reset_code=NULL, reset_expires=NULL, "
                    "reset_sent_at=NULL WHERE id=?", (generate_password_hash(new_pw), user["id"]))
            session.pop("reset_uid", None)
            flash(t("flash.reset_success"), "ok")
            return redirect(url_for("login"))
    return render_template("reset_password.html")


@app.route("/reset-password/resend", methods=["POST"])
def reset_password_resend():
    reset_uid = session.get("reset_uid")
    user = query("SELECT * FROM users WHERE id=?", (reset_uid,), one=True) if reset_uid else None
    if not user:
        return redirect(url_for("forgot_password"))
    now = dt.datetime.now()
    if user["reset_sent_at"]:
        try:
            last_sent = dt.datetime.strptime(user["reset_sent_at"], "%Y-%m-%d %H:%M:%S")
            if (now - last_sent).total_seconds() < VERIFY_RESEND_COOLDOWN_SEC:
                flash(t("flash.verify_resend_wait"), "warn")
                return redirect(url_for("reset_password"))
        except ValueError:
            pass
    code = generate_verify_code()
    execute("UPDATE users SET reset_code=?, reset_expires=?, reset_sent_at=? WHERE id=?",
            (code, (now + dt.timedelta(minutes=VERIFY_CODE_TTL_MIN)).strftime("%Y-%m-%d %H:%M:%S"),
             now.strftime("%Y-%m-%d %H:%M:%S"), user["id"]))
    send_reset_email(user["email"], user["name"], code)
    flash(t("flash.verify_resend_ok"), "ok")
    return redirect(url_for("reset_password"))


@app.route("/logout")
def logout():
    lang = session.get("lang")
    theme = session.get("theme")
    session.clear()
    if lang:
        session["lang"] = lang
    if theme:
        session["theme"] = theme
    flash(t("flash.logged_out"), "ok")
    return redirect(url_for("index"))


# ----------------------------------------------------------------------------
# Courses / lessons
# ----------------------------------------------------------------------------
@app.route("/courses")
def courses():
    level_param = request.args.get("level")
    if level_param is None and g.user and g.user["level_code"]:
        level = g.user["level_code"]      # default to the student's own level
    elif level_param == "all":
        level = ""
    else:
        level = level_param or ""
    subject = request.args.get("subject", "")
    sql = """SELECT c.*, COUNT(l.id) AS n_lessons,
                    SUM(l.is_free) AS n_free,
                    COALESCE(SUM(l.duration_min),0) AS total_min
             FROM courses c LEFT JOIN lessons l ON l.course_id = c.id"""
    where, args = [], []
    if level in all_level_codes():
        where.append("c.level_code = ?"); args.append(level)
    if subject in all_subject_codes():
        where.append("c.subject = ?"); args.append(subject)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " GROUP BY c.id ORDER BY c.subject, c.position, c.id"
    items = query(sql, args)
    return render_template("courses.html", items=items,
                           sel_level=level, sel_subject=subject)


@app.route("/course/<int:cid>")
def course(cid):
    c = query("SELECT * FROM courses WHERE id=?", (cid,), one=True)
    if not c:
        abort(404)
    lessons = query(
        "SELECT * FROM lessons WHERE course_id=? ORDER BY position, id", (cid,))
    quiz = query("SELECT * FROM quizzes WHERE course_id=?", (cid,), one=True)
    n_questions = 0
    if quiz:
        n_questions = query("SELECT COUNT(*) n FROM quiz_questions WHERE quiz_id=?",
                            (quiz["id"],), one=True)["n"]
    return render_template("course.html", c=c, lessons=lessons, quiz=quiz,
                           n_questions=n_questions)


@app.route("/course/<int:cid>/quiz")
@login_required
def course_quiz(cid):
    c = query("SELECT * FROM courses WHERE id=?", (cid,), one=True)
    if not c:
        abort(404)
    if not has_subject_access(c["subject"]):
        flash(t("qz.subscribers_only"), "warn")
        return redirect(url_for("course", cid=cid))
    quiz = query("SELECT * FROM quizzes WHERE course_id=?", (cid,), one=True)
    questions = []
    if quiz:
        qs = query("SELECT * FROM quiz_questions WHERE quiz_id=? ORDER BY position, id",
                   (quiz["id"],))
        for q in qs:
            opts = query("SELECT * FROM quiz_options WHERE question_id=? ORDER BY position, id",
                         (q["id"],))
            questions.append({"id": q["id"], "question": q["question"], "options": opts})
    my_attempts = query(
        "SELECT * FROM quiz_attempts WHERE quiz_id=? AND user_id=? "
        "ORDER BY created_at DESC LIMIT 5", (quiz["id"], g.user["id"])) if quiz else []
    return render_template("quiz.html", c=c, quiz=quiz, questions=questions,
                           my_attempts=my_attempts, result=None)


@app.route("/course/<int:cid>/quiz/submit", methods=["POST"])
@login_required
def course_quiz_submit(cid):
    c = query("SELECT * FROM courses WHERE id=?", (cid,), one=True)
    if not c:
        abort(404)
    if not has_subject_access(c["subject"]):
        abort(403)
    quiz = query("SELECT * FROM quizzes WHERE course_id=?", (cid,), one=True)
    if not quiz:
        abort(404)
    qs = query("SELECT * FROM quiz_questions WHERE quiz_id=? ORDER BY position, id",
              (quiz["id"],))
    score = 0
    questions = []
    for q in qs:
        opts = query("SELECT * FROM quiz_options WHERE question_id=? ORDER BY position, id",
                     (q["id"],))
        correct_opt = next((o for o in opts if o["is_correct"]), None)
        try:
            chosen_id = int(request.form.get(f"q{q['id']}", "0"))
        except ValueError:
            chosen_id = 0
        is_correct = bool(correct_opt) and chosen_id == correct_opt["id"]
        if is_correct:
            score += 1
        questions.append({"id": q["id"], "question": q["question"], "options": opts,
                          "chosen_id": chosen_id,
                          "correct_id": correct_opt["id"] if correct_opt else None})
    total = len(qs)
    execute("INSERT INTO quiz_attempts(quiz_id,user_id,score,total,created_at) VALUES(?,?,?,?,?)",
            (quiz["id"], g.user["id"], score, total, dt.datetime.now().strftime("%Y-%m-%d %H:%M")))
    my_attempts = query(
        "SELECT * FROM quiz_attempts WHERE quiz_id=? AND user_id=? "
        "ORDER BY created_at DESC LIMIT 5", (quiz["id"], g.user["id"]))
    return render_template("quiz.html", c=c, quiz=quiz, questions=questions,
                           my_attempts=my_attempts, result={"score": score, "total": total})


@app.route("/watch/<int:lid>")
@login_required
def watch(lid):
    lesson = query("SELECT * FROM lessons WHERE id=?", (lid,), one=True)
    if not lesson:
        abort(404)
    c = query("SELECT * FROM courses WHERE id=?", (lesson["course_id"],),
              one=True)
    if not lesson["is_free"] and not has_subject_access(c["subject"]):
        flash(t("flash.subscribers_only"),
              "warn")
        return redirect(url_for("pricing"))
    execute("INSERT INTO lesson_views(user_id,lesson_id,viewed_at) VALUES(?,?,?)",
            (g.user["id"], lid, dt.datetime.now().strftime("%Y-%m-%d %H:%M")))
    playlist = query(
        "SELECT * FROM lessons WHERE course_id=? ORDER BY position, id",
        (lesson["course_id"],))
    done_rows = query(
        "SELECT lesson_id FROM lesson_progress WHERE user_id=? AND lesson_id IN "
        "(SELECT id FROM lessons WHERE course_id=?)",
        (g.user["id"], lesson["course_id"]))
    done_ids = {r["lesson_id"] for r in done_rows}
    resources = query(
        "SELECT * FROM lesson_resources WHERE lesson_id=? ORDER BY position, id", (lid,))
    notes = query(
        "SELECT * FROM lesson_notes WHERE user_id=? AND lesson_id=? ORDER BY timestamp_sec",
        (g.user["id"], lid))
    return render_template("watch.html", lesson=lesson, c=c,
                           playlist=playlist, done_ids=done_ids,
                           is_done=lesson["id"] in done_ids, resources=resources,
                           notes=notes)


@app.route("/watch/<int:lid>/toggle", methods=["POST"])
@login_required
def watch_toggle(lid):
    lesson = query("SELECT * FROM lessons WHERE id=?", (lid,), one=True)
    if not lesson:
        abort(404)
    if not lesson["is_free"]:
        c = query("SELECT subject FROM courses WHERE id=?", (lesson["course_id"],), one=True)
        if not c or not has_subject_access(c["subject"]):
            abort(403)
    done = query("SELECT id FROM lesson_progress WHERE user_id=? AND lesson_id=?",
                 (g.user["id"], lid), one=True)
    if done:
        execute("DELETE FROM lesson_progress WHERE id=?", (done["id"],))
    else:
        execute("INSERT INTO lesson_progress(user_id,lesson_id,completed_at) "
                "VALUES(?,?,?)",
                (g.user["id"], lid, dt.datetime.now().strftime("%Y-%m-%d %H:%M")))
    return redirect(url_for("watch", lid=lid))


@app.route("/api/watch-progress", methods=["POST"])
@login_required
def watch_progress():
    redir = student_only()
    if redir:
        return redir
    data = request.get_json(silent=True, force=True) or {}
    lesson_id = data.get("lesson_id")
    seconds = data.get("seconds")
    if not isinstance(lesson_id, int) or not isinstance(seconds, (int, float)) or seconds < 0:
        return jsonify({"ok": False}), 400
    lesson = query("SELECT id, duration_min FROM lessons WHERE id=?", (lesson_id,), one=True)
    if not lesson:
        return jsonify({"ok": False}), 404
    max_allowed = (lesson["duration_min"] or 0) * 60 + 120
    seconds = max(0, min(int(seconds), max_allowed))
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    execute(
        "INSERT INTO lesson_watch(user_id,lesson_id,watched_seconds,updated_at) VALUES(?,?,?,?) "
        "ON CONFLICT(user_id,lesson_id) DO UPDATE SET "
        "watched_seconds = MAX(watched_seconds, excluded.watched_seconds), "
        "updated_at = excluded.updated_at",
        (g.user["id"], lesson_id, seconds, now))
    return jsonify({"ok": True})


def total_watch_minutes(user_id):
    row = query("SELECT COALESCE(SUM(watched_seconds),0) s FROM lesson_watch WHERE user_id=?",
               (user_id,), one=True)
    return round(row["s"] / 60)


# ----------------------------------------------------------------------------
# Timestamped lesson notes + PDF export
# ----------------------------------------------------------------------------
def _lesson_access_check(lesson_id):
    """Fetch (lesson, course) for a lesson the current user may access —
    mirrors watch()'s gate. Returns (None, None) if not found/not allowed."""
    lesson = query("SELECT * FROM lessons WHERE id=?", (lesson_id,), one=True)
    if not lesson:
        return None, None
    course = query("SELECT * FROM courses WHERE id=?", (lesson["course_id"],), one=True)
    if not lesson["is_free"] and not has_subject_access(course["subject"]):
        return None, None
    return lesson, course


@app.route("/api/notes", methods=["POST"])
@login_required
def notes_create():
    data = request.get_json(silent=True) or {}
    lesson_id = data.get("lesson_id")
    timestamp_sec = data.get("timestamp_sec")
    body = (data.get("body") or "").strip()[:2000]
    if not isinstance(lesson_id, int) or not isinstance(timestamp_sec, (int, float)) or not body:
        return jsonify(error=t("flash.note_invalid")), 400
    lesson, course = _lesson_access_check(lesson_id)
    if not lesson:
        return jsonify(error=t("flash.subscribers_only")), 403
    timestamp_sec = max(0, int(timestamp_sec))
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    nid = execute(
        "INSERT INTO lesson_notes(user_id,lesson_id,timestamp_sec,body,created_at) "
        "VALUES(?,?,?,?,?)",
        (g.user["id"], lesson_id, timestamp_sec, body, now))
    return jsonify(id=nid, timestamp_sec=timestamp_sec, body=body, time_label=fmt_hms(timestamp_sec))


@app.route("/api/notes/<int:nid>/delete", methods=["POST"])
@login_required
def notes_delete(nid):
    note = query("SELECT id FROM lesson_notes WHERE id=? AND user_id=?",
                 (nid, g.user["id"]), one=True)
    if not note:
        return jsonify(ok=False), 404
    execute("DELETE FROM lesson_notes WHERE id=?", (nid,))
    return jsonify(ok=True)


def _shape_ar(text):
    """Reshape + bidi-reorder text for fpdf2, which draws glyphs left-to-right
    and has no native Arabic shaping. Safe to call on French/mixed text too —
    arabic_reshaper leaves non-Arabic characters untouched."""
    return get_display(arabic_reshaper.reshape(text))


def build_notes_pdf(course_name, lesson_name, notes):
    pdf = FPDF()
    pdf.add_page()
    pdf.add_font("Naskh", "", ARABIC_FONT_PATH)
    pdf.set_font("Naskh", size=15)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(0, 9, _shape_ar(course_name), align="R")
    pdf.set_x(pdf.l_margin)
    pdf.set_font("Naskh", size=12)
    pdf.multi_cell(0, 8, _shape_ar(lesson_name), align="R")
    pdf.ln(4)
    for n in notes:
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Naskh", size=11)
        pdf.set_text_color(35, 80, 216)
        pdf.multi_cell(0, 7, _shape_ar(fmt_hms(n["timestamp_sec"])), align="R")
        pdf.set_x(pdf.l_margin)
        pdf.set_font("Naskh", size=11)
        pdf.set_text_color(20, 20, 20)
        pdf.multi_cell(0, 7, _shape_ar(n["body"]), align="R")
        pdf.ln(3)
    return bytes(pdf.output())


@app.route("/lesson/<int:lid>/notes/pdf")
@login_required
def notes_pdf(lid):
    if not FPDF:
        abort(503)
    lesson, course = _lesson_access_check(lid)
    if not lesson:
        abort(404)
    notes = query(
        "SELECT * FROM lesson_notes WHERE user_id=? AND lesson_id=? ORDER BY timestamp_sec",
        (g.user["id"], lid))
    if not notes:
        abort(404)
    pdf_bytes = build_notes_pdf(
        course_title(course["level_code"], course["subject"], course["title"]),
        lesson_title(course["level_code"], course["subject"], lesson["position"], lesson["title"]),
        notes)
    return Response(pdf_bytes, mimetype="application/pdf",
                     headers={"Content-Disposition": f'attachment; filename="notes-{lid}.pdf"'})


# ----------------------------------------------------------------------------
# Pricing / checkout
# ----------------------------------------------------------------------------
@app.route("/pricing")
def pricing():
    plans_all = {code: plan_info(code) for code in PLAN_INFO}
    plans_subject = {code: plan_info(code, subject=True) for code in PLAN_INFO}
    return render_template("pricing.html", plans_all=plans_all, plans_subject=plans_subject,
                           subject_count=len(all_subject_codes()))


@app.route("/checkout/<plan>", methods=["GET", "POST"])
@login_required
def checkout(plan):
    if plan not in PLAN_INFO:
        abort(404)
    subject = request.args.get("subject") or None
    if subject and subject not in all_subject_codes():
        subject = None
    p = plan_info(plan, subject=subject)
    if request.method == "POST":
        method = request.form.get("method", "d17")
        if method not in PAY_METHOD_CODES:
            method = "d17"
        reference = request.form.get("reference", "").strip()
        now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
        execute("INSERT INTO payments(user_id,plan,subject,amount,method,reference,"
                "status,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (g.user["id"], plan, subject, p["price"], method, reference,
                 "pending", now))
        flash(t("flash.payment_pending"),
              "ok")
        return redirect(url_for("dashboard"))
    return render_template("checkout.html", plan=plan, subject=subject, p=p,
                           methods=[(c, pay_method_name(c)) for c in PAY_METHOD_CODES])


def _activate(uid, plan, subject=None):
    months = PLAN_INFO[plan]["months"]
    user = query("SELECT sub_until FROM users WHERE id=?", (uid,), one=True)
    start = dt.date.today()
    if user and user["sub_until"]:
        try:
            cur = dt.date.fromisoformat(user["sub_until"])
            if cur > start:
                start = cur          # extend an active subscription
        except ValueError:
            pass
    until = start + dt.timedelta(days=30 * months)
    execute("UPDATE users SET sub_plan=?, sub_until=?, sub_subject=? WHERE id=?",
            (plan, until.isoformat(), subject, uid))


# ----------------------------------------------------------------------------
# Live sessions
# ----------------------------------------------------------------------------
@app.route("/live")
def live():
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    upcoming = query(
        "SELECT * FROM live_sessions WHERE starts_at >= ? ORDER BY starts_at",
        (now,))
    past = query(
        "SELECT * FROM live_sessions WHERE starts_at < ? "
        "ORDER BY starts_at DESC LIMIT 6", (now,))
    return render_template("live.html", upcoming=upcoming, past=past)


# ----------------------------------------------------------------------------
# Student dashboard
# ----------------------------------------------------------------------------
@app.route("/dashboard")
@login_required
def dashboard():
    my_level = g.user["level_code"]
    my_courses = query(
        """SELECT c.*, COUNT(l.id) n_lessons
           FROM courses c LEFT JOIN lessons l ON l.course_id=c.id
           WHERE c.level_code=? GROUP BY c.id ORDER BY c.subject""",
        (my_level,))
    progress = {}
    for c in my_courses:
        total = c["n_lessons"] or 0
        done_n = query(
            "SELECT COUNT(*) n FROM lesson_progress lp "
            "JOIN lessons l ON l.id = lp.lesson_id "
            "WHERE lp.user_id=? AND l.course_id=?",
            (g.user["id"], c["id"]), one=True)["n"]
        next_lesson = query(
            "SELECT * FROM lessons WHERE course_id=? AND id NOT IN "
            "(SELECT lesson_id FROM lesson_progress WHERE user_id=?) "
            "ORDER BY position, id LIMIT 1",
            (c["id"], g.user["id"]), one=True)
        progress[c["subject"]] = {
            "course": c, "total": total, "done": done_n,
            "percent": round(done_n / total * 100) if total else 0,
            "next_lesson": next_lesson,
        }
    payments = query(
        "SELECT * FROM payments WHERE user_id=? ORDER BY id DESC",
        (g.user["id"],))
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    next_lives = query(
        "SELECT * FROM live_sessions WHERE starts_at >= ? AND level_code=? "
        "ORDER BY starts_at LIMIT 3", (now, my_level))
    return render_template("dashboard.html", my_courses=my_courses,
                           progress=progress, payments=payments,
                           next_lives=next_lives,
                           pay_map={c: pay_method_name(c) for c in PAY_METHOD_CODES})


@app.route("/profile")
@login_required
def profile():
    n_completed = query(
        "SELECT COUNT(*) n FROM lesson_progress WHERE user_id=?",
        (g.user["id"],), one=True)["n"]
    quiz_attempts = query(
        """SELECT qa.*, c.id AS course_id, c.level_code, c.subject, c.title AS course_title
           FROM quiz_attempts qa
           JOIN quizzes q ON q.id = qa.quiz_id
           JOIN courses c ON c.id = q.course_id
           WHERE qa.user_id=? ORDER BY qa.created_at DESC LIMIT 10""",
        (g.user["id"],))
    return render_template("profile.html", n_completed=n_completed,
                           quiz_attempts=quiz_attempts,
                           total_watch_min=total_watch_minutes(g.user["id"]))


@app.route("/settings")
@login_required
def settings():
    return render_template("settings.html")


def student_only():
    if g.user["role"] == "admin":
        flash(t("flash.students_only"), "warn")
        return redirect(url_for("admin_panel"))
    return None


# ----------------------------------------------------------------------------
# Study schedule
# ----------------------------------------------------------------------------
REPEAT_CHOICES = ("none", "daily", "weekly")


def block_occurs_on(block, day):
    """Whether a (possibly repeating) study block occurs on the given date."""
    anchor = dt.date.fromisoformat(block["the_date"])
    repeat = block["repeat"] or "none"
    if repeat == "daily":
        return day >= anchor
    if repeat == "weekly":
        return day >= anchor and day.weekday() == anchor.weekday()
    return day == anchor


def schedule_week_bounds(week_offset):
    today = dt.date.today()
    this_monday = today - dt.timedelta(days=today.weekday())
    week_start = this_monday + dt.timedelta(weeks=week_offset)
    return week_start, week_start + dt.timedelta(days=6)


@app.route("/schedule")
@login_required
def schedule():
    redir = student_only()
    if redir:
        return redir
    try:
        week_offset = int(request.args.get("w", "0"))
    except ValueError:
        week_offset = 0
    week_offset = max(-52, min(52, week_offset))
    today = dt.date.today()
    week_start, week_end = schedule_week_bounds(week_offset)
    lang = get_lang()

    blocks = query(
        "SELECT * FROM study_blocks WHERE user_id=? AND "
        "(repeat != 'none' OR (the_date BETWEEN ? AND ?))",
        (g.user["id"], week_start.isoformat(), week_end.isoformat()))
    week_lives = query(
        "SELECT * FROM live_sessions WHERE level_code=? AND starts_at >= ? AND starts_at < ? "
        "ORDER BY starts_at",
        (g.user["level_code"], week_start.strftime("%Y-%m-%d 00:00"),
         (week_end + dt.timedelta(days=1)).strftime("%Y-%m-%d 00:00")))

    days = []
    for i in range(7):
        d = week_start + dt.timedelta(days=i)
        items = []
        for b in blocks:
            if block_occurs_on(b, d):
                items.append({
                    "kind": "block", "id": b["id"], "the_date": b["the_date"],
                    "start_time": b["start_time"], "end_time": b["end_time"],
                    "subject": b["subject"], "note": b["note"],
                    "repeat": b["repeat"] or "none",
                    "title": b["note"] or (subject_name(b["subject"]) if b["subject"] else t("sc.study_block")),
                })
        for s in week_lives:
            sdt = dt.datetime.strptime(s["starts_at"], "%Y-%m-%d %H:%M")
            if sdt.date() == d:
                end_dt = sdt + dt.timedelta(minutes=s["duration_min"])
                items.append({
                    "kind": "live", "id": s["id"], "start_time": sdt.strftime("%H:%M"),
                    "end_time": end_dt.strftime("%H:%M"), "subject": s["subject"],
                    "title": s["title"],
                })
        items.sort(key=lambda x: x["start_time"])
        days.append({"date": d.isoformat(), "day_name": DAY_NAMES[i][lang],
                     "day_num": d.day, "month_name": MONTH_NAMES[d.month][lang],
                     "is_today": d == today, "entries": items})

    week_label = (f"{week_start.day:02d}–{week_end.day:02d} {MONTH_NAMES[week_end.month][lang]} {week_end.year}"
                  if week_start.month == week_end.month else
                  f"{week_start.day:02d} {MONTH_NAMES[week_start.month][lang]} – "
                  f"{week_end.day:02d} {MONTH_NAMES[week_end.month][lang]} {week_end.year}")

    return render_template("schedule.html", days=days, week_offset=week_offset,
                           week_label=week_label, today=today.isoformat())


@app.route("/schedule/add", methods=["POST"])
@login_required
def schedule_add():
    the_date = request.form.get("the_date", "").strip()
    start_time = request.form.get("start_time", "").strip()
    end_time = request.form.get("end_time", "").strip()
    subject = request.form.get("subject", "").strip()
    note = request.form.get("note", "").strip()
    repeat = request.form.get("repeat", "none")
    if repeat not in REPEAT_CHOICES:
        repeat = "none"
    week_offset = request.form.get("week_offset", "0")
    ok_date = True
    try:
        dt.date.fromisoformat(the_date)
    except ValueError:
        ok_date = False
    ok_time = len(start_time) == 5 and len(end_time) == 5 and start_time < end_time
    if the_date and ok_date and ok_time:
        execute("INSERT INTO study_blocks(user_id,the_date,start_time,end_time,"
                "subject,note,repeat,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (g.user["id"], the_date, start_time, end_time, subject, note, repeat,
                 dt.datetime.now().strftime("%Y-%m-%d %H:%M")))
        flash(t("flash.schedule_added"), "ok")
    else:
        flash(t("flash.schedule_invalid"), "error")
    return redirect(url_for("schedule", w=week_offset))


@app.route("/schedule/<int:bid>/edit", methods=["POST"])
@login_required
def schedule_edit(bid):
    block = query("SELECT * FROM study_blocks WHERE id=? AND user_id=?", (bid, g.user["id"]), one=True)
    week_offset = request.form.get("week_offset", "0")
    if not block:
        abort(404)
    the_date = request.form.get("the_date", "").strip()
    start_time = request.form.get("start_time", "").strip()
    end_time = request.form.get("end_time", "").strip()
    subject = request.form.get("subject", "").strip()
    note = request.form.get("note", "").strip()
    repeat = request.form.get("repeat", "none")
    if repeat not in REPEAT_CHOICES:
        repeat = "none"
    ok_date = True
    try:
        dt.date.fromisoformat(the_date)
    except ValueError:
        ok_date = False
    ok_time = len(start_time) == 5 and len(end_time) == 5 and start_time < end_time
    if the_date and ok_date and ok_time:
        execute("UPDATE study_blocks SET the_date=?, start_time=?, end_time=?, subject=?, "
                "note=?, repeat=? WHERE id=?",
                (the_date, start_time, end_time, subject, note, repeat, bid))
        flash(t("flash.schedule_updated"), "ok")
    else:
        flash(t("flash.schedule_invalid"), "error")
    return redirect(url_for("schedule", w=week_offset))


@app.route("/schedule/<int:bid>/delete", methods=["POST"])
@login_required
def schedule_delete(bid):
    week_offset = request.form.get("week_offset", "0")
    execute("DELETE FROM study_blocks WHERE id=? AND user_id=?", (bid, g.user["id"]))
    flash(t("flash.schedule_deleted"), "warn")
    return redirect(url_for("schedule", w=week_offset))


# ----------------------------------------------------------------------------
# Chat (per level, two channels: "general" with the teacher/admin, and
# "students" — a peer-only space. Everyone in a channel can post.)
# ----------------------------------------------------------------------------
CHAT_CHANNELS = ("general", "students")


def notify_chat_recipients(level_code, channel, sender_id, sender_name, body):
    recipients = query(
        "SELECT id FROM users WHERE role='student' AND level_code=? AND id != ?",
        (level_code, sender_id))
    if not recipients:
        return
    preview = body if len(body) <= 80 else body[:77] + "…"
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    title = t("notif.chat_title")
    text = t("notif.chat_body", name=sender_name, msg=preview)
    for r in recipients:
        execute("INSERT INTO notifications(user_id,title,body,created_at) VALUES(?,?,?,?)",
                (r["id"], title, text, now))


@app.route("/chat")
@login_required
def chat():
    redir = student_only()
    if redir:
        return redir
    channel = request.args.get("ch", "general")
    if channel not in CHAT_CHANNELS:
        channel = "general"
    level = g.user["level_code"]
    messages = query(
        """SELECT m.*, u.name AS author_name, u.role AS author_role FROM chat_messages m
           JOIN users u ON u.id = m.author_id
           WHERE m.level_code=? AND m.channel=? ORDER BY m.created_at, m.id""",
        (level, channel))
    reactions = query(
        """SELECT message_id, emoji, COUNT(*) n FROM chat_reactions
           WHERE message_id IN (SELECT id FROM chat_messages WHERE level_code=? AND channel=?)
           GROUP BY message_id, emoji""", (level, channel))
    my_reactions = query(
        """SELECT message_id, emoji FROM chat_reactions
           WHERE user_id=? AND message_id IN
           (SELECT id FROM chat_messages WHERE level_code=? AND channel=?)""",
        (g.user["id"], level, channel))
    react_map = {}
    for r in reactions:
        react_map.setdefault(r["message_id"], []).append((r["emoji"], r["n"]))
    mine_map = {r["message_id"]: r["emoji"] for r in my_reactions}
    return render_template("chat.html", messages=messages, react_map=react_map,
                           mine_map=mine_map, emojis=REACTION_EMOJIS, channel=channel)


@app.route("/chat/send", methods=["POST"])
@login_required
def chat_send():
    redir = student_only()
    if redir:
        return redir
    channel = request.form.get("channel", "general")
    if channel not in CHAT_CHANNELS:
        channel = "general"
    body = request.form.get("body", "").strip()
    if body:
        level = g.user["level_code"]
        execute("INSERT INTO chat_messages(level_code,channel,author_id,body,created_at) "
                "VALUES(?,?,?,?,?)",
                (level, channel, g.user["id"], body,
                 dt.datetime.now().strftime("%Y-%m-%d %H:%M")))
        notify_chat_recipients(level, channel, g.user["id"], g.user["name"], body)
    return redirect(url_for("chat", ch=channel))


@app.route("/chat/<int:mid>/react", methods=["POST"])
@login_required
def chat_react(mid):
    msg = query("SELECT * FROM chat_messages WHERE id=?", (mid,), one=True)
    if not msg or msg["level_code"] != g.user["level_code"]:
        abort(404)
    emoji = request.form.get("emoji", "")
    if emoji not in REACTION_EMOJIS:
        abort(400)
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    existing = query("SELECT * FROM chat_reactions WHERE message_id=? AND user_id=?",
                     (mid, g.user["id"]), one=True)
    if existing and existing["emoji"] == emoji:
        execute("DELETE FROM chat_reactions WHERE id=?", (existing["id"],))
    elif existing:
        execute("UPDATE chat_reactions SET emoji=?, created_at=? WHERE id=?",
                (emoji, now, existing["id"]))
    else:
        execute("INSERT INTO chat_reactions(message_id,user_id,emoji,created_at) "
                "VALUES(?,?,?,?)", (mid, g.user["id"], emoji, now))
    return redirect(url_for("chat", ch=msg["channel"]))


# ----------------------------------------------------------------------------
# Leaderboard
# ----------------------------------------------------------------------------
def leaderboard_rows(level, limit=20):
    return query(
        """SELECT u.id, u.name, COUNT(lp.id) n_done
           FROM users u LEFT JOIN lesson_progress lp ON lp.user_id = u.id
           WHERE u.level_code=? AND u.role='student'
           GROUP BY u.id ORDER BY n_done DESC, u.name LIMIT ?""", (level, limit))


@app.route("/leaderboard")
@login_required
def leaderboard():
    if g.user["role"] == "admin":
        level = request.args.get("level", all_level_codes()[0])
    else:
        level = g.user["level_code"]
    rows = leaderboard_rows(level)
    my_rank = next((i + 1 for i, r in enumerate(rows) if r["id"] == g.user["id"]), None)
    return render_template("leaderboard.html", rows=rows, level=level, my_rank=my_rank)


@app.route("/api/leaderboard")
@login_required
def api_leaderboard():
    if g.user["role"] == "admin":
        level = request.args.get("level", all_level_codes()[0])
    else:
        level = g.user["level_code"]
    rows = leaderboard_rows(level)
    return jsonify(rows=[{"id": r["id"], "name": r["name"], "n_done": r["n_done"]}
                         for r in rows], me=g.user["id"])


# ----------------------------------------------------------------------------
# AI tutor chat
# ----------------------------------------------------------------------------
AI_SYSTEM_PROMPT = (
    "أنت المساعد الذكي لمنصة \"أكاديمية SCROL\"، منصة تونسية لتعليم الرياضيات "
    "والفيزياء من السابعة أساسي إلى البكالوريا وفق البرنامج الرسمي التونسي.\n"
    "أسلوبك: تشرح المفاهيم خطوة بخطوة بلغة عربية بسيطة (يمكن استعمال مصطلحات "
    "فرنسية علمية عند الحاجة كما هو معتاد في المدرسة التونسية)، وتشجّع التلميذ "
    "على الفهم بدل الحفظ.\n"
    "قواعد مهمة: لا تُعطِ الحل الكامل لتمرين مباشرة إن لم يطلبه التلميذ صراحة — "
    "اشرح الخطوة الأولى واسأله أن يحاول، ثم واصل مرافقته. أجوبتك يجب أن تبقى "
    "قصيرة ومركّزة (بضع جمل أو خطوات، وليس مقالًا طويلًا) لأنها تظهر في نافذة "
    "دردشة صغيرة.\n"
    "تنسيق مهم: ردودك تظهر كنص عادي فقط بدون أي تنسيق — لا تستعمل Markdown "
    "إطلاقًا (لا **، لا #، لا -، لا `)، ولا صيغ LaTeX (لا $ ولا \\sqrt أو ما "
    "شابه). للرياضيات استعمل رموزًا عادية يمكن كتابتها في نص بسيط: √25، x²، "
    "3×4، (a+b)، ½، إلخ. للتشديد استعمل الكلمات فقط، وللقوائم استعمل أرقامًا "
    "متبوعة بنقطة في سطر جديد مثل \"1. ...\"."
)


@app.route("/api/ai-chat", methods=["POST"])
@login_required
def ai_chat():
    if not ai_client:
        return jsonify(error=t("flash.ai_disabled")), 503
    if not is_subscribed():
        return jsonify(error=t("flash.ai_no_sub")), 403

    data = request.get_json(silent=True) or {}
    incoming = data.get("messages", [])
    lesson_id = data.get("lesson_id")

    if not isinstance(incoming, list) or not incoming:
        return jsonify(error=t("flash.ai_no_question")), 400

    today = dt.date.today().isoformat()
    usage = query("SELECT * FROM ai_usage WHERE user_id=? AND the_day=?",
                 (g.user["id"], today), one=True)
    if usage and usage["count"] >= AI_DAILY_LIMIT:
        return jsonify(error=t("flash.ai_daily_limit", n=AI_DAILY_LIMIT)), 429

    messages = []
    for m in incoming[-12:]:
        role = m.get("role") if isinstance(m, dict) else None
        content = m.get("content") if isinstance(m, dict) else None
        if role in ("user", "assistant") and isinstance(content, str) and content.strip():
            messages.append({"role": role, "content": content.strip()[:2000]})
    if not messages or messages[-1]["role"] != "user":
        return jsonify(error=t("flash.ai_no_question")), 400

    lang = get_lang()
    system_prompt = AI_SYSTEM_PROMPT
    system_prompt += ("\nأجب بالفرنسية فقط في هذه المحادثة." if lang == "fr"
                       else "\nأجب بالعربية في هذه المحادثة.")
    system_prompt += f"\nمستوى التلميذ: {level_name(g.user['level_code'])}."
    if lesson_id:
        lesson = query(
            """SELECT l.title, l.description, l.position, c.subject, c.level_code
               FROM lessons l JOIN courses c ON c.id = l.course_id
               WHERE l.id=?""", (lesson_id,), one=True)
        if lesson:
            l_title = lesson_title(lesson["level_code"], lesson["subject"],
                                   lesson["position"], lesson["title"])
            l_desc = lesson_description(lesson["level_code"], lesson["subject"],
                                        lesson["position"], lesson["description"])
            system_prompt += (
                f"\nالتلميذ يشاهد الآن درس «{l_title}» "
                f"({subject_name(lesson['subject'])} — "
                f"{level_name(lesson['level_code'])}). "
                f"وصف الدرس: {l_desc or '—'}. "
                "إن سأل عن \"هذا الدرس\" أو \"هذا الجزء\" فهو يقصد هذا الدرس بالذات."
            )

    try:
        resp = ai_client.messages.create(
            model=AI_MODEL, max_tokens=700,
            system=system_prompt, messages=messages,
        )
        reply = "".join(b.text for b in resp.content if b.type == "text").strip()
    except Exception:
        return jsonify(error=t("flash.ai_error")), 502

    if usage:
        execute("UPDATE ai_usage SET count = count + 1 WHERE id=?", (usage["id"],))
    else:
        execute("INSERT INTO ai_usage(user_id,the_day,count) VALUES(?,?,1)",
                (g.user["id"], today))

    return jsonify(reply=reply or t("flash.ai_empty_reply"))


# ----------------------------------------------------------------------------
# Notifications
# ----------------------------------------------------------------------------
@app.route("/notifications")
@login_required
def notifications():
    rows = query("SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 50",
                 (g.user["id"],))
    execute("UPDATE notifications SET read_at=? WHERE user_id=? AND read_at IS NULL",
            (dt.datetime.now().strftime("%Y-%m-%d %H:%M"), g.user["id"]))
    return render_template("notifications.html", rows=rows)


# ----------------------------------------------------------------------------
# Admin
# ----------------------------------------------------------------------------
PROF_ALLOWED_TABS = ("content", "lives", "chat")


@app.route("/admin")
@staff_required
def admin_panel():
    requested_tab = request.args.get("tab")
    if g.user["role"] == "prof":
        if requested_tab and requested_tab not in PROF_ALLOWED_TABS:
            flash(t("flash.staff_tab_restricted"), "warn")
            return redirect(url_for("admin_panel", tab="content"))
        tab = requested_tab or "content"
    else:
        tab = requested_tab or "overview"
    data = {
        "n_students": query("SELECT COUNT(*) c FROM users WHERE role='student'",
                            one=True)["c"],
        "n_subs": query("SELECT COUNT(*) c FROM users WHERE sub_until >= ?",
                        (dt.date.today().isoformat(),), one=True)["c"],
        "n_pending": query("SELECT COUNT(*) c FROM payments WHERE status='pending'",
                           one=True)["c"],
        "revenue": query("SELECT COALESCE(SUM(amount),0) s FROM payments "
                         "WHERE status='approved'", one=True)["s"],
    }
    users = query("SELECT * FROM users ORDER BY id DESC")
    watch_min_map = {r["user_id"]: round(r["s"] / 60) for r in query(
        "SELECT user_id, SUM(watched_seconds) s FROM lesson_watch GROUP BY user_id")}
    payments = query(
        """SELECT p.*, u.name AS user_name, u.email AS user_email
           FROM payments p JOIN users u ON u.id=p.user_id
           ORDER BY CASE p.status WHEN 'pending' THEN 0 ELSE 1 END, p.id DESC""")
    course_rows = query(
        """SELECT c.*, COUNT(l.id) n_lessons FROM courses c
           LEFT JOIN lessons l ON l.course_id=c.id
           GROUP BY c.id ORDER BY c.subject, c.id""")
    lives = query("SELECT * FROM live_sessions ORDER BY starts_at DESC")
    if g.user["role"] == "prof":
        course_rows = [c for c in course_rows if c["level_code"] == g.user["level_code"]]
        lives = [s for s in lives if s["level_code"] == g.user["level_code"]]

    # ---- content tab: lessons (+ resources) and quizzes (+ questions) per course ----
    lessons_by_course = {}
    quiz_by_course = {}
    if tab == "content":
        all_lessons = query("SELECT * FROM lessons ORDER BY course_id, position, id")
        lesson_ids = [l["id"] for l in all_lessons]
        resources_by_lesson = {}
        if lesson_ids:
            ph = ",".join("?" * len(lesson_ids))
            all_resources = query(
                f"SELECT * FROM lesson_resources WHERE lesson_id IN ({ph}) "
                "ORDER BY lesson_id, position, id", lesson_ids)
            for r in all_resources:
                resources_by_lesson.setdefault(r["lesson_id"], []).append(r)
        watch_stats_by_lesson = {r["lesson_id"]: r for r in query(
            "SELECT lesson_id, COUNT(*) n_watchers, AVG(watched_seconds) avg_seconds "
            "FROM lesson_watch GROUP BY lesson_id")}
        for l in all_lessons:
            entry = dict(l)
            entry["resources"] = resources_by_lesson.get(l["id"], [])
            ws = watch_stats_by_lesson.get(l["id"])
            if ws and l["duration_min"]:
                entry["n_watchers"] = ws["n_watchers"]
                entry["avg_watch_pct"] = min(100, round(ws["avg_seconds"] / (l["duration_min"] * 60) * 100))
            else:
                entry["n_watchers"] = 0
                entry["avg_watch_pct"] = None
            lessons_by_course.setdefault(l["course_id"], []).append(entry)

        all_quizzes = query("SELECT * FROM quizzes")
        quiz_ids = [q["id"] for q in all_quizzes]
        questions_by_quiz = {}
        if quiz_ids:
            ph = ",".join("?" * len(quiz_ids))
            all_questions = query(
                f"SELECT * FROM quiz_questions WHERE quiz_id IN ({ph}) "
                "ORDER BY quiz_id, position, id", quiz_ids)
            question_ids = [q["id"] for q in all_questions]
            options_by_question = {}
            if question_ids:
                ph2 = ",".join("?" * len(question_ids))
                all_options = query(
                    f"SELECT * FROM quiz_options WHERE question_id IN ({ph2}) "
                    "ORDER BY question_id, position, id", question_ids)
                for o in all_options:
                    options_by_question.setdefault(o["question_id"], []).append(o)
            for qq in all_questions:
                entry = dict(qq)
                entry["options"] = options_by_question.get(qq["id"], [])
                questions_by_quiz.setdefault(qq["quiz_id"], []).append(entry)
        for qz in all_quizzes:
            entry = dict(qz)
            entry["questions"] = questions_by_quiz.get(qz["id"], [])
            quiz_by_course[qz["course_id"]] = entry

    # ---- taxonomy tab: levels & subjects management with usage counts ----
    all_levels = []
    all_subjects = []
    if tab == "taxonomy":
        level_usage = {r["level_code"]: r["n"] for r in query(
            """SELECT level_code, COUNT(*) n FROM (
                 SELECT level_code FROM users WHERE level_code IS NOT NULL
                 UNION ALL SELECT level_code FROM courses
                 UNION ALL SELECT level_code FROM live_sessions
               ) GROUP BY level_code""")}
        for r in query("SELECT * FROM levels ORDER BY sort_order"):
            entry = dict(r)
            entry["n_uses"] = level_usage.get(r["code"], 0)
            all_levels.append(entry)
        subject_usage = {r["subject"]: r["n"] for r in query(
            """SELECT subject, COUNT(*) n FROM (
                 SELECT subject FROM courses
                 UNION ALL SELECT subject FROM live_sessions
                 UNION ALL SELECT subject FROM study_blocks WHERE subject IS NOT NULL AND subject != ''
               ) GROUP BY subject""")}
        for r in query("SELECT * FROM subjects ORDER BY sort_order"):
            entry = dict(r)
            entry["n_uses"] = subject_usage.get(r["code"], 0)
            all_subjects.append(entry)

    # ---- teachers tab: teacher accounts with per-level course/student counts ----
    all_teachers = []
    if tab == "teachers":
        course_counts = {r["level_code"]: r["n"] for r in query(
            "SELECT level_code, COUNT(*) n FROM courses GROUP BY level_code")}
        student_counts_by_level = {r["level_code"]: r["n"] for r in query(
            "SELECT level_code, COUNT(*) n FROM users WHERE role='student' GROUP BY level_code")}
        for r in query("SELECT * FROM users WHERE role='prof' ORDER BY id DESC"):
            entry = dict(r)
            entry["n_courses"] = course_counts.get(r["level_code"], 0)
            entry["n_students"] = student_counts_by_level.get(r["level_code"], 0)
            all_teachers.append(entry)

    # ---- per-level dashboards ----
    student_counts = query(
        """SELECT level_code,
                  COUNT(*) n_students,
                  COUNT(CASE WHEN sub_until >= ? THEN 1 END) n_subs
           FROM users WHERE role='student' GROUP BY level_code""",
        (dt.date.today().isoformat(),))
    view_counts = query(
        """SELECT c.level_code, COUNT(v.id) n_views
           FROM lesson_views v JOIN lessons l ON l.id = v.lesson_id
           JOIN courses c ON c.id = l.course_id GROUP BY c.level_code""")
    done_counts = query(
        """SELECT c.level_code, COUNT(p.id) n_done
           FROM lesson_progress p JOIN lessons l ON l.id = p.lesson_id
           JOIN courses c ON c.id = l.course_id GROUP BY c.level_code""")
    sc_map = {r["level_code"]: r for r in student_counts}
    vc_map = {r["level_code"]: r["n_views"] for r in view_counts}
    dc_map = {r["level_code"]: r["n_done"] for r in done_counts}
    levels_data = [{
        "code": code, "name": level_name(code),
        "n_students": sc_map[code]["n_students"] if code in sc_map else 0,
        "n_subs": sc_map[code]["n_subs"] if code in sc_map else 0,
        "n_views": vc_map.get(code, 0),
        "n_done": dc_map.get(code, 0),
    } for code in all_level_codes()]

    sel_level = request.args.get("level", "")
    level_courses = []
    if sel_level in all_level_codes():
        level_courses = query(
            """SELECT c.*, COUNT(DISTINCT l.id) n_lessons,
                      COUNT(DISTINCT v.id) n_views,
                      COUNT(DISTINCT p.id) n_done
               FROM courses c
               LEFT JOIN lessons l ON l.course_id = c.id
               LEFT JOIN lesson_views v ON v.lesson_id = l.id
               LEFT JOIN lesson_progress p ON p.lesson_id = l.id
               WHERE c.level_code=? GROUP BY c.id ORDER BY c.subject""",
            (sel_level,))

    # ---- chat (admin/teacher composes per level) ----
    if g.user["role"] == "prof":
        chat_level = g.user["level_code"]
    else:
        chat_level = request.args.get("clevel", all_level_codes()[0])
        if chat_level not in all_level_codes():
            chat_level = all_level_codes()[0]
    chat_history = query(
        """SELECT m.*, u.name AS author_name,
                  (SELECT COUNT(*) FROM chat_reactions r WHERE r.message_id=m.id) n_reactions
           FROM chat_messages m JOIN users u ON u.id = m.author_id
           WHERE m.level_code=? AND m.channel='general'
           ORDER BY m.created_at DESC, m.id DESC LIMIT 30""",
        (chat_level,))

    # ---- notifications history ----
    notif_history = query(
        """SELECT title, body, created_at, COUNT(*) n_recipients
           FROM notifications GROUP BY title, body, created_at
           ORDER BY created_at DESC LIMIT 20""")

    return render_template("admin/panel.html", tab=tab, d=data, users=users,
                           payments=payments, course_rows=course_rows,
                           lives=lives,
                           pay_map={c: pay_method_name(c) for c in PAY_METHOD_CODES},
                           levels_data=levels_data, sel_level=sel_level,
                           level_courses=level_courses, chat_level=chat_level,
                           chat_history=chat_history, notif_history=notif_history,
                           lessons_by_course=lessons_by_course, quiz_by_course=quiz_by_course,
                           watch_min_map=watch_min_map,
                           all_levels=all_levels, all_subjects=all_subjects,
                           all_teachers=all_teachers)


@app.route("/admin/payment/<int:pid>/<action>", methods=["POST"])
@admin_required
def admin_payment(pid, action):
    pay = query("SELECT * FROM payments WHERE id=?", (pid,), one=True)
    if not pay or action not in ("approve", "reject"):
        abort(404)
    if action == "approve":
        execute("UPDATE payments SET status='approved' WHERE id=?", (pid,))
        _activate(pay["user_id"], pay["plan"], pay["subject"])
        flash(t("flash.payment_approved"), "ok")
    else:
        execute("UPDATE payments SET status='rejected' WHERE id=?", (pid,))
        flash(t("flash.payment_rejected"), "warn")
    return redirect(url_for("admin_panel", tab="payments"))


@app.route("/admin/user/<int:uid>/grant", methods=["POST"])
@admin_required
def admin_grant(uid):
    plan = request.form.get("plan", "monthly")
    subject = request.form.get("subject") or None
    if subject and subject not in all_subject_codes():
        subject = None
    if plan in PLAN_INFO:
        _activate(uid, plan, subject)
        flash(t("flash.sub_activated"), "ok")
    return redirect(url_for("admin_panel", tab="users"))


@app.route("/admin/user/<int:uid>/revoke", methods=["POST"])
@admin_required
def admin_revoke(uid):
    execute("UPDATE users SET sub_plan=NULL, sub_until=NULL, sub_subject=NULL WHERE id=?", (uid,))
    flash(t("flash.sub_revoked"), "warn")
    return redirect(url_for("admin_panel", tab="users"))


@app.route("/admin/course/add", methods=["POST"])
@staff_required
def admin_course_add():
    level = g.user["level_code"] if g.user["role"] == "prof" else request.form.get("level_code")
    subject = request.form.get("subject")
    title = request.form.get("title", "").strip()
    if level in all_level_codes() and subject in all_subject_codes() and title:
        execute("INSERT INTO courses(level_code,subject,title,description)"
                " VALUES(?,?,?,?)",
                (level, subject, title,
                 request.form.get("description", "").strip()))
        flash(t("flash.course_added"), "ok")
    else:
        flash(t("flash.course_invalid"), "error")
    return redirect(url_for("admin_panel", tab="content"))


@app.route("/admin/course/<int:cid>/edit", methods=["POST"])
@staff_required
def admin_course_edit(cid):
    enforce_prof_scope(cid)
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    if title:
        execute("UPDATE courses SET title=?, description=? WHERE id=?",
                (title, description, cid))
        flash(t("flash.course_updated"), "ok")
    else:
        flash(t("flash.course_invalid"), "error")
    return redirect(url_for("admin_panel", tab="content"))


@app.route("/admin/course/<int:cid>/delete", methods=["POST"])
@staff_required
def admin_course_delete(cid):
    enforce_prof_scope(cid)
    execute("DELETE FROM courses WHERE id=?", (cid,))
    flash(t("flash.course_deleted"), "warn")
    return redirect(url_for("admin_panel", tab="content"))


def course_id_for_lesson(lid):
    row = query("SELECT course_id FROM lessons WHERE id=?", (lid,), one=True)
    return row["course_id"] if row else None


def course_id_for_resource(rid):
    row = query(
        "SELECT l.course_id AS course_id FROM lesson_resources r "
        "JOIN lessons l ON l.id = r.lesson_id WHERE r.id=?", (rid,), one=True)
    return row["course_id"] if row else None


def course_id_for_quiz_question(qid):
    row = query(
        "SELECT q.course_id AS course_id FROM quiz_questions qq "
        "JOIN quizzes q ON q.id = qq.quiz_id WHERE qq.id=?", (qid,), one=True)
    return row["course_id"] if row else None


def extract_youtube_id(raw):
    """Accepts a full YouTube URL or a bare video id and returns just the id."""
    yt = raw.strip()
    for sep in ("watch?v=", "youtu.be/", "embed/"):
        if sep in yt:
            yt = yt.split(sep)[1].split("&")[0].split("?")[0]
    return yt


@app.route("/admin/lesson/add", methods=["POST"])
@staff_required
def admin_lesson_add():
    try:
        cid = int(request.form.get("course_id", "0"))
    except ValueError:
        cid = 0
    title = request.form.get("title", "").strip()
    yt = extract_youtube_id(request.form.get("youtube_id", ""))
    if cid and title and yt and query("SELECT id FROM courses WHERE id=?",
                                      (cid,), one=True):
        enforce_prof_scope(cid)
        pos = query("SELECT COALESCE(MAX(position),-1)+1 p FROM lessons "
                    "WHERE course_id=?", (cid,), one=True)["p"]
        execute("INSERT INTO lessons(course_id,title,description,youtube_id,"
                "duration_min,is_free,position) VALUES(?,?,?,?,?,?,?)",
                (cid, title, request.form.get("description", "").strip(), yt,
                 int(request.form.get("duration_min", 20) or 20),
                 1 if request.form.get("is_free") else 0, pos))
        flash(t("flash.lesson_added"), "ok")
    else:
        flash(t("flash.lesson_invalid"), "error")
    return redirect(url_for("admin_panel", tab="content"))


@app.route("/admin/lesson/<int:lid>/edit", methods=["POST"])
@staff_required
def admin_lesson_edit(lid):
    enforce_prof_scope(course_id_for_lesson(lid))
    title = request.form.get("title", "").strip()
    yt = extract_youtube_id(request.form.get("youtube_id", ""))
    if title and yt:
        execute("UPDATE lessons SET title=?, youtube_id=?, duration_min=?, is_free=? "
                "WHERE id=?",
                (title, yt, int(request.form.get("duration_min", 20) or 20),
                 1 if request.form.get("is_free") else 0, lid))
        flash(t("flash.lesson_updated"), "ok")
    else:
        flash(t("flash.lesson_invalid"), "error")
    return redirect(url_for("admin_panel", tab="content"))


@app.route("/admin/lesson/<int:lid>/delete", methods=["POST"])
@staff_required
def admin_lesson_delete(lid):
    enforce_prof_scope(course_id_for_lesson(lid))
    execute("DELETE FROM lessons WHERE id=?", (lid,))
    flash(t("flash.lesson_deleted"), "warn")
    return redirect(url_for("admin_panel", tab="content"))


@app.route("/admin/lesson/<int:lid>/move/<direction>", methods=["POST"])
@staff_required
def admin_lesson_move(lid, direction):
    lesson = query("SELECT * FROM lessons WHERE id=?", (lid,), one=True)
    if not lesson or direction not in ("up", "down"):
        abort(404)
    enforce_prof_scope(lesson["course_id"])
    if direction == "up":
        sibling = query(
            "SELECT * FROM lessons WHERE course_id=? AND position < ? "
            "ORDER BY position DESC LIMIT 1",
            (lesson["course_id"], lesson["position"]), one=True)
    else:
        sibling = query(
            "SELECT * FROM lessons WHERE course_id=? AND position > ? "
            "ORDER BY position ASC LIMIT 1",
            (lesson["course_id"], lesson["position"]), one=True)
    if sibling:
        execute("UPDATE lessons SET position=? WHERE id=?", (sibling["position"], lesson["id"]))
        execute("UPDATE lessons SET position=? WHERE id=?", (lesson["position"], sibling["id"]))
    return redirect(url_for("admin_panel", tab="content"))


@app.route("/admin/lesson/<int:lid>/resource/add", methods=["POST"])
@staff_required
def admin_resource_add(lid):
    enforce_prof_scope(course_id_for_lesson(lid))
    title = request.form.get("title", "").strip()
    url = request.form.get("url", "").strip()
    if title and url:
        pos = query("SELECT COALESCE(MAX(position),-1)+1 p FROM lesson_resources "
                    "WHERE lesson_id=?", (lid,), one=True)["p"]
        execute("INSERT INTO lesson_resources(lesson_id,title,url,position) VALUES(?,?,?,?)",
                (lid, title, url, pos))
        flash(t("flash.resource_added"), "ok")
    else:
        flash(t("flash.resource_invalid"), "error")
    return redirect(url_for("admin_panel", tab="content"))


@app.route("/admin/resource/<int:rid>/delete", methods=["POST"])
@staff_required
def admin_resource_delete(rid):
    enforce_prof_scope(course_id_for_resource(rid))
    execute("DELETE FROM lesson_resources WHERE id=?", (rid,))
    flash(t("flash.resource_deleted"), "warn")
    return redirect(url_for("admin_panel", tab="content"))


@app.route("/admin/course/<int:cid>/quiz/question/add", methods=["POST"])
@staff_required
def admin_quiz_question_add(cid):
    enforce_prof_scope(cid)
    question = request.form.get("question", "").strip()
    options = [request.form.get(f"option{i}", "").strip() for i in range(1, 5)]
    try:
        correct = int(request.form.get("correct", "-1"))
    except ValueError:
        correct = -1
    if question and all(options) and 0 <= correct <= 3:
        quiz = query("SELECT * FROM quizzes WHERE course_id=?", (cid,), one=True)
        if not quiz:
            course = query("SELECT * FROM courses WHERE id=?", (cid,), one=True)
            quiz_title = (course_title(course["level_code"], course["subject"], course["title"])
                          if course else "Quiz")
            quiz_id = execute("INSERT INTO quizzes(course_id,title,created_at) VALUES(?,?,?)",
                              (cid, quiz_title, dt.datetime.now().strftime("%Y-%m-%d %H:%M")))
        else:
            quiz_id = quiz["id"]
        pos = query("SELECT COALESCE(MAX(position),-1)+1 p FROM quiz_questions "
                    "WHERE quiz_id=?", (quiz_id,), one=True)["p"]
        qid = execute("INSERT INTO quiz_questions(quiz_id,question,position) VALUES(?,?,?)",
                      (quiz_id, question, pos))
        for i, opt in enumerate(options):
            execute("INSERT INTO quiz_options(question_id,option_text,is_correct,position) "
                    "VALUES(?,?,?,?)", (qid, opt, 1 if i == correct else 0, i))
        flash(t("flash.quiz_question_added"), "ok")
    else:
        flash(t("flash.quiz_question_invalid"), "error")
    return redirect(url_for("admin_panel", tab="content"))


@app.route("/admin/quiz/question/<int:qid>/delete", methods=["POST"])
@staff_required
def admin_quiz_question_delete(qid):
    enforce_prof_scope(course_id_for_quiz_question(qid))
    execute("DELETE FROM quiz_questions WHERE id=?", (qid,))
    flash(t("flash.quiz_question_deleted"), "warn")
    return redirect(url_for("admin_panel", tab="content"))


@app.route("/admin/live/add", methods=["POST"])
@staff_required
def admin_live_add():
    title = request.form.get("title", "").strip()
    subject = request.form.get("subject")
    level = g.user["level_code"] if g.user["role"] == "prof" else request.form.get("level_code")
    starts = request.form.get("starts_at", "").strip().replace("T", " ")
    if title and subject in all_subject_codes() and level in all_level_codes() and starts:
        execute("INSERT INTO live_sessions(title,subject,level_code,teacher,"
                "starts_at,duration_min,meet_url) VALUES(?,?,?,?,?,?,?)",
                (title, subject, level,
                 request.form.get("teacher", "").strip(), starts,
                 int(request.form.get("duration_min", 60) or 60),
                 request.form.get("meet_url", "").strip()))
        flash(t("flash.live_added"), "ok")
    else:
        flash(t("flash.live_invalid"), "error")
    return redirect(url_for("admin_panel", tab="lives"))


@app.route("/admin/live/<int:lid>/delete", methods=["POST"])
@staff_required
def admin_live_delete(lid):
    if g.user["role"] == "prof":
        live = query("SELECT level_code FROM live_sessions WHERE id=?", (lid,), one=True)
        if not live or live["level_code"] != g.user["level_code"]:
            abort(403)
    execute("DELETE FROM live_sessions WHERE id=?", (lid,))
    flash(t("flash.live_deleted"), "warn")
    return redirect(url_for("admin_panel", tab="lives"))


@app.route("/admin/chat/send", methods=["POST"])
@staff_required
def admin_chat_send():
    level = g.user["level_code"] if g.user["role"] == "prof" else request.form.get("level_code", "")
    body = request.form.get("body", "").strip()
    if level in all_level_codes() and body:
        execute("INSERT INTO chat_messages(level_code,channel,author_id,body,created_at) "
                "VALUES(?,?,?,?,?)",
                (level, "general", g.user["id"], body,
                 dt.datetime.now().strftime("%Y-%m-%d %H:%M")))
        notify_chat_recipients(level, "general", g.user["id"], g.user["name"], body)
        flash(t("flash.chat_sent"), "ok")
    else:
        flash(t("flash.chat_invalid"), "error")
    return redirect(url_for("admin_panel", tab="chat", clevel=level))


@app.route("/admin/notify/send", methods=["POST"])
@admin_required
def admin_notify_send():
    title = request.form.get("title", "").strip()
    body = request.form.get("body", "").strip()
    target = request.form.get("target", "all")
    if not title or not body:
        flash(t("flash.notify_invalid"), "error")
        return redirect(url_for("admin_panel", tab="notifications"))
    if target == "all":
        recipients = query("SELECT id FROM users WHERE role='student'")
    elif target in all_level_codes():
        recipients = query("SELECT id FROM users WHERE role='student' AND level_code=?",
                           (target,))
    else:
        recipients = []
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    for r in recipients:
        execute("INSERT INTO notifications(user_id,title,body,created_at) "
                "VALUES(?,?,?,?)", (r["id"], title, body, now))
    flash(t("flash.notify_sent", n=len(recipients)), "ok")
    return redirect(url_for("admin_panel", tab="notifications"))


# ----------------------------------------------------------------------------
# Taxonomy — levels & subjects, fully admin-managed
# ----------------------------------------------------------------------------
CODE_RE = re.compile(r"^[a-z0-9]{2,8}$")


@app.route("/admin/levels/add", methods=["POST"])
@admin_required
def admin_level_add():
    code = request.form.get("code", "").strip().lower()
    name_ar = request.form.get("name_ar", "").strip()
    name_fr = request.form.get("name_fr", "").strip()
    if not CODE_RE.match(code) or not name_ar or not name_fr:
        flash(t("flash.taxonomy_invalid"), "error")
    elif query("SELECT code FROM levels WHERE code=?", (code,), one=True):
        flash(t("flash.taxonomy_code_taken"), "error")
    else:
        next_order = query("SELECT COALESCE(MAX(sort_order),-1)+1 n FROM levels", one=True)["n"]
        execute("INSERT INTO levels(code,name_ar,name_fr,sort_order) VALUES(?,?,?,?)",
                (code, name_ar, name_fr, next_order))
        flash(t("flash.level_added"), "ok")
    return redirect(url_for("admin_panel", tab="taxonomy"))


@app.route("/admin/levels/<code>/edit", methods=["POST"])
@admin_required
def admin_level_edit(code):
    name_ar = request.form.get("name_ar", "").strip()
    name_fr = request.form.get("name_fr", "").strip()
    if name_ar and name_fr:
        execute("UPDATE levels SET name_ar=?, name_fr=? WHERE code=?",
                (name_ar, name_fr, code))
        flash(t("flash.level_updated"), "ok")
    else:
        flash(t("flash.taxonomy_invalid"), "error")
    return redirect(url_for("admin_panel", tab="taxonomy"))


@app.route("/admin/levels/<code>/delete", methods=["POST"])
@admin_required
def admin_level_delete(code):
    n_users = query("SELECT COUNT(*) c FROM users WHERE level_code=?", (code,), one=True)["c"]
    n_courses = query("SELECT COUNT(*) c FROM courses WHERE level_code=?", (code,), one=True)["c"]
    n_lives = query("SELECT COUNT(*) c FROM live_sessions WHERE level_code=?", (code,), one=True)["c"]
    if n_users or n_courses or n_lives:
        flash(t("flash.taxonomy_in_use"), "error")
    else:
        execute("DELETE FROM levels WHERE code=?", (code,))
        flash(t("flash.level_deleted"), "warn")
    return redirect(url_for("admin_panel", tab="taxonomy"))


@app.route("/admin/subjects/add", methods=["POST"])
@admin_required
def admin_subject_add():
    code = request.form.get("code", "").strip().lower()
    name_ar = request.form.get("name_ar", "").strip()
    name_fr = request.form.get("name_fr", "").strip()
    color = request.form.get("color", "").strip() or "#2350D8"
    glyph = request.form.get("glyph", "").strip() or "📘"
    if not CODE_RE.match(code) or not name_ar or not name_fr:
        flash(t("flash.taxonomy_invalid"), "error")
    elif query("SELECT code FROM subjects WHERE code=?", (code,), one=True):
        flash(t("flash.taxonomy_code_taken"), "error")
    else:
        next_order = query("SELECT COALESCE(MAX(sort_order),-1)+1 n FROM subjects", one=True)["n"]
        execute("INSERT INTO subjects(code,name_ar,name_fr,color,glyph,sort_order) "
                "VALUES(?,?,?,?,?,?)",
                (code, name_ar, name_fr, color, glyph, next_order))
        flash(t("flash.subject_added"), "ok")
    return redirect(url_for("admin_panel", tab="taxonomy"))


@app.route("/admin/subjects/<code>/edit", methods=["POST"])
@admin_required
def admin_subject_edit(code):
    name_ar = request.form.get("name_ar", "").strip()
    name_fr = request.form.get("name_fr", "").strip()
    color = request.form.get("color", "").strip() or "#2350D8"
    glyph = request.form.get("glyph", "").strip() or "📘"
    if name_ar and name_fr:
        execute("UPDATE subjects SET name_ar=?, name_fr=?, color=?, glyph=? WHERE code=?",
                (name_ar, name_fr, color, glyph, code))
        flash(t("flash.subject_updated"), "ok")
    else:
        flash(t("flash.taxonomy_invalid"), "error")
    return redirect(url_for("admin_panel", tab="taxonomy"))


@app.route("/admin/subjects/<code>/delete", methods=["POST"])
@admin_required
def admin_subject_delete(code):
    n_courses = query("SELECT COUNT(*) c FROM courses WHERE subject=?", (code,), one=True)["c"]
    n_lives = query("SELECT COUNT(*) c FROM live_sessions WHERE subject=?", (code,), one=True)["c"]
    n_blocks = query("SELECT COUNT(*) c FROM study_blocks WHERE subject=?", (code,), one=True)["c"]
    if n_courses or n_lives or n_blocks:
        flash(t("flash.taxonomy_in_use"), "error")
    else:
        execute("DELETE FROM subjects WHERE code=?", (code,))
        flash(t("flash.subject_deleted"), "warn")
    return redirect(url_for("admin_panel", tab="taxonomy"))


# ----------------------------------------------------------------------------
# Teachers — admin-only account management for the "prof" role
# ----------------------------------------------------------------------------
@app.route("/admin/teachers/add", methods=["POST"])
@admin_required
def admin_teacher_add():
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    pw = request.form.get("password", "")
    level = request.form.get("level_code", "")
    if not name or not email or len(pw) < 6 or level not in all_level_codes():
        flash(t("flash.teacher_invalid"), "error")
    elif query("SELECT id FROM users WHERE email=?", (email,), one=True):
        flash(t("flash.email_taken"), "error")
    else:
        execute("INSERT INTO users(name,email,password_hash,level_code,role,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (name, email, generate_password_hash(pw), level, "prof",
                 dt.datetime.now().strftime("%Y-%m-%d %H:%M")))
        flash(t("flash.teacher_added"), "ok")
    return redirect(url_for("admin_panel", tab="teachers"))


@app.route("/admin/teachers/<int:uid>/edit", methods=["POST"])
@admin_required
def admin_teacher_edit(uid):
    teacher = query("SELECT id FROM users WHERE id=? AND role='prof'", (uid,), one=True)
    if not teacher:
        abort(404)
    name = request.form.get("name", "").strip()
    level = request.form.get("level_code", "")
    if name and level in all_level_codes():
        execute("UPDATE users SET name=?, level_code=? WHERE id=?", (name, level, uid))
        flash(t("flash.teacher_updated"), "ok")
    else:
        flash(t("flash.teacher_invalid"), "error")
    return redirect(url_for("admin_panel", tab="teachers"))


@app.route("/admin/teachers/<int:uid>/delete", methods=["POST"])
@admin_required
def admin_teacher_delete(uid):
    execute("DELETE FROM users WHERE id=? AND role='prof'", (uid,))
    flash(t("flash.teacher_deleted"), "warn")
    return redirect(url_for("admin_panel", tab="teachers"))


# ----------------------------------------------------------------------------
# Background reminders — live sessions and (possibly recurring) study blocks
# starting in about an hour get a one-time notification. This is a single
# lightweight process (SQLite, no task queue), so a daemon thread polling
# every minute is enough; idempotency comes from `reminded_at` / the
# block_reminders UNIQUE constraint rather than precise scheduling.
# ----------------------------------------------------------------------------
REMINDER_LEAD_MINUTES = 60


def _send_live_reminders(now):
    window_start = now + dt.timedelta(minutes=REMINDER_LEAD_MINUTES)
    window_end = window_start + dt.timedelta(minutes=1)
    lives = query(
        "SELECT * FROM live_sessions WHERE reminded_at IS NULL "
        "AND starts_at >= ? AND starts_at < ?",
        (window_start.strftime("%Y-%m-%d %H:%M"), window_end.strftime("%Y-%m-%d %H:%M")))
    now_s = now.strftime("%Y-%m-%d %H:%M")
    for s in lives:
        recipients = query("SELECT id FROM users WHERE role='student' AND level_code=?",
                           (s["level_code"],))
        title = "🔴 حصة مباشرة تبدأ قريبًا"
        body = f"«{s['title']}» تبدأ الساعة {s['starts_at'][-5:]} — خلال ساعة تقريبًا."
        for r in recipients:
            execute("INSERT INTO notifications(user_id,title,body,created_at) VALUES(?,?,?,?)",
                    (r["id"], title, body, now_s))
        execute("UPDATE live_sessions SET reminded_at=? WHERE id=?", (now_s, s["id"]))


def _send_block_reminders(now):
    window_start = now + dt.timedelta(minutes=REMINDER_LEAD_MINUTES)
    target_date = window_start.date()
    target_hhmm = window_start.strftime("%H:%M")
    now_s = now.strftime("%Y-%m-%d %H:%M")
    blocks = query("SELECT * FROM study_blocks WHERE start_time=?", (target_hhmm,))
    for b in blocks:
        if not block_occurs_on(b, target_date):
            continue
        try:
            execute("INSERT INTO block_reminders(block_id,the_date,created_at) VALUES(?,?,?)",
                    (b["id"], target_date.isoformat(), now_s))
        except sqlite3.IntegrityError:
            continue  # already reminded for this occurrence
        label = b["note"] or (subject_name(b["subject"]) if b["subject"] else "فترة مراجعة")
        title = "⏰ فترة مراجعة تبدأ قريبًا"
        body = f"«{label}» تبدأ الساعة {b['start_time']} — خلال ساعة تقريبًا."
        execute("INSERT INTO notifications(user_id,title,body,created_at) VALUES(?,?,?,?)",
                (b["user_id"], title, body, now_s))


def _reminder_loop():
    while True:
        try:
            with app.app_context():
                now = dt.datetime.now()
                _send_live_reminders(now)
                _send_block_reminders(now)
        except Exception:
            pass
        time.sleep(60)


def start_reminder_thread():
    threading.Thread(target=_reminder_loop, daemon=True).start()


if __name__ != "__main__":
    # Imported by a production server (e.g. gunicorn) — no dev reloader
    # involved, so this only ever runs once per process.
    start_reminder_thread()


# ----------------------------------------------------------------------------
# Errors
# ----------------------------------------------------------------------------
@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, msg=t("error.404")), 404


@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, msg=t("error.403")), 403


# ----------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        # The reloader's watcher process re-executes this whole module too;
        # only the actual serving child sets this, so start the thread once.
        start_reminder_thread()
    app.run(debug=True, host="127.0.0.1", port=5000)
