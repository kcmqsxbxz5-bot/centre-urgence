
from flask import Flask, render_template, request, redirect, url_for, session, g, jsonify, send_file, abort
import sqlite3, hashlib as hl, os, io
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle, Image
from reportlab.lib import colors
import qrcode

APP_DIR = os.path.dirname(__file__)
DB_PATH = os.path.join(APP_DIR, "data.db")
LOGO_PATH = os.path.join(APP_DIR, "static", "logo.png")

ORG_NAME = "Centre d'Urgence Médicale"
ORG_ADDRESS = "Nouakchott, Mauritanie"
ORG_PHONE = "Tél: 101 / 116 / 117"
ORG_EMAIL = "contact@centre-urgence.mr"

# Private key for digital signature (change in production)
SIGN_KEY = "CHANGE_ME_SECRET_KEY"

app = Flask(__name__)
app.secret_key = "change-this-secret"

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def hash_pw(pw):
    return hl.sha256(pw.encode()).hexdigest()

def sign_data(data: str):
    return hl.sha256((data + SIGN_KEY).encode()).hexdigest()

def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        role TEXT NOT NULL,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS patients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        lname TEXT, fname TEXT, phone TEXT
    );
    CREATE TABLE IF NOT EXISTS cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id INTEGER,
        priority TEXT,
        reason TEXT,
        diagnosis TEXT,
        treatment TEXT,
        status TEXT DEFAULT 'open',
        archived INTEGER DEFAULT 0,
        legal_hash TEXT,
        signature TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        closed_at DATETIME,
        FOREIGN KEY(patient_id) REFERENCES patients(id)
    );
    CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user TEXT,
        role TEXT,
        action TEXT,
        entity TEXT,
        entity_id INTEGER,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    """)
    cur = db.execute("SELECT COUNT(*) c FROM users")
    if cur.fetchone()["c"] == 0:
        db.execute("INSERT INTO users (name, role, username, password) VALUES (?,?,?,?)",
                   ("Admin", "admin", "admin", hash_pw("admin123")))
    db.commit()

@app.before_request
def before():
    init_db()

def audit(action, entity, entity_id=None):
    if 'user' in session:
        db = get_db()
        db.execute("INSERT INTO audit (user, role, action, entity, entity_id) VALUES (?,?,?,?,?)",
                   (session['user']['name'], session['user']['role'], action, entity, entity_id))
        db.commit()

def require_role(*roles):
    if 'user' not in session: abort(401)
    if session['user']['role'] not in roles: abort(403)

@app.route("/", methods=["GET"])
def home():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template("dashboard.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        u = request.form["username"]
        p = hash_pw(request.form["password"])
        db = get_db()
        cur = db.execute("SELECT * FROM users WHERE username=? AND password=?", (u,p))
        row = cur.fetchone()
        if row:
            session["user"] = dict(row)
            audit("login", "user", row["id"])
            return redirect(url_for("home"))
        return render_template("login.html", error="Identifiants incorrects")
    return render_template("login.html")

@app.route("/logout")
def logout():
    if 'user' in session:
        audit("logout", "user", session['user']['id'])
    session.clear()
    return redirect(url_for("login"))

@app.route("/api/case", methods=["POST"])
def add_case():
    require_role("admin","doctor")
    data = request.json
    db = get_db()
    cur = db.execute("INSERT INTO patients (lname,fname,phone) VALUES (?,?,?)",
                     (data.get("lname"), data.get("fname"), data.get("phone")))
    pid = cur.lastrowid
    cur = db.execute("""INSERT INTO cases (patient_id, priority, reason, diagnosis, treatment)
                        VALUES (?,?,?,?,?)""",
                     (pid, data.get("priority"), data.get("reason"), data.get("diagnosis"), data.get("treatment")))
    cid = cur.lastrowid
    db.commit()
    audit("create", "case", cid)
    return jsonify({"case_id": cid})

@app.route("/api/archive/<int:cid>", methods=["POST"])
def archive_case(cid):
    require_role("admin","doctor")
    db = get_db()
    row = db.execute("SELECT * FROM cases WHERE id=?", (cid,)).fetchone()
    if not row: return ("Not found",404)
    content = f"{row['id']}{row['patient_id']}{row['priority']}{row['reason']}{row['diagnosis']}{row['treatment']}{row['created_at']}"
    legal_hash = hl.sha256(content.encode()).hexdigest()
    signature = sign_data(legal_hash)
    db.execute("UPDATE cases SET archived=1, status='closed', closed_at=CURRENT_TIMESTAMP, legal_hash=?, signature=? WHERE id=?",
               (legal_hash, signature, cid))
    db.commit()
    audit("archive", "case", cid)
    return jsonify({"ok": True, "hash": legal_hash, "signature": signature})

# -------- PDF WITH QR & SIGNATURE --------
def build_pdf(title_fr, title_ar, items, qr_data, signature):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    styles = getSampleStyleSheet()
    flow = []
    header = Table([
        [Image(LOGO_PATH, width=80, height=40) if os.path.exists(LOGO_PATH) else "",
         Paragraph(f"<b>{ORG_NAME}</b><br/>{ORG_ADDRESS}<br/>{ORG_PHONE}<br/>{ORG_EMAIL}", styles['Normal'])]
    ], colWidths=[90, 410])
    header.setStyle(TableStyle([('BOX',(0,0),(-1,-1),0.5,colors.black)]))
    flow.append(header)
    flow.append(Paragraph(f"{title_fr} / {title_ar}", styles['Title']))
    table = Table(items, repeatRows=1, colWidths=[180, 320])
    table.setStyle(TableStyle([('GRID',(0,0),(-1,-1),0.5,colors.black)]))
    flow.append(table)

    qr = qrcode.make(qr_data)
    qr_path = os.path.join(APP_DIR, "static", "tmp_qr.png")
    qr.save(qr_path)
    flow.append(Paragraph("Vérification / التحقق:", styles['Normal']))
    flow.append(Image(qr_path, width=100, height=100))
    flow.append(Paragraph(f"Signature: {signature}", styles['Normal']))

    doc.build(flow)
    buffer.seek(0)
    return buffer

@app.route("/pdf/rapport/<int:cid>")
def rapport_pdf(cid):
    require_role("admin","doctor")
    db = get_db()
    r = db.execute("""
      SELECT p.lname, p.fname, c.priority, c.reason, c.diagnosis, c.treatment, c.legal_hash, c.signature
      FROM cases c JOIN patients p ON p.id=c.patient_id WHERE c.id=?""",(cid,)).fetchone()
    if not r: return ("Not found",404)
    items = [
        ["Patient / المريض", f"{r['lname']} {r['fname']}"],
        ["Priorité / الأولوية", r["priority"]],
        ["Motif / السبب", r["reason"] or ""],
        ["Diagnostic / التشخيص", r["diagnosis"] or ""],
        ["Traitement / العلاج", r["treatment"] or ""],
    ]
    qr_data = url_for('public_verify', cid=cid, _external=True)
    buf = build_pdf("Rapport médical", "تقرير طبي", items, qr_data, r["signature"])
    audit("print", "rapport", cid)
    return send_file(buf, as_attachment=True, download_name=f"rapport_{cid}.pdf", mimetype="application/pdf")

# -------- PUBLIC VERIFICATION --------
@app.route("/verify/<int:cid>")
def public_verify(cid):
    db = get_db()
    r = db.execute("SELECT legal_hash, signature FROM cases WHERE id=? AND archived=1",(cid,)).fetchone()
    if not r: return "Document non trouvé ou non archivé",404
    # verify signature
    valid = (r["signature"] == sign_data(r["legal_hash"]))
    return render_template("verify.html", cid=cid, valid=valid, hash=r["legal_hash"], signature=r["signature"])

# -------- EXPORT LEGAL ARCHIVES PDF --------
@app.route("/pdf/archives")
def export_archives():
    require_role("admin")
    db = get_db()
    rows = db.execute("""
      SELECT c.id, p.lname, p.fname, c.legal_hash, c.signature, c.closed_at
      FROM cases c JOIN patients p ON p.id=c.patient_id WHERE c.archived=1 ORDER BY c.closed_at DESC
    """).fetchall()
    items = [["ID","Patient","Hash","Signature","Date"]]
    for r in rows:
        items.append([str(r["id"]), f"{r['lname']} {r['fname']}", r["legal_hash"], r["signature"], r["closed_at"]])
    buf = build_pdf("Archives légales","الأرشيف القانوني", items, "ARCHIVES", "SYSTEM")
    audit("export", "archives", None)
    return send_file(buf, as_attachment=True, download_name="archives_legales.pdf", mimetype="application/pdf")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
