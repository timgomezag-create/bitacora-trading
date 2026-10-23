import os
import sqlite3
import hashlib
import secrets
from contextlib import contextmanager
from datetime import datetime
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import libsql_client

app = FastAPI(title="Bitácora de Trading Pro")

# ---------- Configuración de Base de Datos ----------
TURSO_URL = os.environ.get("TURSO_DATABASE_URL")
TURSO_TOKEN = os.environ.get("TURSO_AUTH_TOKEN")
USE_TURSO = bool(TURSO_URL and TURSO_TOKEN)
DB_LOCAL = "journal.db"

@contextmanager
def get_db():
    if USE_TURSO:
        # Normalizar la URL de Turso para libsql_client
        url = TURSO_URL.replace("libsql://", "https://") if TURSO_URL.startswith("libsql://") else TURSO_URL
        client = libsql_client.create_client_sync(url=url, auth_token=TURSO_TOKEN)
        try:
            yield client
        finally:
            client.close()
    else:
        conn = sqlite3.connect(DB_LOCAL)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

def db_execute(query, params=(), fetch=False):
    with get_db() as c:
        if USE_TURSO:
            res = c.execute(query, list(params))
            if fetch:
                return [dict(row) for row in res.rows]
            return res
        else:
            cur = c.execute(query, params)
            if fetch:
                return [dict(row) for row in cur.fetchall()]
            return cur

def init_db():
    with get_db() as c:
        if USE_TURSO:
            statements = [
                "CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, share_token TEXT UNIQUE, is_public INTEGER DEFAULT 0, initial_capital REAL DEFAULT 10000)",
                "CREATE TABLE IF NOT EXISTS tokens(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL)",
                """CREATE TABLE IF NOT EXISTS trades(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    user_id INTEGER NOT NULL, 
                    symbol TEXT NOT NULL, 
                    side TEXT NOT NULL,
                    session TEXT,
                    setup TEXT,
                    result TEXT,
                    pips REAL,
                    lot_size REAL,
                    pip_value REAL DEFAULT 10,
                    risk_pips REAL,
                    notes TEXT,
                    chart_image TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )"""
            ]
            for stmt in statements:
                c.execute(stmt)
        else:
            c.executescript("""
            CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, share_token TEXT UNIQUE, is_public INTEGER DEFAULT 0, initial_capital REAL DEFAULT 10000);
            CREATE TABLE IF NOT EXISTS tokens(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS trades(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                symbol TEXT NOT NULL,
                side TEXT NOT NULL,
                session TEXT,
                setup TEXT,
                result TEXT,
                pips REAL,
                lot_size REAL,
                pip_value REAL DEFAULT 10,
                risk_pips REAL,
                notes TEXT,
                chart_image TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            """)
    
    # Migraciones seguras para añadir columnas nuevas a tablas existentes
    nuevas_columnas = [
        ("session", "TEXT"),
        ("setup", "TEXT"),
        ("result", "TEXT"),
        ("pips", "REAL"),
        ("lot_size", "REAL"),
        ("pip_value", "REAL DEFAULT 10"),
        ("risk_pips", "REAL")
    ]
    for col, tipo in nuevas_columnas:
        try:
            db_execute(f"ALTER TABLE trades ADD COLUMN {col} {tipo}")
        except Exception:
            pass  # La columna ya existe

# --- INICIALIZACIÓN SEGURA ---
_db_initialized = False

def ensure_db():
    global _db_initialized
    if _db_initialized:
        return
    try:
        init_db()
        _db_initialized = True
    except Exception as e:
        print(f"⚠️ Error al inicializar la DB (se reintentará luego): {e}")

# Intentar inicializar al arrancar, pero SIN bloquear si falla
try:
    ensure_db()
except Exception:
    pass

@app.get("/health")
def health_check():
    return {"status": "ok", "db_initialized": _db_initialized}

# ---------- Utilidades de Autenticación ----------
def hash_pw(pw):
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100000).hex()
    return f"{salt}${h}"

def check_pw(pw, stored):
    salt, h = stored.split("$")
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 100000).hex() == h

def current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "No autenticado")
    token = authorization[7:]
    rows = db_execute("SELECT user_id FROM tokens WHERE token=?", (token,), fetch=True)
    if not rows:
        raise HTTPException(401, "Token inválido")
    return rows[0]["user_id"]

# ---------- Modelos de Datos ----------
class AuthIn(BaseModel):
    username: str
    password: str

class TradeIn(BaseModel):
    symbol: str
    side: str
    session: Optional[str] = None
    setup: Optional[str] = None
    result: Optional[str] = None
    pips: Optional[float] = None
    lot_size: Optional[float] = None
    pip_value: Optional[float] = 10
    risk_pips: Optional[float] = None
    notes: Optional[str] = None
    chart_image: Optional[str] = None

class ShareIn(BaseModel):
    enabled: bool

class CapitalIn(BaseModel):
    amount: float

# ---------- Rutas de Autenticación ----------
@app.post("/api/register")
def register(data: AuthIn):
    ensure_db() # <-- Asegurar DB
    if len(data.username) < 3 or len(data.password) < 6:
        raise HTTPException(400, "Usuario mínimo 3 y contraseña mínimo 6")
    try:
        db_execute("INSERT INTO users(username, password_hash, share_token) VALUES(?,?,?)",
                   (data.username, hash_pw(data.password), secrets.token_urlsafe(16)))
        user = db_execute("SELECT id FROM users WHERE username=?", (data.username,), fetch=True)[0]
        token = secrets.token_urlsafe(32)
        db_execute("INSERT INTO tokens(token, user_id) VALUES(?,?)", (token, user["id"]))
        return {"token": token, "username": data.username}
    except Exception as e:
        if "UNIQUE" in str(e):
            raise HTTPException(400, "El usuario ya existe")
        raise HTTPException(500, str(e))

@app.post("/api/login")
def login(data: AuthIn):
    ensure_db() # <-- Asegurar DB
    rows = db_execute("SELECT * FROM users WHERE username=?", (data.username,), fetch=True)
    if not rows or not check_pw(data.password, rows[0]["password_hash"]):
        raise HTTPException(401, "Credenciales incorrectas")
    token = secrets.token_urlsafe(32)
    db_execute("INSERT INTO tokens(token, user_id) VALUES(?,?)", (token, rows[0]["id"]))
    return {"token": token, "username": rows[0]["username"]}

@app.get("/api/me")
def me(authorization: str = Header(None)):
    ensure_db() # <-- Asegurar DB
    uid = current_user(authorization)
    return db_execute("SELECT id, username, share_token, is_public, initial_capital FROM users WHERE id=?", (uid,), fetch=True)[0]

@app.put("/api/settings")
def update_settings(data: CapitalIn, authorization: str = Header(None)):
    ensure_db() # <-- Asegurar DB
    uid = current_user(authorization)
    db_execute("UPDATE users SET initial_capital=? WHERE id=?", (data.amount, uid))
    return {"ok": True}

# ---------- Rutas de Operaciones ----------
@app.get("/api/trades")
def list_trades(authorization: str = Header(None)):
    ensure_db() # <-- Asegurar DB
    uid = current_user(authorization)
    return db_execute("""
        SELECT id, user_id, symbol, side, session, setup, result, pips, lot_size, pip_value, risk_pips, notes,
               (chart_image IS NOT NULL) as has_image, created_at
        FROM trades WHERE user_id=? ORDER BY created_at DESC
    """, (uid,), fetch=True)

@app.get("/api/trades/{trade_id}/image")
def get_trade_image(trade_id: int, authorization: str = Header(None)):
    ensure_db() # <-- Asegurar DB
    uid = current_user(authorization)
    rows = db_execute("SELECT chart_image FROM trades WHERE id=? AND user_id=?", (trade_id, uid), fetch=True)
    if not rows or not rows[0]["chart_image"]:
        raise HTTPException(404, "Sin imagen")
    return {"image": rows[0]["chart_image"]}

@app.post("/api/trades")
def create_trade(t: TradeIn, authorization: str = Header(None)):
    ensure_db() # <-- Asegurar DB
    uid = current_user(authorization)
    db_execute("""
        INSERT INTO trades(user_id, symbol, side, session, setup, result, pips, lot_size, pip_value, risk_pips, notes, chart_image)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
    """, (uid, t.symbol, t.side, t.session, t.setup, t.result, t.pips, t.lot_size, t.pip_value, t.risk_pips, t.notes, t.chart_image))
    return {"ok": True}

@app.put("/api/trades/{trade_id}")
def update_trade(trade_id: int, t: TradeIn, authorization: str = Header(None)):
    ensure_db() # <-- Asegurar DB
    uid = current_user(authorization)
    db_execute("""
        UPDATE trades SET symbol=?, side=?, session=?, setup=?, result=?, pips=?, lot_size=?, pip_value=?, risk_pips=?, notes=?, chart_image=COALESCE(?, chart_image)
        WHERE id=? AND user_id=?
    """, (t.symbol, t.side, t.session, t.setup, t.result, t.pips, t.lot_size, t.pip_value, t.risk_pips, t.notes, t.chart_image, trade_id, uid))
    return {"ok": True}

@app.delete("/api/trades/{trade_id}")
def delete_trade(trade_id: int, authorization: str = Header(None)):
    ensure_db() # <-- Asegurar DB
    uid = current_user(authorization)
    db_execute("DELETE FROM trades WHERE id=? AND user_id=?", (trade_id, uid))
    return {"ok": True}

# ---------- Rutas para Compartir ----------
@app.post("/api/share")
def toggle_share(data: ShareIn, authorization: str = Header(None)):
    ensure_db() # <-- Asegurar DB
    uid = current_user(authorization)
    db_execute("UPDATE users SET is_public=? WHERE id=?", (1 if data.enabled else 0, uid))
    rows = db_execute("SELECT share_token FROM users WHERE id=?", (uid,), fetch=True)
    return {"enabled": data.enabled, "share_token": rows[0]["share_token"]}

@app.get("/api/public/{share_token}")
def public_view(share_token: str):
    ensure_db() # <-- Asegurar DB
    users = db_execute("SELECT id, username, is_public, initial_capital FROM users WHERE share_token=?", (share_token,), fetch=True)
    if not users or not users[0]["is_public"]:
        raise HTTPException(404, "Bitácora no disponible")
    trades = db_execute("""
        SELECT id, symbol, side, session, setup, result, pips, lot_size, pip_value, risk_pips, notes,
               (chart_image IS NOT NULL) as has_image, created_at
        FROM trades WHERE user_id=? ORDER BY created_at DESC
    """, (users[0]["id"],), fetch=True)
    return {"username": users[0]["username"], "trades": trades, "initial_capital": users[0]["initial_capital"]}

# ---------- Frontend ----------
HTML = r"""
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bitácora de Trading Pro</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  :root{--bg:#0f1720;--card:#17212b;--line:#243140;--txt:#e6edf3;--mut:#8aa0b4;--acc:#3fb950;--neg:#f85149;--blue:#58a6ff}
  *{box-sizing:border-box} body{margin:0;font-family:system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--txt)}
  header{display:flex;justify-content:space-between;align-items:center;padding:14px 22px;border-bottom:1px solid var(--line);background:#0b1219}
  h1{font-size:18px;margin:0} .mut{color:var(--mut);font-size:13px}
  .container{max-width:1250px;margin:0 auto;padding:22px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
  .metric{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
  .metric .v{font-size:20px;font-weight:600;margin-top:4px}
  .metric .l{font-size:11px;color:var(--mut);text-transform:uppercase;letter-spacing:.5px}
  .pos{color:var(--acc)} .neg{color:var(--neg)}
  button{background:var(--blue);color:#04121f;border:none;padding:9px 14px;border-radius:8px;font-weight:600;cursor:pointer}
  button.ghost{background:transparent;color:var(--txt);border:1px solid var(--line)}
  button.danger{background:var(--neg);color:#fff}
  input,select,textarea{width:100%;background:#0d151d;border:1px solid var(--line);color:var(--txt);padding:9px;border-radius:8px;margin-top:4px}
  label{font-size:12px;color:var(--mut)}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{padding:8px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}
  th{color:var(--mut);font-weight:500;font-size:12px;text-transform:uppercase}
  .row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
  .modal{position:fixed;inset:0;background:rgba(0,0,0,.8);display:none;align-items:center;justify-content:center;padding:20px;z-index:50}
  .modal.open{display:flex}
  .modal .card{max-width:640px;width:100%;max-height:90vh;overflow:auto}
  .modal-img{max-width:95vw;max-height:95vh;border-radius:8px}
  .two{display:grid;grid-template-columns:1fr 1fr;gap:10px}
  .hidden{display:none!important}
  a{color:var(--blue)}
  .banner{background:#1f2a12;border:1px solid #3fb95033;color:var(--acc);padding:8px 12px;border-radius:8px;font-size:13px}
  .img-preview{max-width:100%;max-height:200px;border-radius:8px;margin-top:8px;object-fit:contain;background:#0b1219}
  .edge-card{background:#0d151d;border:1px solid var(--line);border-radius:8px;padding:12px}
</style>
</head>
<body>
<header>
  <div class="row"><strong>📓 Bitácora Pro</strong><span id="userLabel" class="mut"></span></div>
  <div class="row" id="topActions">
    <button class="ghost hidden" id="configBtn" onclick="openConfig()">⚙️ Config</button>
    <button class="ghost hidden" id="shareBtn" onclick="toggleShare()">Compartir</button>
    <button class="ghost hidden" id="logoutBtn" onclick="logout()">Salir</button>
  </div>
</header>

<div class="container" id="authView">
  <div class="card" style="max-width:420px;margin:60px auto">
    <h1 id="authTitle">Ingresar</h1>
    <p class="mut" id="authHelp">Creá una cuenta o iniciá sesión.</p>
    <label>Usuario<input id="username" autocomplete="username"></label>
    <label style="display:block;margin-top:10px">Contraseña<input id="password" type="password" autocomplete="current-password"></label>
    <div class="row" style="margin-top:16px">
      <button id="submitAuth" onclick="doAuth()">Ingresar</button>
      <button class="ghost" onclick="switchAuth()"><span id="switchLabel">Crear cuenta</span></button>
    </div>
    <p class="mut" id="authError" style="color:var(--neg)"></p>
  </div>
</div>

<div class="container hidden" id="appView">
  <div id="publicBanner" class="banner hidden"></div>
  
  <div class="grid" id="metricsGrid"></div>
  
  <!-- Dashboard de Edge -->
  <div class="card">
    <strong>📊 Dashboard de Edge (Mejor rendimiento)</strong>
    <div class="grid" style="margin-top:12px" id="edgeGrid">
        <div class="edge-card"><div class="l">Mejor Activo</div><div class="v" id="bestAsset">—</div></div>
        <div class="edge-card"><div class="l">Mejor Sesión</div><div class="v" id="bestSession">—</div></div>
        <div class="edge-card"><div class="l">Mejor Setup</div><div class="v" id="bestSetup">—</div></div>
        <div class="edge-card"><div class="l">Mejor Día</div><div class="v" id="bestDay">—</div></div>
    </div>
  </div>

  <div class="card">
    <div class="row" style="justify-content:space-between;margin-bottom:10px">
      <strong>Curva de Capital</strong>
      <div class="row">
        <label style="margin:0">Desde: <input type="date" id="filterFrom" onchange="renderAll()" style="width:auto;padding:4px"></label>
        <label style="margin:0">Hasta: <input type="date" id="filterTo" onchange="renderAll()" style="width:auto;padding:4px"></label>
      </div>
    </div>
    <canvas id="equityChart" height="90"></canvas>
  </div>

  <div class="card">
    <div class="row" style="justify-content:space-between;margin-bottom:12px">
      <strong>Operaciones</strong>
      <div class="row">
        <select id="filterSession" onchange="renderAll()" style="width:130px"></select>
        <select id="filterSymbol" onchange="renderAll()" style="width:120px"></select>
        <button id="addBtn" onclick="openForm()">+ Nueva operación</button>
      </div>
    </div>
    <div style="overflow:auto"><table id="tradesTable"></table></div>
  </div>
</div>

<!-- Modal de Formulario -->
<div class="modal" id="modal">
  <div class="card">
    <div class="row" style="justify-content:space-between"><strong id="formTitle">Nueva operación</strong>
      <button class="ghost" onclick="closeForm()">✕</button></div>
    <input type="hidden" id="tradeId">
    
    <div class="two" style="margin-top:12px">
      <div><label>Fecha y Hora</label><input id="created_at" type="datetime-local"></div>
      <div><label>Activo</label><input id="symbol" placeholder="EURUSD, XAUUSD..."></div>
      
      <div><label>Dirección</label><select id="side"><option value="long">Long</option><option value="short">Short</option></select></div>
      <div><label>Sesión</label><select id="session">
        <option value="Asia">Asia</option>
        <option value="Londres">Londres</option>
        <option value="NY">NY</option>
      </select></div>
      
      <div><label>Setup</label><select id="setup">
        <option value="1">Setup 1</option>
        <option value="2">Setup 2</option>
        <option value="3">Setup 3</option>
        <option value="4">Setup 4</option>
      </select></div>
      <div><label>Resultado</label><select id="result">
        <option value="TP Full">TP Full</option>
        <option value="TP Parcial">TP Parcial</option>
        <option value="BE">BE</option>
        <option value="SL">SL</option>
      </select></div>
      
      <div><label>Pips Ganados/Perdidos</label><input id="pips" type="text" placeholder="Ej: +50 o -20"></div>
      <div><label>Lotaje</label><input id="lot_size" type="text" placeholder="Ej: 0.5"></div>
      
      <div><label>Valor del Pip</label><input id="pip_value" type="text" value="10"></div>
      <div><label>Pips de Riesgo (Stop Loss)</label><input id="risk_pips" type="text" placeholder="Ej: 20"></div>
    </div>

    <div style="margin-top:12px">
        <label>Notas</label>
        <textarea id="notes" rows="2" placeholder="Observaciones de la operación..."></textarea>
    </div>

    <div style="margin-top:12px">
      <label>Captura de TradingView (Opcional)</label>
      <input type="file" id="chart_image_input" accept="image/*" onchange="handleImageUpload(event)" style="background:transparent;border:none;padding-left:0">
      <img id="image_preview" class="img-preview hidden" src="">
    </div>

    <div class="row" style="margin-top:16px;justify-content:flex-end">
      <button class="ghost" onclick="closeForm()">Cancelar</button>
      <button onclick="saveTrade()">Guardar Operación</button>
    </div>
  </div>
</div>

<!-- Modal de Configuración -->
<div class="modal" id="configModal">
  <div class="card" style="max-width:400px">
    <div class="row" style="justify-content:space-between"><strong>⚙️ Configuración</strong>
      <button class="ghost" onclick="closeConfig()">✕</button></div>
    <p class="mut" style="margin-top:12px">Capital inicial para calcular métricas y curva de capital.</p>
    <label>Capital Inicial (USD)</label>
    <input type="text" id="initialCapitalInput" placeholder="Ej: 10000">
    <div class="row" style="margin-top:16px;justify-content:flex-end">
      <button class="ghost" onclick="closeConfig()">Cancelar</button>
      <button onclick="saveConfig()">Guardar</button>
    </div>
  </div>
</div>

<div class="modal" id="imageModal" onclick="closeImage()">
  <div style="text-align:center">
    <img id="fullImage" class="modal-img" src="">
    <br><button class="ghost" style="margin-top:10px" onclick="closeImage()">Cerrar</button>
  </div>
</div>

<script>
const $ = id => document.getElementById(id);
const state = { token: localStorage.getItem('token'), user: null, trades: [], publicMode: false, chart: null, authMode: 'login', currentImageBase64: null };

async function api(path, opts = {}) {
  opts.headers = Object.assign({'Content-Type': 'application/json'}, opts.headers || {});
  if (state.token && !state.publicMode) opts.headers['Authorization'] = 'Bearer ' + state.token;
  const res = await fetch(path, opts);
  if (!res.ok) { const e = await res.json().catch(() => ({detail: 'Error'})); throw new Error(e.detail || 'Error'); }
  return res.json();
}

function parseNum(val) {
  if (val === null || val === undefined || val === '') return null;
  return parseFloat(String(val).replace(',', '.'));
}

function switchAuth() {
  state.authMode = state.authMode === 'login' ? 'register' : 'login';
  $('authTitle').textContent = state.authMode === 'login' ? 'Ingresar' : 'Crear cuenta';
  $('submitAuth').textContent = state.authMode === 'login' ? 'Ingresar' : 'Registrarme';
  $('switchLabel').textContent = state.authMode === 'login' ? 'Crear cuenta' : 'Ya tengo cuenta';
  $('authError').textContent = '';
}

async function doAuth() {
  const username = $('username').value.trim(), password = $('password').value;
  $('authError').textContent = '';
  try {
    const data = await api('/api/' + (state.authMode === 'login' ? 'login' : 'register'), { method: 'POST', body: JSON.stringify({username, password}) });
    state.token = data.token; localStorage.setItem('token', data.token); await boot();
  } catch (e) { $('authError').textContent = e.message; }
}

function logout() {
  localStorage.removeItem('token'); state.token = null; state.user = null; state.trades = [];
  $('appView').classList.add('hidden'); $('authView').classList.remove('hidden');
  $('userLabel').textContent = ''; $('shareBtn').classList.add('hidden'); $('logoutBtn').classList.add('hidden'); $('configBtn').classList.add('hidden');
}

async function boot() {
  if (location.pathname.startsWith('/share/')) {
    state.publicMode = true;
    try {
      const data = await api('/api/public/' + location.pathname.split('/share/')[1]);
      state.trades = data.trades;
      state.user = { initial_capital: data.initial_capital };
      $('userLabel').textContent = 'Vista pública de @' + data.username;
      $('publicBanner').classList.remove('hidden');
      $('publicBanner').textContent = 'Bitácora compartida en modo solo lectura.';
      $('authView').classList.add('hidden'); $('appView').classList.remove('hidden');
      $('addBtn').classList.add('hidden'); renderAll();
    } catch (e) { $('authView').classList.remove('hidden'); $('authError').textContent = 'Enlace no válido.'; }
    return;
  }
  if (!state.token) { $('authView').classList.remove('hidden'); return; }
  try {
    state.user = await api('/api/me'); state.trades = await api('/api/trades');
    $('authView').classList.add('hidden'); $('appView').classList.remove('hidden');
    $('userLabel').textContent = '@' + state.user.username;
    $('logoutBtn').classList.remove('hidden'); $('shareBtn').classList.remove('hidden'); $('configBtn').classList.remove('hidden');
    updateShareBtn(); renderAll();
  } catch (e) { logout(); }
}

function updateShareBtn() { $('shareBtn').textContent = state.user?.is_public ? '🔗 Compartida' : 'Compartir'; }

async function toggleShare() {
  if (!state.user) return;
  if (state.user.is_public) {
    const url = location.origin + '/share/' + state.user.share_token;
    navigator.clipboard?.writeText(url); alert('Enlace copiado:\n' + url); return;
  }
  const data = await api('/api/share', {method: 'POST', body: JSON.stringify({enabled: true})});
  state.user.is_public = 1; state.user.share_token = data.share_token; updateShareBtn();
  const url = location.origin + '/share/' + data.share_token;
  navigator.clipboard?.writeText(url); alert('¡Bitácora pública! Enlace copiado:\n' + url);
}

function openConfig() {
  $('initialCapitalInput').value = state.user?.initial_capital || 10000;
  $('configModal').classList.add('open');
}
function closeConfig() { $('configModal').classList.remove('open'); }

async function saveConfig() {
  const cap = parseNum($('initialCapitalInput').value) || 10000;
  await api('/api/settings', {method: 'PUT', body: JSON.stringify({amount: cap})});
  state.user.initial_capital = cap;
  closeConfig(); renderAll();
}

function calcPnL(t) {
    if (t.pips == null || t.lot_size == null) return null;
    const pipVal = t.pip_value || 10;
    const dir = t.side === 'long' ? 1 : -1;
    return t.pips * pipVal * t.lot_size * dir;
}

function computeMetrics(trades) {
  const initialCap = state.user?.initial_capital || 10000;
  const closed = trades.filter(t => t.pips != null && t.lot_size != null);
  
  const rows = closed.map(t => {
    const pnl = calcPnL(t);
    const risk = t.risk_pips ? t.risk_pips * (t.pip_value || 10) * t.lot_size : null;
    return {...t, pnl, r: (risk && pnl != null) ? pnl / risk : null};
  }).sort((a, b) => new Date(a.created_at || 0) - new Date(b.created_at || 0));

  const wins = rows.filter(r => r.pnl > 0), losses = rows.filter(r => r.pnl < 0);
  const grossProfit = wins.reduce((s, r) => s + r.pnl, 0), grossLoss = Math.abs(losses.reduce((s, r) => s + r.pnl, 0));
  const netPnl = rows.reduce((s, r) => s + r.pnl, 0);

  let currentCapital = initialCap, peak = initialCap, maxDD = 0;
  const curve = [{date: 'Inicio', value: initialCap}];
  rows.forEach(r => { 
    currentCapital += r.pnl; 
    peak = Math.max(peak, currentCapital); 
    maxDD = Math.max(maxDD, peak - currentCapital); 
    curve.push({date: new Date(r.created_at).toLocaleDateString(), value: currentCapital}); 
  });
  
  const maxDDpct = peak > 0 ? (maxDD / peak) * 100 : 0;
  const roi = ((currentCapital - initialCap) / initialCap) * 100;
  const rs = rows.filter(r => r.r != null).map(r => r.r);

  // --- Cálculos de Edge ---
  const groupBy = (arr, key) => arr.reduce((acc, obj) => {
      const k = obj[key] || 'N/A';
      if (!acc[k]) acc[k] = {pnl: 0, count: 0, wins: 0};
      acc[k].pnl += obj.pnl; acc[k].count++; if(obj.pnl > 0) acc[k].wins++;
      return acc;
  }, {});
  
  const findBest = (grouped) => {
      let best = {name: '—', pnl: -Infinity};
      for (const [name, data] of Object.entries(grouped)) {
          if (data.pnl > best.pnl) best = {name, pnl: data.pnl};
      }
      return best;
  };

  const daysOfWeek = ['Domingo', 'Lunes', 'Martes', 'Miércoles', 'Jueves', 'Viernes', 'Sábado'];
  rows.forEach(r => {
      if (r.created_at) {
          const d = new Date(r.created_at).getDay();
          r.dayName = daysOfWeek[d];
      }
  });

  const bestAsset = findBest(groupBy(rows, 'symbol'));
  const bestSession = findBest(groupBy(rows, 'session'));
  const bestSetup = findBest(groupBy(rows, 'setup'));
  const bestDay = findBest(groupBy(rows, 'dayName'));

  return {
    count: rows.length, winRate: rows.length ? (wins.length / rows.length) * 100 : 0,
    profitFactor: grossLoss ? grossProfit / grossLoss : (grossProfit ? Infinity : 0),
    netPnl, expectancy: rows.length ? netPnl / rows.length : 0,
    avgWin: wins.length ? grossProfit / wins.length : 0, avgLoss: losses.length ? -grossLoss / losses.length : 0,
    maxDD, maxDDpct, roi, avgR: rs.length ? rs.reduce((a, b) => a + b, 0) / rs.length : null, curve, rows,
    bestAsset, bestSession, bestSetup, bestDay
  };
}

function fmt(n, d = 2) { return n == null || isNaN(n) ? '—' : n.toLocaleString('es-AR', {minimumFractionDigits: d, maximumFractionDigits: d}); }
function pct(n) { return n == null || isNaN(n) ? '—' : n.toFixed(2) + '%'; }
function money(n) { return n == null ? '—' : (n >= 0 ? '+' : '') + fmt(n); }

function renderMetrics(m) {
  const cards = [
    ['Operaciones', m.count, ''],
    ['Win Rate', pct(m.winRate), ''],
    ['Profit Factor', m.profitFactor === Infinity ? '∞' : fmt(m.profitFactor), ''],
    ['PnL Neto', money(m.netPnl), m.netPnl >= 0 ? 'pos' : 'neg'],
    ['ROI', pct(m.roi), m.roi >= 0 ? 'pos' : 'neg'],
    ['Expectancy', money(m.expectancy), m.expectancy >= 0 ? 'pos' : 'neg'],
    ['Avg R', m.avgR == null ? '—' : fmt(m.avgR), m.avgR >= 0 ? 'pos' : 'neg'],
    ['Max Drawdown', fmt(m.maxDD) + ' (' + pct(m.maxDDpct) + ')', 'neg']
  ];
  $('metricsGrid').innerHTML = cards.map(c => `<div class="metric"><div class="l">${c[0]}</div><div class="v ${c[2]}">${c[1]}</div></div>`).join('');
}

function renderEdge(m) {
    $('bestAsset').innerHTML = m.bestAsset.name !== '—' ? `${m.bestAsset.name} <span class="${m.bestAsset.pnl >= 0 ? 'pos' : 'neg'}">(${money(m.bestAsset.pnl)})</span>` : '—';
    $('bestSession').innerHTML = m.bestSession.name !== '—' ? `${m.bestSession.name} <span class="${m.bestSession.pnl >= 0 ? 'pos' : 'neg'}">(${money(m.bestSession.pnl)})</span>` : '—';
    $('bestSetup').innerHTML = m.bestSetup.name !== '—' ? `${m.bestSetup.name} <span class="${m.bestSetup.pnl >= 0 ? 'pos' : 'neg'}">(${money(m.bestSetup.pnl)})</span>` : '—';
    $('bestDay').innerHTML = m.bestDay.name !== '—' ? `${m.bestDay.name} <span class="${m.bestDay.pnl >= 0 ? 'pos' : 'neg'}">(${money(m.bestDay.pnl)})</span>` : '—';
}

function renderChart(curve) {
  if (state.chart) state.chart.destroy();
  state.chart = new Chart($('equityChart').getContext('2d'), {
    type: 'line', data: { labels: curve.map(p => p.date), datasets: [{ label: 'Capital', data: curve.map(p => p.value), borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,.15)', fill: true, tension: .25, pointRadius: 2 }] },
    options: { plugins: {legend: {display: false}}, scales: { x: {ticks: {color: '#8aa0b4', maxTicksLimit: 8}, grid: {color: '#243140'}}, y: {ticks: {color: '#8aa0b4'}, grid: {color: '#243140'}} } }
  });
}

function renderFilters() {
  const sessions = [...new Set(state.trades.map(t => t.session).filter(Boolean))].sort();
  const symbols = [...new Set(state.trades.map(t => t.symbol).filter(Boolean))].sort();
  const fs = $('filterSession'), fsn = $('filterSymbol'), curS = fs.value, curSym = fsn.value;
  fs.innerHTML = '<option value="">Todas las sesiones</option>' + sessions.map(s => `<option value="${s}">${s}</option>`).join('');
  fsn.innerHTML = '<option value="">Todos los activos</option>' + symbols.map(s => `<option value="${s}">${s}</option>`).join('');
  if (sessions.includes(curS)) fs.value = curS;
  if (symbols.includes(curSym)) fsn.value = curSym;
}

function filteredTrades() {
  const fs = $('filterSession').value, fsn = $('filterSymbol').value, fFrom = $('filterFrom').value, fTo = $('filterTo').value;
  return state.trades.filter(t => {
    if (fs && t.session !== fs) return false;
    if (fsn && t.symbol !== fsn) return false;
    const date = (t.created_at || '').split('T')[0];
    if (fFrom && date < fFrom) return false;
    if (fTo && date > fTo) return false;
    return true;
  });
}

function renderTable(rows) {
  const all = filteredTrades();
  const sorted = [...all].sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
  let html = `<thead><tr><th>Fecha</th><th>Activo</th><th>Dir.</th><th>Sesión</th><th>Setup</th><th>Resultado</th><th>Pips</th><th>Lotaje</th><th>PnL</th><th>R</th><th>Gráfico</th><th></th></tr></thead><tbody>`;
  if (!sorted.length) html += `<tr><td colspan="12" class="mut">Sin operaciones.</td></tr>`;
  for (const t of sorted) {
    const pnl = calcPnL(t);
    const risk = t.risk_pips ? t.risk_pips * (t.pip_value || 10) * t.lot_size : null;
    const r = (pnl != null && risk) ? pnl / risk : null;
    const cls = pnl == null ? '' : (pnl >= 0 ? 'pos' : 'neg');
    const imgBtn = t.has_image ? `<button class="ghost" onclick="viewImage(${t.id})">📸 Ver</button>` : '—';
    const fecha = t.created_at ? new Date(t.created_at).toLocaleDateString() : '—';

    html += `<tr>
      <td>${fecha}</td>
      <td><strong>${t.symbol}</strong></td>
      <td>${t.side === 'long' ? '🟢 L' : '🔴 S'}</td>
      <td>${t.session || '—'}</td>
      <td>${t.setup || '—'}</td>
      <td>${t.result || '—'}</td>
      <td>${t.pips != null ? fmt(t.pips) : '—'}</td>
      <td>${fmt(t.lot_size)}</td>
      <td class="${cls}">${pnl == null ? '—' : money(pnl)}</td>
      <td class="${cls}">${r == null ? '—' : fmt(r) + 'R'}</td>
      <td>${imgBtn}</td>
      <td>${state.publicMode ? '' : `<button class="ghost" onclick="openForm(${t.id})">✎</button> <button class="danger" onclick="delTrade(${t.id})">🗑</button>`}</td>
    </tr>`;
  }
  $('tradesTable').innerHTML = html + '</tbody>';
}

function renderAll() {
  renderFilters();
  const m = computeMetrics(filteredTrades());
  renderMetrics(m); renderEdge(m); renderChart(m.curve); renderTable(m.rows);
}

function handleImageUpload(event) {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    const img = new Image();
    img.onload = () => {
      const canvas = document.createElement('canvas');
      let width = img.width, height = img.height;
      const MAX_SIZE = 1000;
      if (width > height && width > MAX_SIZE) { height *= MAX_SIZE / width; width = MAX_SIZE; }
      else if (height > MAX_SIZE) { width *= MAX_SIZE / height; height = MAX_SIZE; }
      canvas.width = width; canvas.height = height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0, width, height);
      state.currentImageBase64 = canvas.toDataURL('image/jpeg', 0.7);
      $('image_preview').src = state.currentImageBase64;
      $('image_preview').classList.remove('hidden');
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
}

async function viewImage(id) {
  try {
    const data = await api('/api/trades/' + id + '/image');
    $('fullImage').src = data.image;
    $('imageModal').classList.add('open');
  } catch (e) { alert('Error al cargar la imagen'); }
}

function closeImage() { $('imageModal').classList.remove('open'); }

function openForm(id) {
  const t = id ? state.trades.find(x => x.id === id) : null;
  $('formTitle').textContent = t ? 'Editar operación' : 'Nueva operación';
  $('tradeId').value = t ? t.id : '';
  
  // Llenar campos
  const fields = ['symbol','side','session','setup','result','pips','lot_size','pip_value','risk_pips','notes'];
  fields.forEach(k => {
    if (t && t[k] != null) {
      $(k).value = t[k];
    } else {
      // Valores por defecto
      if (k === 'pip_value') $(k).value = 10;
      else if (k === 'side') $(k).value = 'long';
      else if (k === 'session') $(k).value = 'Londres';
      else if (k === 'setup') $(k).value = '1';
      else if (k === 'result') $(k).value = 'TP Full';
      else $(k).value = '';
    }
  });
  
  // Manejar fecha
  if (t && t.created_at) {
      $('created_at').value = t.created_at.slice(0, 16); // Formato datetime-local
  } else {
      $('created_at').value = new Date().toISOString().slice(0, 16);
  }

  state.currentImageBase64 = null;
  $('chart_image_input').value = '';
  $('image_preview').classList.add('hidden');
  $('image_preview').src = '';
  $('modal').classList.add('open');
}
function closeForm() { $('modal').classList.remove('open'); }

async function saveTrade() {
  const id = $('tradeId').value;
  const body = {
    symbol: $('symbol').value.trim().toUpperCase(),
    side: $('side').value,
    session: $('session').value,
    setup: $('setup').value,
    result: $('result').value,
    pips: parseNum($('pips').value),
    lot_size: parseNum($('lot_size').value),
    pip_value: parseNum($('pip_value').value) || 10,
    risk_pips: parseNum($('risk_pips').value),
    notes: $('notes').value.trim() || null,
    chart_image: state.currentImageBase64
  };
  if (!body.symbol) { alert('El símbolo es obligatorio'); return; }
  try {
    if (id) await api('/api/trades/' + id, {method: 'PUT', body: JSON.stringify(body)});
    else await api('/api/trades', {method: 'POST', body: JSON.stringify(body)});
    state.trades = await api('/api/trades');
    closeForm(); renderAll();
  } catch (e) { alert('Error: ' + e.message); }
}

async function delTrade(id) {
  if (!confirm('¿Eliminar esta operación?')) return;
  await api('/api/trades/' + id, {method: 'DELETE'});
  state.trades = await api('/api/trades'); renderAll();
}

switchAuth(); boot();
</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def index(): return HTML

@app.get("/share/{token}", response_class=HTMLResponse)
def share_page(token: str): return HTML
