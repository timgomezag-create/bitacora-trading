import sqlite3, hashlib, secrets, os
from contextlib import contextmanager
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, HTTPException, Header
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

# Importamos la librería correcta
try:
    import turso_serverless
    TURSO_AVAILABLE = True
except ImportError:
    TURSO_AVAILABLE = False

app = FastAPI(title="Bitácora de Trading")

# ---------- Configuración de Base de Datos ----------
TURSO_URL = os.environ.get("TURSO_DATABASE_URL")
TURSO_TOKEN = os.environ.get("TURSO_AUTH_TOKEN")
USE_TURSO = TURSO_AVAILABLE and bool(TURSO_URL and TURSO_TOKEN)
DB = "journal.db"

@contextmanager
def get_db():
    if USE_TURSO:
        # Conexión usando turso_serverless (HTTP)
        conn = turso_serverless.connect(database=TURSO_URL, auth_token=TURSO_TOKEN)
        try:
            yield conn
        finally:
            conn.close()
    else:
        # Fallback local para pruebas
        conn = sqlite3.connect(DB)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

def db_execute(query, params=(), fetch=False):
    with get_db() as c:
        if USE_TURSO:
            cur = c.execute(query, params)
            if fetch:
                return [dict(row) for row in cur.fetchall()]
            c.commit()
            return cur
        else:
            cur = c.execute(query, params)
            if fetch:
                return [dict(row) for row in cur.fetchall()]
            return cur

def init_db():
    with get_db() as c:
        c.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, share_token TEXT UNIQUE, is_public INTEGER DEFAULT 0, initial_capital REAL DEFAULT 10000)")
        c.execute("CREATE TABLE IF NOT EXISTS tokens(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL)")
        c.execute("""CREATE TABLE IF NOT EXISTS trades(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, symbol TEXT NOT NULL, side TEXT NOT NULL,
            entry_date TEXT, exit_date TEXT, entry_price REAL, exit_price REAL, quantity REAL,
            stop_loss REAL, take_profit REAL, fees REAL DEFAULT 0, strategy TEXT, notes TEXT, 
            chart_image TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP)""")
        c.commit()

init_db()

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
    if not rows: raise HTTPException(401, "Token inválido")
    return rows[0]["user_id"]

# ---------- Modelos ----------
class AuthIn(BaseModel):
    username: str
    password: str

class TradeIn(BaseModel):
    symbol: str
    side: str
    entry_date: Optional[str] = None
    exit_date: Optional[str] = None
    entry_price: Optional[float] = None
    exit_price: Optional[float] = None
    quantity: Optional[float] = None
    stop_loss: Optional[float] = None
    take_profit: Optional[float] = None
    fees: Optional[float] = 0
    strategy: Optional[str] = None
    notes: Optional[str] = None
    chart_image: Optional[str] = None

class ShareIn(BaseModel):
    enabled: bool

class CapitalIn(BaseModel):
    amount: float

# ---------- Rutas Auth ----------
@app.post("/api/register")
def register(data: AuthIn):
    if len(data.username) < 3 or len(data.password) < 6: raise HTTPException(400, "Usuario mínimo 3 y contraseña mínimo 6")
    try:
        db_execute("INSERT INTO users(username, password_hash, share_token) VALUES(?,?,?)", (data.username, hash_pw(data.password), secrets.token_urlsafe(16)))
        user = db_execute("SELECT id FROM users WHERE username=?", (data.username,), fetch=True)[0]
        token = secrets.token_urlsafe(32)
        db_execute("INSERT INTO tokens(token, user_id) VALUES(?,?)", (token, user["id"]))
        return {"token": token, "username": data.username}
    except Exception as e:
        if "UNIQUE" in str(e): raise HTTPException(400, "El usuario ya existe")
        raise HTTPException(500, str(e))

@app.post("/api/login")
def login(data: AuthIn):
    rows = db_execute("SELECT * FROM users WHERE username=?", (data.username,), fetch=True)
    if not rows or not check_pw(data.password, rows[0]["password_hash"]): raise HTTPException(401, "Credenciales incorrectas")
    token = secrets.token_urlsafe(32)
    db_execute("INSERT INTO tokens(token, user_id) VALUES(?,?)", (token, rows[0]["id"]))
    return {"token": token, "username": rows[0]["username"]}

@app.get("/api/me")
def me(authorization: str = Header(None)):
    uid = current_user(authorization)
    return db_execute("SELECT id, username, share_token, is_public, initial_capital FROM users WHERE id=?", (uid,), fetch=True)[0]

@app.put("/api/settings")
def update_settings(data: CapitalIn, authorization: str = Header(None)):
    uid = current_user(authorization)
    db_execute("UPDATE users SET initial_capital=? WHERE id=?", (data.amount, uid))
    return {"ok": True}

# ---------- Rutas Trades ----------
@app.get("/api/trades")
def list_trades(authorization: str = Header(None)):
    uid = current_user(authorization)
    return db_execute("SELECT id, user_id, symbol, side, entry_date, exit_date, entry_price, exit_price, quantity, stop_loss, take_profit, fees, strategy, notes, (chart_image IS NOT NULL) as has_image FROM trades WHERE user_id=? ORDER BY COALESCE(exit_date, entry_date) DESC", (uid,), fetch=True)

@app.get("/api/trades/{trade_id}/image")
def get_trade_image(trade_id: int, authorization: str = Header(None)):
    uid = current_user(authorization)
    rows = db_execute("SELECT chart_image FROM trades WHERE id=? AND user_id=?", (trade_id, uid), fetch=True)
    if not rows or not rows[0]["chart_image"]: raise HTTPException(404, "Sin imagen")
    return {"image": rows[0]["chart_image"]}

@app.post("/api/trades")
def create_trade(t: TradeIn, authorization: str = Header(None)):
    uid = current_user(authorization)
    db_execute("""INSERT INTO trades(user_id, symbol, side, entry_date, exit_date, entry_price, exit_price, quantity, stop_loss, take_profit, fees, strategy, notes, chart_image)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (uid, t.symbol, t.side, t.entry_date, t.exit_date, t.entry_price, t.exit_price, t.quantity, t.stop_loss, t.take_profit, t.fees, t.strategy, t.notes, t.chart_image))
    return {"ok": True}

@app.put("/api/trades/{trade_id}")
def update_trade(trade_id: int, t: TradeIn, authorization: str = Header(None)):
    uid = current_user(authorization)
    db_execute("""UPDATE trades SET symbol=?, side=?, entry_date=?, exit_date=?, entry_price=?, exit_price=?, quantity=?, stop_loss=?, take_profit=?, fees=?, strategy=?, notes=?, chart_image=COALESCE(?, chart_image)
        WHERE id=? AND user_id=?""",
        (t.symbol, t.side, t.entry_date, t.exit_date, t.entry_price, t.exit_price, t.quantity, t.stop_loss, t.take_profit, t.fees, t.strategy, t.notes, t.chart_image, trade_id, uid))
    return {"ok": True}

@app.delete("/api/trades/{trade_id}")
def delete_trade(trade_id: int, authorization: str = Header(None)):
    uid = current_user(authorization)
    db_execute("DELETE FROM trades WHERE id=? AND user_id=?", (trade_id, uid))
    return {"ok": True}

# ---------- Rutas Compartir ----------
@app.post("/api/share")
def toggle_share(data: ShareIn, authorization: str = Header(None)):
    uid = current_user(authorization)
    db_execute("UPDATE users SET is_public=? WHERE id=?", (1 if data.enabled else 0, uid))
    rows = db_execute("SELECT share_token FROM users WHERE id=?", (uid,), fetch=True)
    return {"enabled": data.enabled, "share_token": rows[0]["share_token"]}

@app.get("/api/public/{share_token}")
def public_view(share_token: str):
    users = db_execute("SELECT id, username, is_public, initial_capital FROM users WHERE share_token=?", (share_token,), fetch=True)
    if not users or not users[0]["is_public"]: raise HTTPException(404, "Bitácora no disponible")
    trades = db_execute("SELECT id, symbol, side, entry_date, exit_date, entry_price, exit_price, quantity, stop_loss, take_profit, fees, strategy, notes, (chart_image IS NOT NULL) as has_image FROM trades WHERE user_id=? ORDER BY COALESCE(exit_date, entry_date) DESC", (users[0]["id"],), fetch=True)
    return {"username": users[0]["username"], "trades": trades, "initial_capital": users[0]["initial_capital"]}

# ---------- Frontend (El mismo de antes) ----------
HTML = r"""
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Bitácora de Trading</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  :root{--bg:#0f1720;--card:#17212b;--line:#243140;--txt:#e6edf3;--mut:#8aa0b4;--acc:#3fb950;--neg:#f85149;--blue:#58a6ff}
  *{box-sizing:border-box} body{margin:0;font-family:system-ui,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--txt)}
  header{display:flex;justify-content:space-between;align-items:center;padding:14px 22px;border-bottom:1px solid var(--line);background:#0b1219}
  h1{font-size:18px;margin:0} .mut{color:var(--mut);font-size:13px}
  .container{max-width:1200px;margin:0 auto;padding:22px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:12px}
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
</style>
</head>
<body>
<header>
  <div class="row"><strong>📓 Bitácora de Trading</strong><span id="userLabel" class="mut"></span></div>
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
  <div class="card">
    <div class="row" style="justify-content:space-between;margin-bottom:10px">
      <strong>Curva de capital</strong>
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
        <select id="filterStrategy" onchange="renderAll()" style="width:140px"></select>
        <select id="filterSymbol" onchange="renderAll()" style="width:120px"></select>
        <button id="addBtn" onclick="openForm()">+ Nueva operación</button>
      </div>
    </div>
    <div style="overflow:auto"><table id="tradesTable"></table></div>
  </div>
</div>

<div class="modal" id="modal">
  <div class="card">
    <div class="row" style="justify-content:space-between"><strong id="formTitle">Nueva operación</strong>
      <button class="ghost" onclick="closeForm()">✕</button></div>
    <input type="hidden" id="tradeId">
    <div class="two" style="margin-top:12px">
      <div><label>Símbolo</label><input id="symbol" placeholder="AAPL"></div>
      <div><label>Dirección</label><select id="side"><option value="long">Long</option><option value="short">Short</option></select></div>
      <div><label>Fecha entrada</label><input id="entry_date" type="date"></div>
      <div><label>Fecha salida</label><input id="exit_date" type="date"></div>
      <div><label>Precio entrada</label><input id="entry_price" type="text" placeholder="Ej: 1,11916"></div>
      <div><label>Precio salida</label><input id="exit_price" type="text" placeholder="Ej: 1,11955"></div>
      <div><label>Cantidad</label><input id="quantity" type="text" placeholder="Ej: 1"></div>
      <div><label>Stop loss</label><input id="stop_loss" type="text" placeholder="Ej: 1,11937"></div>
      <div><label>Take profit</label><input id="take_profit" type="text" placeholder="Ej: 1,11955"></div>
      <div><label>Comisiones</label><input id="fees" type="text" value="0"></div>
      <div><label>Estrategia</label><input id="strategy" placeholder="Breakout..."></div>
      <div><label>Notas</label><input id="notes" placeholder="Observaciones"></div>
    </div>
    <div style="margin-top:12px">
      <label>Captura de TradingView (Opcional)</label>
      <input type="file" id="chart_image_input" accept="image/*" onchange="handleImageUpload(event)" style="background:transparent;border:none;padding-left:0">
      <img id="image_preview" class="img-preview hidden" src="">
    </div>
    <div class="row" style="margin-top:16px;justify-content:flex-end">
      <button class="ghost" onclick="closeForm()">Cancelar</button>
      <button onclick="saveTrade()">Guardar</button>
    </div>
  </div>
</div>

<div class="modal" id="configModal">
  <div class="card" style="max-width:400px">
    <div class="row" style="justify-content:space-between"><strong>⚙️ Configuración</strong>
      <button class="ghost" onclick="closeConfig()">✕</button></div>
    <p class="mut" style="margin-top:12px">Configurá tu capital inicial para que las métricas y la curva se ajusten a tu cuenta real.</p>
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

function computeMetrics(trades) {
  const initialCap = state.user?.initial_capital || 10000;
  const closed = trades.filter(t => t.exit_price != null && t.exit_date && t.entry_price != null && t.quantity != null);
  const rows = closed.map(t => {
    const dir = t.side === 'long' ? 1 : -1;
    const pnl = (t.exit_price - t.entry_price) * t.quantity * dir - (t.fees || 0);
    const risk = t.stop_loss ? Math.abs(t.entry_price - t.stop_loss) * t.quantity : null;
    let durationDays = 0;
    if (t.entry_date && t.exit_date) durationDays = (new Date(t.exit_date) - new Date(t.entry_date)) / (1000 * 60 * 60 * 24);
    return {...t, pnl, r: risk ? pnl / risk : null, durationDays};
  }).sort((a, b) => new Date(a.exit_date) - new Date(b.exit_date));

  const wins = rows.filter(r => r.pnl > 0), losses = rows.filter(r => r.pnl < 0);
  const grossProfit = wins.reduce((s, r) => s + r.pnl, 0), grossLoss = Math.abs(losses.reduce((s, r) => s + r.pnl, 0));
  const netPnl = rows.reduce((s, r) => s + r.pnl, 0);

  let maxWinStreak = 0, maxLossStreak = 0, currentStreak = 0;
  rows.forEach(r => {
    if (r.pnl > 0) { currentStreak = currentStreak > 0 ? currentStreak + 1 : 1; maxWinStreak = Math.max(maxWinStreak, currentStreak); }
    else if (r.pnl < 0) { currentStreak = currentStreak < 0 ? currentStreak - 1 : -1; maxLossStreak = Math.max(maxLossStreak, Math.abs(currentStreak)); }
  });

  const longs = rows.filter(r => r.side === 'long'), shorts = rows.filter(r => r.side === 'short');
  const winRateLong = longs.length ? (longs.filter(r => r.pnl > 0).length / longs.length) * 100 : 0;
  const winRateShort = shorts.length ? (shorts.filter(r => r.pnl > 0).length / shorts.length) * 100 : 0;
  const avgDuration = rows.length ? rows.reduce((s, r) => s + r.durationDays, 0) / rows.length : 0;

  let currentCapital = initialCap, peak = initialCap, maxDD = 0;
  const curve = [{date: 'Inicio', value: initialCap}];
  rows.forEach(r => { 
    currentCapital += r.pnl; 
    peak = Math.max(peak, currentCapital); 
    maxDD = Math.max(maxDD, peak - currentCapital); 
    curve.push({date: r.exit_date, value: currentCapital}); 
  });
  
  const maxDDpct = peak > 0 ? (maxDD / peak) * 100 : 0;
  const roi = ((currentCapital - initialCap) / initialCap) * 100;
  const rs = rows.filter(r => r.r != null).map(r => r.r);

  return {
    count: rows.length, winRate: rows.length ? (wins.length / rows.length) * 100 : 0,
    profitFactor: grossLoss ? grossProfit / grossLoss : (grossProfit ? Infinity : 0),
    netPnl, expectancy: rows.length ? netPnl / rows.length : 0,
    avgWin: wins.length ? grossProfit / wins.length : 0, avgLoss: losses.length ? -grossLoss / losses.length : 0,
    maxDD, maxDDpct, roi, avgR: rs.length ? rs.reduce((a, b) => a + b, 0) / rs.length : null, curve, rows, maxWinStreak, maxLossStreak, winRateLong, winRateShort, avgDuration
  };
}

function fmt(n, d = 2) { return n == null || isNaN(n) ? '—' : n.toLocaleString('es-AR', {minimumFractionDigits: d, maximumFractionDigits: d}); }
function pct(n) { return n == null || isNaN(n) ? '—' : n.toFixed(2) + '%'; }
function money(n) { return (n >= 0 ? '+' : '') + fmt(n); }

function renderMetrics(m) {
  const cards = [
    ['Operaciones', m.count, ''],
    ['Win Rate', pct(m.winRate), ''],
    ['Profit Factor', m.profitFactor === Infinity ? '∞' : fmt(m.profitFactor), ''],
    ['PnL Neto', money(m.netPnl), m.netPnl >= 0 ? 'pos' : 'neg'],
    ['ROI', pct(m.roi), m.roi >= 0 ? 'pos' : 'neg'],
    ['Expectancy', money(m.expectancy), m.expectancy >= 0 ? 'pos' : 'neg'],
    ['Avg R', m.avgR == null ? '—' : fmt(m.avgR), m.avgR >= 0 ? 'pos' : 'neg'],
    ['Max Drawdown', fmt(m.maxDD) + ' (' + pct(m.maxDDpct) + ')', 'neg'],
    ['Avg Win / Loss', money(m.avgWin) + ' / ' + money(m.avgLoss), ''],
    ['Racha Max Wins', m.maxWinStreak, 'pos'],
    ['Racha Max Losses', m.maxLossStreak, 'neg'],
    ['Win Rate Long', pct(m.winRateLong), ''],
    ['Win Rate Short', pct(m.winRateShort), ''],
    ['Duración Media', fmt(m.avgDuration, 1) + ' días', '']
  ];
  $('metricsGrid').innerHTML = cards.map(c => `<div class="metric"><div class="l">${c[0]}</div><div class="v ${c[2]}">${c[1]}</div></div>`).join('');
}

function renderChart(curve) {
  if (state.chart) state.chart.destroy();
  state.chart = new Chart($('equityChart').getContext('2d'), {
    type: 'line', data: { labels: curve.map(p => p.date), datasets: [{ label: 'Capital', data: curve.map(p => p.value), borderColor: '#58a6ff', backgroundColor: 'rgba(88,166,255,.15)', fill: true, tension: .25, pointRadius: 2 }] },
    options: { plugins: {legend: {display: false}}, scales: { x: {ticks: {color: '#8aa0b4', maxTicksLimit: 8}, grid: {color: '#243140'}}, y: {ticks: {color: '#8aa0b4'}, grid: {color: '#243140'}} } }
  });
}

function renderFilters() {
  const strategies = [...new Set(state.trades.map(t => t.strategy).filter(Boolean))].sort();
  const symbols = [...new Set(state.trades.map(t => t.symbol).filter(Boolean))].sort();
  const fs = $('filterStrategy'), fsn = $('filterSymbol'), curS = fs.value, curSym = fsn.value;
  fs.innerHTML = '<option value="">Todas las estrategias</option>' + strategies.map(s => `<option value="${s}">${s}</option>`).join('');
  fsn.innerHTML = '<option value="">Todos los símbolos</option>' + symbols.map(s => `<option value="${s}">${s}</option>`).join('');
  if (strategies.includes(curS)) fs.value = curS;
  if (symbols.includes(curSym)) fsn.value = curSym;
}

function filteredTrades() {
  const fs = $('filterStrategy').value, fsn = $('filterSymbol').value, fFrom = $('filterFrom').value, fTo = $('filterTo').value;
  return state.trades.filter(t => {
    if (fs && t.strategy !== fs) return false;
    if (fsn && t.symbol !== fsn) return false;
    const date = t.exit_date || t.entry_date;
    if (fFrom && date < fFrom) return false;
    if (fTo && date > fTo) return false;
    return true;
  });
}

function renderTable(rows) {
  const all = filteredTrades();
  const sorted = [...all].sort((a, b) => new Date(b.exit_date || b.entry_date || 0) - new Date(a.exit_date || a.entry_date || 0));
  let html = `<thead><tr><th>Símbolo</th><th>Dir.</th><th>Entrada</th><th>Salida</th><th>Precio E</th><th>Precio S</th><th>Cant.</th><th>PnL</th><th>R</th><th>Estrategia</th><th>Gráfico</th><th></th></tr></thead><tbody>`;
  if (!sorted.length) html += `<tr><td colspan="12" class="mut">Sin operaciones.</td></tr>`;
  for (const t of sorted) {
    const closed = t.exit_price != null && t.entry_price != null && t.quantity != null;
    const dir = t.side === 'long' ? 1 : -1;
    const pnl = closed ? (t.exit_price - t.entry_price) * t.quantity * dir - (t.fees || 0) : null;
    const risk = t.stop_loss ? Math.abs(t.entry_price - t.stop_loss) * t.quantity : null;
    const r = closed && risk ? pnl / risk : null;
    const cls = pnl == null ? '' : (pnl >= 0 ? 'pos' : 'neg');
    
    const imgBtn = t.has_image ? `<button class="ghost" onclick="viewImage(${t.id})">📸 Ver</button>` : '—';

    html += `<tr>
      <td><strong>${t.symbol}</strong></td>
      <td>${t.side === 'long' ? '🟢 L' : '🔴 S'}</td>
      <td>${t.entry_date || '—'}</td>
      <td>${t.exit_date || 'abierta'}</td>
      <td>${fmt(t.entry_price, 4)}</td>
      <td>${t.exit_price == null ? '—' : fmt(t.exit_price, 4)}</td>
      <td>${fmt(t.quantity)}</td>
      <td class="${cls}">${pnl == null ? '—' : money(pnl)}</td>
      <td class="${cls}">${r == null ? '—' : fmt(r) + 'R'}</td>
      <td>${t.strategy || '—'}</td>
      <td>${imgBtn}</td>
      <td>${state.publicMode ? '' : `<button class="ghost" onclick="openForm(${t.id})">✎</button> <button class="danger" onclick="delTrade(${t.id})">🗑</button>`}</td>
    </tr>`;
  }
  $('tradesTable').innerHTML = html + '</tbody>';
}

function renderAll() {
  renderFilters();
  const m = computeMetrics(filteredTrades());
  renderMetrics(m); renderChart(m.curve); renderTable(m.rows);
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
  ['symbol','side','entry_date','exit_date','entry_price','exit_price','quantity','stop_loss','take_profit','fees','strategy','notes'].forEach(k => {
    $(k).value = t && t[k] != null ? t[k] : (k === 'fees' ? 0 : '');
  });
  if (!t) $('side').value = 'long';
  
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
    symbol: $('symbol').value.trim().toUpperCase(), side: $('side').value,
    entry_date: $('entry_date').value || null, exit_date: $('exit_date').value || null,
    entry_price: parseNum($('entry_price').value), exit_price: parseNum($('exit_price').value),
    quantity: parseNum($('quantity').value), stop_loss: parseNum($('stop_loss').value),
    take_profit: parseNum($('take_profit').value), fees: parseNum($('fees').value) || 0,
    strategy: $('strategy').value.trim() || null, notes: $('notes').value.trim() || null,
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
