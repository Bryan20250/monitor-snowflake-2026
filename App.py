import time
import json
import hmac
import hashlib
import base64
import re
import threading
from datetime import datetime
import zoneinfo
import streamlit as st
import pandas as pd
import pyotp
import plotly.express as px
from snowflake.snowpark import Session
from streamlit_js_eval import streamlit_js_eval

# Configuración fija y estable de la página
st.set_page_config(
    layout="wide",
    page_title="Monitor de Analitycs",
    initial_sidebar_state="expanded"
)

# Carga de Bootstrap 5 CDN + FontAwesome Iconos
st.markdown("""
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
""", unsafe_allow_html=True)

# =============================================================================
# ⚙️ CONFIGURACIÓN DE TEXTOS, PÁGINAS Y BOTONES
# =============================================================================
PAGE_HOME = "Vista Control-M"
PAGE_DASHBOARD = "Inicio / Dashboard"
PAGE_GESTION = "Gestión de Tablas"

TEXTO_BOTON_HOME = "🖥️  Home"
TEXTO_BOTON_DASHBOARD = "📊 Reporte De Auditoría"
TEXTO_BOTON_GESTION = "⚙️  Gestión de Tablas"
TEXTO_BOTON_REFRESCAR = "🔄 Refrescar Datos"
TEXTO_BOTON_SALIR = "🚪 SALIR"

TITULOS_PAGINAS = {
    PAGE_HOME: "Vista de automatización de cargas de trabajo",
    PAGE_DASHBOARD: "Panel Principal de Auditoría",
    PAGE_GESTION: "Gestión de Tablas a Monitorear"
}

TEXTO_TITULO_LOGIN = "❄️ MONITOR ANALITYCS"
TEXTO_SUBTITULO_FORM = "#### Iniciar sesión con Snowflake"
TEXTO_BOTON_LOGIN_SNOWFLAKE = "Ingresar con Snowflake"
TEXTO_BOTON_LOGIN_INVITADO = "🌐 Entrar como Invitado "

ADMIN_USERS = st.secrets.get("ADMIN_USERS", {
    "BRY_AMAD": {"puesto": "Analista De Datos", "puede_gestionar": True},
    "EST_CAME": {"puesto": "Analista De Datos", "puede_gestionar": True},
})

# =============================================================================
# CONEXIÓN PRINCIPAL MAESTRA A SNOWFLAKE CON RECONEXIÓN AUTOMÁTICA DE TOKEN
# =============================================================================
def crear_nueva_sesion_snowflake():
    mfa_secret = st.secrets["MFA_SECRET_KEY"]
    totp = pyotp.TOTP(mfa_secret)
    passcode = totp.now()

    connection_parameters = {
        "account": st.secrets["ACCOUNT"],
        "user": st.secrets["USER"],
        "password": st.secrets["PASSWORD"],
        "passcode": passcode,
        "role": st.secrets["ROLE"],
        "warehouse": st.secrets["WAREHOUSE"],
        "database": st.secrets["DATABASE"],
        "schema": st.secrets["SCHEMA"]
    }
    return Session.builder.configs(connection_parameters).create()

@st.cache_resource(show_spinner="Conectando a Snowflake...")
def init_snowflake_session():
    try:
        return crear_nueva_sesion_snowflake()
    except KeyError as e:
        st.error(f"🚨 Falta la variable de configuración en secrets: {e}")
        st.stop()
    except Exception as ex:
        st.error(f"🚨 Error de conexión a Snowflake: {ex}")
        st.stop()

session = init_snowflake_session()

def get_active_session():
    """Valida la conexión actual y se reconecta si el token expiró."""
    global session
    try:
        session.sql("SELECT 1").collect()
        return session
    except Exception:
        # Si falla por token expirado u otra desconexión, recreamos la sesión
        init_snowflake_session.clear()
        session = init_snowflake_session()
        return session

# =============================================================================
# 🔐 SESIÓN PERSISTENTE (sobrevive al F5, muere al cerrar la pestaña/navegador)
# =============================================================================
# Se guarda un token FIRMADO en sessionStorage del navegador:
#   - Refrescar (F5)        -> sessionStorage se conserva  -> sigue logueado
#   - Cerrar pestaña / navegador -> sessionStorage se borra -> pide login
#   - Botón SALIR           -> se borra explícitamente
SESSION_STORAGE_KEY = "monitor_auth_token"
AUTH_TOKEN_TTL_SECONDS = 12 * 3600  # caducidad máxima del token (12 h)
GUEST_ID = "INVITADO_PUBLICO"

def _token_secret() -> bytes:
    # Recomendado: agrega AUTH_TOKEN_SECRET a tus secrets (cadena larga aleatoria)
    return str(st.secrets.get("AUTH_TOKEN_SECRET", st.secrets["MFA_SECRET_KEY"])).encode()

def crear_token_sesion(user_id: str) -> str:
    payload = {"u": user_id, "exp": int(time.time()) + AUTH_TOKEN_TTL_SECONDS}
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()
    sig = hmac.new(_token_secret(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"

def validar_token_sesion(token: str):
    """Devuelve el user_id si el token es válido y no ha expirado; si no, None."""
    try:
        body, sig = token.rsplit(".", 1)
        expected = hmac.new(_token_secret(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(base64.urlsafe_b64decode(body.encode()))
        if payload["exp"] < time.time():
            return None
        return payload["u"]
    except Exception:
        return None

def aplicar_perfil_usuario(user_id: str):
    """Rellena session_state según el usuario (admin, consultor o invitado)."""
    st.session_state["authenticated"] = True
    st.session_state["user_id"] = user_id
    if user_id == GUEST_ID:
        st.session_state["user_puesto"] = "Visitante Público"
        st.session_state["can_manage"] = False
    elif user_id in ADMIN_USERS:
        st.session_state["user_puesto"] = ADMIN_USERS[user_id]["puesto"]
        st.session_state["can_manage"] = ADMIN_USERS[user_id]["puede_gestionar"]
    else:
        st.session_state["user_puesto"] = "Consultor Snowflake"
        st.session_state["can_manage"] = False

def cerrar_sesion():
    st.session_state["authenticated"] = False
    st.session_state["user_id"] = None
    st.session_state["user_puesto"] = None
    st.session_state["can_manage"] = False
    st.session_state["current_page"] = PAGE_HOME
    st.session_state["logout_pending"] = True   # borra el token en el siguiente run
    st.session_state.pop("pending_token", None)

def registrar_bitacora_acceso(usuario, tipo_acceso, puesto):
    try:
        get_active_session().sql(
            """
            INSERT INTO FUNNEL.MONITOR.BITACORA_ACCESOS (USUARIO, TIPO_ACCESO, PUESTO_CATEGORIA)
            VALUES (?, ?, ?)
            """,
            params=[str(usuario), str(tipo_acceso), str(puesto)]
        ).collect()
    except Exception:
        pass

# --- Los nombres de objetos (DB, esquema, tabla) no se pueden enviar como parámetros ---
# --- (?), así que se validan estrictamente antes de usarlos en SHOW ...            ---
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]*$")

def identificador_seguro(nombre: str) -> str:
    if not isinstance(nombre, str) or not _IDENT_RE.match(nombre):
        raise ValueError(f"Identificador no válido: {nombre!r}")
    return nombre

@st.cache_data(ttl=60, show_spinner=False)
def contar_tablas_monitoreadas():
    """Total de tablas activas. Se cachea 60 s; se refresca al editar/guardar/eliminar."""
    return get_active_session().sql(
        "SELECT COUNT(*) FROM FUNNEL.MONITOR.TABLAS_MONITOREADAS WHERE MONITOREAR = 1"
    ).collect()[0][0]

# =============================================================================
# 🛡️ LÍMITE DE INTENTOS DE LOGIN (persistente en el servidor, no se salta con F5)
# =============================================================================
MAX_LOGIN_ATTEMPTS = 5          # fallos permitidos
LOGIN_LOCKOUT_SECONDS = 300     # bloqueo de 5 minutos

@st.cache_resource
def _login_state():
    return {"lock": threading.Lock(), "attempts": {}}

def _llaves_intento(usuario: str):
    # Se cuenta por usuario y también por sesión del navegador
    sid = st.session_state.setdefault("login_sid", str(time.time_ns()))
    return [f"user:{usuario}", f"sid:{sid}"]

def segundos_bloqueo_restantes(usuario: str) -> int:
    estado = _login_state()
    ahora = time.time()
    restante = 0
    with estado["lock"]:
        for k in _llaves_intento(usuario):
            info = estado["attempts"].get(k)
            if info and info["locked_until"] > ahora:
                restante = max(restante, int(info["locked_until"] - ahora) + 1)
    return restante

def registrar_intento_fallido(usuario: str):
    estado = _login_state()
    ahora = time.time()
    with estado["lock"]:
        for k in _llaves_intento(usuario):
            info = estado["attempts"].setdefault(k, {"fails": 0, "locked_until": 0})
            if info["locked_until"] and info["locked_until"] <= ahora:
                info.update(fails=0, locked_until=0)   # el bloqueo anterior ya venció
            info["fails"] += 1
            if info["fails"] >= MAX_LOGIN_ATTEMPTS:
                info["locked_until"] = ahora + LOGIN_LOCKOUT_SECONDS

def limpiar_intentos(usuario: str):
    estado = _login_state()
    with estado["lock"]:
        for k in _llaves_intento(usuario):
            estado["attempts"].pop(k, None)

def validar_login_snowflake(usuario_input, password_input, passcode_input):
    try:
        connection_params = {
            "account": st.secrets["ACCOUNT"],
            "user": usuario_input.strip().upper(),
            "password": password_input,
            "passcode": passcode_input.strip(),
            "role": st.secrets["ROLE"],
            "warehouse": st.secrets["WAREHOUSE"],
            "database": st.secrets["DATABASE"],
            "schema": st.secrets["SCHEMA"]
        }
        test_session = Session.builder.configs(connection_params).create()
        test_session.close()
        return True, "Ok"
    except Exception as ex:
        return False, str(ex)

if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "user_id" not in st.session_state:
    st.session_state["user_id"] = None
if "user_puesto" not in st.session_state:
    st.session_state["user_puesto"] = None
if "can_manage" not in st.session_state:
    st.session_state["can_manage"] = False
if "current_page" not in st.session_state or st.session_state["current_page"] not in TITULOS_PAGINAS:
    st.session_state["current_page"] = PAGE_HOME

# =============================================================================
# ESTILOS PERSONALIZADOS & CSS ANIMACIÓN CARGANDO
# =============================================================================
st.markdown("""
    <style>
    :root {
        --apex-brand: #0076d6;
        --apex-card-bg: #1e222b;
        --apex-card-border: #2d323e;
        --apex-subtext: #94a3b8;
        --apex-text: #ffffff;
    }

    header[data-testid="stHeader"] { background-color: transparent !important; z-index: 99 !important; }
    div[class*="_link_gzau3_"], div[class*="_viewerBadge_"], a[class*="_viewerBadge_"], .viewerBadge_container__13233, [data-testid="stStatusWidget"] { display: none !important; }

    .top-toolbar-title-box { display: flex; align-items: center; gap: 12px; }
    .top-toolbar-badge { background: #0076d6; color: white; border-radius: 6px; width: 36px; height: 36px; display: flex; align-items: center; justify-content: center; font-weight: 800; font-size: 16px; }
    .top-toolbar-heading { font-size: 18px; font-weight: 800; color: var(--apex-text); margin: 0; line-height: 1.2; }
    .top-toolbar-subheading { font-size: 11px; color: var(--apex-subtext); }

    .stAppHasBG {
        background-image: linear-gradient(rgba(15, 23, 42, 0.75), rgba(15, 23, 42, 0.85)), 
                          url('https://images.unsplash.com/photo-1558494949-ef010cbdcc31?q=80&w=2000&auto=format&fit=crop');
        background-size: cover; background-position: center; background-attachment: fixed;
    }

    /* Estilos Login Bootstrap Moderno */
    .login-box {
        background-color: rgba(30, 41, 59, 0.90);
        border: 1px solid rgba(255, 255, 255, 0.15);
        border-radius: 16px;
        padding: 35px;
        box-shadow: 0 20px 30px -5px rgba(0, 0, 0, 0.6);
        backdrop-filter: blur(12px);
        margin-top: 4vh;
    }
    .login-title {
        color: #ffffff;
        font-size: 26px;
        font-weight: 800;
        text-align: center;
        margin-bottom: 20px;
    }

    [data-testid="stSidebar"] { border-right: 1px solid var(--apex-card-border) !important; }
    .apex-nav-section { font-size: 11px; font-weight: 700; color: var(--apex-subtext); text-transform: uppercase; letter-spacing: 0.8px; padding: 12px 0 6px 0; }

    [data-testid="stSidebar"] .stButton > button {
        width: 100% !important; background-color: transparent !important; color: var(--text-color) !important;
        border: none !important; text-align: left !important; justify-content: flex-start !important;
        padding: 9px 12px !important; font-size: 14px !important; border-radius: 6px !important; margin-bottom: 3px !important;
    }
    [data-testid="stSidebar"] .stButton > button:hover { background-color: rgba(128, 128, 128, 0.1) !important; }
    [data-testid="stSidebar"] .stButton > button[kind="primary"] { background-color: rgba(0, 118, 214, 0.2) !important; color: #38bdf8 !important; font-weight: bold !important; border-left: 4px solid #0076d6 !important; }

    .ctm-border-green { border-top: 5px solid #10b981 !important; }
    .ctm-border-yellow { border-top: 5px solid #f59e0b !important; }
    .ctm-border-gray { border-top: 5px solid #94a3b8 !important; }
    .ctm-border-red { border-top: 5px solid #ef4444 !important; }

    .loading-container {
        display: flex;
        flex-direction: column;
        align-items: center;
        justify-content: center;
        padding: 30px 10px;
        background-color: rgba(255, 255, 255, 0.95);
        border-radius: 12px;
        box-shadow: 0 10px 25px rgba(0,0,0,0.3);
        margin: 20px 0;
    }

    .loading-text { font-size: 22px; font-weight: 700; margin-bottom: 15px; }
    .loading { transform: translate(0%, -50%); }

    .l { color: black; opacity: 0; animation: op 2s ease-in-out infinite; animation-delay: 0.2s; }
    .o { color: black; opacity: 0; animation: op 2s ease-in-out infinite; animation-delay: 0.4s; }
    .a { color: black; opacity: 0; animation: op 2s ease-in-out infinite; animation-delay: 0.6s; }
    .d { color: black; opacity: 0; animation: op 2s ease-in-out infinite; animation-delay: 0.8s; }
    .i { color: black; opacity: 0; animation: op 2s ease-in-out infinite; animation-delay: 1s; }
    .n { color: black; opacity: 0; animation: op 2s ease-in-out infinite; animation-delay: 1.2s; }
    .g { color: black; opacity: 0; animation: op 2s ease-in-out infinite; animation-delay: 1.4s; }
    .d1 { color: black; opacity: 0; animation: op1 2s ease-in-out infinite; animation-delay: 1.6s; }
    .d2 { color: black; opacity: 0; animation: op1 2s ease-in-out infinite; animation-delay: 2s; }

    .load { position: relative; width: 1.2em; height: 1.2em; border-radius: 50%; }

    .progress {
        top: 50%; left: -80%; position: absolute; margin-top: 2.2em;
        transform: translate(10%, -50%); content: ''; width: 3.1em; height: 3.1em;
        background: transparent; border-radius: 50%;
        animation: load_37100 2s ease-in-out infinite; animation-delay: 1s;
    }

    @keyframes load_37100 {
        0% { background-color: #DB4437; }
        25% { background-color: #F4B400; }
        75% { background-color: #0F9D58; }
        100% { background-color: #4285F4; }
    }

    .progress:nth-child(2) { left: 50%; animation-delay: 1.3s; }
    .progress:nth-child(3) { left: 180%; animation-delay: 1.7s; }
    .progress:nth-child(4) { left: 300%; animation-delay: 2s; }

    @keyframes op { 0% { color: black; opacity: 1; } 50% { color: green; opacity: 1; } 100% { color: black; opacity: 1; } }
    @keyframes op1 { 0% { color: black; opacity: 1; } 50% { color: green; opacity: 0; } 100% { color: black; opacity: 1; } }

    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    </style>
""", unsafe_allow_html=True)

# =============================================================================
# PANTALLA PRINCIPAL DE AUTENTICACIÓN
# =============================================================================
if not st.session_state["authenticated"]:
    st.markdown("<style>[data-testid='stSidebar'] { display: none; }</style>", unsafe_allow_html=True)

    # --- Logout pendiente: borrar el token del navegador ---
    if st.session_state.get("logout_pending"):
        cleared = streamlit_js_eval(
            js_expressions=f"sessionStorage.removeItem('{SESSION_STORAGE_KEY}') || 'cleared'",
            key="clear_auth_token",
        )
        if cleared is None:
            st.stop()
        st.session_state.pop("logout_pending", None)
    else:
        # --- Intentar restaurar sesión desde sessionStorage (caso F5) ---
        stored_token = streamlit_js_eval(
            js_expressions=f"sessionStorage.getItem('{SESSION_STORAGE_KEY}') || ''",
            key="read_auth_token",
        )
        if stored_token is None:
            # El navegador aún no responde: evita mostrar el login por un instante
            st.markdown("<div style='text-align:center; margin-top:20vh; color:#94a3b8;'>Cargando sesión...</div>", unsafe_allow_html=True)
            st.stop()
        restored_user = validar_token_sesion(stored_token) if stored_token else None
        if restored_user:
            aplicar_perfil_usuario(restored_user)
            st.rerun()

    col_empty1, col_login_box, col_empty2 = st.columns([1, 1.8, 1])

    with col_login_box:
        st.markdown(f"""
            <div class="login-box shadow-lg">
                <div class="text-center mb-3">
                    <i class="fa-solid fa-snowflake text-info fs-1 mb-2"></i>
                    <div class="login-title">{TEXTO_TITULO_LOGIN}</div>
                    <p class="text-secondary small">Monitoreo de cargas de trabajo y auditoría</p>
                </div>
            </div>
        """, unsafe_allow_html=True)

        login_placeholder = st.empty()

        with login_placeholder.container():
            with st.form("form_login_snowflake"):
                st.markdown(TEXTO_SUBTITULO_FORM)
                usr_input = st.text_input("Usuario Snowflake", placeholder="Ej. BRY_AMAD").strip().upper()
                pwd_input = st.text_input("Contraseña", type="password")
                mfa_input = st.text_input("Código MFA (App Autenticadora)", placeholder="123456", max_chars=6)

                btn_snowflake = st.form_submit_button(TEXTO_BOTON_LOGIN_SNOWFLAKE, type="primary", use_container_width=True)

                if btn_snowflake:
                    espera = segundos_bloqueo_restantes(usr_input) if usr_input else 0
                    if espera > 0:
                        st.error(f"🔒 Demasiados intentos fallidos. Intenta de nuevo en {-(-espera // 60)} min.")
                    elif usr_input and pwd_input and mfa_input:
                        login_placeholder.markdown("""
                            <div class="loading-container">
                                <div class="loading-text">
                                    <span class="l">L</span>
                                    <span class="o">o</span>
                                    <span class="a">a</span>
                                    <span class="d">d</span>
                                    <span class="i">i</span>
                                    <span class="n">n</span>
                                    <span class="g">g</span>
                                    <span class="d1">.</span>
                                    <span class="d2">.</span>
                                </div>
                                <div class="load">
                                    <div class="progress"></div>
                                    <div class="progress"></div>
                                    <div class="progress"></div>
                                    <div class="progress"></div>
                                </div>
                            </div>
                        """, unsafe_allow_html=True)

                        ok, msg = validar_login_snowflake(usr_input, pwd_input, mfa_input)

                        if ok:
                            limpiar_intentos(usr_input)
                            time.sleep(1)
                            aplicar_perfil_usuario(usr_input)
                            st.session_state["pending_token"] = crear_token_sesion(usr_input)

                            registrar_bitacora_acceso(st.session_state["user_id"], "SNOWFLAKE_MFA", st.session_state["user_puesto"])
                            st.session_state["current_page"] = PAGE_HOME
                            st.rerun()
                        else:
                            registrar_intento_fallido(usr_input)
                            if segundos_bloqueo_restantes(usr_input) > 0:
                                st.error(f"🔒 Cuenta bloqueada {LOGIN_LOCKOUT_SECONDS // 60} min por demasiados intentos fallidos.")
                            else:
                                st.error("🚨 Credenciales o código MFA incorrectos.")
                    else:
                        st.warning("⚠️ Complete todos los campos.")

        st.markdown("<div style='text-align: center; color: #94a3b8; margin: 10px 0;'>— O —</div>", unsafe_allow_html=True)

        if st.button(TEXTO_BOTON_LOGIN_INVITADO, use_container_width=True):
            aplicar_perfil_usuario(GUEST_ID)
            st.session_state["pending_token"] = crear_token_sesion(GUEST_ID)

            registrar_bitacora_acceso(st.session_state["user_id"], "PUBLICO_INVITADO", st.session_state["user_puesto"])
            st.session_state["current_page"] = PAGE_HOME
            st.rerun()

    st.stop()

# --- Guardar el token recién creado en sessionStorage (una sola vez) ---
if st.session_state.get("pending_token"):
    _saved = streamlit_js_eval(
        js_expressions=f"sessionStorage.setItem('{SESSION_STORAGE_KEY}', '{st.session_state['pending_token']}') || 'saved'",
        key="write_auth_token",
    )
    if _saved is not None:
        st.session_state.pop("pending_token", None)

# =============================================================================
# TOP TOOLBAR DINÁMICA
# =============================================================================
opcion_menu = st.session_state["current_page"]
titulo_actual = TITULOS_PAGINAS.get(opcion_menu, TITULOS_PAGINAS[PAGE_HOME])

hdr_col1, hdr_col2 = st.columns([3, 1.2])

with hdr_col1:
    st.markdown(f"""
        <div class="top-toolbar-title-box">
            <div class="top-toolbar-badge"><i class="fa-solid fa-network-wired"></i></div>
            <div>
                <div class="top-toolbar-heading">{titulo_actual}</div>
                <div class="top-toolbar-subheading">ANALITYCS MONITOR</div>
            </div>
        </div>
    """, unsafe_allow_html=True)

with hdr_col2:
    col_user_info, col_btn_exit = st.columns([2, 1])
    with col_user_info:
        st.markdown(f"""
            <div style="text-align: right; font-size:12px; font-weight:bold; color:#38bdf8;">👤 {st.session_state['user_id']}</div>
            <div style="text-align: right; font-size:10px; color:#94a3b8;">{st.session_state['user_puesto']}</div>
        """, unsafe_allow_html=True)
    with col_btn_exit:
        if st.button(TEXTO_BOTON_SALIR, key="btn_logout_top", use_container_width=True):
            cerrar_sesion()
            st.rerun()

st.divider()

# =============================================================================
# BARRA LATERAL
# =============================================================================
with st.sidebar:
    st.markdown('<div class="apex-nav-section">Navegación Principal</div>', unsafe_allow_html=True)

    is_ctm = st.session_state["current_page"] == PAGE_HOME
    if st.button(TEXTO_BOTON_HOME, key="nav_ctm", type="primary" if is_ctm else "secondary"):
        st.session_state["current_page"] = PAGE_HOME
        st.rerun()

    is_home = st.session_state["current_page"] == PAGE_DASHBOARD
    if st.button(TEXTO_BOTON_DASHBOARD, key="nav_home", type="primary" if is_home else "secondary"):
        st.session_state["current_page"] = PAGE_DASHBOARD
        st.rerun()

    if st.session_state["can_manage"]:
        try:
            total_monitored = contar_tablas_monitoreadas()
        except Exception:
            total_monitored = 0

        is_gestion = st.session_state["current_page"] == PAGE_GESTION
        if st.button(f"{TEXTO_BOTON_GESTION} [{total_monitored}]", key="nav_gestion", type="primary" if is_gestion else "secondary"):
            st.session_state["current_page"] = PAGE_GESTION
            st.rerun()

    st.markdown('<div class="apex-nav-section">Acciones</div>', unsafe_allow_html=True)
    if st.button(TEXTO_BOTON_REFRESCAR, key="nav_refresh"):
        st.cache_data.clear()
        init_snowflake_session.clear()
        st.rerun()

# =============================================================================
# FUNCIONES CACHÉ METADATOS
# =============================================================================
@st.cache_data(ttl=60, show_spinner=False)
def obtener_databases():
    try:
        rows = get_active_session().sql("SHOW DATABASES").collect()
        db_list = sorted([str(r["name"]).upper() for r in rows if "name" in r])
        if db_list: return db_list
    except Exception: pass
    return []

@st.cache_data(ttl=60, show_spinner=False)
def obtener_esquemas(database_name):
    if not database_name or database_name == "-- Seleccionar --": return []
    try:
        rows = get_active_session().sql(f"SHOW SCHEMAS IN DATABASE {identificador_seguro(database_name)}").collect()
        sch_list = sorted([str(r["name"]).upper() for r in rows if r["name"] != "INFORMATION_SCHEMA"])
        if sch_list: return sch_list
    except Exception: pass
    return []

@st.cache_data(ttl=60, show_spinner=False)
def obtener_objetos(database_name, schema_name):
    if not database_name or database_name == "-- Seleccionar --" or not schema_name or schema_name == "-- Seleccionar --": return []
    try:
        rows = get_active_session().sql(f"SHOW TABLES IN {identificador_seguro(database_name)}.{identificador_seguro(schema_name)}").collect()
        tbl_list = sorted([str(r["name"]).upper() for r in rows if "name" in r])
        if tbl_list: return tbl_list
    except Exception: pass
    return []

# =============================================================================
# MODALES FLOTANTES DE EDICIÓN Y ELIMINACIÓN
# =============================================================================
@st.dialog("Editar Registro de Tabla")
def modal_editar_registro(id_registro, db_actual, schema_actual, tabla_actual, monitorear_actual):
    st.caption(f"📝 Modificando Registro ID: #{id_registro}")
    
    list_db = obtener_databases()
    idx_db = list_db.index(db_actual) if db_actual in list_db else 0
    edit_db = st.selectbox("DATABASE_NAME", options=list_db, index=idx_db, key=f"dlg_db_{id_registro}")
    
    list_sch = obtener_esquemas(edit_db)
    idx_sch = list_sch.index(schema_actual) if schema_actual in list_sch else 0
    edit_sch = st.selectbox("SCHEMA_NAME", options=list_sch, index=idx_sch, key=f"dlg_sch_{id_registro}")
    
    list_tbl = obtener_objetos(edit_db, edit_sch)
    idx_tbl = list_tbl.index(tabla_actual) if tabla_actual in list_tbl else 0
    edit_tbl = st.selectbox("TABLE_NAME", options=list_tbl, index=idx_tbl, key=f"dlg_tbl_{id_registro}")
    
    edit_mon = st.selectbox(
        "ESTADO MONITOREO", 
        options=[1, 0], 
        index=0 if monitorear_actual == 1 else 1,
        format_func=lambda x: "1 (Activo)" if x == 1 else "0 (Inactivo)",
        key=f"dlg_mon_{id_registro}"
    )
    
    col_save, col_cancel = st.columns(2)
    with col_save:
        if st.button("Guardar Cambios", type="primary", use_container_width=True):
            with st.spinner("Actualizando en Snowflake..."):
                get_active_session().sql(
                    """
                    UPDATE FUNNEL.MONITOR.TABLAS_MONITOREADAS
                    SET DATABASE_NAME = ?,
                        SCHEMA_NAME = ?,
                        TABLE_NAME = ?,
                        MONITOREAR = ?
                    WHERE ID = ?
                    """,
                    params=[str(edit_db), str(edit_sch), str(edit_tbl), int(edit_mon), int(id_registro)]
                ).collect()
            
            st.session_state["toast_msg"] = f"Registro #{id_registro} actualizado por {st.session_state['user_id']}."
            st.session_state["toast_icon"] = "✅"
            st.cache_data.clear()
            st.rerun()
            
    with col_cancel:
        if st.button("Cancelar", use_container_width=True):
            st.rerun()

@st.dialog("Confirmar Eliminación")
def modal_confirmar_eliminacion(id_registro, db_name, schema_name, table_name):
    st.error("⚠️ ¿Desea eliminar este objeto del catálogo de monitoreo?")
    st.write(f"**Objeto a eliminar:** `{db_name}.{schema_name}.{table_name}`")
    
    col_confirm, col_cancel = st.columns(2)
    with col_confirm:
        if st.button("Sí, Eliminar", type="primary", use_container_width=True):
            with st.spinner("Eliminando objeto..."):
                get_active_session().sql(
                    "DELETE FROM FUNNEL.MONITOR.TABLAS_MONITOREADAS WHERE ID = ?",
                    params=[int(id_registro)]
                ).collect()
            
            st.session_state["toast_msg"] = f"Objeto {table_name} eliminado por {st.session_state['user_id']}."
            st.session_state["toast_icon"] = "🗑️"
            st.cache_data.clear()
            st.rerun()
            
    with col_cancel:
        if st.button("Cancelar", use_container_width=True):
            st.rerun()

# =============================================================================
# VISTA PRINCIPAL (HOME): CONTROL-M WORKLOAD (DINÁMICO CON ESTADOS REALES Y HORA MÉXICO)
# =============================================================================
if opcion_menu == PAGE_HOME:
    st.caption("Flujo de trabajo de procesos.")

    # CÁLCULO DE FECHA DE HOY ZONA HORARIA MÉXICO (CDMX / CST)
    try:
        fecha_actual_hoy = datetime.now(zoneinfo.ZoneInfo("America/Mexico_City")).date()
    except Exception:
        # Fallback restando 6 horas a UTC
        fecha_actual_hoy = (datetime.utcnow() - pd.Timedelta(hours=6)).date()

    fecha_str = fecha_actual_hoy.strftime('%Y-%m-%d')

    try:
        df_ctm = get_active_session().sql("""
            SELECT 
                m.DATABASE_NAME, 
                m.SCHEMA_NAME, 
                m.TABLE_NAME, 
                c.FECHA_PROCESO,
                COALESCE(c.REGISTROS_HOY, 0) AS REGISTROS_HOY,
                COALESCE(c.REGISTROS_AYER, 0) AS REGISTROS_AYER,
                COALESCE(c.DIFERENCIA_REGISTROS, 0) AS DIFERENCIA_REGISTROS,
                COALESCE(c.PORCENTAJE_VARIACION, 0) AS PORCENTAJE_VARIACION,
                c.ESTADO_VARIACION
            FROM FUNNEL.MONITOR.TABLAS_MONITOREADAS m
            INNER JOIN FUNNEL.MONITOR.V_COMPARATIVO_CONTEO_DIARIO c
                ON m.DATABASE_NAME = c.DATABASE_NAME 
                AND m.SCHEMA_NAME = c.SCHEMA_NAME 
                AND m.TABLE_NAME = c.TABLE_NAME
            WHERE m.MONITOREAR = 1
              AND c.FECHA_PROCESO = ?
            ORDER BY m.DATABASE_NAME, m.SCHEMA_NAME, m.TABLE_NAME
        """, params=[fecha_str]).to_pandas()
        df_ctm.columns = [col.upper() for col in df_ctm.columns]
    except Exception as ex_ctm:
        st.error(f"🚨 Error al consultar la vista Control-M: {ex_ctm}")
        df_ctm = pd.DataFrame()

    if not df_ctm.empty:
        df_ctm['FECHA_PROCESO_DT'] = pd.to_datetime(df_ctm['FECHA_PROCESO']).dt.date

        def calcular_estado_controlm(row):
            estado_var = str(row['ESTADO_VARIACION']).strip() if pd.notna(row['ESTADO_VARIACION']) else ""
            reg_hoy = row['REGISTROS_HOY']

            if estado_var == "Primer Registro" or "Primer" in estado_var:
                return "Primer Registro", "text-info", "fa-solid fa-circle-plus text-info", "ctm-border-gray"
            elif "Incremento" in estado_var:
                return "Incremento de datos", "text-success", "fa-solid fa-circle-check text-success", "ctm-border-green"
            elif "Decremento" in estado_var:
                return "Decremento de datos", "text-warning", "fa-solid fa-triangle-exclamation text-warning", "ctm-border-yellow"
            elif "Sin variación" in estado_var or estado_var == "OK":
                return "OK", "text-success", "fa-solid fa-circle-check text-success", "ctm-border-green"
            elif reg_hoy == 0 or estado_var == "Sin Datos":
                return "Sin Datos", "text-danger", "fa-solid fa-circle-xmark text-danger", "ctm-border-red"
            else:
                return estado_var if estado_var else "Sin Datos", "text-secondary", "fa-solid fa-circle-minus text-secondary", "ctm-border-gray"

        res = df_ctm.apply(calcular_estado_controlm, axis=1)
        df_ctm['ESTADO_LABEL'] = [r[0] for r in res]
        df_ctm['TEXT_CLASS'] = [r[1] for r in res]
        df_ctm['ICON_FA'] = [r[2] for r in res]
        df_ctm['BORDER_CLASS'] = [r[3] for r in res]

        col_view, col_chart = st.columns([3.2, 1])

        with col_view:
            st.markdown(f"##### <i class='fa-solid fa-diagram-project text-info'></i> Mapa de Procesos Ejecutados ({fecha_str})", unsafe_allow_html=True)
            
            with st.container(height=680, border=True):
                for db_name, group_db in df_ctm.groupby('DATABASE_NAME'):
                    st.markdown(f"""
                        <div class="card bg-dark border-danger mb-4 shadow">
                            <div class="card-header bg-danger text-white font-weight-bold d-flex justify-content-between align-items-center">
                                <span><i class="fa-solid fa-database me-2"></i> DATABASE: <strong>{db_name}</strong></span>
                                <span class="badge bg-light text-dark">{len(group_db)} objetos</span>
                            </div>
                            <div class="card-body p-2 bg-dark text-light">
                    """, unsafe_allow_html=True)

                    for sch_name, group_sch in group_db.groupby('SCHEMA_NAME'):
                        html_schema = f"""
                        <div class="border border-secondary rounded p-2 mb-3 bg-body-tertiary text-dark">
                            <div class="d-flex align-items-center mb-2 pb-1 border-bottom border-secondary">
                                <i class="fa-solid fa-folder-open text-warning me-2"></i>
                                <small class="fw-bold text-uppercase text-secondary">SCHEMA: {sch_name}</small>
                            </div>
                            <div style="display: flex; flex-direction: row; overflow-x: auto; padding: 10px 0; gap: 15px;">
                        """

                        rows_list = [row for _, row in group_sch.iterrows()]
                        chunks = [rows_list[i:i + 3] for i in range(0, len(rows_list), 3)]

                        for chunk in chunks:
                            html_schema += '<div style="display: flex; flex-direction: column; min-width: 210px; max-width: 210px; width: 210px; flex: 0 0 210px; gap: 0px;">'
                            for idx, row in enumerate(chunk):
                                f_display = str(row['FECHA_PROCESO']) if pd.notna(row['FECHA_PROCESO']) else "Sin Fecha"
                                html_schema += f"""
                                    <div style="width: 210px; background-color: #f8fafc; color: #0f172a; border: 1px solid #cbd5e1; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); overflow: hidden;" class="{row['BORDER_CLASS']}">
                                        <div style="padding: 8px 10px;">
                                            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2px;">
                                                <i class="{row['ICON_FA']}"></i>
                                                <span style="font-weight: bold; font-size: 10px;" class="{row['TEXT_CLASS']}">{row['ESTADO_LABEL']}</span>
                                            </div>
                                            <div style="font-weight: bold; font-size: 11px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: #0f172a;" title="{row['TABLE_NAME']}">
                                                {row['TABLE_NAME']}
                                            </div>
                                            <div style="display: flex; justify-content: space-between; align-items: center; font-size: 9px; color: #64748b; margin-top: 4px; border-top: 1px solid #e2e8f0; padding-top: 3px;">
                                                <span>Regs: <strong style="color: #0284c7;">{row['REGISTROS_HOY']:,}</strong></span>
                                                <span><i class="fa-regular fa-clock me-1"></i>{f_display}</span>
                                            </div>
                                        </div>
                                    </div>
                                """
                                if idx < len(chunk) - 1:
                                    html_schema += '<div style="text-align: center; color: #0284c7; font-size: 12px; margin: 2px 0;"><i class="fa-solid fa-arrow-down"></i></div>'

                            html_schema += '</div>'

                        html_schema += '</div></div>'
                        st.markdown(html_schema, unsafe_allow_html=True)

                    st.markdown("</div></div>", unsafe_allow_html=True)

        with col_chart:
            st.markdown('<div class="ctm-sticky-panel">', unsafe_allow_html=True)
            st.markdown(f"##### <i class='fa-solid fa-chart-pie text-info'></i> Estado de Cargas", unsafe_allow_html=True)
            summary_counts = df_ctm['ESTADO_LABEL'].value_counts().reset_index()
            summary_counts.columns = ['Estado', 'Cantidad']

            color_map = {
                "Primer Registro": "#38bdf8",
                "Incremento de datos": "#10b981",
                "Decremento de datos": "#f59e0b",
                "OK": "#059669",
                "Sin Datos": "#ef4444"
            }

            fig_pie = px.pie(
                summary_counts,
                names='Estado',
                values='Cantidad',
                color='Estado',
                color_discrete_map=color_map,
                hole=0.45
            )
            fig_pie.update_layout(
                margin=dict(t=0, b=0, l=0, r=0),
                showlegend=True,
                legend=dict(orientation="h", y=-0.1)
            )
            st.plotly_chart(fig_pie, use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)
    else:
        st.info(f"No hay registros cargados el día de hoy ({fecha_str}) en la vista Control-M.", icon="ℹ️")

# =============================================================================
# VISTA 1: DASHBOARD DE AUDITORÍA
# =============================================================================
elif opcion_menu == PAGE_DASHBOARD:
    st.caption("Resumen del estado y volumen de datos en FUNNEL.MONITOR")
    
    try:
        df_view = get_active_session().sql("""
            SELECT DATABASE_NAME, SCHEMA_NAME, TABLE_NAME, FECHA_PROCESO,
                   REGISTROS_HOY, REGISTROS_AYER, DIFERENCIA_REGISTROS,
                   PORCENTAJE_VARIACION, ESTADO_VARIACION
            FROM FUNNEL.MONITOR.V_COMPARATIVO_CONTEO_DIARIO 
            ORDER BY FECHA_PROCESO DESC, TABLE_NAME ASC
        """).to_pandas()
        df_view.columns = [col.upper() for col in df_view.columns]
    except Exception as ex_dash:
        st.error(f"🚨 Error al obtener los datos de la vista de auditoría: {ex_dash}")
        df_view = pd.DataFrame()

    if not df_view.empty:
        df_view['FECHA_PROCESO_DT'] = pd.to_datetime(df_view['FECHA_PROCESO']).dt.date
        min_fecha_db = df_view['FECHA_PROCESO_DT'].min()
        max_fecha_db = df_view['FECHA_PROCESO_DT'].max()

        total_tablas = len(df_view[['DATABASE_NAME', 'SCHEMA_NAME', 'TABLE_NAME']].drop_duplicates())
        ultima_fecha = max_fecha_db
        df_ultima_fecha = df_view[df_view['FECHA_PROCESO_DT'] == ultima_fecha]
        
        incrementos = len(df_ultima_fecha[df_ultima_fecha['ESTADO_VARIACION'] == 'Incremento de datos'])
        decrementos = len(df_ultima_fecha[df_ultima_fecha['ESTADO_VARIACION'] == 'Decremento de datos'])
        
        k1, k2, k3, k4 = st.columns(4)
        with k1:
            st.markdown(f'<div class="card text-bg-dark border-secondary p-3"><div class="text-uppercase text-secondary fw-bold" style="font-size:11px;">Tablas Auditadas</div><div class="fs-3 fw-bold text-info">{total_tablas}</div></div>', unsafe_allow_html=True)
        with k2:
            st.markdown(f'<div class="card text-bg-dark border-secondary p-3"><div class="text-uppercase text-secondary fw-bold" style="font-size:11px;">Último Proceso</div><div class="fs-4 fw-bold text-white">{ultima_fecha}</div></div>', unsafe_allow_html=True)
        with k3:
            st.markdown(f'<div class="card text-bg-dark border-secondary p-3"><div class="text-uppercase text-secondary fw-bold" style="font-size:11px;">Con Incremento</div><div class="fs-3 fw-bold text-success">{incrementos}</div></div>', unsafe_allow_html=True)
        with k4:
            st.markdown(f'<div class="card text-bg-dark border-secondary p-3"><div class="text-uppercase text-secondary fw-bold" style="font-size:11px;">Con Decremento</div><div class="fs-3 fw-bold text-danger">{decrementos}</div></div>', unsafe_allow_html=True)
        
        st.divider()
        
        with st.expander("🔍 Filtros de Búsqueda y Rango de Fechas", expanded=True):
            col_f1, col_f2 = st.columns(2)
            with col_f1:
                fecha_inicio = st.date_input("Desde:", value=min_fecha_db, min_value=min_fecha_db, max_value=max_fecha_db, key="hm_fecha_inicio")
            with col_f2:
                fecha_fin = st.date_input("Hasta:", value=max_fecha_db, min_value=min_fecha_db, max_value=max_fecha_db, key="hm_fecha_fin")

            if fecha_inicio > fecha_fin:
                fecha_inicio, fecha_fin = fecha_fin, fecha_inicio

            df_fechas_step = df_view[(df_view['FECHA_PROCESO_DT'] >= fecha_inicio) & (df_view['FECHA_PROCESO_DT'] <= fecha_fin)]

            c_db, c_sch, c_tbl, c_est = st.columns(4)
            list_db_home = sorted(df_fechas_step['DATABASE_NAME'].unique().tolist())
            with c_db: sel_db_home = st.selectbox("Base de Datos:", options=["Todas"] + list_db_home, key="hm_db")
            
            df_step1 = df_fechas_step.copy() if sel_db_home == "Todas" else df_fechas_step[df_fechas_step['DATABASE_NAME'] == sel_db_home]
            list_sch_home = sorted(df_step1['SCHEMA_NAME'].unique().tolist())
            with c_sch: sel_sch_home = st.selectbox("Esquema:", options=["Todos"] + list_sch_home, key="hm_sch")
                
            df_step2 = df_step1.copy() if sel_sch_home == "Todos" else df_step1[df_step1['SCHEMA_NAME'] == sel_sch_home]
            list_tbl_home = sorted(df_step2['TABLE_NAME'].unique().tolist())
            with c_tbl: sel_tbl_home = st.selectbox("Nombre de Tabla:", options=["Todas"] + list_tbl_home, key="hm_tbl")
                
            df_step3 = df_step2.copy() if sel_tbl_home == "Todas" else df_step2[df_step2['TABLE_NAME'] == sel_tbl_home]
            list_est_home = sorted(df_fechas_step['ESTADO_VARIACION'].dropna().unique().tolist())
            with c_est: sel_est_home = st.selectbox("Estado de Variación:", options=["Todos"] + list_est_home, key="hm_est")
                
            df_filtrado = df_step3.copy() if sel_est_home == "Todos" else df_step3[df_step3['ESTADO_VARIACION'] == sel_est_home]

        st.divider()

        if not df_filtrado.empty:
            if sel_tbl_home != "Todas" and len(df_filtrado['TABLE_NAME'].unique()) == 1:
                ultimo_registro = df_filtrado.iloc[0]
                tabla_nombre_completo = f"{ultimo_registro['DATABASE_NAME']}.{ultimo_registro['SCHEMA_NAME']}.{ultimo_registro['TABLE_NAME']}"
                
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Registros Hoy", f"{ultimo_registro['REGISTROS_HOY']:,}")
                m2.metric("Registros Ayer", f"{ultimo_registro['REGISTROS_AYER']:,}")
                m3.metric("Diferencia", f"{ultimo_registro['DIFERENCIA_REGISTROS']:,}", delta=f"{ultimo_registro['PORCENTAJE_VARIACION']}%")
                m4.metric("Estado", ultimo_registro['ESTADO_VARIACION'])

                st.subheader(f"Tendencia de Volumen: `{tabla_nombre_completo}`")
                df_chart = df_filtrado.sort_values("FECHA_PROCESO").set_index("FECHA_PROCESO")[["REGISTROS_HOY"]]
                st.line_chart(df_chart)

            else:
                st.subheader("Comparativo General del Grupo Seleccionado")
                df_chart_multi = df_filtrado.copy()
                df_chart_multi['OBJETO'] = df_chart_multi['DATABASE_NAME'] + '.' + df_chart_multi['SCHEMA_NAME'] + '.' + df_chart_multi['TABLE_NAME']
                df_pivot = df_chart_multi.pivot_table(index='FECHA_PROCESO', columns='OBJETO', values='REGISTROS_HOY', aggfunc='sum').sort_index()
                st.line_chart(df_pivot)

            st.subheader(f"Histórico de Ejecuciones ({fecha_inicio} al {fecha_fin})")
            df_display = df_filtrado.drop(columns=['FECHA_PROCESO_DT']) if 'FECHA_PROCESO_DT' in df_filtrado.columns else df_filtrado
            st.dataframe(df_display, use_container_width=True, hide_index=True)
        else:
            st.info("No hay registros que coincidan con los filtros.", icon="ℹ️")
    else:
        st.warning("No se encontraron registros de ejecuciones.", icon="⚠️")

# =============================================================================
# VISTA 2: GESTIÓN DE TABLAS
# =============================================================================
elif opcion_menu == PAGE_GESTION and st.session_state["can_manage"]:
    st.caption("Esquema: FUNNEL.MONITOR")
    
    if "toast_msg" in st.session_state:
        st.toast(st.session_state["toast_msg"], icon=st.session_state.get("toast_icon", "ℹ️"))
        del st.session_state["toast_msg"]
        if "toast_icon" in st.session_state: del st.session_state["toast_icon"]

    with st.container(border=True):
        st.subheader("Registrar Nueva Tabla")
        lista_databases = ["-- Seleccionar --"] + obtener_databases()
        col1, col2, col3, col4 = st.columns([3, 3, 3, 2])
        
        with col1: db_seleccionada = st.selectbox("DATABASE_NAME", options=lista_databases, index=0, key="reg_db")
        lista_esquemas = ["-- Seleccionar --"] + obtener_esquemas(db_seleccionada) if db_seleccionada != "-- Seleccionar --" else ["-- Seleccionar --"]
        with col2: esquema_seleccionado = st.selectbox("SCHEMA_NAME", options=lista_esquemas, index=0, key="reg_sch")
        lista_tablas = ["-- Seleccionar --"] + obtener_objetos(db_seleccionada, esquema_seleccionado) if esquema_seleccionado != "-- Seleccionar --" else ["-- Seleccionar --"]
        with col3: tabla_seleccionada = st.selectbox("TABLE_NAME", options=lista_tablas, index=0, key="reg_tbl")
        with col4: monitorear_input = st.selectbox("ESTADO", options=[1, 0], format_func=lambda x: "1 (Activo)" if x == 1 else "0 (Inactivo)", key="reg_mon")
            
        if st.button("Guardar Tabla", type="primary"):
            if db_seleccionada != "-- Seleccionar --" and esquema_seleccionado != "-- Seleccionar --" and tabla_seleccionada != "-- Seleccionar --":
                with st.spinner("Guardando registro en Snowflake..."):
                    get_active_session().sql(
                        """
                        INSERT INTO FUNNEL.MONITOR.TABLAS_MONITOREADAS
                        (DATABASE_NAME, SCHEMA_NAME, TABLE_NAME, MONITOREAR)
                        VALUES (?, ?, ?, ?)
                        """,
                        params=[str(db_seleccionada), str(esquema_seleccionado), str(tabla_seleccionada), int(monitorear_input)]
                    ).collect()
                st.toast("Tabla registrada con éxito.", icon="✅")
                st.cache_data.clear()
                st.rerun()
            else:
                st.error("Seleccione opciones válidas.", icon="🚨")

    st.divider()
    st.subheader("Catálogo de Tablas Configuradas")
    
    try:
        df_catalog = get_active_session().sql("""
            SELECT ID, DATABASE_NAME, SCHEMA_NAME, TABLE_NAME, MONITOREAR 
            FROM FUNNEL.MONITOR.TABLAS_MONITOREADAS 
            ORDER BY DATABASE_NAME, SCHEMA_NAME, TABLE_NAME
        """).to_pandas()
        df_catalog.columns = [col.upper() for col in df_catalog.columns]
    except Exception as ex_cat:
        st.error(f"🚨 Error al consultar la tabla FUNNEL.MONITOR.TABLAS_MONITOREADAS: {ex_cat}")
        df_catalog = pd.DataFrame()

    if not df_catalog.empty:
        f_col1, f_col2, f_col3, f_col4 = st.columns([3, 3, 4, 2])
        list_db_cat = sorted(df_catalog['DATABASE_NAME'].unique().tolist())
        with f_col1: f_db = st.selectbox("Filtrar Base:", options=["Todas"] + list_db_cat, key="cat_f_db")
        df_f1 = df_catalog if f_db == "Todas" else df_catalog[df_catalog['DATABASE_NAME'] == f_db]

        list_sch_cat = sorted(df_f1['SCHEMA_NAME'].unique().tolist())
        with f_col2: f_sch = st.selectbox("Filtrar Esquema:", options=["Todos"] + list_sch_cat, key="cat_f_sch")
        df_f2 = df_f1 if f_sch == "Todos" else df_f1[df_f1['SCHEMA_NAME'] == f_sch]

        list_tablas_disponibles = sorted(df_f2['TABLE_NAME'].unique().tolist())
        with f_col3: selected_table_search = st.selectbox("Buscar Tabla:", options=["-- Todas --"] + list_tablas_disponibles, index=0, key="cat_search_select")
        with f_col4: f_est = st.selectbox("Estado:", options=["Todos", "1 (Activo)", "0 (Inactivo)"], key="cat_f_est")

        if selected_table_search != "-- Todas --": df_f2 = df_f2[df_f2['TABLE_NAME'] == selected_table_search]
        if f_est == "1 (Activo)": df_f2 = df_f2[df_f2['MONITOREAR'] == 1]
        elif f_est == "0 (Inactivo)": df_f2 = df_f2[df_f2['MONITOREAR'] == 0]

        # Orden: base de datos -> esquema -> tabla
        df_f2 = df_f2.sort_values(["DATABASE_NAME", "SCHEMA_NAME", "TABLE_NAME"]).reset_index(drop=True)

        # --- Paginación ---
        total_rows = len(df_f2)
        pg_col1, pg_col2 = st.columns([8, 2])
        with pg_col2:
            page_size = st.selectbox("Por página:", options=[5, 10, 20, 50], index=1, key="cat_page_size")

        total_pages = max(1, -(-total_rows // page_size))  # techo de la división

        # Si cambian filtros o tamaño de página, regresar a la página 1
        filtro_actual = (f_db, f_sch, selected_table_search, f_est, page_size)
        if st.session_state.get("cat_filtro_prev") != filtro_actual:
            st.session_state["cat_page"] = 1
            st.session_state["cat_filtro_prev"] = filtro_actual

        # Evitar quedar en una página inexistente (ej. tras eliminar registros)
        st.session_state["cat_page"] = min(max(1, st.session_state.get("cat_page", 1)), total_pages)
        pagina = st.session_state["cat_page"]

        inicio = (pagina - 1) * page_size
        df_pagina = df_f2.iloc[inicio:inicio + page_size]

        with pg_col1:
            st.caption(
                f"Mostrando {inicio + 1 if total_rows else 0}-{min(inicio + page_size, total_rows)} "
                f"de {total_rows} filtrados ({len(df_catalog)} configurados en total)"
            )

        if not df_f2.empty:
            for index, row in df_pagina.iterrows():
                with st.container(border=True):
                    col_info, col_status, col_btn_edit, col_btn_del = st.columns([5, 2, 2, 2])
                    
                    with col_info: 
                        st.markdown(f"**`{row['DATABASE_NAME']}`.**`{row['SCHEMA_NAME']}`.**`{row['TABLE_NAME']}`**")
                    
                    with col_status:
                        if row['MONITOREAR'] == 1:
                            st.markdown("<span class='badge bg-success'>● ACTIVO</span>", unsafe_allow_html=True)
                        else:
                            st.markdown("<span class='badge bg-danger'>○ INACTIVO</span>", unsafe_allow_html=True)

                    with col_btn_edit:
                        if st.button("Editar", key=f"btn_edit_trigger_{row['ID']}", use_container_width=True):
                            modal_editar_registro(
                                row['ID'], 
                                row['DATABASE_NAME'], 
                                row['SCHEMA_NAME'], 
                                row['TABLE_NAME'], 
                                row['MONITOREAR']
                            )

                    with col_btn_del:
                        if st.button("Eliminar", key=f"btn_del_trigger_{row['ID']}", use_container_width=True):
                            modal_confirmar_eliminacion(
                                row['ID'], 
                                row['DATABASE_NAME'], 
                                row['SCHEMA_NAME'], 
                                row['TABLE_NAME']
                            )

            # --- Controles de navegación ---
            nav1, nav2, nav3, nav4, nav5 = st.columns([1, 1, 2, 1, 1])
            with nav1:
                if st.button("⏮", key="pg_first", use_container_width=True, disabled=pagina == 1):
                    st.session_state["cat_page"] = 1
                    st.rerun()
            with nav2:
                if st.button("◀", key="pg_prev", use_container_width=True, disabled=pagina == 1):
                    st.session_state["cat_page"] = pagina - 1
                    st.rerun()
            with nav3:
                st.markdown(
                    f"<div style='text-align:center; padding-top:6px; color:#94a3b8;'>Página <b>{pagina}</b> de <b>{total_pages}</b></div>",
                    unsafe_allow_html=True
                )
            with nav4:
                if st.button("▶", key="pg_next", use_container_width=True, disabled=pagina == total_pages):
                    st.session_state["cat_page"] = pagina + 1
                    st.rerun()
            with nav5:
                if st.button("⏭", key="pg_last", use_container_width=True, disabled=pagina == total_pages):
                    st.session_state["cat_page"] = total_pages
                    st.rerun()
        else:
            st.info("No se encontraron objetos.", icon="ℹ️")
    else:
        st.info("No hay tablas registradas.", icon="ℹ️")
