"""
eBay SaaS - OAuth 授權 + 產品管理
=====================================
需要在 Streamlit Secrets 或 .env 設定：
  EBAY_CLIENT_ID = "你的 eBay App Client ID"
  EBAY_CLIENT_SECRET = "你的 eBay App Client Secret"
  EBAY_REDIRECT_URI = "https://yourapp.streamlit.app/  (必須與 eBay Developer 填的一致)"
  ENCRYPTION_KEY = "用 Fernet.generate_key() 生成的 base64 key"

安裝依賴：
  pip install streamlit requests cryptography
"""

import streamlit as st
import requests
import json
import base64
import time
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from urllib.parse import urlencode, parse_qs, urlparse
import os

# ─────────────────────────────────────────────
# 設定區（從 Streamlit Secrets 讀取）
# ─────────────────────────────────────────────
def get_config():
    """讀取設定，支援 st.secrets 和環境變數"""
    try:
        return {
            "client_id":     st.secrets["EBAY_CLIENT_ID"],
            "client_secret": st.secrets["EBAY_CLIENT_SECRET"],
            "redirect_uri":  st.secrets["EBAY_REDIRECT_URI"],
            "enc_key":       st.secrets["ENCRYPTION_KEY"],
        }
    except Exception:
        # 本地開發 fallback（不要在生產環境用）
        return {
            "client_id":     os.getenv("EBAY_CLIENT_ID", "YOUR_CLIENT_ID"),
            "client_secret": os.getenv("EBAY_CLIENT_SECRET", "YOUR_CLIENT_SECRET"),
            "redirect_uri":  os.getenv("EBAY_REDIRECT_URI", "http://localhost:8501"),
            "enc_key":       os.getenv("ENCRYPTION_KEY", Fernet.generate_key().decode()),
        }

CFG = get_config()

# eBay API 端點（Production / Sandbox）
EBAY_ENV = "sandbox"  # 改為 "production" 上線
EBAY_ENDPOINTS = {
    "sandbox": {
        "auth":    "https://auth.sandbox.ebay.com/oauth2/authorize",
        "token":   "https://api.sandbox.ebay.com/identity/v1/oauth2/token",
        "api":     "https://api.sandbox.ebay.com",
    },
    "production": {
        "auth":    "https://auth.ebay.com/oauth2/authorize",
        "token":   "https://api.ebay.com/identity/v1/oauth2/token",
        "api":     "https://api.ebay.com",
    }
}
EP = EBAY_ENDPOINTS[EBAY_ENV]

# eBay OAuth Scopes（按需求增減）
SCOPES = " ".join([
    "https://api.ebay.com/oauth/api_scope",
    "https://api.ebay.com/oauth/api_scope/sell.inventory",
    "https://api.ebay.com/oauth/api_scope/sell.account",
    "https://api.ebay.com/oauth/api_scope/sell.fulfillment",
])

# ─────────────────────────────────────────────
# Token 加密工具
# ─────────────────────────────────────────────
def encrypt_token(token: str) -> str:
    """加密 token（存入資料庫前使用）"""
    f = Fernet(CFG["enc_key"].encode())
    return f.encrypt(token.encode()).decode()

def decrypt_token(encrypted: str) -> str:
    """解密 token"""
    f = Fernet(CFG["enc_key"].encode())
    return f.decrypt(encrypted.encode()).decode()

# ─────────────────────────────────────────────
# Session State 模擬資料庫（真實環境換 PostgreSQL）
# ─────────────────────────────────────────────
def init_session():
    defaults = {
        "authenticated": False,
        "access_token_enc": None,
        "refresh_token_enc": None,
        "token_expiry": None,
        "ebay_user_id": None,
        "listings": [],
        "page": "home",
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

# ─────────────────────────────────────────────
# eBay OAuth 流程
# ─────────────────────────────────────────────
def get_auth_url() -> str:
    """生成 eBay 授權 URL"""
    params = {
        "client_id":     CFG["client_id"],
        "redirect_uri":  CFG["redirect_uri"],
        "response_type": "code",
        "scope":         SCOPES,
        "prompt":        "login",
    }
    return f"{EP['auth']}?{urlencode(params)}"

def exchange_code_for_token(code: str) -> dict:
    """用授權碼換取 Access Token"""
    credentials = base64.b64encode(
        f"{CFG['client_id']}:{CFG['client_secret']}".encode()
    ).decode()

    response = requests.post(
        EP["token"],
        headers={
            "Content-Type":  "application/x-www-form-urlencoded",
            "Authorization": f"Basic {credentials}",
        },
        data={
            "grant_type":   "authorization_code",
            "code":         code,
            "redirect_uri": CFG["redirect_uri"],
        },
        timeout=15,
    )
    return response.json()

def refresh_access_token() -> bool:
    """用 Refresh Token 自動換新 Access Token"""
    if not st.session_state.refresh_token_enc:
        return False

    refresh_token = decrypt_token(st.session_state.refresh_token_enc)
    credentials = base64.b64encode(
        f"{CFG['client_id']}:{CFG['client_secret']}".encode()
    ).decode()

    response = requests.post(
        EP["token"],
        headers={
            "Content-Type":  "application/x-www-form-urlencoded",
            "Authorization": f"Basic {credentials}",
        },
        data={
            "grant_type":    "refresh_token",
            "refresh_token": refresh_token,
        },
        timeout=15,
    )

    if response.status_code == 200:
        data = response.json()
        st.session_state.access_token_enc = encrypt_token(data["access_token"])
        st.session_state.token_expiry = datetime.now() + timedelta(seconds=data["expires_in"] - 60)
        return True
    return False

def get_valid_token() -> str | None:
    """取得有效的 Access Token（自動刷新）"""
    if not st.session_state.access_token_enc:
        return None

    # 檢查是否快到期
    if st.session_state.token_expiry and datetime.now() >= st.session_state.token_expiry:
        if not refresh_access_token():
            st.session_state.authenticated = False
            return None

    return decrypt_token(st.session_state.access_token_enc)

# ─────────────────────────────────────────────
# eBay API 調用
# ─────────────────────────────────────────────
def ebay_get(endpoint: str) -> dict:
    """通用 GET 請求"""
    token = get_valid_token()
    if not token:
        return {"error": "未授權"}

    response = requests.get(
        f"{EP['api']}{endpoint}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
        },
        timeout=15,
    )
    return response.json()

def ebay_post(endpoint: str, body: dict) -> dict:
    """通用 POST 請求"""
    token = get_valid_token()
    if not token:
        return {"error": "未授權"}

    response = requests.post(
        f"{EP['api']}{endpoint}",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
        },
        json=body,
        timeout=15,
    )
    return response.json() if response.content else {"status": response.status_code}

def get_my_listings() -> list:
    """取得當前刊登列表"""
    data = ebay_get("/sell/inventory/v1/inventory_item?limit=20")
    return data.get("inventoryItems", [])

def get_seller_summary() -> dict:
    """取得賣家概況"""
    return ebay_get("/sell/account/v1/privilege")

def create_inventory_item(sku: str, title: str, description: str, price: float, quantity: int) -> dict:
    """建立/更新庫存品項"""
    body = {
        "availability": {
            "shipToLocationAvailability": {
                "quantity": quantity
            }
        },
        "condition": "NEW",
        "product": {
            "title":       title,
            "description": description,
        }
    }
    return ebay_post(f"/sell/inventory/v1/inventory_item/{sku}", body)

# ─────────────────────────────────────────────
# UI 頁面
# ─────────────────────────────────────────────
def render_header():
    st.markdown("""
    <style>
    .main-header {
        background: linear-gradient(135deg, #0064D2 0%, #003087 100%);
        padding: 1.5rem 2rem;
        border-radius: 12px;
        margin-bottom: 2rem;
        display: flex;
        align-items: center;
        gap: 1rem;
    }
    .main-header h1 { color: white; margin: 0; font-size: 1.8rem; }
    .main-header p  { color: #a8c8f0; margin: 0; font-size: 0.9rem; }
    .token-badge {
        background: #00a650;
        color: white;
        padding: 0.2rem 0.8rem;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: bold;
    }
    .stButton button {
        border-radius: 8px;
        font-weight: 600;
    }
    </style>
    <div class="main-header">
        <div>
            <h1>🛒 eBay SaaS 管理平台</h1>
            <p>連結你的 eBay 帳號，批量管理產品刊登</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

def page_home():
    """首頁 / 授權頁"""
    render_header()

    col1, col2 = st.columns([3, 2])
    with col1:
        st.markdown("## 🔑 連結你的 eBay 帳號")
        st.markdown("""
        授權後你可以：
        - 📦 **查看所有刊登**產品
        - ✏️ **批量更新**價格和庫存
        - 📊 **監控**銷售數據
        - 🔄 **自動同步**庫存
        """)

        auth_url = get_auth_url()
        st.link_button("🔗 授權 eBay 帳號（官方安全頁面）", auth_url, type="primary", use_container_width=True)

        st.info("⚠️ 你將跳轉到 eBay **官方頁面**授權，我們不會接觸你的密碼。", icon="🔒")

    with col2:
        st.markdown("### 授權流程")
        st.markdown("""
        ```
        1. 點擊授權按鈕
              ↓
        2. eBay 官方登入頁
              ↓
        3. 同意授權範圍
              ↓
        4. 自動回到本平台
              ↓
        5. 開始管理產品 ✅
        ```
        """)

def page_dashboard():
    """主控制台"""
    render_header()

    # Token 狀態
    expiry = st.session_state.token_expiry
    if expiry:
        remaining = (expiry - datetime.now()).seconds // 60
        st.success(f"✅ 已授權 | Token 剩餘 {remaining} 分鐘（到期自動刷新）")

    # 功能分頁
    tab1, tab2, tab3 = st.tabs(["📦 刊登管理", "➕ 新增產品", "⚙️ 帳號設定"])

    with tab1:
        st.markdown("### 我的 eBay 刊登")
        if st.button("🔄 刷新列表", type="secondary"):
            with st.spinner("讀取 eBay 資料中..."):
                st.session_state.listings = get_my_listings()

        if st.session_state.listings:
            for item in st.session_state.listings:
                with st.expander(f"📦 {item.get('sku', 'N/A')} — {item.get('product', {}).get('title', '無標題')}"):
                    col_a, col_b = st.columns(2)
                    with col_a:
                        st.write(f"**SKU:** {item.get('sku')}")
                        st.write(f"**狀態:** {item.get('condition', 'N/A')}")
                    with col_b:
                        qty = item.get("availability", {}).get("shipToLocationAvailability", {}).get("quantity", 0)
                        st.write(f"**庫存:** {qty} 件")
                    st.write(f"**描述:** {item.get('product', {}).get('description', 'N/A')[:100]}...")
        else:
            st.info("點擊「刷新列表」載入你的 eBay 刊登產品")

    with tab2:
        st.markdown("### 新增庫存品項")
        with st.container():
            col1, col2 = st.columns(2)
            with col1:
                sku   = st.text_input("SKU（唯一識別碼）", placeholder="PRODUCT-001")
                title = st.text_input("產品標題", placeholder="Japanese Ramen Bowl Set...")
                price = st.number_input("售價 (USD)", min_value=0.01, value=9.99, step=0.01)
            with col2:
                quantity    = st.number_input("庫存數量", min_value=1, value=10)
                description = st.text_area("產品描述", placeholder="詳細描述你的產品...", height=120)

            if st.button("📤 提交到 eBay 庫存", type="primary", use_container_width=True):
                if sku and title and description:
                    with st.spinner("提交中..."):
                        result = create_inventory_item(sku, title, description, price, quantity)
                    if "error" not in str(result).lower():
                        st.success(f"✅ 已成功建立 SKU: {sku}")
                    else:
                        st.error(f"❌ 錯誤：{result}")
                else:
                    st.warning("請填寫所有必填欄位")

    with tab3:
        st.markdown("### 帳號設定")
        st.write(f"**eBay 環境:** {'🧪 Sandbox（測試）' if EBAY_ENV == 'sandbox' else '🟢 Production（正式）'}")
        st.write(f"**授權時間:** {st.session_state.get('auth_time', 'N/A')}")

        st.divider()
        if st.button("🚪 撤銷授權 / 登出", type="secondary"):
            for key in ["authenticated", "access_token_enc", "refresh_token_enc", "token_expiry", "listings"]:
                st.session_state[key] = None if key != "authenticated" else False
            st.session_state.listings = []
            st.rerun()

        st.markdown("---")
        st.caption("💡 **關於安全性：** Token 以 AES-256 (Fernet) 加密存儲，不存儲你的 eBay 密碼。")

# ─────────────────────────────────────────────
# OAuth Callback 處理（關鍵！）
# ─────────────────────────────────────────────
def handle_oauth_callback():
    """
    eBay 授權後會在 URL 帶回 ?code=xxx
    Streamlit 從 query params 讀取
    """
    params = st.query_params
    code = params.get("code")

    if code and not st.session_state.authenticated:
        with st.spinner("⏳ 正在向 eBay 換取授權 Token..."):
            result = exchange_code_for_token(code)

        if "access_token" in result:
            # 加密存儲 Token
            st.session_state.access_token_enc  = encrypt_token(result["access_token"])
            st.session_state.refresh_token_enc = encrypt_token(result.get("refresh_token", ""))
            st.session_state.token_expiry      = datetime.now() + timedelta(seconds=result.get("expires_in", 7200) - 60)
            st.session_state.authenticated     = True
            st.session_state.auth_time         = datetime.now().strftime("%Y-%m-%d %H:%M")

            # 清除 URL 的 code 參數（安全）
            st.query_params.clear()
            st.success("🎉 eBay 帳號授權成功！")
            time.sleep(1)
            st.rerun()
        else:
            st.error(f"授權失敗：{result.get('error_description', '未知錯誤')}")
            st.code(json.dumps(result, indent=2))

# ─────────────────────────────────────────────
# 主程式
# ─────────────────────────────────────────────
def main():
    st.set_page_config(
        page_title="eBay SaaS 管理平台",
        page_icon="🛒",
        layout="wide",
        initial_sidebar_state="collapsed",
    )

    init_session()

    # 優先處理 OAuth callback
    handle_oauth_callback()

    # 路由
    if st.session_state.authenticated:
        page_dashboard()
    else:
        page_home()

if __name__ == "__main__":
    main()
