"""
股票監控儀表板 - 完整修復版 v3.0
==================================
v2.0 修復清單：
 1. matched_rank 未定義 NameError → 先初始化為 None
 2. while True + time.sleep() → time.sleep() + st.rerun()（Streamlit Cloud 相容）
 3. @st.cache_data 接收不可哈希 DataFrame → 改用 ticker/period/interval 字串作 key
 4. VIX merge 時區不符全為 NaN → 統一 tz_localize(None)
 5. make_subplots 中 yaxis2/yaxis3 overlaying 衝突 → 改用 4 行獨立子圖
 6. px.line()["data"][0] 不規範 → 全用 go.Scatter
 7. generate_comprehensive_interpretation dense_desc 在 return 後無效 → 前移
 8. VWAP 跨日累積錯誤 → 按日分組計算
 9. 新增完整回測系統（組合信號勝率分析）
10. send_email_alert 參數過多 → 整合為 dict

v3.0 修復清單：
11. BUG-01: MFI 背離浮點精確比較 → 改用 0.2% 容差
12. BUG-02: 回測勝率最後一根 NaN→False → 排除 NaN 行
13. BUG-03: Telegram 重複發送 → 加 session_state 去重
14. BUG-04: 回測中 data 變量被覆蓋 → 使用獨立變量名
15. BUG-05: RSI 使用 SMA → 改用 Wilder's Smoothing (EWM)
16. BUG-06: MACD/EMA 買入 RSI<50 矛盾 → 放寬到 RSI<70
17. BUG-07: VIX 短週期全 NaN → 改用按日期合併
18. BUG-08: 回測進場價=當根收盤 → 改用下一根開盤
19. BUG-09: 勝率與詳細回測不一致提示
20. BUG-10: MFI fillna(50) → 保持 NaN
"""

import streamlit as st
import yfinance as yf
import pandas as pd
import numpy as np
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
import os
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import requests
from itertools import combinations
import time
import traceback
import json

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(page_title="📈 股票監控儀表板", layout="wide", page_icon="📈")
load_dotenv()

SENDER_EMAIL    = os.getenv("SENDER_EMAIL", "")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD", "")
RECIPIENT_EMAIL = os.getenv("RECIPIENT_EMAIL", "")

try:
    BOT_TOKEN      = st.secrets["telegram"]["BOT_TOKEN"]
    CHAT_ID        = st.secrets["telegram"]["CHAT_ID"]
    telegram_ready = True
except Exception:
    BOT_TOKEN = CHAT_ID = None
    telegram_ready = False

# ── Sell-signal set (used in success-rate & backtest direction logic) ─────────
SELL_SIGNALS = {
    "📉 High<Low","📉 MACD賣出","📉 EMA賣出","📉 價格趨勢賣出","📉 價格趨勢賣出(量)",
    "📉 價格趨勢賣出(量%)","📉 普通跳空(下)","📉 突破跳空(下)","📉 持續跳空(下)",
    "📉 衰竭跳空(下)","📉 連續向下賣出","📉 SMA50下降趨勢","📉 SMA50_200下降趨勢",
    "📉 新卖出信号","📉 RSI-MACD Overbought Crossover","📉 EMA-SMA Downtrend Sell",
    "📉 Volume-MACD Sell","📉 EMA10_30賣出","📉 EMA10_30_40強烈賣出","📉 看跌吞沒",
    "📉 烏雲蓋頂","📉 上吊線","📉 黃昏之星","📉 VWAP賣出","📉 MFI熊背離賣出",
    "📉 OBV突破賣出","📉 VIX恐慌賣出","📉 VIX上升趨勢賣出",
}

# ═════════════════════════════════════════════════════════════════════════════
#  INDICATOR FUNCTIONS
# ═════════════════════════════════════════════════════════════════════════════


def send_telegram_alert(msg: str, ticker: str = None) -> tuple:
    """
    Send a plain-text message via Telegram Bot API.
    Returns (success: bool, error_msg: str).

    FIX: 統一在函數入口檢查所有開關狀態（熔斷機制）
    - 1️⃣ 檢查全域靜音開關 (tg_global_mute)
    - 2️⃣ 檢查該股票的 tg_enabled_{ticker}
    - 3️⃣ 無論呼叫端是否忘記檢查開關，都會被攔截
    """
    # 熔斷機制 1：全域靜音（panic stop）
    try:
        if st.session_state.get("tg_global_mute", False):
            return False, "Telegram 全域靜音已開啟"
    except Exception:
        pass

    # 熔斷機制 2：個別股票開關
    if ticker is not None:
        try:
            if not st.session_state.get(f"tg_enabled_{ticker}", True):
                return False, f"Telegram 已關閉 ({ticker})"
        except Exception:
            pass

    if not (BOT_TOKEN and CHAT_ID):
        return False, "Telegram 未設定（請在 secrets.toml 中設定 BOT_TOKEN 和 CHAT_ID）"
    try:
        url     = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        payload = {
            "chat_id":                  CHAT_ID,
            "text":                     msg,
            "disable_web_page_preview": True,
            "disable_notification":     False,
        }
        r = requests.post(url, json=payload, timeout=15)
        resp = r.json()
        if r.status_code == 200 and resp.get("ok"):
            return True, ""
        else:
            err = resp.get("description", f"HTTP {r.status_code}")
            return False, f"Telegram API 錯誤：{err}"
    except requests.exceptions.Timeout:
        return False, "Telegram 發送逾時（15 秒）"
    except Exception as e:
        return False, f"Telegram 發送例外：{e}"


def _fmt_vol(vol) -> str:
    """Format volume as readable string: 1,234,567 → 1.23M"""
    try:
        v = float(vol)
        if v >= 1_000_000:
            return f"{v/1_000_000:.2f}M"
        elif v >= 1_000:
            return f"{v/1_000:.1f}K"
        else:
            return f"{v:.0f}"
    except Exception:
        return str(vol)


def calculate_macd(df, fast=12, slow=26, signal=9):
    e1 = df["Close"].ewm(span=fast, adjust=False).mean()
    e2 = df["Close"].ewm(span=slow, adjust=False).mean()
    macd = e1 - e2
    sig  = macd.ewm(span=signal, adjust=False).mean()
    return macd, sig, macd - sig


# ── FIX BUG-05: RSI 改用 Wilder's Smoothing ──────────────────────────────────
def calculate_rsi(df, periods=14):
    delta = df["Close"].diff()
    gain  = delta.where(delta > 0, 0)
    loss  = (-delta.where(delta < 0, 0))
    # Wilder's Smoothing = EWM with alpha=1/periods
    avg_gain = gain.ewm(alpha=1/periods, min_periods=periods, adjust=False).mean()
    avg_loss = loss.ewm(alpha=1/periods, min_periods=periods, adjust=False).mean()
    rs    = avg_gain / avg_loss.replace(0, np.nan)
    return 100 - (100 / (1 + rs))


def calculate_vwap(df: pd.DataFrame) -> pd.Series:
    """
    FIX: group by calendar date so VWAP resets each day.
    """
    df2 = df.copy()
    df2["_dt"] = pd.to_datetime(df2["Datetime"]).dt.date
    typical = (df2["High"] + df2["Low"] + df2["Close"]) / 3
    tp_vol  = typical * df2["Volume"]

    vwap_vals = []
    for date, grp in df2.groupby("_dt", sort=False):
        cum_tv = tp_vol.loc[grp.index].cumsum()
        cum_v  = df2.loc[grp.index, "Volume"].cumsum().replace(0, np.nan)
        vwap_vals.append(cum_tv / cum_v)

    result = pd.concat(vwap_vals).reindex(df2.index)
    return result


# ── FIX BUG-10: MFI 不再 fillna(50)，保持 NaN ───────────────────────────────
def calculate_mfi(df, periods=14):
    typical    = (df["High"] + df["Low"] + df["Close"]) / 3
    mf         = typical * df["Volume"]
    pos_mf     = mf.where(typical > typical.shift(1), 0).rolling(window=periods).sum()
    neg_mf     = mf.where(typical < typical.shift(1), 0).rolling(window=periods).sum()
    mfi        = 100 - (100 / (1 + pos_mf / neg_mf.replace(0, np.nan)))
    return mfi  # 不再 fillna(50)


def calculate_obv(df):
    return (np.sign(df["Close"].diff()) * df["Volume"]).fillna(0).cumsum()


def calculate_volume_profile(df, bins=50, window=100, top_n=3):
    n = min(len(df), window)
    recent = df.tail(n).copy()
    pmin, pmax = recent["Low"].min(), recent["High"].max()
    if pmax == pmin:
        return []
    edges   = np.linspace(pmin, pmax, bins + 1)
    centers = (edges[:-1] + edges[1:]) / 2
    profile = np.zeros(bins)
    for _, row in recent.iterrows():
        lo_i = max(0, int(np.searchsorted(edges, row["Low"],  "left")  - 1))
        hi_i = max(0, min(int(np.searchsorted(edges, row["High"], "right") - 1), bins - 1))
        lo_i = min(lo_i, bins - 1)
        span = hi_i - lo_i + 1
        for j in range(lo_i, hi_i + 1):
            profile[j] += row["Volume"] / span
    top_idx = np.argsort(profile)[-top_n:][::-1]
    return [{"price_center": centers[i], "volume": profile[i],
             "price_low": edges[i], "price_high": edges[i + 1]}
            for i in top_idx if profile[i] > 0]


def get_vix_data(period, interval):
    try:
        vdf = yf.Ticker("^VIX").history(period=period, interval=interval).reset_index()
        if vdf.empty:
            return pd.DataFrame()
        if "Date" in vdf.columns:
            vdf = vdf.rename(columns={"Date": "Datetime"})
        vdf["Datetime"]      = pd.to_datetime(vdf["Datetime"]).dt.tz_localize(None)
        vdf["VIX_Change_Pct"]= vdf["Close"].pct_change().round(4) * 100
        return vdf[["Datetime", "Close", "VIX_Change_Pct"]].rename(columns={"Close": "VIX"})
    except Exception:
        return pd.DataFrame()


# ── FIX BUG-07: VIX 按日期合併（解決短週期全 NaN 問題）─────────────────────
def merge_vix_data(data: pd.DataFrame, vix_df: pd.DataFrame,
                   interval: str) -> pd.DataFrame:
    """
    智能合併 VIX 數據：
    - 日線及以上：按精確 Datetime 合併（與原邏輯一致）
    - 短週期（分鐘/小時）：按日期合併（避免時間戳不對齊導致全 NaN）
    """
    if vix_df.empty:
        data["VIX"] = np.nan
        data["VIX_Change_Pct"] = np.nan
        return data

    # 判斷是否為短週期
    _intraday = interval in ("1m", "5m", "15m", "30m", "60m", "1h")

    if _intraday:
        # 按日期合併
        data["_merge_date"] = pd.to_datetime(data["Datetime"]).dt.date
        vix_df = vix_df.copy()
        vix_df["_merge_date"] = pd.to_datetime(vix_df["Datetime"]).dt.date
        # VIX 日線可能有重複日期，取最後一筆
        vix_daily = vix_df.drop_duplicates(subset=["_merge_date"], keep="last")
        data = data.merge(
            vix_daily[["_merge_date", "VIX", "VIX_Change_Pct"]],
            on="_merge_date", how="left"
        ).drop(columns=["_merge_date"])
    else:
        # 日線及以上：原邏輯
        data = data.merge(vix_df, on="Datetime", how="left")

    return data


# ── FIX BUG-01: MFI 背離使用容差比較 ─────────────────────────────────────────
def compute_mfi_divergence(df: pd.DataFrame, window: int) -> pd.DataFrame:
    """
    計算 MFI 背離，使用 0.2% 容差替代精確浮點比較。
    回傳帶有 MFI_Bull_Div / MFI_Bear_Div 欄位的 DataFrame。
    """
    df = df.copy()
    df["Close_Roll_Max"] = df["Close"].rolling(window).max()
    df["Close_Roll_Min"] = df["Close"].rolling(window).min()
    df["MFI_Roll_Max"]   = df["MFI"].rolling(window).max()
    df["MFI_Roll_Min"]   = df["MFI"].rolling(window).min()

    # 容差比較：收盤價在滾動極值的 0.2% 以內即視為「觸及」
    _tol = 0.002
    _close_near_max = (
        (df["Close"] - df["Close_Roll_Max"]).abs() /
        df["Close_Roll_Max"].replace(0, np.nan)
    ) < _tol
    _close_near_min = (
        (df["Close"] - df["Close_Roll_Min"]).abs() /
        df["Close_Roll_Min"].replace(0, np.nan)
    ) < _tol

    # 熊背離：價格觸及新高但 MFI 低於前期高點
    df["MFI_Bear_Div"] = _close_near_max & (df["MFI"] < df["MFI_Roll_Max"].shift(1))
    # 牛背離：價格觸及新低但 MFI 高於前期低點
    df["MFI_Bull_Div"] = _close_near_min & (df["MFI"] > df["MFI_Roll_Min"].shift(1))

    return df


def _enrich_data(df: pd.DataFrame, params: dict, mfi_win: int,
                 include_vix: bool = False, vix_period: str = "",
                 vix_interval: str = "",
                 vix_ema_fast: int = 5, vix_ema_slow: int = 10) -> pd.DataFrame:
    """
    共用指標計算流程（消除 3 處重複代碼）。
    主監控和回測統一呼叫此函數。
    """
    df = df.copy()
    df["Price Change %"]  = df["Close"].pct_change().round(4) * 100
    df["Volume Change %"] = df["Volume"].pct_change().round(4) * 100
    df["前5均量"]          = df["Volume"].rolling(5).mean()

    df["MACD"], df["Signal_Line"], df["Histogram"] = calculate_macd(df)
    df["RSI"] = calculate_rsi(df)
    for span, name in [(5, "EMA5"), (10, "EMA10"), (30, "EMA30"), (40, "EMA40")]:
        df[name] = df["Close"].ewm(span=span, adjust=False).mean()
    df["SMA50"]  = df["Close"].rolling(50).mean()
    df["SMA200"] = df["Close"].rolling(200).mean()
    df["VWAP"]   = calculate_vwap(df)
    df["MFI"]    = calculate_mfi(df)
    df["OBV"]    = calculate_obv(df)

    df["Up"]   = (df["Close"] > df["Close"].shift(1)).astype(int)
    df["Down"] = (df["Close"] < df["Close"].shift(1)).astype(int)
    df["Continuous_Up"]   = df["Up"]   * (df["Up"].groupby(  (df["Up"]   == 0).cumsum()).cumcount() + 1)
    df["Continuous_Down"] = df["Down"] * (df["Down"].groupby((df["Down"] == 0).cumsum()).cumcount() + 1)

    W = int(mfi_win)
    df["High_Max"] = df["High"].rolling(W).max()
    df["Low_Min"]  = df["Low"].rolling(W).min()
    df = compute_mfi_divergence(df, W)
    df["OBV_Roll_Max"] = df["OBV"].rolling(20).max()
    df["OBV_Roll_Min"] = df["OBV"].rolling(20).min()

    if include_vix and vix_period and vix_interval:
        vix_df = get_vix_data(vix_period, vix_interval)
        df = merge_vix_data(df, vix_df, vix_interval)
        for col in ["VIX", "VIX_Change_Pct"]:
            if col not in df.columns:
                df[col] = np.nan
        if not df["VIX"].isna().all():
            df["VIX_EMA_Fast"] = df["VIX"].ewm(span=vix_ema_fast, adjust=False).mean()
            df["VIX_EMA_Slow"] = df["VIX"].ewm(span=vix_ema_slow, adjust=False).mean()
        else:
            df["VIX_EMA_Fast"] = np.nan; df["VIX_EMA_Slow"] = np.nan
    else:
        for col in ["VIX", "VIX_Change_Pct", "VIX_EMA_Fast", "VIX_EMA_Slow"]:
            if col not in df.columns:
                df[col] = np.nan

    return df


def _attach_kline_and_vol(df: pd.DataFrame, ticker: str, period: str,
                          interval: str, body_ratio: float, shadow_ratio: float,
                          doji_body: float) -> pd.DataFrame:
    """共用 K 線形態合併 + 成交量標記（消除重複代碼）。"""
    _buster = str(round(float(df["Close"].iloc[-1]), 4))
    kdf = get_kline_patterns(ticker, period, interval,
                             body_ratio, shadow_ratio, doji_body, _buster)
    kdf["Datetime"] = pd.to_datetime(kdf["Datetime"]).dt.tz_localize(None)
    df = df.merge(kdf, on="Datetime", how="left")
    df["K線形態"]  = df["K線形態"].fillna("普通K線")
    if "單根解讀" in df.columns:
        df["單根解讀"] = df["單根解讀"].fillna("波動有限")
    df["成交量標記"] = np.where(
        pd.notna(df["前5均量"]) & (df["Volume"] > df["前5均量"]),
        "放量", "縮量"
    )
    return df


# ═════════════════════════════════════════════════════════════════════════════
#  CACHED K-LINE PATTERN (FIX: use hashable params, not DataFrame)
# ═════════════════════════════════════════════════════════════════════════════

@st.cache_data(ttl=300)
def get_kline_patterns(ticker: str, period: str, interval: str,
                       body_ratio: float, shadow_ratio: float, doji_body: float,
                       _cache_buster: str) -> pd.DataFrame:
    df = yf.Ticker(ticker).history(period=period, interval=interval).reset_index()
    if df.empty:
        return pd.DataFrame(columns=["Datetime","K線形態","單根解讀"])
    if "Date" in df.columns:
        df = df.rename(columns={"Date": "Datetime"})
    df["Datetime"]  = pd.to_datetime(df["Datetime"]).dt.tz_localize(None)
    df["前5均量"]   = df["Volume"].rolling(window=5).mean()

    patterns, interps = [], []
    for idx, row in df.iterrows():
        p, t = _classify_kline(row, idx, df, body_ratio, shadow_ratio, doji_body)
        patterns.append(p); interps.append(t)
    df["K線形態"]  = patterns
    df["單根解讀"] = interps
    return df[["Datetime","K線形態","單根解讀"]]


def _classify_kline(row, idx, df, body_ratio, shadow_ratio, doji_body):
    p, t = "普通K線", "波動有限，方向不明顯"
    if idx == 0:
        return p, t
    po, pc = df["Open"].iloc[idx-1], df["Close"].iloc[idx-1]
    ph, pl = df["High"].iloc[idx-1], df["Low"].iloc[idx-1]
    co, cc, ch, cl = row["Open"], row["Close"], row["High"], row["Low"]
    body   = abs(cc - co)
    rng    = ch - cl if ch != cl else 1e-9
    hi_vol = row["Volume"] > row.get("前5均量", 0)
    is_up  = df["Close"].iloc[max(0, idx-5):idx].mean() < cc if idx >= 5 else False
    is_dn  = df["Close"].iloc[max(0, idx-5):idx].mean() > cc if idx >= 5 else False
    lower  = min(co, cc) - cl
    upper  = ch - max(co, cc)

    if body < rng*0.3 and lower >= shadow_ratio*max(body,1e-9) and upper < lower and is_dn:
        p = "錘子線"; t = "下方支撐，多方承接" + ("，放量增強" if hi_vol else "")
    elif body < rng*0.3 and upper >= shadow_ratio*max(body,1e-9) and lower < upper and is_up:
        p = "射擊之星"; t = "高位拋壓" + ("，放量賣出" if hi_vol else "")
    elif body < doji_body*rng:
        p = "十字星"; t = "市場猶豫，方向未明"
    elif cc > co and body > body_ratio*rng:
        p = "大陽線"; t = "多方強勢" + ("，放量有力" if hi_vol else "")
    elif cc < co and body > body_ratio*rng:
        p = "大陰線"; t = "空方強勢" + ("，放量偏空" if hi_vol else "")
    elif cc > co and pc < po and co <= pc and cc >= po and hi_vol:
        # FIX: 看漲吞噬允許等於（co <= pc, cc >= po）
        p = "看漲吞噬"; t = "陽線包覆前日陰線，預示反轉"
    elif cc < co and pc > po and co >= pc and cc <= po and hi_vol:
        # FIX: 看跌吞噬允許等於
        p = "看跌吞噬"; t = "陰線包覆前日陽線，預示反轉"
    elif is_up and cc < co and pc > po and co > pc and cc < (po+pc)/2:
        p = "烏雲蓋頂"; t = "上升趨勢中陰線壓制，賣壓加重"
    elif is_dn and cc > co and pc < po and co < pc and cc > (po+pc)/2:
        p = "刺透形態"; t = "下跌趨勢中陽線反攻，買方介入"
    elif (idx > 1 and
          df["Close"].iloc[idx-2] < df["Open"].iloc[idx-2] and
          abs(df["Close"].iloc[idx-1]-df["Open"].iloc[idx-1]) < 0.3*abs(df["Close"].iloc[idx-2]-df["Open"].iloc[idx-2]) and
          cc > co and cc > (po+pc)/2 and hi_vol):
        p = "早晨之星"; t = "下跌後強陽，預示反轉"
    elif (idx > 1 and
          df["Close"].iloc[idx-2] > df["Open"].iloc[idx-2] and
          abs(df["Close"].iloc[idx-1]-df["Open"].iloc[idx-1]) < 0.3*abs(df["Close"].iloc[idx-2]-df["Open"].iloc[idx-2]) and
          cc < co and cc < (po+pc)/2 and hi_vol):
        p = "黃昏之星"; t = "上漲後強陰，預示反轉"
    return p, t


# ═════════════════════════════════════════════════════════════════════════════
#  EMAIL (FIX: consolidated dict param)
# ═════════════════════════════════════════════════════════════════════════════

def send_email_alert(ticker: str, price_pct: float, volume_pct: float, active_signals: dict):
    if not all([SENDER_EMAIL, SENDER_PASSWORD, RECIPIENT_EMAIL]):
        return
    desc = {
        "macd_buy":"📈 MACD買入","macd_sell":"📉 MACD賣出",
        "ema_buy":"📈 EMA買入","ema_sell":"📉 EMA賣出",
        "new_buy":"📈 新買入","new_sell":"📉 新賣出",
        "vwap_buy":"📈 VWAP買入","vwap_sell":"📉 VWAP賣出",
        "mfi_bull":"📈 MFI牛背離","mfi_bear":"📉 MFI熊背離",
        "obv_buy":"📈 OBV突破買入","obv_sell":"📉 OBV突破賣出",
        "vix_panic":"📉 VIX恐慌賣出","vix_calm":"📈 VIX平靜買入",
        "bullish_eng":"📈 看漲吞沒","bearish_eng":"📉 看跌吞沒",
        "morning_star":"📈 早晨之星","evening_star":"📉 黃昏之星",
        "hammer":"📈 錘頭線","hanging_man":"📉 上吊線",
    }
    lines = [f"股票: {ticker}", f"股價變動: {price_pct:.2f}%",
             f"成交量變動: {volume_pct:.2f}%", ""]
    for k, label in desc.items():
        if active_signals.get(k):
            lines.append(label)
    lines.append("\n⚠️ 系統偵測到異動，請立即查看市場情況。")
    msg = MIMEMultipart()
    msg["From"]    = SENDER_EMAIL
    msg["To"]      = RECIPIENT_EMAIL
    msg["Subject"] = f"📣 股票異動通知：{ticker}"
    msg.attach(MIMEText("\n".join(lines), "plain"))
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as srv:
            srv.login(SENDER_EMAIL, SENDER_PASSWORD)
            srv.sendmail(SENDER_EMAIL, RECIPIENT_EMAIL, msg.as_string())
        st.toast(f"📬 Email 已發送")
    except Exception as e:
        st.error(f"Email 發送失敗：{e}")




# ═════════════════════════════════════════════════════════════════════════════
#  BACKTEST: combination win-rate
# ═════════════════════════════════════════════════════════════════════════════

def _calc_wr(sub_next_up: "np.ndarray", is_sell: bool) -> float:
    """
    Helper: compute win rate from a boolean array of next-bar direction.
    """
    n = len(sub_next_up)
    if n == 0:
        return 0.0
    mean_up = float(np.asarray(sub_next_up, dtype=float).mean())
    return (1 - mean_up) * 100 if is_sell else mean_up * 100


def _calc_avg_pnl(close_arr: "np.ndarray", next_close_arr: "np.ndarray",
                  mask: "np.ndarray", is_sell: bool) -> float:
    """
    計算命中該組合的所有K線的平均每筆盈虧(%)。
    """
    c  = close_arr[mask]
    nc = next_close_arr[mask]
    if len(c) == 0:
        return 0.0
    safe_c = np.where(c == 0, np.nan, c)
    pnl    = (nc - c) / safe_c * 100
    if is_sell:
        pnl = -pnl
    valid = pnl[~np.isnan(pnl)]
    return round(float(valid.mean()), 2) if len(valid) > 0 else 0.0


def _build_onehot(df: "pd.DataFrame") -> "tuple[list, dict, np.ndarray]":
    """
    共用前置步驟：解析信號 → one-hot 布林矩陣。
    """
    signal_sets = []
    for marks in df["異動標記"].fillna(""):
        sigs = {s.strip() for s in str(marks).split(", ")
                if s.strip() and "🔥" not in s}
        signal_sets.append(sigs)

    all_s     = sorted({s for ss in signal_sets for s in ss})
    sig_index = {s: i for i, s in enumerate(all_s)}
    n_sigs    = len(all_s)
    n_rows    = len(df)

    onehot = np.zeros((n_rows, n_sigs), dtype=bool)
    for row_i, sset in enumerate(signal_sets):
        for s in sset:
            if s in sig_index:
                onehot[row_i, sig_index[s]] = True

    return all_s, sig_index, onehot


def _combo_mask(combo: tuple, sig_index: dict,
                onehot: "np.ndarray") -> "np.ndarray":
    """
    給定一個信號組合 tuple，回傳 shape=(n_rows,) 的布林陣列。
    """
    cols = [sig_index[s] for s in combo if s in sig_index]
    if not cols:
        return np.zeros(onehot.shape[0], dtype=bool)
    return onehot[:, cols].all(axis=1)


# ── FIX BUG-02: 回測勝率排除最後一根 NaN ─────────────────────────────────────
def _base_signal_combos(df: "pd.DataFrame", min_combo: int, max_combo: int,
                         min_occ: int) -> "pd.DataFrame":
    """
    維度 1：純信號組合勝率（向量化加速版）
    """
    df = df.copy()
    close_arr      = df["Close"].to_numpy()
    next_close_arr = df["Close"].shift(-1).to_numpy()
    next_up        = (next_close_arr > close_arr)

    # FIX BUG-02: 排除最後一根 (shift(-1) 產生 NaN，會被當成 False)
    _valid = ~np.isnan(next_close_arr)

    all_s, sig_index, onehot = _build_onehot(df)

    rows = []
    for r in range(min_combo, min(max_combo + 1, len(all_s) + 1)):
        for combo in combinations(all_s, r):
            mask    = _combo_mask(combo, sig_index, onehot) & _valid
            n_hit   = int(mask.sum())
            if n_hit < min_occ:
                continue
            is_sell = sum(1 for s in combo if s in SELL_SIGNALS) > len(combo) / 2
            rows.append({
                "維度":        "信號組合",
                "信號組合":    " + ".join(combo),
                "成交量標記":  "—",
                "K線形態":     "—",
                "信號數量":    r,
                "勝率(%)":     round(_calc_wr(next_up[mask], is_sell), 1),
                "平均盈虧(%)": _calc_avg_pnl(close_arr, next_close_arr, mask, is_sell),
                "出現次數":    n_hit,
                "方向":        "做空" if is_sell else "做多",
            })
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows).sort_values("勝率(%)", ascending=False).head(30)


def _signal_x_volume_combos(df: "pd.DataFrame", min_combo: int, max_combo: int,
                              min_occ: int) -> "pd.DataFrame":
    """
    維度 2：信號組合 × 成交量標記（向量化加速版）
    """
    if "成交量標記" not in df.columns:
        return pd.DataFrame()
    df = df.copy()
    close_arr      = df["Close"].to_numpy()
    next_close_arr = df["Close"].shift(-1).to_numpy()
    next_up        = (next_close_arr > close_arr)
    _valid = ~np.isnan(next_close_arr)  # FIX BUG-02

    vol_arr  = df["成交量標記"].to_numpy()
    vol_放量 = (vol_arr == "放量")
    vol_縮量 = (vol_arr == "縮量")

    all_s, sig_index, onehot = _build_onehot(df)

    rows = []
    for r in range(min_combo, min(max_combo + 1, len(all_s) + 1)):
        for combo in combinations(all_s, r):
            base_mask = _combo_mask(combo, sig_index, onehot) & _valid
            n_base    = int(base_mask.sum())
            if n_base < min_occ:
                continue
            is_sell = sum(1 for s in combo if s in SELL_SIGNALS) > len(combo) / 2
            for vol_label, vol_mask in [("放量", vol_放量), ("縮量", vol_縮量)]:
                mask  = base_mask & vol_mask
                n_hit = int(mask.sum())
                if n_hit < min_occ:
                    continue
                rows.append({
                    "維度":        "信號+成交量",
                    "信號組合":    " + ".join(combo),
                    "成交量標記":  vol_label,
                    "K線形態":     "—",
                    "信號數量":    r,
                    "勝率(%)":     round(_calc_wr(next_up[mask], is_sell), 1),
                    "平均盈虧(%)": _calc_avg_pnl(close_arr, next_close_arr, mask, is_sell),
                    "出現次數":    n_hit,
                    "方向":        "做空" if is_sell else "做多",
                })
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows).sort_values("勝率(%)", ascending=False).head(30)


def _signal_x_kline_combos(df: "pd.DataFrame", min_combo: int, max_combo: int,
                             min_occ: int) -> "pd.DataFrame":
    """
    維度 3：信號組合 × K線形態（向量化加速版）
    """
    if "K線形態" not in df.columns:
        return pd.DataFrame()
    df = df.copy()
    close_arr      = df["Close"].to_numpy()
    next_close_arr = df["Close"].shift(-1).to_numpy()
    next_up        = (next_close_arr > close_arr)
    _valid = ~np.isnan(next_close_arr)  # FIX BUG-02

    kline_arr  = df["K線形態"].fillna("普通K線").to_numpy()
    kline_vals = [k for k in df["K線形態"].dropna().unique()
                  if k and k != "普通K線"]

    kline_masks = {kl: (kline_arr == kl) for kl in kline_vals}

    all_s, sig_index, onehot = _build_onehot(df)

    rows = []
    for r in range(min_combo, min(max_combo + 1, len(all_s) + 1)):
        for combo in combinations(all_s, r):
            base_mask = _combo_mask(combo, sig_index, onehot) & _valid
            n_base    = int(base_mask.sum())
            if n_base < min_occ:
                continue
            is_sell = sum(1 for s in combo if s in SELL_SIGNALS) > len(combo) / 2
            for kl, kl_mask in kline_masks.items():
                mask  = base_mask & kl_mask
                n_hit = int(mask.sum())
                if n_hit < min_occ:
                    continue
                rows.append({
                    "維度":        "信號+K線形態",
                    "信號組合":    " + ".join(combo),
                    "成交量標記":  "—",
                    "K線形態":     kl,
                    "信號數量":    r,
                    "勝率(%)":     round(_calc_wr(next_up[mask], is_sell), 1),
                    "平均盈虧(%)": _calc_avg_pnl(close_arr, next_close_arr, mask, is_sell),
                    "出現次數":    n_hit,
                    "方向":        "做空" if is_sell else "做多",
                })
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows).sort_values("勝率(%)", ascending=False).head(30)


# ── FIX BUG-08: 進場價改用下一根開盤 ─────────────────────────────────────────
def _detailed_backtest(df: "pd.DataFrame",
                       signal_combo: str,
                       vol_filter: str = "—",
                       kline_filter: str = "—",
                       direction: str = "做多",
                       hold_bars: int = 1) -> "pd.DataFrame":
    """
    對單一信號組合逐筆展開所有交易記錄，計算每筆盈虧。

    FIX v3.0: 進場價改用信號出現後的下一根 K 線開盤價（更貼近真實交易）。
    """
    if df.empty or "異動標記" not in df.columns:
        return pd.DataFrame()

    df = df.copy().reset_index(drop=True)

    required_sigs = [s.strip() for s in signal_combo.split(" + ") if s.strip()]

    def _hit(row):
        marks = str(row.get("異動標記", ""))
        sigs  = {s.strip() for s in marks.split(", ") if s.strip()}
        sig_ok = all(s in sigs for s in required_sigs)
        vol_ok = (vol_filter in ("—", "全部") or
                  str(row.get("成交量標記","")) == vol_filter)
        kl_ok  = (kline_filter in ("—", "全部") or
                  str(row.get("K線形態","")) == kline_filter)
        return sig_ok and vol_ok and kl_ok

    hit_mask = df.apply(_hit, axis=1)
    hit_idx  = df.index[hit_mask].tolist()

    records = []
    for i in hit_idx:
        # FIX BUG-08: 信號在第 i 根確認後，下一根 (i+1) 開盤進場
        entry_i = i + 1
        if entry_i >= len(df):
            continue  # 信號出現在最後一根，無法進場

        exit_i = entry_i + hold_bars
        if exit_i >= len(df):
            continue  # 無出場K線

        signal_bar = df.iloc[i]       # 信號確認那根（用於記錄觸發資訊）
        entry_bar  = df.iloc[entry_i]  # 實際進場那根
        exit_bar   = df.iloc[exit_i]

        # 進場價 = 下一根開盤（信號確認後最早可執行的價格）
        entry_price = float(entry_bar["Open"])
        exit_price  = float(exit_bar["Close"])

        if entry_price <= 0:
            continue

        if direction == "做多":
            pnl_pct  = (exit_price - entry_price) / entry_price * 100
            win      = exit_price > entry_price
        else:
            pnl_pct  = (entry_price - exit_price) / entry_price * 100
            win      = exit_price < entry_price

        # RSI / MACD at signal bar (not entry bar)
        entry_rsi  = round(float(signal_bar.get("RSI",  float("nan"))), 1)
        entry_macd = round(float(signal_bar.get("MACD", float("nan"))), 4)
        entry_vol  = signal_bar.get("成交量標記", "—")
        entry_kl   = signal_bar.get("K線形態",    "—")

        # High / Low in the holding period
        hold_slice      = df.iloc[entry_i : exit_i + 1]
        max_high        = float(hold_slice["High"].max()) if not hold_slice.empty else exit_price
        min_low         = float(hold_slice["Low"].min())  if not hold_slice.empty else exit_price

        if direction == "做多":
            max_runup_pct  = (max_high - entry_price) / entry_price * 100
            max_drawdown_pct = (entry_price - min_low) / entry_price * 100
        else:
            max_runup_pct  = (entry_price - min_low)  / entry_price * 100
            max_drawdown_pct = (max_high - entry_price) / entry_price * 100

        signal_dt = signal_bar.get("Datetime", "")
        entry_dt  = entry_bar.get("Datetime", "")
        exit_dt   = exit_bar.get("Datetime",  "")

        records.append({
            "序號":        len(records) + 1,
            "信號時間":    str(signal_dt)[:19],
            "進場時間":    str(entry_dt)[:19],
            "出場時間":    str(exit_dt)[:19],
            "持倉根數":    hold_bars,
            "進場價":      round(entry_price, 4),
            "出場價":      round(exit_price,  4),
            "方向":        direction,
            "盈虧(%)":     round(pnl_pct, 2),
            "勝負":        "✅ 勝" if win else "❌ 敗",
            "最大順勢(%)": round(max_runup_pct,   2),
            "最大逆勢(%)": round(max_drawdown_pct, 2),
            "信號RSI":     entry_rsi,
            "信號MACD":    entry_macd,
            "成交量標記":  str(entry_vol),
            "K線形態":     str(entry_kl),
            "觸發信號":    str(signal_bar.get("異動標記", ""))[:120],
        })

    if not records:
        return pd.DataFrame()

    detail_df = pd.DataFrame(records)
    detail_df["累計盈虧(%)"] = detail_df["盈虧(%)"].cumsum().round(2)

    wins = (detail_df["勝負"] == "✅ 勝").astype(int)
    loss = (1 - wins)
    streak_win = wins  * (wins .groupby((wins  == 0).cumsum()).cumcount() + 1)
    streak_loss= loss  * (loss.groupby((loss == 0).cumsum()).cumcount() + 1)
    detail_df["連勝數"] = streak_win
    detail_df["連敗數"] = streak_loss

    return detail_df


def _summary_stats(detail_df: "pd.DataFrame") -> dict:
    """從逐筆交易記錄計算統計摘要。"""
    if detail_df.empty:
        return {}

    total    = len(detail_df)
    wins     = (detail_df["勝負"] == "✅ 勝").sum()
    losses   = total - wins
    wr       = wins / total * 100 if total else 0

    pnl      = detail_df["盈虧(%)"]
    win_pnl  = pnl[detail_df["勝負"] == "✅ 勝"]
    loss_pnl = pnl[detail_df["勝負"] == "❌ 敗"]

    avg_win  = win_pnl.mean()  if len(win_pnl)  else 0
    avg_loss = loss_pnl.mean() if len(loss_pnl) else 0

    total_profit = win_pnl.sum()   if len(win_pnl)  else 0
    total_loss   = abs(loss_pnl.sum()) if len(loss_pnl) else 0
    profit_factor = total_profit / total_loss if total_loss > 0 else float("inf")

    cum = detail_df["累計盈虧(%)"]
    roll_max = cum.cummax()
    drawdown = cum - roll_max
    max_dd   = drawdown.min()

    expectancy = (wr/100) * avg_win + ((1 - wr/100)) * avg_loss

    calmar = (cum.iloc[-1] / abs(max_dd)) if max_dd != 0 else float("inf")

    max_streak_win  = detail_df["連勝數"].max()
    max_streak_loss = detail_df["連敗數"].max()

    return {
        "總交易筆數":      total,
        "勝出筆數":        int(wins),
        "敗出筆數":        int(losses),
        "實際勝率(%)":     round(wr, 1),
        "平均盈利(%)":     round(avg_win,  2),
        "平均虧損(%)":     round(avg_loss, 2),
        "盈虧比":          round(abs(avg_win / avg_loss), 2) if avg_loss != 0 else "∞",
        "獲利因子":        round(profit_factor, 2) if profit_factor != float("inf") else "∞",
        "期望值每筆(%)":   round(expectancy, 2),
        "累計盈虧(%)":     round(float(cum.iloc[-1]), 2),
        "最大回撤(%)":     round(float(max_dd), 2),
        "Calmar比率":      round(calmar, 2) if calmar != float("inf") else "∞",
        "最大連勝":        int(max_streak_win),
        "最大連敗":        int(max_streak_loss),
    }

def backtest_signal_combinations(df: "pd.DataFrame", min_combo=2,
                                  max_combo=4, min_occ=3) -> "pd.DataFrame":
    """保留舊介面相容。"""
    return _base_signal_combos(df, min_combo, max_combo, min_occ)




# ═════════════════════════════════════════════════════════════════════════════
#  SIGNAL MARKING  (core logic, returns comma-joined string)
# ═════════════════════════════════════════════════════════════════════════════

def compute_all_signals(data: pd.DataFrame,
                        params: dict) -> pd.Series:
    """
    Vectorised-friendly signal marker.
    Returns pd.Series of strings aligned to data index.
    """
    results = []
    for idx, row in data.iterrows():
        results.append(_mark_one(row, idx, data, params))
    return pd.Series(results, index=data.index)


def _prev(data, col, idx, n=1):
    i = idx - n
    if i < 0:
        return np.nan
    return data[col].iloc[i]


def _mark_one(row, idx, data, p):
    sigs = []
    macd = row["MACD"]
    rsi  = row["RSI"]
    # FIX: MFI 不再 fillna(50)，需要安全處理 NaN
    rsi_valid = pd.notna(rsi)
    rsi_val = float(rsi) if rsi_valid else 50.0  # 預設中性

    fma  = row["前5均量"] if pd.notna(row["前5均量"]) else 0

    def pv(col, n=1):
        return _prev(data, col, idx, n)

    # ── 量價 ──────────────────────────────────────────────────────────────────
    pa = row.get("📈 股價漲跌幅(%)", np.nan)
    va = row.get("📊 成交量變動幅(%)", np.nan)
    if pd.notna(pa) and pd.notna(va) and abs(pa) >= p["PRICE_TH"] and abs(va) >= p["VOLUME_TH"]:
        sigs.append("✅ 量價")

    # ── Low>High / High<Low ───────────────────────────────────────────────────
    if idx > 0:
        if row["Low"]  > pv("High"):  sigs.append("📈 Low>High")
        if row["High"] < pv("Low"):   sigs.append("📉 High<Low")

    # ── Close position ────────────────────────────────────────────────────────
    cnh = row.get("Close_N_High", np.nan)
    cnl = row.get("Close_N_Low",  np.nan)
    if pd.notna(cnh) and cnh >= p["HIGH_N_HIGH_TH"]:  sigs.append("📈 HIGH_N_HIGH")
    if pd.notna(cnl) and cnl >= p["LOW_N_LOW_TH"]:    sigs.append("📉 LOW_N_LOW")

    # ── MACD ──────────────────────────────────────────────────────────────────
    # FIX BUG-06: 放寬 RSI 過濾到 <70 / >30（原為 <50 / >50，導致信號幾乎不觸發）
    if idx > 0:
        if macd > 0  and pv("MACD") <= 0 and rsi_val < 70: sigs.append("📈 MACD買入")
        if macd <= 0 and pv("MACD") > 0  and rsi_val > 30: sigs.append("📉 MACD賣出")

    # ── EMA5/10 ───────────────────────────────────────────────────────────────
    # FIX BUG-06: 同上
    if idx > 0:
        if row["EMA5"] > row["EMA10"] and pv("EMA5") <= pv("EMA10") and rsi_val < 70:
            sigs.append("📈 EMA買入")
        if row["EMA5"] < row["EMA10"] and pv("EMA5") >= pv("EMA10") and rsi_val > 30:
            sigs.append("📉 EMA賣出")

    # ── Price trend ───────────────────────────────────────────────────────────
    # FIX BUG-06: 放寬 RSI 過濾
    if idx > 0:
        ph, pl, pc = pv("High"), pv("Low"), pv("Close")
        vc = row.get("Volume Change %", 0) or 0
        if row["High"] > ph and row["Low"] > pl and row["Close"] > pc:
            if macd > 0:                              sigs.append("📈 價格趨勢買入")
            if row["Volume"] > fma and rsi_val < 70:  sigs.append("📈 價格趨勢買入(量)")
            if vc > 15 and rsi_val < 70:              sigs.append("📈 價格趨勢買入(量%)")
        if row["High"] < ph and row["Low"] < pl and row["Close"] < pc:
            if macd < 0:                              sigs.append("📉 價格趨勢賣出")
            if row["Volume"] > fma and rsi_val > 30:  sigs.append("📉 價格趨勢賣出(量)")
            if vc > 15 and rsi_val > 30:              sigs.append("📉 價格趨勢賣出(量%)")

    # ── Gaps ──────────────────────────────────────────────────────────────────
    if idx > 0:
        gap_pct = (row["Open"] - pv("Close")) / (pv("Close") or 1) * 100
        is_up   = gap_pct >  p["GAP_TH"]
        is_dn   = gap_pct < -p["GAP_TH"]
        if is_up or is_dn:
            window5 = data["Close"].iloc[max(0, idx-5):idx]
            trend   = window5.mean() if len(window5) else row["Close"]
            prev5   = data["Close"].iloc[max(0, idx-6):idx-1].mean() if idx >= 6 else trend
            hi_vol  = row["Volume"] > fma
            reversal = (idx < len(data)-1 and
                        ((is_up and data["Close"].iloc[idx+1] < row["Close"]) or
                         (is_dn and data["Close"].iloc[idx+1] > row["Close"])))
            if is_up:
                if reversal and hi_vol:
                    sigs.append("📈 衰竭跳空(上)")
                elif row["Close"] > trend > prev5 and hi_vol:
                    sigs.append("📈 持續跳空(上)")
                elif row["High"] > data["High"].iloc[max(0,idx-5):idx].max() and hi_vol:
                    sigs.append("📈 突破跳空(上)")
                else:
                    sigs.append("📈 普通跳空(上)")
            else:
                if reversal and hi_vol:
                    sigs.append("📉 衰竭跳空(下)")
                elif row["Close"] < trend < prev5 and hi_vol:
                    sigs.append("📉 持續跳空(下)")
                elif row["Low"] < data["Low"].iloc[max(0,idx-5):idx].min() and hi_vol:
                    sigs.append("📉 突破跳空(下)")
                else:
                    sigs.append("📉 普通跳空(下)")

    # ── Continuous ────────────────────────────────────────────────────────────
    if row.get("Continuous_Up",   0) >= p["CONT_UP"]   and rsi_val < 70: sigs.append("📈 連續向上買入")
    if row.get("Continuous_Down", 0) >= p["CONT_DOWN"]  and rsi_val > 30: sigs.append("📉 連續向下賣出")

    # ── SMA50/200 ─────────────────────────────────────────────────────────────
    if pd.notna(row.get("SMA50")):
        if row["Close"] > row["SMA50"] and macd > 0:   sigs.append("📈 SMA50上升趨勢")
        elif row["Close"] < row["SMA50"] and macd < 0: sigs.append("📉 SMA50下降趨勢")
    if pd.notna(row.get("SMA50")) and pd.notna(row.get("SMA200")):
        if row["Close"] > row["SMA50"] > row["SMA200"] and macd > 0:   sigs.append("📈 SMA50_200上升趨勢")
        elif row["Close"] < row["SMA50"] < row["SMA200"] and macd < 0: sigs.append("📉 SMA50_200下降趨勢")

    # ── New buy/sell ──────────────────────────────────────────────────────────
    if idx > 0:
        pc = pv("Close")
        if row["Close"] > row["Open"] > pc and rsi_val < 70: sigs.append("📈 新买入信号")
        if row["Close"] < row["Open"] < pc and rsi_val > 30: sigs.append("📉 新卖出信号")

    # ── Pivot ─────────────────────────────────────────────────────────────────
    pr = row.get("Price Change %", 0) or 0
    vc_ = row.get("Volume Change %", 0) or 0
    if abs(pr) > p["PC_TH"] and abs(vc_) > p["VC_TH"] and macd > row.get("Signal_Line", 0):
        sigs.append("🔄 新转折点")
    if len(sigs) > 8:
        sigs.append(f"🔥 關鍵轉折({len(sigs)}信號)")

    # ── RSI-MACD composite ────────────────────────────────────────────────────
    if idx > 0:
        if rsi_val < 30 and macd > 0 and pv("MACD") <= 0:   sigs.append("📈 RSI-MACD Oversold Crossover")
        if rsi_val > 70 and macd < 0 and pv("MACD") >= 0:   sigs.append("📉 RSI-MACD Overbought Crossover")

    # ── EMA-SMA trend ─────────────────────────────────────────────────────────
    s50 = row.get("SMA50", np.nan)
    if pd.notna(s50):
        if row["EMA5"] > row["EMA10"] and row["Close"] > s50: sigs.append("📈 EMA-SMA Uptrend Buy")
        if row["EMA5"] < row["EMA10"] and row["Close"] < s50: sigs.append("📉 EMA-SMA Downtrend Sell")

    # ── Volume-MACD ───────────────────────────────────────────────────────────
    if idx > 0:
        if row["Volume"] > fma and macd > 0 and pv("MACD") <= 0: sigs.append("📈 Volume-MACD Buy")
        if row["Volume"] > fma and macd < 0 and pv("MACD") >= 0: sigs.append("📉 Volume-MACD Sell")

    # ── EMA 10/30/40 ─────────────────────────────────────────────────────────
    if idx > 0:
        if row["EMA10"] > row["EMA30"] and pv("EMA10") <= pv("EMA30"):
            sigs.append("📈 EMA10_30買入")
            if row["EMA10"] > row.get("EMA40", 0): sigs.append("📈 EMA10_30_40強烈買入")
        if row["EMA10"] < row["EMA30"] and pv("EMA10") >= pv("EMA30"):
            sigs.append("📉 EMA10_30賣出")
            if row["EMA10"] < row.get("EMA40", 999999): sigs.append("📉 EMA10_30_40強烈賣出")

    # ── Candlestick patterns ───────────────────────────────────────────────────
    if idx > 0:
        co, cc, ch, cl = row["Open"], row["Close"], row["High"], row["Low"]
        po, pc2 = pv("Open"), pv("Close")
        body = abs(cc - co); rng = ch - cl if ch != cl else 1e-9
        hi_vol = row["Volume"] > fma
        lower = min(co, cc) - cl; upper = ch - max(co, cc)

        if pc2 < po and cc > co and co <= pc2 and cc >= po and hi_vol and rsi_val < 70:
            sigs.append("📈 看漲吞沒")
        if pc2 > po and cc < co and co >= pc2 and cc <= po and hi_vol and rsi_val > 30:
            sigs.append("📉 看跌吞沒")
        if body < rng*0.3 and lower >= 2*max(body,1e-9) and upper < lower and hi_vol and rsi_val < 70:
            sigs.append("📈 錘頭線")
        if body < rng*0.3 and lower >= 2*max(body,1e-9) and upper < lower and hi_vol and rsi_val > 30:
            sigs.append("📉 上吊線")
        if pc2 > po and co > pc2 and cc < co and cc < (po+pc2)/2 and hi_vol:
            sigs.append("📉 烏雲蓋頂")
        if pc2 < po and co < pc2 and cc > co and cc > (po+pc2)/2 and hi_vol:
            sigs.append("📈 刺透形態")

    if idx > 1:
        p2o, p2c = data["Open"].iloc[idx-2], data["Close"].iloc[idx-2]
        p1o, p1c = data["Open"].iloc[idx-1], data["Close"].iloc[idx-1]
        co2, cc2 = row["Open"], row["Close"]
        hi_vol = row["Volume"] > fma
        if p2c < p2o and abs(p1c-p1o) < 0.3*abs(p2c-p2o) and cc2 > co2 and cc2 > (p2o+p2c)/2 and hi_vol and rsi_val < 70:
            sigs.append("📈 早晨之星")
        if p2c > p2o and abs(p1c-p1o) < 0.3*abs(p2c-p2o) and cc2 < co2 and cc2 < (p2o+p2c)/2 and hi_vol and rsi_val > 30:
            sigs.append("📉 黃昏之星")

    # ── Breakout ──────────────────────────────────────────────────────────────
    if idx > 0 and pd.notna(row.get("High_Max")) and row["High"] > data["High_Max"].iloc[idx-1]:
        sigs.append("📈 BreakOut_5K")
    if idx > 0 and pd.notna(row.get("Low_Min")) and row["Low"] < data["Low_Min"].iloc[idx-1]:
        sigs.append("📉 BreakDown_5K")

    # ── VWAP ─────────────────────────────────────────────────────────────────
    if idx > 0 and pd.notna(row.get("VWAP")) and pd.notna(pv("VWAP")):
        if row["Close"] > row["VWAP"] and pv("Close") <= pv("VWAP"):  sigs.append("📈 VWAP買入")
        elif row["Close"] < row["VWAP"] and pv("Close") >= pv("VWAP"): sigs.append("📉 VWAP賣出")

    # ── MFI divergence ────────────────────────────────────────────────────────
    w = p["MFI_WIN"]
    if idx >= w:
        if data.get("MFI_Bull_Div") is not None and data["MFI_Bull_Div"].iloc[idx]:
            sigs.append("📈 MFI牛背離買入")
        if data.get("MFI_Bear_Div") is not None and data["MFI_Bear_Div"].iloc[idx]:
            sigs.append("📉 MFI熊背離賣出")

    # ── OBV breakout ──────────────────────────────────────────────────────────
    if idx > 0 and pd.notna(row.get("OBV")):
        if row["Close"] > pv("Close") and row["OBV"] > data["OBV_Roll_Max"].iloc[idx-1]:
            sigs.append("📈 OBV突破買入")
        elif row["Close"] < pv("Close") and row["OBV"] < data["OBV_Roll_Min"].iloc[idx-1]:
            sigs.append("📉 OBV突破賣出")

    # ── VIX ───────────────────────────────────────────────────────────────────
    vix_now = row.get("VIX", np.nan)
    if idx > 0 and pd.notna(vix_now):
        vix_prev = data["VIX"].iloc[idx-1]
        if pd.notna(vix_prev):
            if vix_now > p["VIX_HIGH"] and vix_now > vix_prev:  sigs.append("📉 VIX恐慌賣出")
            elif vix_now < p["VIX_LOW"] and vix_now < vix_prev: sigs.append("📈 VIX平靜買入")
        ef = row.get("VIX_EMA_Fast", np.nan)
        es = row.get("VIX_EMA_Slow", np.nan)
        ef_p = data["VIX_EMA_Fast"].iloc[idx-1] if "VIX_EMA_Fast" in data.columns else np.nan
        es_p = data["VIX_EMA_Slow"].iloc[idx-1] if "VIX_EMA_Slow" in data.columns else np.nan
        if pd.notna(ef) and pd.notna(es) and pd.notna(ef_p) and pd.notna(es_p):
            if ef > es and ef_p <= es_p:  sigs.append("📉 VIX上升趨勢賣出")
            elif ef < es and ef_p >= es_p: sigs.append("📈 VIX下降趨勢買入")

    return ", ".join(sigs) if sigs else ""


# ═════════════════════════════════════════════════════════════════════════════
#  COMPREHENSIVE INTERPRETATION
# ═════════════════════════════════════════════════════════════════════════════

def comprehensive_interp(df: pd.DataFrame, dense_areas, VIX_HIGH, VIX_LOW) -> str:
    last5  = df.tail(5)
    bull   = last5["K線形態"].isin(["錘子線","大陽線","看漲吞噬","刺透形態","早晨之星"]).sum()
    bear   = last5["K線形態"].isin(["射擊之星","大陰線","看跌吞噬","烏雲蓋頂","黃昏之星"]).sum()
    hi_vol = (last5["成交量標記"] == "放量").sum()

    dense_desc = ""
    if dense_areas:
        ctrs = [f"{a['price_center']:.2f}" for a in dense_areas]
        dense_desc = f"，成交密集區：{', '.join(ctrs)}"

    vwap_v = last5["VWAP"].iloc[-1]; c_v = last5["Close"].iloc[-1]
    vwap_s = "多頭" if pd.notna(vwap_v) and c_v > vwap_v else "空頭"
    mfi_v  = last5["MFI"].iloc[-1]
    if pd.notna(mfi_v):
        mfi_s = f"MFI={mfi_v:.0f}({'超賣' if mfi_v<20 else '超買' if mfi_v>80 else '中性'})"
    else:
        mfi_s = "MFI=N/A"
    obv_s  = "OBV↑確認量能" if last5["OBV"].iloc[-1] > last5["OBV"].iloc[0] else "OBV↓警示"
    vix_v  = last5["VIX"].iloc[-1]
    vix_s  = f"VIX={'N/A' if pd.isna(vix_v) else f'{vix_v:.1f}(恐慌)' if vix_v>VIX_HIGH else f'{vix_v:.1f}(平靜)' if vix_v<VIX_LOW else f'{vix_v:.1f}'}"
    suffix = f"｜{vwap_s} VWAP，{mfi_s}，{obv_s}，{vix_s}{dense_desc}"

    if bull >= 3 and hi_vol >= 3:
        return f"多方主導，多根看漲形態放量，強勢上漲趨勢。{suffix}。💡 建議關注買入機會。"
    elif bear >= 3 and hi_vol >= 3:
        return f"空方主導，多根看跌形態放量，強勢下跌趨勢。{suffix}。⚠️ 建議注意賣出風險。"
    elif bull >= 2 and bear >= 2:
        return f"多空激烈爭奪，方向不明。{suffix}。📊 建議觀望。"
    else:
        return f"無明顯趨勢，持續觀察。{suffix}。"




# ═════════════════════════════════════════════════════════════════════════════
#  UI - SIDEBAR
# ═════════════════════════════════════════════════════════════════════════════

# 回測用：各 interval 允許的 period 清單（yfinance 限制）
INTERVAL_PERIOD_MAP = {
    "1m":  {"periods": ["1d","5d","7d"],       "default": "7d",  "help": "1m 最多 7 天"},
    "5m":  {"periods": ["5d","1mo","60d"],     "default": "60d", "help": "5m 最多 60 天"},
    "15m": {"periods": ["5d","1mo","60d"],     "default": "60d", "help": "15m 最多 60 天"},
    "30m": {"periods": ["5d","1mo","60d"],     "default": "60d", "help": "30m 最多 60 天"},
    "1h":  {"periods": ["1mo","3mo","6mo","1y","2y"], "default": "2y", "help": "1h 最多 730 天"},
    "1d":  {"periods": ["3mo","6mo","1y","2y","5y","ytd","max"], "default": "2y", "help": "日線建議 2y+"},
    "1wk": {"periods": ["6mo","1y","2y","5y","ytd","max"], "default": "5y", "help": "週線建議 5y+"},
    "1mo": {"periods": ["1y","2y","5y","ytd","max"], "default": "max", "help": "月線建議 max"},
}
ALL_BT_INTERVALS = ["1m","5m","15m","30m","1h","1d","1wk","1mo"]

with st.sidebar:
    st.header("⚙️ 參數設定")
    input_tickers     = st.text_input("股票代號（逗號分隔）",
                                       "TSLA, UVXY, UVIX, NIO, TSLL, XPEV, GLD, META, GOOGL, AAPL, NVDA, AMZN, TSM, MSFT, INTC, SNDK, AMD,PLTR, COIN")
    selected_period   = st.selectbox("時間範圍",
                                      ["1d","5d","1mo","3mo","6mo","1y","2y","5y","ytd","max"], index=5)
    selected_interval = st.selectbox("資料間隔",
                                      ["1m","5m","15m","30m","60m","1h","1d","5d","1wk","1mo"], index=6)
    st.subheader("信號閾值")
    HIGH_N_HIGH_TH   = st.number_input("Close-to-High",     0.1, 1.0, 0.9, 0.1)
    LOW_N_LOW_TH     = st.number_input("Close-to-Low",      0.1, 1.0, 0.9, 0.1)
    PRICE_TH         = st.number_input("股價異動閾值 (%)",   0.1, 200.0, 80.0, 0.1)
    VOLUME_TH        = st.number_input("成交量異動閾值 (%)", 0.1, 200.0, 80.0, 0.1)
    PC_TH            = st.number_input("轉折 Price (%)",     0.1, 200.0,  5.0, 0.1)
    VC_TH            = st.number_input("轉折 Volume (%)",    0.1, 200.0, 10.0, 0.1)
    GAP_TH           = st.number_input("跳空閾值 (%)",       0.1,  50.0,  1.0, 0.1)
    CONT_UP          = st.number_input("連續上漲閾值 (根)",  1, 20, 3, 1)
    CONT_DOWN        = st.number_input("連續下跌閾值 (根)",  1, 20, 3, 1)
    PERCENTILE_TH    = st.selectbox("百分位 (%)",            [1, 5, 10, 20], index=1)
    st.subheader("K 線形態")
    BODY_RATIO_TH    = st.number_input("實體占比",  0.1, 0.9, 0.6, 0.05)
    SHADOW_RATIO_TH  = st.number_input("影線長度",  0.1, 3.0, 2.0, 0.1)
    DOJI_BODY_TH     = st.number_input("十字星閾值",0.01, 0.2, 0.1, 0.01)
    st.subheader("MFI")
    MFI_WIN          = st.number_input("MFI 背離窗口", 3, 20, 5, 1)
    st.subheader("VIX")
    VIX_HIGH_TH      = st.number_input("VIX 恐慌閾值", 20.0, 50.0, 30.0, 1.0)
    VIX_LOW_TH       = st.number_input("VIX 平靜閾值", 10.0, 25.0, 20.0, 1.0)
    VIX_EMA_FAST     = st.number_input("VIX EMA 快", 3, 15,  5, 1)
    VIX_EMA_SLOW     = st.number_input("VIX EMA 慢", 8, 25, 10, 1)
    st.subheader("成交密集區")
    VP_BINS          = st.number_input("分箱數量",  10, 200, 50,  5)
    VP_WINDOW        = st.number_input("K 線根數",  20, 500, 100, 10)
    VP_TOP_N         = st.number_input("顯示前 N",   1,   5,   3,  1)
    VP_SHOW          = st.checkbox("標記密集區", True)
    st.subheader("回測")
    BT_MIN_COMBO     = st.number_input("最少組合數", 2, 3, 2, 1)
    BT_MAX_COMBO     = st.number_input("最多組合數", 2, 5, 3, 1)
    BT_MIN_OCC       = st.number_input("最少次數",   2, 10, 3, 1)
    st.subheader("刷新")
    REFRESH_INTERVAL = st.selectbox("刷新間隔 (秒)", [30, 60, 90, 120, 180, 300], index=4)

PARAMS = dict(
    HIGH_N_HIGH_TH=HIGH_N_HIGH_TH, LOW_N_LOW_TH=LOW_N_LOW_TH,
    PRICE_TH=PRICE_TH, VOLUME_TH=VOLUME_TH,
    PC_TH=PC_TH, VC_TH=VC_TH, GAP_TH=GAP_TH,
    CONT_UP=CONT_UP, CONT_DOWN=CONT_DOWN,
    MFI_WIN=int(MFI_WIN),
    VIX_HIGH=VIX_HIGH_TH, VIX_LOW=VIX_LOW_TH,
)

selected_tickers = [t.strip().upper() for t in (input_tickers or "").split(",") if t.strip()]

# ── Telegram signal selection ─────────────────────────────────────────────────
ALL_SIGNAL_TYPES = sorted([
    "📈 Low>High","📈 MACD買入","📈 EMA買入","📈 價格趨勢買入","📈 價格趨勢買入(量)",
    "📈 價格趨勢買入(量%)","📈 普通跳空(上)","📈 突破跳空(上)","📈 持續跳空(上)",
    "📈 衰竭跳空(上)","📈 連續向上買入","📈 SMA50上升趨勢","📈 SMA50_200上升趨勢",
    "📈 新买入信号","📈 RSI-MACD Oversold Crossover","📈 EMA-SMA Uptrend Buy",
    "📈 Volume-MACD Buy","📈 EMA10_30買入","📈 EMA10_30_40強烈買入",
    "📈 看漲吞沒","📈 刺透形態","📈 錘頭線","📈 早晨之星",
    "📈 VWAP買入","📈 MFI牛背離買入","📈 OBV突破買入",
    "📈 VIX平靜買入","📈 VIX下降趨勢買入","✅ 量價","🔄 新转折点",
] + list(SELL_SIGNALS))

# ── 每支股票預設條件表 ─────────────────────────────────────────────────────────
# ── 每支股票預設條件表 ─────────────────────────────────────────────────────────
# FIX: 預設為空表，而非預填做多信號。
# 原因：Streamlit Cloud 重啟時 session_state/query_params/localStorage 可能全部丟失，
#       如果 fallback 到有信號的預設表，會意外觸發 Telegram 推送。
#       空表 = 不會匹配任何條件 = 安全。用戶需要先執行回測才能填入條件。
_TG_DEFAULT = pd.DataFrame({
    "排名":       pd.Series(dtype="str"),
    "異動標記":   pd.Series(dtype="str"),
    "成交量標記": pd.Series(dtype="str"),
    "K線形態":    pd.Series(dtype="str"),
    "回測勝率":   pd.Series(dtype="str"),
    "方向":       pd.Series(dtype="str"),
})

import zlib, base64

_TG_COLS = ["排名","異動標記","成交量標記","K線形態","回測勝率","方向"]

def _ls_key(ticker: str) -> str:
    return f"streamlit_tg_conds_{ticker}"

def _qp_key(ticker: str) -> str:
    return f"tc_{ticker}"

def _ss_key(ticker: str) -> str:
    return f"tg_conds_{ticker}"


def _tg_encode(df: pd.DataFrame) -> str:
    try:
        records = df[_TG_COLS].fillna("").to_dict(orient="records")
        raw     = json.dumps(records, ensure_ascii=False, separators=(",", ":"))
        return base64.urlsafe_b64encode(
            zlib.compress(raw.encode("utf-8"), level=9)
        ).decode("ascii")
    except Exception:
        return ""


def _tg_decode(s: str) -> pd.DataFrame:
    try:
        raw     = zlib.decompress(base64.urlsafe_b64decode(s)).decode("utf-8")
        records = json.loads(raw)
        df      = pd.DataFrame(records)
        for col in _TG_COLS:
            if col not in df.columns:
                df[col] = "做多" if col == "方向" else ""
        return df[_TG_COLS].fillna("")
    except Exception:
        return pd.DataFrame()


def _tg_save(df: pd.DataFrame, ticker: str):
    encoded = _tg_encode(df)
    if not encoded:
        return
    try:
        st.query_params[_qp_key(ticker)] = encoded
    except Exception:
        pass
    try:
        import streamlit.components.v1 as components
        _lsk = _ls_key(ticker)
        _ls_js = f"""<script>
        try {{ localStorage.setItem({json.dumps(_lsk)}, {json.dumps(encoded)}); }} catch(e) {{}}
        </script>"""
        components.html(_ls_js, height=0, scrolling=False)
    except Exception:
        pass


def _tg_load_ls_component(ticker: str):
    try:
        import streamlit.components.v1 as components
        _lsk  = _ls_key(ticker)
        _qpk  = _qp_key(ticker)
        _cur  = st.query_params.get(_qpk, "")
        _js   = f"""<script>
        (function(){{
            var ls=""; try{{ls=localStorage.getItem({json.dumps(_lsk)})||"";}}catch(e){{}}
            var qp={json.dumps(_cur)};
            if(ls && ls!==qp){{
                var url=new URL(window.parent.location.href);
                url.searchParams.set({json.dumps(_qpk)},ls);
                window.parent.history.replaceState(null,"",url.toString());
                window.parent.location.reload();
            }}
        }})();
        </script>"""
        components.html(_js, height=0, scrolling=False)
    except Exception:
        pass


def _tg_init(ticker: str) -> pd.DataFrame:
    ssk = _ss_key(ticker)
    qpk = _qp_key(ticker)

    if ssk in st.session_state:
        df = st.session_state[ssk]
    else:
        qp_enc = st.query_params.get(qpk, "")
        if qp_enc:
            df = _tg_decode(qp_enc)
            if df.empty:
                df = _TG_DEFAULT.copy()
                _tg_load_ls_component(ticker)
        else:
            df = _TG_DEFAULT.copy()
            _tg_load_ls_component(ticker)

    for col in _TG_COLS:
        if col not in df.columns:
            df[col] = "做多" if col == "方向" else ""
    df = df[_TG_COLS].fillna("")
    st.session_state[ssk] = df
    return df


def _tg_editor(ticker: str) -> pd.DataFrame:
    ssk = _ss_key(ticker)
    tc  = st.data_editor(
        st.session_state[ssk],
        num_rows="dynamic",
        key=f"tg_editor_{ticker}",
        column_config={
            "排名":       st.column_config.TextColumn("排名",       width="small"),
            "異動標記":   st.column_config.TextColumn("異動標記",   width="large"),
            "成交量標記": st.column_config.SelectboxColumn(
                            "成交量標記", options=["","放量","縮量","—"], width="small"),
            "K線形態":    st.column_config.TextColumn("K線形態",    width="medium"),
            "回測勝率":   st.column_config.TextColumn("回測勝率",   width="small",
                            help="由回測一鍵加入時自動填入"),
            "方向":       st.column_config.TextColumn("方向",       width="small",
                            help="填入「做多」或「做空」；一鍵加入時自動帶入"),
        },
        use_container_width=True,
    )
    _tc = tc.copy()
    for col in _tc.columns:
        _tc[col] = _tc[col].where(_tc[col].notna(), "").astype(str).str.strip()
    st.session_state[ssk] = _tc
    _tg_save(_tc, ticker)
    return _tc




def _run_backtest_for_ticker(
    tk: str,
    period: str,
    interval: str,
    min_combo: int,
    max_combo: int,
    min_occ: int,
) -> "tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, int] | tuple[None,None,None,str]":
    """
    對單支股票執行完整回測流程。
    成功回傳 (df_sig, df_vol, df_kl, n_bars)。
    失敗回傳 (None, None, None, error_message)。
    """
    try:
        bt_data = yf.Ticker(tk).history(period=period, interval=interval).reset_index()
        if "Date" in bt_data.columns:
            bt_data = bt_data.rename(columns={"Date": "Datetime"})
        bt_data["Datetime"] = pd.to_datetime(bt_data["Datetime"]).dt.tz_localize(None)
        if len(bt_data) < 30:
            return None, None, None, f"資料不足（{len(bt_data)} 根K線 < 30）"

        # 共用指標計算（回測不含 VIX）
        bt_data = _enrich_data(bt_data, PARAMS, int(MFI_WIN))
        for _nc in ["📈 股價漲跌幅(%)","📊 成交量變動幅(%)","Close_N_High","Close_N_Low"]:
            bt_data[_nc] = np.nan

        bt_data["異動標記"] = compute_all_signals(bt_data, PARAMS)
        bt_data = _attach_kline_and_vol(bt_data, tk, period, interval,
                                         BODY_RATIO_TH, SHADOW_RATIO_TH, DOJI_BODY_TH)

        _kw = dict(min_combo=min_combo, max_combo=max_combo, min_occ=min_occ)
        df_sig = _base_signal_combos(bt_data, **_kw)
        df_vol = _signal_x_volume_combos(bt_data, **_kw)
        df_kl  = _signal_x_kline_combos(bt_data, **_kw)

        return df_sig, df_vol, df_kl, len(bt_data)

    except Exception as e:
        return None, None, None, str(e)


def _merge_dims_to_conds(
    df_sig: pd.DataFrame,
    df_vol: pd.DataFrame,
    df_kl:  pd.DataFrame,
    wr_thr: float,
    pnl_thr: float = 0.0,
) -> pd.DataFrame:
    """把三個維度的回測結果合併成 Telegram 條件表格式。"""
    def _pass(r) -> bool:
        wr_ok  = r["勝率(%)"] >= wr_thr
        pnl_ok = (pnl_thr == 0.0) or (
            "平均盈虧(%)" in r.index and pd.notna(r["平均盈虧(%)"]) and float(r["平均盈虧(%)"]) >= pnl_thr
        )
        return wr_ok and pnl_ok

    rows = []
    # 統一遍歷三個維度
    dim_specs = [
        (df_sig, "—", "—"),      # (df, 成交量標記欄位, K線形態欄位)
        (df_vol, "成交量標記", "—"),
        (df_kl,  "—", "K線形態"),
    ]
    for df_dim, vol_col, kl_col in dim_specs:
        for _, r in df_dim.iterrows():
            if _pass(r):
                rows.append({
                    "異動標記":   r["信號組合"].replace(" + ", ", "),
                    "成交量標記": r.get(vol_col, "—") if vol_col != "—" else "—",
                    "K線形態":    r.get(kl_col,  "—") if kl_col  != "—" else "—",
                    "回測勝率":   f"{r['勝率(%)']:.1f}%",
                    "方向":       r.get("方向", "做多"),
                    "_wr":        r["勝率(%)"],
                })
    if not rows:
        return pd.DataFrame()
    merged = (
        pd.DataFrame(rows)
        .sort_values("_wr", ascending=False)
        .drop_duplicates(subset=["異動標記","成交量標記","K線形態"], keep="first")
        .drop(columns=["_wr"])
        .reset_index(drop=True)
    )
    merged["排名"] = [str(i+1) for i in range(len(merged))]
    return merged[_TG_COLS]




# ═════════════════════════════════════════════════════════════════════════════
#  MAIN UI
# ═════════════════════════════════════════════════════════════════════════════

st.title("📊 股票監控儀表板")

# ── 總開關 ────────────────────────────────────────────────────────────────────
if "app_running" not in st.session_state:
    st.session_state["app_running"] = False
if "last_refresh" not in st.session_state:
    st.session_state["last_refresh"] = 0.0

col_btn1, col_btn2, col_status = st.columns([1, 1, 4])

with col_btn1:
    if not st.session_state["app_running"]:
        if st.button("▶️ 啟動監控", type="primary", use_container_width=True):
            st.session_state["app_running"] = True
            st.session_state["last_refresh"] = time.time()
            st.rerun()
    else:
        if st.button("⏹️ 停止監控", type="secondary", use_container_width=True):
            st.session_state["app_running"] = False
            st.rerun()

with col_btn2:
    if st.session_state["app_running"]:
        if st.button("🔄 立即刷新", use_container_width=True):
            st.session_state["last_refresh"] = time.time()
            st.rerun()

with col_status:
    if st.session_state["app_running"]:
        st.success(f"🟢 監控運行中　｜　每 **{REFRESH_INTERVAL}** 秒自動刷新", icon="📡")
    else:
        st.warning("⏸️ 已停止，調好參數後按啟動", icon="⚙️")

st.caption(f"⏱ 更新時間：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

# ── 全域 Telegram 開關 ────────────────────────────────────────────────────────
if selected_tickers:
    # 初始化全域靜音開關
    if "tg_global_mute" not in st.session_state:
        st.session_state["tg_global_mute"] = False

    # ── 1️⃣ 全域靜音熔斷開關（優先級最高）──────────────────────────────────
    _mute_col1, _mute_col2 = st.columns([1, 5])
    with _mute_col1:
        _mute_on = st.session_state["tg_global_mute"]
        if st.button(
            "🔔 解除全域靜音" if _mute_on else "🔇 全域靜音（總開關）",
            key="tg_global_mute_btn",
            use_container_width=True,
            type="secondary" if _mute_on else "primary",
            help="一鍵徹底阻止所有 Telegram 發送，無視其他設定",
        ):
            st.session_state["tg_global_mute"] = not _mute_on
            st.rerun()
    with _mute_col2:
        if _mute_on:
            st.error(
                "🔇 **全域靜音已啟用** — 所有 Telegram 訊息都被強制攔截，"
                "無視個別股票開關。點擊左側按鈕可解除。",
                icon="🚫",
            )
        else:
            st.caption("💡 如果「全部關閉」後仍收到訊息，點擊左邊的「🔇 全域靜音」強制阻止所有發送")

    # ── 2️⃣ 個別股票開關（在全域靜音未啟用時才顯示）──────────────────────
    _n_on  = sum(1 for _tk in selected_tickers
                 if st.session_state.get(f"tg_enabled_{_tk}", True))
    _n_all = len(selected_tickers)
    _all_on  = (_n_on == _n_all)
    _all_off = (_n_on == 0)

    _gc1, _gc2, _gc3 = st.columns([1, 1, 4])

    with _gc1:
        if st.button(
            f"🟢 全部開啟",
            key="tg_all_on",
            use_container_width=True,
            disabled=_all_on or _mute_on,
            help=f"將全部 {_n_all} 支股票的 Telegram 開啟",
        ):
            for _tk in selected_tickers:
                st.session_state[f"tg_enabled_{_tk}"] = True
            st.rerun()

    with _gc2:
        if st.button(
            f"🔴 全部關閉",
            key="tg_all_off",
            use_container_width=True,
            disabled=_all_off,
            help=f"將全部 {_n_all} 支股票的 Telegram 關閉（靜音模式）",
        ):
            for _tk in selected_tickers:
                st.session_state[f"tg_enabled_{_tk}"] = False
            st.rerun()

    with _gc3:
        if _mute_on:
            st.warning(f"🔇 全域靜音優先，個別股票開關（{_n_on}/{_n_all} 開啟）暫時無效", icon="ℹ️")
        elif _all_on:
            st.success(f"🟢 **全部 {_n_all} 支股票 Telegram 已開啟**", icon="✅")
        elif _all_off:
            st.warning(f"🔴 **全部 {_n_all} 支股票 Telegram 已關閉**（靜音模式）", icon="🔕")
        else:
            _on_names  = [t for t in selected_tickers
                          if st.session_state.get(f"tg_enabled_{t}", True)]
            _off_names = [t for t in selected_tickers
                          if not st.session_state.get(f"tg_enabled_{t}", True)]
            st.info(
                f"⚡ **部分開啟**（{_n_on}/{_n_all}）：🟢 {', '.join(_on_names)}　"
                f"🔴 {', '.join(_off_names)}",
                icon="ℹ️",
            )

    # ── 3️⃣ 突破新高 / 跌破新低 總開關 ──────────────────────────────────
    _bo_n_high = sum(1 for _tk in selected_tickers
                     if st.session_state.get(f"bo_high_{_tk}", True))
    _bo_n_low  = sum(1 for _tk in selected_tickers
                     if st.session_state.get(f"bo_low_{_tk}", True))

    _bo_col1, _bo_col2, _bo_col3, _bo_col4, _bo_info = st.columns([1, 1, 1, 1, 3])

    with _bo_col1:
        if st.button(
            f"🚀 全部開啟新高",
            key="bo_high_all_on",
            use_container_width=True,
            disabled=(_bo_n_high == _n_all),
        ):
            for _tk in selected_tickers:
                st.session_state[f"bo_high_{_tk}"] = True
            st.rerun()

    with _bo_col2:
        if st.button(
            f"🚫 全部關閉新高",
            key="bo_high_all_off",
            use_container_width=True,
            disabled=(_bo_n_high == 0),
        ):
            for _tk in selected_tickers:
                st.session_state[f"bo_high_{_tk}"] = False
            st.rerun()

    with _bo_col3:
        if st.button(
            f"🔻 全部開啟新低",
            key="bo_low_all_on",
            use_container_width=True,
            disabled=(_bo_n_low == _n_all),
        ):
            for _tk in selected_tickers:
                st.session_state[f"bo_low_{_tk}"] = True
            st.rerun()

    with _bo_col4:
        if st.button(
            f"🚫 全部關閉新低",
            key="bo_low_all_off",
            use_container_width=True,
            disabled=(_bo_n_low == 0),
        ):
            for _tk in selected_tickers:
                st.session_state[f"bo_low_{_tk}"] = False
            st.rerun()

    with _bo_info:
        st.caption(
            f"🚀 突破新高：{_bo_n_high}/{_n_all} 開啟　｜　"
            f"🔻 跌破新低：{_bo_n_low}/{_n_all} 開啟"
        )

# ── 一鍵全部股票回測 ─────────────────────────────────────────────────────────
_AUTO_PERIOD_MAP = {
    "1d":"1d","5d":"5d","1mo":"1mo","3mo":"3mo","6mo":"6mo",
    "1y":"1y","2y":"2y","5y":"5y","10y":"max",
}
_AUTO_INTERVAL_MAX = {
    "1m": {"1d","5d"},
    "5m": {"1d","5d","1mo"},
    "15m":{"1d","5d","1mo"},
    "30m":{"1d","5d","1mo"},
    "1h": {"1d","5d","1mo","3mo","6mo","1y","2y"},
    "1d": {"1d","5d","1mo","3mo","6mo","1y","2y","5y","10y"},
    "1wk":{"1mo","3mo","6mo","1y","2y","5y","10y"},
    "1mo":{"3mo","6mo","1y","2y","5y","10y"},
}

with st.expander("⚡ 一鍵全部股票自動回測 & 更新 Telegram 條件表", expanded=False):
    st.caption(
        "對所有監控股票依序執行回測，自動用三維合併結果覆蓋各自的 Telegram 觸發條件表。"
    )

    _ac1, _ac2 = st.columns(2)
    _auto_interval = _ac1.selectbox(
        "K線間隔",
        ["1m","5m","15m","30m","1h","1d","1wk","1mo"],
        index=5,
        key="auto_bt_interval",
        help="短週期間隔受 yfinance 限制，可選時間範圍較少",
    )
    _allowed_periods = _AUTO_INTERVAL_MAX.get(_auto_interval,
                       {"1d","5d","1mo","3mo","6mo","1y","2y","5y","10y"})
    _all_periods_ordered = ["1d","5d","1mo","3mo","6mo","1y","2y","5y","10y"]
    _period_opts = [p for p in _all_periods_ordered if p in _allowed_periods]
    _period_def  = "1y" if "1y" in _period_opts else _period_opts[-1]
    _auto_period = _ac2.selectbox(
        "時間範圍",
        _period_opts,
        index=_period_opts.index(_period_def),
        key="auto_bt_period",
        help="10y = 使用 yfinance max（全部歷史）",
    )

    _bc1, _bc2, _bc3, _bc4, _bc5 = st.columns(5)
    _auto_wr_thr   = _bc1.number_input(
        "合併勝率閾值 (%)", min_value=0, max_value=100, value=90, step=5,
        key="auto_bt_wr_thr",
    )
    _auto_min_occ  = _bc2.number_input(
        "最少出現次數", min_value=2, max_value=50, value=10, step=1,
        key="auto_bt_min_occ",
    )
    _auto_pnl_thr  = _bc3.number_input(
        "最低平均盈虧 (%)", min_value=-10.0, max_value=20.0, value=0.5, step=0.1,
        format="%.1f",
        key="auto_bt_pnl_thr",
    )
    _auto_min_combo = _bc4.number_input(
        "最少信號組合數", min_value=2, max_value=5, value=2, step=1,
        key="auto_bt_min_combo",
    )
    _auto_max_combo = _bc5.number_input(
        "最多信號組合數", min_value=2, max_value=5, value=3, step=1,
        key="auto_bt_max_combo",
    )

    if _auto_interval in ("1m","5m","15m","30m","1h"):
        st.warning(
            f"⚠️ {_auto_interval} 短週期：yfinance 限制資料範圍，"
            f"樣本數可能較少，建議降低「最少出現次數」至 3～5。",
            icon="⚠️",
        )

    if st.button(
        f"⚡ 開始自動回測所有股票（共 {len(selected_tickers)} 支）",
        type="primary",
        key="auto_bt_run",
        disabled=(len(selected_tickers) == 0),
    ):
        _fetch_period = _AUTO_PERIOD_MAP.get(_auto_period, _auto_period)

        _auto_results = []
        _prog_bar  = st.progress(0, text="準備開始…")
        _status_ph = st.empty()

        for _ai, _atk in enumerate(selected_tickers):
            _prog = _ai / len(selected_tickers)
            _prog_bar.progress(_prog, text=f"正在處理 {_atk}（{_ai+1}/{len(selected_tickers)}）…")
            _status_ph.info(f"⏳ **{_atk}**：下載 {_auto_period} / {_auto_interval} 資料並計算中…")

            _dsig, _dvol, _dkl, _n_or_err = _run_backtest_for_ticker(
                tk        = _atk,
                period    = _fetch_period,
                interval  = _auto_interval,
                min_combo = int(_auto_min_combo),
                max_combo = int(max(_auto_max_combo, _auto_min_combo)),
                min_occ   = int(_auto_min_occ),
            )

            if _dsig is None:
                _auto_results.append({
                    "ticker": _atk, "status": "❌", "n_conds": 0,
                    "msg": str(_n_or_err),
                })
                _status_ph.error(f"❌ **{_atk}** 回測失敗：{_n_or_err}")
                continue

            _merged = _merge_dims_to_conds(
                _dsig, _dvol, _dkl,
                wr_thr  = float(_auto_wr_thr),
                pnl_thr = float(_auto_pnl_thr),
            )

            if _merged.empty:
                _cond_str = f"勝率 ≥ {_auto_wr_thr}%"
                if _auto_pnl_thr != 0:
                    _cond_str += f" 且 平均盈虧 ≥ {_auto_pnl_thr}%"
                _auto_results.append({
                    "ticker": _atk, "status": "⚠️", "n_conds": 0,
                    "msg": f"無符合條件（{_cond_str}）的組合，條件表未更新",
                })
                _status_ph.warning(f"⚠️ **{_atk}**：無符合條件的組合")
                continue

            st.session_state[_ss_key(_atk)] = _merged
            _tg_save(_merged, _atk)

            _auto_results.append({
                "ticker": _atk, "status": "✅",
                "n_conds": len(_merged),
                "msg": (
                    f"寫入 {len(_merged)} 條條件"
                    f"（{_auto_period}/{_auto_interval}，"
                    f"勝率 ≥ {_auto_wr_thr}%，盈虧 ≥ {_auto_pnl_thr}%）"
                ),
            })
            _status_ph.success(f"✅ **{_atk}**：寫入 {len(_merged)} 條條件")

        _prog_bar.progress(1.0, text="全部完成！")
        _status_ph.empty()

        _ok_list   = [r for r in _auto_results if r["status"] == "✅"]
        _warn_list = [r for r in _auto_results if r["status"] == "⚠️"]
        _err_list  = [r for r in _auto_results if r["status"] == "❌"]

        st.markdown("---")
        st.subheader("📊 自動回測結果總結")
        _sc1, _sc2, _sc3 = st.columns(3)
        _sc1.metric("✅ 成功", len(_ok_list))
        _sc2.metric("⚠️ 無符合條件", len(_warn_list))
        _sc3.metric("❌ 失敗", len(_err_list))

        for _r in _auto_results:
            st.write(f"{_r['status']} **{_r['ticker']}**：{_r['msg']}")

        if _ok_list:
            n_ok = len(_ok_list)
            st.success(
                f"🎯 成功更新 **{n_ok}** 支股票的 Telegram 條件表！"
                " 請切換到各股票 Tab 確認條件表內容。",
                icon="🎯",
            )
            st.balloons()

tabs = st.tabs([f"📈 {t}" for t in selected_tickers] + ["🔬 回測分析"])


# ── FIX BUG-03: Telegram 去重輔助函數 ─────────────────────────────────────────
def _tg_dedup_key(ticker: str, last_dt) -> str:
    """為每支股票 + 每根K線的 Datetime 生成唯一的去重 key。"""
    return f"tg_sent_{ticker}_{str(last_dt)[:19]}"


def _tg_already_sent(key: str, sig_or_rank: str) -> bool:
    """檢查某信號/條件是否已在本根K線中發送過。"""
    sent_set = st.session_state.get(key, set())
    return sig_or_rank in sent_set


def _tg_mark_sent(key: str, sig_or_rank: str):
    """標記某信號/條件已發送，並清理過期記錄。"""
    if key not in st.session_state:
        st.session_state[key] = set()
    st.session_state[key].add(sig_or_rank)

    # 清理舊記錄（保留最近 10 筆）
    _prefix = key.rsplit("_", 1)[0]  # tg_sent_TICKER
    _old_keys = sorted([k for k in st.session_state if k.startswith(_prefix + "_")])
    if len(_old_keys) > 10:
        for _ok in _old_keys[:-10]:
            try:
                del st.session_state[_ok]
            except KeyError:
                pass


def _build_cond_id(raw_marks: str, c_vol: str, c_kline: str) -> str:
    """
    FIX BUG-11/12: 用條件內容的 hash 作為唯一 ID（而非排名）。

    解決問題：
    - 用戶編輯條件表後，排名不變但內容改變 → 不應被誤判為已發送
    - 用戶手動填入重複排名 → 每條都要能獨立去重

    內容相同 → hash 相同 → 去重生效
    內容不同 → hash 不同 → 獨立去重
    """
    import hashlib
    # 正規化：空白/—/全部都視為空，去除多餘空白
    _norm_vol   = "" if c_vol   in ("", "—", "全部") else c_vol.strip()
    _norm_kline = "" if c_kline in ("", "—", "全部") else c_kline.strip()
    # 信號排序後 join（避免順序不同造成不同 hash）
    _sorted_sigs = sorted([s.strip() for s in raw_marks.split(",") if s.strip()])
    content = f"{','.join(_sorted_sigs)}|{_norm_vol}|{_norm_kline}"
    h = hashlib.md5(content.encode("utf-8")).hexdigest()[:10]
    return f"cond_{h}"




# ═════════════════════════════════════════════════════════════════════════════
#  MAIN LOOP  (each ticker)
# ═════════════════════════════════════════════════════════════════════════════

for tab_idx, ticker in enumerate(selected_tickers):
    with tabs[tab_idx]:
        _tk_conds = _tg_init(ticker)

        # ── 每支股票獨立的 Telegram 開關 ──────────────────────────────────────
        _tg_en_key = f"tg_enabled_{ticker}"
        if _tg_en_key not in st.session_state:
            st.session_state[_tg_en_key] = True

        _sw_col, _sw_info = st.columns([1, 5])
        with _sw_col:
            # FIX: 按鈕顯示「下一步動作」，更符合直覺
            _sw_label = (
                f"🔴 關閉 {ticker} Telegram"
                if st.session_state[_tg_en_key]
                else f"🟢 開啟 {ticker} Telegram"
            )
            if st.button(_sw_label, key=f"tg_toggle_{ticker}", use_container_width=True):
                st.session_state[_tg_en_key] = not st.session_state[_tg_en_key]
                st.rerun()
        with _sw_info:
            if st.session_state[_tg_en_key]:
                st.success(f"🟢 **{ticker} Telegram 開啟**：條件匹配時自動推送", icon="✅")
            else:
                st.warning(
                    f"🔴 **{ticker} Telegram 已關閉（靜音模式）**：只顯示 UI 提示，不發送訊息。",
                    icon="🔕",
                )

        selected_signals = st.multiselect(
            f"選擇 {ticker} 需要 Telegram 推播的信號",
            ALL_SIGNAL_TYPES,
            default=["📈 新买入信号"],
            key=f"selected_signals_{ticker}",
        )

        # ── 突破新高/跌破新低 開關 ────────────────────────────────────────
        _bo_col1, _bo_col2 = st.columns(2)
        with _bo_col1:
            _bo_high_on = st.checkbox(
                "🚀 突破新高提醒",
                value=st.session_state.get(f"bo_high_{ticker}", True),
                key=f"bo_high_{ticker}",
                help=f"當 {ticker} 股價創 MFI窗口 根K線新高時推送 Telegram",
            )
        with _bo_col2:
            _bo_low_on = st.checkbox(
                "🔻 跌破新低提醒",
                value=st.session_state.get(f"bo_low_{ticker}", True),
                key=f"bo_low_{ticker}",
                help=f"當 {ticker} 股價創 MFI窗口 根K線新低時推送 Telegram",
            )

        st.subheader(f"📋 {ticker} Telegram 觸發條件配置（可編輯）")

        if tab_idx > 0 and len(selected_tickers) > 1:
            _first_ticker = selected_tickers[0]
            _first_ssk    = _ss_key(_first_ticker)
            if st.button(
                f"📋 複製 {_first_ticker} 條件表 → {ticker}",
                key=f"copy_conds_{ticker}",
            ):
                if _first_ssk in st.session_state:
                    _copied = st.session_state[_first_ssk].copy()
                    st.session_state[_ss_key(ticker)] = _copied
                    _tg_save(_copied, ticker)
                    st.success(f"✅ 已複製 {_first_ticker} 的條件表到 {ticker}")
                    st.rerun()

        _tk_conds = _tg_editor(ticker)

        # 條件表為空時提示用戶
        if _tk_conds.empty or len(_tk_conds) == 0 or _tk_conds["異動標記"].str.strip().replace("", pd.NA).dropna().empty:
            st.warning(
                f"⚠️ **{ticker} 條件表為空**，不會觸發任何 Telegram 推送。\n\n"
                "請先展開下方「🔬 回測分析」執行回測，再用「➕ 一鍵加入」或「🔀 合併」填入條件。",
                icon="📋",
            )

        try:
            # ── Fetch data ────────────────────────────────────────────────────
            stock = yf.Ticker(ticker)
            data  = stock.history(period=selected_period, interval=selected_interval).reset_index()
            if data.empty or len(data) < 5:
                st.warning(f"⚠️ {ticker} 數據不足"); continue

            if "Date" in data.columns:
                data = data.rename(columns={"Date": "Datetime"})
            data["Datetime"] = pd.to_datetime(data["Datetime"]).dt.tz_localize(None)

            # ── Basic columns ─────────────────────────────────────────────────
            hl_range = (data["High"] - data["Low"]).replace(0, np.nan)
            data["Close_N_High"]      = (data["Close"] - data["Low"])   / hl_range
            data["Close_N_Low"]       = (data["High"]  - data["Close"]) / hl_range

            # ── 共用指標計算（含 VIX）──────────────────────────────────────
            data = _enrich_data(
                data, PARAMS, int(MFI_WIN),
                include_vix=True,
                vix_period=selected_period,
                vix_interval=selected_interval,
                vix_ema_fast=int(VIX_EMA_FAST),
                vix_ema_slow=int(VIX_EMA_SLOW),
            )

            # ── 額外的異動幅度欄位（主監控專用）──
            data["前5均價ABS"]         = data["Price Change %"].abs().rolling(5).mean()
            data["📈 股價漲跌幅(%)"]   = ((data["Price Change %"].abs() - data["前5均價ABS"]) /
                                           data["前5均價ABS"].replace(0, np.nan)).round(4) * 100
            data["📊 成交量變動幅(%)"] = ((data["Volume"] - data["前5均量"]) /
                                           data["前5均量"].replace(0, np.nan)).round(4) * 100

            # ── Signals ───────────────────────────────────────────────────────
            data["異動標記"] = compute_all_signals(data, PARAMS)

            # ── K-line patterns + volume tag (shared) ─────────────────────────
            data = _attach_kline_and_vol(data, ticker, selected_period, selected_interval,
                                          BODY_RATIO_TH, SHADOW_RATIO_TH, DOJI_BODY_TH)

            # ── Volume profile ────────────────────────────────────────────────
            dense_areas = calculate_volume_profile(data, int(VP_BINS), int(VP_WINDOW), int(VP_TOP_N))
            latest_close = data["Close"].iloc[-1]
            near_dense = False; near_dense_info = ""
            for a in dense_areas:
                if a["price_low"] <= latest_close <= a["price_high"]:
                    near_dense = True; near_dense_info = f"位於密集區 {a['price_low']:.2f}~{a['price_high']:.2f}"; break
                if abs(latest_close - a["price_center"]) / a["price_center"] * 100 <= 1.0:
                    near_dense = True; near_dense_info = f"接近密集中心 {a['price_center']:.2f}"; break

            # ── Metrics row ───────────────────────────────────────────────────
            try:
                prev_close = stock.info.get("previousClose", data["Close"].iloc[-2])
            except Exception:
                prev_close = data["Close"].iloc[-2]
            cur_price = data["Close"].iloc[-1]
            px_chg = cur_price - prev_close
            px_pct = px_chg / prev_close * 100 if prev_close else 0
            cur_vol = data["Volume"].iloc[-1]; prev_vol = data["Volume"].iloc[-2]
            v_chg = cur_vol - prev_vol; v_pct = v_chg / prev_vol * 100 if prev_vol else 0

            c1, c2, c3, c4, c5 = st.columns(5)
            c1.metric(f"💰 {ticker}", f"${cur_price:.2f}", f"{px_chg:+.2f} ({px_pct:+.2f}%)")
            c2.metric("📊 成交量", f"{cur_vol:,.0f}", f"{v_pct:+.1f}%")
            c3.metric("📈 RSI", f"{data['RSI'].iloc[-1]:.1f}" if pd.notna(data['RSI'].iloc[-1]) else "N/A")
            c4.metric("📉 MACD", f"{data['MACD'].iloc[-1]:.3f}")
            vix_v = data["VIX"].iloc[-1]
            c5.metric("⚡ VIX", f"{vix_v:.1f}" if pd.notna(vix_v) else "N/A")

            if near_dense:
                st.info(f"⚠️ {ticker} 靠近成交密集區：{near_dense_info}")

            # ── Comprehensive interpretation ───────────────────────────────────
            st.subheader("📝 綜合解讀")
            st.write(comprehensive_interp(data, dense_areas, VIX_HIGH_TH, VIX_LOW_TH))

            # ── Chart (4 rows) ─────────────────────────────────────────────────
            st.subheader(f"📈 {ticker} K 線技術圖表")
            plot_d = data.tail(60).copy()
            fig = make_subplots(
                rows=4, cols=1, shared_xaxes=True,
                subplot_titles=("K線 / EMA / VWAP", "成交量 / OBV", "RSI", "MFI"),
                row_heights=[0.45, 0.2, 0.175, 0.175],
                vertical_spacing=0.04,
            )
            fig.add_trace(go.Candlestick(
                x=plot_d["Datetime"], open=plot_d["Open"],
                high=plot_d["High"], low=plot_d["Low"], close=plot_d["Close"],
                name="K線", increasing_line_color="#26a69a", decreasing_line_color="#ef5350",
                increasing_fillcolor="#26a69a", decreasing_fillcolor="#ef5350",
            ), row=1, col=1)
            for col_n, clr, w in [("EMA5","#FF6B6B",1.2), ("EMA10","#4ECDC4",1.2),
                                    ("EMA30","#45B7D1",1.2), ("EMA40","#96CEB4",1.2),
                                    ("VWAP","#BB86FC",2.0)]:
                if col_n in plot_d.columns:
                    fig.add_trace(go.Scatter(x=plot_d["Datetime"], y=plot_d[col_n],
                                             mode="lines", name=col_n,
                                             line=dict(color=clr, width=w)), row=1, col=1)
            if VP_SHOW and dense_areas and len(plot_d) >= 10:
                x0 = plot_d["Datetime"].iloc[-min(50, len(plot_d))]
                x1 = plot_d["Datetime"].iloc[-1]
                for i, a in enumerate(dense_areas):
                    fig.add_shape(type="rect", x0=x0, x1=x1,
                                  y0=a["price_low"], y1=a["price_high"],
                                  fillcolor="rgba(255,165,0,0.12)", line_width=0,
                                  row=1, col=1)
                    fig.add_hline(y=a["price_center"], line_dash="dot", line_color="orange",
                                  annotation_text=f"密集 {a['price_center']:.2f}",
                                  annotation_position="left" if i%2==0 else "right",
                                  row=1, col=1)
            vcols = ["#26a69a" if c>=o else "#ef5350" for c,o in zip(plot_d["Close"], plot_d["Open"])]
            fig.add_trace(go.Bar(x=plot_d["Datetime"], y=plot_d["Volume"],
                                  name="成交量", marker_color=vcols, opacity=0.6), row=2, col=1)
            fig.add_trace(go.Scatter(x=plot_d["Datetime"], y=plot_d["OBV"],
                                      mode="lines", name="OBV",
                                      line=dict(color="#FF8C00", width=1.5),
                                      yaxis="y4"), row=2, col=1)
            fig.add_trace(go.Scatter(x=plot_d["Datetime"], y=plot_d["RSI"],
                                      mode="lines", name="RSI",
                                      line=dict(color="#2196F3", width=1.5)), row=3, col=1)
            for lvl, clr in [(70,"red"),(50,"gray"),(30,"green")]:
                fig.add_hline(y=lvl, line_dash="dash", line_color=clr, line_width=0.7, row=3, col=1)
            fig.add_trace(go.Scatter(x=plot_d["Datetime"], y=plot_d["MFI"],
                                      mode="lines", name="MFI",
                                      line=dict(color="#8B4513", width=1.5)), row=4, col=1)
            for lvl, clr in [(80,"red"),(20,"green")]:
                fig.add_hline(y=lvl, line_dash="dash", line_color=clr, line_width=0.7, row=4, col=1)
            # Signal annotations
            annot_cfg = {
                "📈 新买入信号":  ("▲","#2ecc71","bottom center",1),
                "📉 新卖出信号":  ("▼","#e74c3c","top center",   1),
                "📈 VWAP買入":   ("V↑","#BB86FC","bottom center",1),
                "📉 VWAP賣出":   ("V↓","#BB86FC","top center",   1),
                "📈 OBV突破買入":("O↑","#FF8C00","bottom center",2),
                "📉 OBV突破賣出":("O↓","#FF8C00","top center",   2),
                "📈 MFI牛背離買入":("M↑","#8B4513","bottom center",4),
                "📉 MFI熊背離賣出":("M↓","#8B4513","top center",  4),
                "📈 MACD買入":   ("MC↑","#4ECDC4","bottom center",1),
                "📉 MACD賣出":   ("MC↓","#FF6B6B","top center",   1),
            }
            for i in range(1, len(plot_d)):
                marks = str(plot_d["異動標記"].iloc[i])
                dt, cl = plot_d["Datetime"].iloc[i], plot_d["Close"].iloc[i]
                for sig, (sym, clr, pos, row_n) in annot_cfg.items():
                    if sig in marks:
                        fig.add_trace(go.Scatter(
                            x=[dt], y=[cl], mode="markers+text",
                            marker=dict(symbol="circle", size=9, color=clr),
                            text=[sym], textposition=pos,
                            showlegend=False,
                        ), row=row_n, col=1)

            fig.update_layout(
                height=920, template="plotly_dark", showlegend=True,
                xaxis_rangeslider_visible=False,
                legend=dict(orientation="h", y=-0.04, font=dict(size=11)),
                margin=dict(l=40, r=40, t=60, b=40),
            )
            fig.update_yaxes(title_text="價格",  row=1, col=1)
            fig.update_yaxes(title_text="成交量", row=2, col=1)
            fig.update_yaxes(title_text="RSI",   row=3, col=1, range=[0,100])
            fig.update_yaxes(title_text="MFI",   row=4, col=1, range=[0,100])
            st.plotly_chart(fig, use_container_width=True,
                            key=f"chart_{ticker}_{datetime.now().strftime('%H%M%S')}")

            # ── Signal success rate ────────────────────────────────────────────
            st.subheader(f"📊 {ticker} 各信號勝率")
            data["_next_up"]  = data["Close"].shift(-1) > data["Close"]
            data["_next_dn"]  = data["Close"].shift(-1) < data["Close"]
            sr_rows = []
            all_sigs_found = set()
            for marks in data["異動標記"].dropna():
                for s in str(marks).split(", "):
                    if s.strip():
                        all_sigs_found.add(s.strip())
            for sig in sorted(all_sigs_found):
                sub = data[data["異動標記"].str.contains(sig, na=False, regex=False)]
                # FIX BUG-02: 排除最後一根（shift(-1) NaN）
                sub = sub[sub["Close"].shift(-1).notna()] if len(sub) > 0 else sub
                n   = len(sub)
                if n == 0:
                    continue
                if sig in SELL_SIGNALS:
                    ok = sub["_next_dn"].sum(); dir_ = "做空"
                else:
                    ok = sub["_next_up"].sum(); dir_ = "做多"
                wr = ok / n * 100
                sr_rows.append({"信號":sig,"方向":dir_,"勝率(%)":f"{wr:.1f}%","次數":n})
            if sr_rows:
                sr_df = pd.DataFrame(sr_rows).sort_values("勝率(%)", ascending=False)
                st.dataframe(sr_df, use_container_width=True,
                             column_config={"信號": st.column_config.TextColumn(width="large")})

            # ── History table ─────────────────────────────────────────────────
            st.subheader(f"📋 {ticker} 歷史資料（最近 20 筆）")
            show_cols = [c for c in ["Datetime","Open","Low","High","Close","Volume",
                                      "Price Change %","Volume Change %","MACD","RSI",
                                      "VWAP","MFI","OBV","VIX",
                                      "異動標記","成交量標記","K線形態","單根解讀"] if c in data.columns]
            st.dataframe(data[show_cols].tail(20), height=460, use_container_width=True,
                         column_config={"異動標記":   st.column_config.TextColumn(width="large"),
                                        "單根解讀": st.column_config.TextColumn(width="large")})

            # ── Percentile table ───────────────────────────────────────────────
            with st.expander(f"📊 前 {PERCENTILE_TH}% 數據範圍"):
                rng_rows = []
                for cn in ["Price Change %","Volume Change %","Volume","📈 股價漲跌幅(%)","📊 成交量變動幅(%)"]:
                    if cn not in data.columns: continue
                    s = data[cn].dropna().sort_values(ascending=False)
                    n = max(1, int(len(s) * PERCENTILE_TH / 100))
                    rng_rows += [
                        {"指標":cn,"範圍":"Top",    "最大":f"{s.head(n).max():.2f}","最小":f"{s.head(n).min():.2f}"},
                        {"指標":cn,"範圍":"Bottom", "最大":f"{s.tail(n).max():.2f}","最小":f"{s.tail(n).min():.2f}"},
                    ]
                if rng_rows:
                    st.dataframe(pd.DataFrame(rng_rows), use_container_width=True)

            st.download_button(
                label=f"📥 下載 {ticker} CSV",
                data=data.to_csv(index=False).encode("utf-8-sig"),
                file_name=f"{ticker}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
            )

            # ══════════════════════════════════════════════════════════════════
            #  TELEGRAM / EMAIL ALERTS  (FIX BUG-03: 去重機制)
            # ══════════════════════════════════════════════════════════════════
            K_str  = str(data["異動標記"].iloc[-1])
            K_list = [s.strip() for s in K_str.split(", ") if s.strip()]

            # FIX BUG-03: 生成去重 key（基於最新K線的 Datetime）
            _dedup_key_sig  = _tg_dedup_key(ticker, data["Datetime"].iloc[-1])
            _dedup_key_cond = f"tg_cond_sent_{ticker}_{str(data['Datetime'].iloc[-1])[:19]}"

            # ── 信號 → 方向查找表 ──────────────────────────────────────────
            _live_tg_p1 = _tk_conds
            _sig_dir_map: dict = {}
            for _, _p1_row in _live_tg_p1.iterrows():
                _p1_marks = str(_p1_row.get("異動標記", ""))
                _p1_dir   = str(_p1_row.get("方向", "")).strip()
                if _p1_dir not in ("做多", "做空"):
                    continue
                for _p1_sig in _p1_marks.split(","):
                    _s = _p1_sig.strip()
                    if _s and _s not in _sig_dir_map:
                        _sig_dir_map[_s] = _p1_dir

            # ── Selected-signal push (with dedup) ──────────────────────────
            for sig in selected_signals:
                if sig in K_list and not _tg_already_sent(_dedup_key_sig, sig):
                    _p1_dir_val = _sig_dir_map.get(sig, "")
                    if not _p1_dir_val:
                        _p1_dir_val = "做空" if sig in SELL_SIGNALS else "做多"
                    _p1_dir_label = "🔴 做空（賣出）" if _p1_dir_val == "做空" else "🟢 做多（買入）"

                    _msg = (
                        f"📡 信號提醒\n"
                        f"股票：{ticker} ({selected_interval})\n"
                        f"信號：{sig}\n"
                        f"操作方向：{_p1_dir_label}\n"
                        f"價格：${cur_price:.2f}\n"
                        f"RSI：{data['RSI'].iloc[-1]:.1f}  MACD：{data['MACD'].iloc[-1]:.3f}\n"
                        f"成交量：{_fmt_vol(data['Volume'].iloc[-1])}  "
                        f"({data['成交量標記'].iloc[-1]})"
                    )
                    if st.session_state.get(f"tg_enabled_{ticker}", True):
                        _ok, _err = send_telegram_alert(_msg, ticker=ticker)
                        if _ok:
                            _tg_mark_sent(_dedup_key_sig, sig)
                            st.toast(f"📡 Telegram 已推送：{sig} ({_p1_dir_label})", icon="✅")
                        else:
                            st.warning(f"⚠️ Telegram 推送失敗（{sig}）：{_err}")
                    else:
                        _tg_mark_sent(_dedup_key_sig, sig)  # 即使關閉也標記為已處理
                        st.toast(f"🔕 {sig} 已匹配，Telegram 已關閉", icon="🔕")

            # ── Condition matching (with dedup) ────────────────────────────
            def _safe_str(v) -> str:
                if v is None:
                    return ""
                s = str(v).strip()
                return "" if s.lower() in ("none", "nan", "nat", "") else s

            if "tg_match_mode" not in st.session_state:
                st.session_state["tg_match_mode"] = "first"

            _col_mode, _col_info = st.columns([1, 4])
            with _col_mode:
                _mode_label = (
                    "🔁 模式：**全部比對**（點擊切換為第一個）"
                    if st.session_state["tg_match_mode"] == "all"
                    else "1️⃣ 模式：**第一個匹配**（點擊切換為全部）"
                )
                if st.button(_mode_label, key=f"tg_mode_btn_{ticker}"):
                    st.session_state["tg_match_mode"] = (
                        "first" if st.session_state["tg_match_mode"] == "all" else "all"
                    )
                    st.rerun()
            with _col_info:
                if st.session_state["tg_match_mode"] == "all":
                    st.caption("🔁 **全部比對模式**：逐行掃描條件表，每一個符合的條件都各自發一條 Telegram 訊息。")
                else:
                    st.caption("1️⃣ **第一個匹配模式**：從排名第 1 行開始比對，找到第一個符合的條件就觸發並停止。")

            _scan_all  = (st.session_state["tg_match_mode"] == "all")
            # 直接使用 _tk_conds（來自 _tg_editor 的最新輸出），而非重新讀取 session_state
            # 確保比對邏輯與 UI 上顯示的條件表完全一致
            _live_tg   = _tk_conds
            _cur_vol   = _safe_str(data["成交量標記"].iloc[-1])
            _cur_kline = _safe_str(data["K線形態"].iloc[-1])

            _rsi_val  = float(data["RSI"].iloc[-1]) if pd.notna(data["RSI"].iloc[-1]) else 0.0
            _macd_val = float(data["MACD"].iloc[-1])
            _sig_line = float(data["Signal_Line"].iloc[-1]) if "Signal_Line" in data.columns else 0.0
            _vix_val  = data["VIX"].iloc[-1]
            _vix_str  = f"{_vix_val:.1f}" if pd.notna(_vix_val) else "N/A"
            _near_str = near_dense_info if near_dense else "無密集區靠近"
            _dir_icon = "🟢" if px_pct >= 0 else "🔴"
            _rsi_icon = "🔥" if _rsi_val > 70 else ("🧊" if _rsi_val < 30 else "⚪")
            _vol_icon = "📈" if _cur_vol == "放量" else "📉"

            def _build_tg_msg(rank, backtest_wr, match_no, total_matches,
                             direction="做多", matched_signals=""):
                _header = (
                    f"{'='*28}\n"
                    f"🚨 Telegram 觸發條件匹配"
                    + (f"（第 {match_no}/{total_matches} 條）" if total_matches > 1 else "")
                    + f"\n{'='*28}"
                )
                if direction == "做多":
                    _dir_label = "🟢 做多（買入）"
                elif direction == "做空":
                    _dir_label = "🔴 做空（賣出）"
                else:
                    _dir_label = "未設定"
                _lines = [
                    _header, "",
                    f"股票代號  : {ticker}",
                    f"時間框架  : {selected_interval}",
                    f"觸發時間  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                    "",
                    "--- 價格資訊 ---",
                    f"現價      : ${cur_price:.2f}  {_dir_icon} {px_pct:+.2f}%",
                    f"成交量    : {_fmt_vol(data['Volume'].iloc[-1])}  {_vol_icon} {_cur_vol}  ({v_pct:+.1f}%)",
                    "",
                    "--- 技術指標 ---",
                    f"RSI       : {_rsi_val:.1f}  {_rsi_icon}",
                    f"MACD      : {_macd_val:.4f}  (Signal: {_sig_line:.4f})",
                    f"K線形態   : {_cur_kline}",
                    f"VIX       : {_vix_str}",
                    f"密集區    : {_near_str}",
                    "",
                    "--- 匹配條件 ---",
                    f"條件排名  : #{rank}",
                    f"回測勝率  : {backtest_wr}",
                    f"方向      : {_dir_label}",
                ]
                # 顯示匹配到的條件表信號（不是全部 K_list）
                if matched_signals:
                    _lines.append(f"條件信號  : {matched_signals}")
                _lines += [
                    "",
                    "--- 當前K線全部信號 ---",
                ]
                for _s in K_list[:12]:
                    _lines.append(f"  {_s}")
                if len(K_list) > 12:
                    _lines.append(f"  ... 共 {len(K_list)} 個信號")
                _lines.append(f"{'='*28}")
                return "\n".join(_lines)

            # ── 核心比對迴圈 ──────────────────────────────────────────────
            _matched_list = []

            for _ci, cond_row in _live_tg.iterrows():
                _raw_marks = _safe_str(cond_row.get("異動標記", ""))
                if not _raw_marks:
                    continue
                req = [s.strip() for s in _raw_marks.split(",") if s.strip()]
                if not req:
                    continue

                c_vol   = _safe_str(cond_row.get("成交量標記", ""))
                c_kline = _safe_str(cond_row.get("K線形態", ""))
                vol_ok    = (c_vol   == "") or (c_vol   in ("—", "全部")) or (c_vol   == _cur_vol)
                kline_ok  = (c_kline == "") or (c_kline in ("—", "全部")) or (c_kline == _cur_kline)
                signals_ok = all(s in K_list for s in req)

                if signals_ok and vol_ok and kline_ok:
                    _rank_raw = _safe_str(cond_row.get("排名", ""))
                    _rank     = _rank_raw if _rank_raw else f"#{_ci + 1}"
                    _wr_raw   = _safe_str(cond_row.get("回測勝率", ""))
                    _wr       = _wr_raw if _wr_raw else "N/A"
                    _dir_raw  = _safe_str(cond_row.get("方向", ""))
                    _dir      = _dir_raw if _dir_raw in ("做多", "做空") else ""
                    _matched_list.append((_rank, _wr, _ci, _dir, _raw_marks))

                    if not _scan_all:
                        break

            _total_matched = len(_matched_list)

            if _total_matched > 0:
                # UI 摘要
                if _total_matched == 1:
                    _rank0, _wr0, _, _dir0, _sigs0 = _matched_list[0]
                    _dir0_label = ("🟢 做多" if _dir0 == "做多"
                                   else "🔴 做空" if _dir0 == "做空"
                                   else "未設定")
                    st.info(
                        f"🎯 **條件匹配！** 排名 {_rank0}，回測勝率 {_wr0}，方向 {_dir0_label}\n\n"
                        f"信號：{K_str[:120]}\n成交量：{_cur_vol}  K線：{_cur_kline}",
                    )
                else:
                    _ranks_str = "、".join(r for r, _, __, ___, ____ in _matched_list)
                    st.info(
                        f"🎯 **共匹配 {_total_matched} 條條件！** 排名：{_ranks_str}\n\n"
                        f"信號：{K_str[:120]}\n成交量：{_cur_vol}  K線：{_cur_kline}",
                    )

                # FIX BUG-03: 帶去重的發送邏輯
                _tg_on = st.session_state.get(f"tg_enabled_{ticker}", True)
                _send_ok_count  = 0
                _send_err_msgs  = []

                if not _tg_on:
                    _ranks_muted = "、".join(r for r,_,__,___,____ in _matched_list)
                    st.warning(
                        f"🔕 **Telegram 已關閉**，訊息未發送。匹配條件：排名 {_ranks_muted}。",
                        icon="🔕",
                    )
                    # 即使關閉也標記為已處理，避免開啟後重複發送舊信號
                    for _rank, _, _ci, _, _msigs in _matched_list:
                        # FIX BUG-11/12: 用條件內容 hash 作為去重 key
                        _row = _live_tg.iloc[_ci]
                        _cid = _build_cond_id(
                            _safe_str(_row.get("異動標記", "")),
                            _safe_str(_row.get("成交量標記", "")),
                            _safe_str(_row.get("K線形態", "")),
                        )
                        _tg_mark_sent(_dedup_key_cond, _cid)
                else:
                    for _mn, (_rank, _wr, _ci, _dir, _msigs) in enumerate(_matched_list, start=1):
                        # FIX BUG-11/12: 用條件內容 hash 作為去重 key，而非排名
                        _row = _live_tg.iloc[_ci]
                        _cond_id = _build_cond_id(
                            _safe_str(_row.get("異動標記", "")),
                            _safe_str(_row.get("成交量標記", "")),
                            _safe_str(_row.get("K線形態", "")),
                        )
                        if _tg_already_sent(_dedup_key_cond, _cond_id):
                            continue  # 已發送過，跳過

                        _msg = _build_tg_msg(
                            rank=_rank, backtest_wr=_wr,
                            match_no=_mn, total_matches=_total_matched,
                            direction=_dir, matched_signals=_msigs,
                        )
                        _ok, _err = send_telegram_alert(_msg, ticker=ticker)
                        if _ok:
                            _send_ok_count += 1
                            _tg_mark_sent(_dedup_key_cond, _cond_id)
                            st.toast(
                                f"✅ {ticker} 條件 #{_rank} 匹配，Telegram 已推送"
                                + (f"（{_mn}/{_total_matched}）" if _total_matched > 1 else ""),
                                icon="📨",
                            )
                        else:
                            _send_err_msgs.append(f"排名 {_rank}：{_err}")

                    if _send_ok_count > 0 and not _send_err_msgs:
                        st.success(f"📨 **Telegram 發送成功！** 共 {_send_ok_count} 條訊息", icon="✅")
                    elif _send_ok_count > 0 and _send_err_msgs:
                        st.warning(f"⚠️ 部分發送成功（{_send_ok_count}/{_total_matched}）。\n" + "\n".join(_send_err_msgs))
                    elif _send_err_msgs:
                        st.error(f"❌ **Telegram 全部發送失敗**：\n" + "\n".join(_send_err_msgs), icon="🚨")
                    # 如果 _send_ok_count == 0 且無 err（都已去重跳過），靜默不顯示

            # ── Breakout / Breakdown alerts (with dedup + toggle) ─────────
            _tg_on_bo = st.session_state.get(f"tg_enabled_{ticker}", True)

            if st.session_state.get(f"bo_high_{ticker}", True) and \
               pd.notna(data["High_Max"].iloc[-1]) and data["High"].iloc[-1] >= data["High_Max"].iloc[-1]:
                if not _tg_already_sent(_dedup_key_sig, "breakout_high"):
                    _bo_msg = (
                        f"🚀 突破新高提醒\n股票：{ticker} ({selected_interval})\n"
                        f"現價 ${data['High'].iloc[-1]:.2f} 創 {int(MFI_WIN)} 根K線新高\n"
                        f"成交量：{_fmt_vol(data['Volume'].iloc[-1])}  ({_cur_vol})\n方向：🟢 做多（買入）"
                    )
                    if _tg_on_bo:
                        _ok, _err = send_telegram_alert(_bo_msg, ticker=ticker)
                        if _ok:
                            _tg_mark_sent(_dedup_key_sig, "breakout_high")
                            st.toast(f"🚀 {ticker} 破 {int(MFI_WIN)}K 新高，Telegram 已推送", icon="🚀")
                    else:
                        _tg_mark_sent(_dedup_key_sig, "breakout_high")

            if st.session_state.get(f"bo_low_{ticker}", True) and \
               pd.notna(data["Low_Min"].iloc[-1]) and data["Low"].iloc[-1] <= data["Low_Min"].iloc[-1]:
                if not _tg_already_sent(_dedup_key_sig, "breakdown_low"):
                    _bd_msg = (
                        f"🔻 跌破新低提醒\n股票：{ticker} ({selected_interval})\n"
                        f"現價 ${data['Low'].iloc[-1]:.2f} 創 {int(MFI_WIN)} 根K線新低\n"
                        f"成交量：{_fmt_vol(data['Volume'].iloc[-1])}  ({_cur_vol})\n方向：🔴 做空（賣出）"
                    )
                    if _tg_on_bo:
                        _ok, _err = send_telegram_alert(_bd_msg, ticker=ticker)
                        if _ok:
                            _tg_mark_sent(_dedup_key_sig, "breakdown_low")
                            st.toast(f"🔻 {ticker} 穿 {int(MFI_WIN)}K 新低，Telegram 已推送", icon="🔻")
                    else:
                        _tg_mark_sent(_dedup_key_sig, "breakdown_low")

            # Email (consolidated)
            sig_dict = {
                "macd_buy":       "📈 MACD買入"  in K_list,
                "macd_sell":      "📉 MACD賣出"  in K_list,
                "new_buy":        "📈 新买入信号" in K_list,
                "new_sell":       "📉 新卖出信号" in K_list,
                "vwap_buy":       "📈 VWAP買入"  in K_list,
                "vwap_sell":      "📉 VWAP賣出"  in K_list,
                "obv_buy":        "📈 OBV突破買入" in K_list,
                "obv_sell":       "📉 OBV突破賣出" in K_list,
                "mfi_bull":       "📈 MFI牛背離買入" in K_list,
                "mfi_bear":       "📉 MFI熊背離賣出" in K_list,
                "vix_panic":      "📉 VIX恐慌賣出" in K_list,
                "vix_calm":       "📈 VIX平靜買入" in K_list,
                "bullish_eng":    "📈 看漲吞沒"   in K_list,
                "bearish_eng":    "📉 看跌吞沒"   in K_list,
                "morning_star":   "📈 早晨之星"   in K_list,
                "evening_star":   "📉 黃昏之星"   in K_list,
                "hammer":         "📈 錘頭線"     in K_list,
                "hanging_man":    "📉 上吊線"     in K_list,
            }
            if any(sig_dict.values()):
                send_email_alert(ticker, px_pct, v_pct, sig_dict)



            # ─────────────────────────────────────────────────────────────────
            # 🔬 回測分析（每支股票獨立）
            # ─────────────────────────────────────────────────────────────────
            with st.expander(f"🔬 {ticker} 回測分析（點擊展開）", expanded=False):
                st.header("🔬 回測：三維信號勝率分析")

                st.info(
                    "**三個維度分開計算，找出歷史勝率最高的組合**\n\n"
                    "| 維度 | 說明 |\n"
                    "|------|------|\n"
                    "| 📊 信號組合 | 多個技術指標同時出現（基礎維度）|\n"
                    "| 📦 信號+成交量 | 信號組合 × 放量/縮量 |\n"
                    "| 🕯️ 信號+K線形態 | 信號組合 × K線形態（大陽線、錘子線…）|\n\n"
                    "⚠️ 回測僅供參考，請結合風險管理進行決策。"
                )

                _col_i, _col_p = st.columns(2)
                bt_interval = _col_i.selectbox(
                    "回測K線間隔", ALL_BT_INTERVALS, index=5,
                    key=f"bt_interval_{ticker}",
                )
                _period_cfg  = INTERVAL_PERIOD_MAP.get(bt_interval, INTERVAL_PERIOD_MAP["1d"])
                _period_opts = _period_cfg["periods"]
                _period_def  = _period_cfg["default"]
                _period_idx  = _period_opts.index(_period_def) if _period_def in _period_opts else 0
                bt_period = _col_p.selectbox(
                    "回測時間範圍", _period_opts, index=_period_idx,
                    key=f"bt_period_{ticker}", help=_period_cfg["help"],
                )

                col_a, col_b, col_c = st.columns(3)
                bt_min    = col_a.number_input("最少信號組合數", 2, 3, int(BT_MIN_COMBO), 1, key=f"bt_min_{ticker}")
                bt_max    = col_b.number_input("最多信號組合數", 2, 5, int(BT_MAX_COMBO), 1, key=f"bt_max_{ticker}")
                bt_occ    = col_c.number_input("最少出現次數",   2, 20, int(BT_MIN_OCC),  1, key=f"bt_occ_{ticker}")

                col_d, col_e, _ = st.columns([1, 1, 1])
                bt_wr_thr  = col_d.number_input("高勝率閾值 (%)", 50, 95, 60, 5, key=f"bt_wr_thr_{ticker}")
                bt_pnl_thr = col_e.number_input(
                    "最低平均盈虧 (%)", -10.0, 20.0, 0.0, 0.1,
                    key=f"bt_pnl_thr_{ticker}", format="%.1f",
                )

                if st.button("🚀 開始回測", type="primary", key=f"bt_run_{ticker}"):
                    with st.spinner(f"正在計算 {ticker}（{bt_period} / {bt_interval}）三維勝率…"):
                        try:
                            # 直接呼叫共用回測函數（消除重複代碼）
                            _dsig, _dvol, _dkl, _n_or_err = _run_backtest_for_ticker(
                                tk=ticker, period=bt_period, interval=bt_interval,
                                min_combo=int(bt_min), max_combo=int(bt_max), min_occ=int(bt_occ),
                            )
                            if _dsig is None:
                                st.warning(f"回測失敗：{_n_or_err}"); st.stop()

                            # 額外保存原始回測數據用於逐筆驗證
                            _bt_raw = yf.Ticker(ticker).history(
                                period=bt_period, interval=bt_interval).reset_index()
                            if "Date" in _bt_raw.columns:
                                _bt_raw = _bt_raw.rename(columns={"Date": "Datetime"})
                            _bt_raw["Datetime"] = pd.to_datetime(_bt_raw["Datetime"]).dt.tz_localize(None)
                            _bt_raw = _enrich_data(_bt_raw, PARAMS, int(MFI_WIN))
                            for _nc in ["📈 股價漲跌幅(%)","📊 成交量變動幅(%)","Close_N_High","Close_N_Low"]:
                                _bt_raw[_nc] = np.nan
                            _bt_raw["異動標記"] = compute_all_signals(_bt_raw, PARAMS)
                            _bt_raw = _attach_kline_and_vol(_bt_raw, ticker, bt_period, bt_interval,
                                                             BODY_RATIO_TH, SHADOW_RATIO_TH, DOJI_BODY_TH)
                            st.session_state[f"bt_raw_data_{ticker}"] = _bt_raw

                            df_sig, df_vol, df_kl = _dsig, _dvol, _dkl
                            st.session_state[f"bt_df_sig_{ticker}"]      = df_sig
                            st.session_state[f"bt_df_vol_{ticker}"]      = df_vol
                            st.session_state[f"bt_df_kl_{ticker}"]       = df_kl
                            st.session_state[f"_result_wr_thr_{ticker}"]     = int(bt_wr_thr)
                            st.session_state[f"_result_pnl_thr_{ticker}"]    = float(bt_pnl_thr)
                            st.session_state[f"_result_ticker_{ticker}"]     = ticker
                            st.session_state[f"_result_period_{ticker}"]     = bt_period
                            st.session_state[f"_result_interval_{ticker}"]   = bt_interval
                            st.session_state[f"_result_total_bars_{ticker}"] = len(_bt_raw)

                        except Exception as e:
                            st.error(f"回測失敗：{e}")
                            with st.expander("詳細錯誤"):
                                st.code(traceback.format_exc())

                # ── Results ───────────────────────────────────────────────────
                if f"bt_df_sig_{ticker}" in st.session_state:
                    df_sig  = st.session_state[f"bt_df_sig_{ticker}"]
                    df_vol  = st.session_state[f"bt_df_vol_{ticker}"]
                    df_kl   = st.session_state[f"bt_df_kl_{ticker}"]
                    _wr_thr          = st.session_state.get(f"_result_wr_thr_{ticker}", 60)
                    _pnl_thr         = st.session_state.get(f"_result_pnl_thr_{ticker}", 0.0)
                    _bt_lbl          = st.session_state.get(f"_result_ticker_{ticker}",   ticker)
                    _bt_period_used  = st.session_state.get(f"_result_period_{ticker}",   "?")
                    _bt_interval_used= st.session_state.get(f"_result_interval_{ticker}", "?")
                    _bt_bars_used    = st.session_state.get(f"_result_total_bars_{ticker}",   "?")

                    st.info(
                        f"📊 本次回測：**{_bt_lbl}**　{_bt_period_used} / {_bt_interval_used}　"
                        f"共 **{_bt_bars_used}** 根K線"
                    )

                    def _render_dim(df_dim, title, wr_thr, col_order, dim_key, pnl_thr=0.0):
                        if df_dim.empty:
                            st.warning(f"{title}：無有效組合"); return

                        hi = df_dim[df_dim["勝率(%)"] >= wr_thr].copy()
                        if "平均盈虧(%)" in hi.columns and pnl_thr != 0.0:
                            hi = hi[hi["平均盈虧(%)"] >= pnl_thr]

                        total = len(df_dim)
                        st.success(f"✅ {title}：{total} 組，{len(hi)} 組勝率 ≥ {wr_thr}%")

                        m1, m2, m3 = st.columns(3)
                        m1.metric("最高勝率", f"{df_dim['勝率(%)'].max():.1f}%")
                        m2.metric("平均勝率", f"{df_dim['勝率(%)'].mean():.1f}%")
                        m3.metric(f"≥{wr_thr}%", len(hi))

                        if not hi.empty:
                            disp_cols = [c for c in col_order if c in hi.columns]
                            st.dataframe(hi[disp_cols], use_container_width=True,
                                         height=min(400, 38*(len(hi)+1)+40))

                            if st.button(f"➕ 一鍵加入 {title} 高勝率組合", key=f"add_{dim_key}_{ticker}", type="primary"):
                                _one_click_add(hi, dim_key)

                        # Detail validation
                        with st.expander(f"🔬 {title} 詳細驗證 & CSV"):
                            _source_df = hi if not hi.empty else df_dim
                            _combo_choices = []
                            for _, _r in _source_df.iterrows():
                                _lbl = _r["信號組合"]
                                if _r.get("成交量標記","—") != "—": _lbl += f"  [{_r['成交量標記']}]"
                                if _r.get("K線形態","—") != "—": _lbl += f"  [{_r['K線形態']}]"
                                _lbl += f"  ({_r['勝率(%)']}%  {_r['出現次數']}次)"
                                _combo_choices.append(_lbl)

                            if not _combo_choices:
                                st.info("無可選組合"); return

                            _sel = st.selectbox("選擇組合", _combo_choices, key=f"detail_sel_{dim_key}_{ticker}")
                            _sel_idx = _combo_choices.index(_sel)
                            _sel_row = _source_df.iloc[_sel_idx]

                            _hold_bars = st.number_input("持倉根數", 1, 20, 1, 1, key=f"hold_{dim_key}_{ticker}")

                            # FIX BUG-09: 提示勝率計算差異
                            if _hold_bars > 1:
                                st.caption(
                                    f"⚠️ 勝率表基於「1 根K線後」計算，此處使用 **{_hold_bars} 根**持倉，"
                                    "實際勝率可能不同。"
                                )

                            if st.button(f"📊 展開逐筆記錄", key=f"detail_btn_{dim_key}_{ticker}"):
                                _bt_raw = st.session_state.get(f"bt_raw_data_{ticker}")
                                if _bt_raw is None:
                                    st.warning("請重新點擊「🚀 開始回測」"); return

                                with st.spinner("計算中..."):
                                    _detail = _detailed_backtest(
                                        _bt_raw,
                                        signal_combo  = _sel_row["信號組合"],
                                        vol_filter    = _sel_row.get("成交量標記","—"),
                                        kline_filter  = _sel_row.get("K線形態","—"),
                                        direction     = _sel_row.get("方向","做多"),
                                        hold_bars     = int(_hold_bars),
                                    )

                                if _detail.empty:
                                    st.warning("無完整交易記錄"); return

                                _stats = _summary_stats(_detail)

                                st.subheader("📈 統計摘要")
                                _sc = st.columns(4)
                                _sc[0].metric("實際勝率", f"{_stats.get('實際勝率(%)','N/A')}%")
                                _sc[1].metric("期望值/筆", f"{_stats.get('期望值每筆(%)','N/A')}%")
                                _sc[2].metric("獲利因子", str(_stats.get("獲利因子","N/A")))
                                _sc[3].metric("最大回撤", f"{_stats.get('最大回撤(%)','N/A')}%")

                                _sc2 = st.columns(4)
                                _sc2[0].metric("總筆數", _stats.get("總交易筆數","N/A"))
                                _sc2[1].metric("平均盈利/筆", f"{_stats.get('平均盈利(%)','N/A')}%")
                                _sc2[2].metric("平均虧損/筆", f"{_stats.get('平均虧損(%)','N/A')}%")
                                _sc2[3].metric("盈虧比", str(_stats.get("盈虧比","N/A")))

                                # Cumulative PnL chart
                                _fig_pnl = go.Figure()
                                _fig_pnl.add_trace(go.Scatter(
                                    x=_detail["序號"], y=_detail["累計盈虧(%)"],
                                    mode="lines+markers", name="累計盈虧",
                                    line=dict(color="#2ecc71", width=2),
                                    fill="tozeroy", fillcolor="rgba(46,204,113,0.12)",
                                ))
                                _fig_pnl.add_hline(y=0, line_dash="dash", line_color="gray")
                                _fig_pnl.update_layout(
                                    title="累計盈虧曲線", xaxis_title="交易序號",
                                    yaxis_title="累計盈虧 (%)", template="plotly_dark", height=320,
                                )
                                st.plotly_chart(_fig_pnl, use_container_width=True, key=f"pnl_{dim_key}_{ticker}")

                                # Detail table
                                st.subheader("📋 逐筆交易記錄")
                                _disp_cols = [c for c in [
                                    "序號","信號時間","進場時間","出場時間","持倉根數",
                                    "進場價","出場價","方向","盈虧(%)","勝負",
                                    "最大順勢(%)","最大逆勢(%)","累計盈虧(%)",
                                    "信號RSI","信號MACD","成交量標記","K線形態",
                                    "連勝數","連敗數","觸發信號",
                                ] if c in _detail.columns]
                                st.dataframe(_detail[_disp_cols], use_container_width=True,
                                             height=min(600, 35*(len(_detail)+1)+40))

                                # CSV export
                                import io, csv as _csv
                                _buf = io.StringIO()
                                _detail.to_csv(_buf, index=False)
                                st.download_button(
                                    "📥 下載逐筆交易 CSV",
                                    data=_buf.getvalue().encode("utf-8-sig"),
                                    file_name=f"{ticker}_detail_{datetime.now().strftime('%Y%m%d')}.csv",
                                    mime="text/csv",
                                )

                        # Full table
                        with st.expander(f"📊 {title} 全部 {total} 組"):
                            disp_all = [c for c in col_order if c in df_dim.columns]
                            st.dataframe(df_dim[disp_all], use_container_width=True, height=420)

                    # One-click add helper
                    def _one_click_add(hi_df, dim_key):
                        existing = st.session_state.get(_ss_key(ticker), pd.DataFrame()).copy()
                        if "回測勝率" not in existing.columns:
                            existing["回測勝率"] = "N/A"
                        new_rows = []
                        for _, row in hi_df.iterrows():
                            new_rows.append({
                                "排名": "", "異動標記": row["信號組合"].replace(" + ", ", "),
                                "成交量標記": row.get("成交量標記","—"),
                                "K線形態": row.get("K線形態","—"),
                                "回測勝率": f"{row['勝率(%)']:.1f}%",
                                "方向": row.get("方向", "做多"),
                            })
                        combined = pd.concat([existing, pd.DataFrame(new_rows)], ignore_index=True)
                        combined = combined.drop_duplicates(subset=["異動標記","成交量標記","K線形態"], keep="last")
                        def _parse(v):
                            try: return float(str(v).replace("%","").strip())
                            except: return 0.0
                        combined["_n"] = combined["回測勝率"].apply(_parse)
                        combined = combined.sort_values("_n", ascending=False).drop(columns=["_n"]).reset_index(drop=True)
                        combined["排名"] = [str(i+1) for i in range(len(combined))]
                        _saved = combined[_TG_COLS]
                        st.session_state[_ss_key(ticker)] = _saved
                        _tg_save(_saved, ticker)
                        st.success(f"✅ 已追加到 Telegram 條件表（共 {len(_saved)} 條）")

                    # Render 3 dimensions
                    dim_tab1, dim_tab2, dim_tab3 = st.tabs([
                        "📊 信號組合", "📦 信號+成交量", "🕯️ 信號+K線形態"])

                    COLS_SIG = ["信號組合","信號數量","勝率(%)","平均盈虧(%)","出現次數","方向"]
                    COLS_VOL = ["信號組合","成交量標記","信號數量","勝率(%)","平均盈虧(%)","出現次數","方向"]
                    COLS_KL  = ["信號組合","K線形態","信號數量","勝率(%)","平均盈虧(%)","出現次數","方向"]

                    with dim_tab1:
                        _render_dim(df_sig, f"{_bt_lbl} 信號組合", _wr_thr, COLS_SIG, "sig", pnl_thr=_pnl_thr)
                    with dim_tab2:
                        _render_dim(df_vol, f"{_bt_lbl} 信號+成交量", _wr_thr, COLS_VOL, "vol", pnl_thr=_pnl_thr)
                    with dim_tab3:
                        _render_dim(df_kl, f"{_bt_lbl} 信號+K線形態", _wr_thr, COLS_KL, "kl", pnl_thr=_pnl_thr)

                    # Best combo summary
                    st.markdown("---")
                    st.subheader("💡 三維綜合最佳建議")
                    all_hi = []
                    for df_d, lbl in [(df_sig,"信號組合"),(df_vol,"信號+成交量"),(df_kl,"信號+K線形態")]:
                        hi_d = df_d[df_d["勝率(%)"] >= _wr_thr] if not df_d.empty else pd.DataFrame()
                        if not hi_d.empty and "平均盈虧(%)" in hi_d.columns and _pnl_thr != 0.0:
                            hi_d = hi_d[hi_d["平均盈虧(%)"] >= _pnl_thr]
                        if not hi_d.empty:
                            best_row = hi_d.iloc[0].copy(); best_row["_dim"] = lbl
                            all_hi.append(best_row)

                    if all_hi:
                        overall_best = max(all_hi, key=lambda r: r["勝率(%)"])
                        st.success(
                            f"🏆 **全局最佳**（{overall_best['_dim']}）\n\n"
                            f"📊 **{overall_best['信號組合']}**\n\n"
                            f"勝率：**{overall_best['勝率(%)']}%** | "
                            f"平均盈虧：**{overall_best.get('平均盈虧(%)','N/A')}%** | "
                            f"次數：**{overall_best['出現次數']}** | "
                            f"方向：**{overall_best['方向']}**\n\n"
                            "⚠️ 回測基於歷史數據，未來不保證相同表現。"
                        )
                    else:
                        st.info(f"三個維度均無 ≥ {_wr_thr}% 勝率組合。")

                    # Merge button
                    st.markdown("---")
                    st.subheader("🔀 一鍵合併三維度 → Telegram 條件")
                    _merge_thr = st.number_input("納入勝率閾值 (%)", 0, 100, _wr_thr, 5, key=f"merge_thr_{ticker}")

                    _preview_rows = []
                    for _df_m in [df_sig, df_vol, df_kl]:
                        for _, r in _df_m.iterrows():
                            if r["勝率(%)"] >= _merge_thr:
                                _preview_rows.append({
                                    "異動標記": r["信號組合"].replace(" + ", ", "),
                                    "成交量標記": r.get("成交量標記","—"),
                                    "K線形態": r.get("K線形態","—"),
                                    "回測勝率": f"{r['勝率(%)']:.1f}%",
                                    "方向": r.get("方向","做多"),
                                    "_wr": r["勝率(%)"],
                                })
                    if _preview_rows:
                        _preview_df = (pd.DataFrame(_preview_rows)
                            .sort_values("_wr", ascending=False)
                            .drop_duplicates(subset=["異動標記","成交量標記","K線形態"], keep="first")
                            .drop(columns=["_wr"]).reset_index(drop=True))
                        _preview_df["排名"] = [str(i+1) for i in range(len(_preview_df))]
                        _preview_df = _preview_df[_TG_COLS]
                    else:
                        _preview_df = pd.DataFrame()

                    _n_preview = len(_preview_df)
                    st.metric("合併後條數", f"{_n_preview} 條")

                    if _n_preview > 0 and st.button(
                        f"🔀 確認合併（共 {_n_preview} 條）", type="primary", key=f"merge_btn_{ticker}"):
                        st.session_state[_ss_key(ticker)] = _preview_df
                        _tg_save(_preview_df, ticker)
                        st.success(f"🎯 **覆蓋完成！** {_n_preview} 條條件。")
                        st.balloons()

        except Exception as e:
            st.error(f"⚠️ {ticker} 發生錯誤：{e}")
            with st.expander("詳細錯誤"):
                st.code(traceback.format_exc())

# ── 回測分析 Tab placeholder ──────────────────────────────────────────────────
with tabs[-1]:
    pass

# ═════════════════════════════════════════════════════════════════════════════
#  AUTO REFRESH（使用 @st.fragment 實現非阻塞自動刷新）
# ═════════════════════════════════════════════════════════════════════════════
st.divider()


@st.fragment
def _auto_refresh_fragment():
    """
    獨立 fragment：在背景 sleep 後觸發整頁 rerun。

    為什麼原來的方式不工作：
    - Streamlit 腳本執行完畢後進入「等待用戶操作」狀態
    - 沒有 sleep/timer，腳本不會自己再次執行
    - 必須有一個「活著的」元素去觸發 rerun

    @st.fragment 解法：
    - fragment 是獨立於主腳本的可重新執行區塊
    - time.sleep() 在 fragment 中不會凍結整個頁面
    - sleep 結束後呼叫 st.rerun() 刷新整頁
    """
    if not st.session_state.get("app_running", False):
        st.caption("⏸️ 監控已停止，自動刷新暫停")
        return

    _remaining = max(1, REFRESH_INTERVAL)
    st.caption(f"⏳ 下次自動刷新：{_remaining} 秒後…")

    time.sleep(_remaining)

    st.session_state["last_refresh"] = time.time()
    st.rerun()


_auto_refresh_fragment()
