# app.py
import streamlit as st
from PIL import Image
import io, os, hashlib, base64, time, uuid
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from datetime import datetime
import textwrap

# ---------------------------
# Page config
# ---------------------------
st.set_page_config(page_title="CyberSafe — Awareness & Tools", layout="wide")
st.title("🔒 CyberSafe — Protection + Education + Awareness")

# ---------------------------
# Utilities & session state
# ---------------------------
if "fernet_key" not in st.session_state:
    st.session_state["fernet_key"] = Fernet.generate_key()

def compute_md5_sha256(file_bytes: bytes):
    md5 = hashlib.md5(file_bytes).hexdigest()
    sha256 = hashlib.sha256(file_bytes).hexdigest()
    return md5, sha256

def save_temp_file(file_bytes: bytes, filename: str):
    tmpdir = "tmp_shared"
    os.makedirs(tmpdir, exist_ok=True)
    path = os.path.join(tmpdir, filename)
    with open(path, "wb") as f:
        f.write(file_bytes)
    return path

# ---------------------------
# Sidebar navigation
# ---------------------------
menu = st.sidebar.selectbox("Modules", [
    "Home",
    "Threat Detection",
    "Data Protection Tools",
    "Awareness & Quizzes",
    "Reporting & Support",
    "Dashboard"
])

# ---------------------------
# HOME
# ---------------------------
if menu == "Home":
    st.header("Welcome to CyberSafe (Prototype)")
    st.markdown("""
    This is a local prototype built with Streamlit. Use the sidebar to explore:
    - Threat detection (URL heuristics, simple phishing detector, file hash)
    - Data protection (Fernet AES, RSA, steganography, hashing)
    - Learning and quizzes
    - Reporting & dashboard
    """)
    st.info("For production, integrate APIs (VirusTotal, Google Safe Browsing, HaveIBeenPwned) and add user authentication + encrypted storage.")

# ---------------------------
# THREAT DETECTION
# ---------------------------
if menu == "Threat Detection":
    st.header("🛡 Threat Detection Tools")

    st.subheader("Suspicious link & website safety checker")
    st.markdown("Enter a URL and run heuristics. Replace with Google Safe Browsing integration for production.")
    url = st.text_input("Enter URL (include https://)")
    if st.button("Check URL"):
        if not url:
            st.error("Enter a URL.")
        else:
            issues = []
            if url.lower().startswith("http://"):
                issues.append("Not using HTTPS.")
            if url.count("-") > 3 or "%20" in url:
                issues.append("Suspicious characters or many hyphens.")
            if len(url) > 120:
                issues.append("Unusually long URL.")
            if issues:
                st.warning("Heuristics flagged possible issues:")
                for i in issues: st.write("- " + i)
            else:
                st.success("No simple heuristics flagged the URL. (Not a guarantee of safety.)")

    st.markdown("---")
    st.subheader("Email / Phishing message detector (heuristic)")
    st.markdown("Paste message content to get heuristic indicators.")
    email_text = st.text_area("Email / Message body")
    if st.button("Analyze Message for Phishing"):
        if not email_text.strip():
            st.error("Paste message text.")
        else:
            score = 0
            reasons = []
            text_low = email_text.lower()
            suspicious_keywords = ["verify your account", "click here", "urgent", "password", "bank", "wire", "login", "update your", "suspend"]
            for kw in suspicious_keywords:
                if kw in text_low:
                    score += 1
                    reasons.append(f"Contains '{kw}'")
            if score >= 2:
                st.error(f"Phishing-like indicators found (score {score}). Reasons:")
                for r in reasons: st.write("- " + r)
            else:
                st.success("No major phishing keywords found. Still check sender & links.")

    st.markdown("---")
    st.subheader("Malware file scanner (hash only in prototype)")
    uploaded_file = st.file_uploader("Upload file to inspect (we compute hashes only)", type=None)
    if uploaded_file:
        b = uploaded_file.getvalue()
        md5, sha256 = compute_md5_sha256(b)
        st.text(f"Filename: {uploaded_file.name}")
        st.text(f"MD5: {md5}")
        st.text(f"SHA256: {sha256}")
        st.info("To fully scan, send the hash/file to VirusTotal or similar (requires API key).")

# ---------------------------
# DATA PROTECTION TOOLS
# ---------------------------
if menu == "Data Protection Tools":
    st.header("🔐 Data Protection Tools")

    st.subheader("Text encryption & decryption (Fernet symmetric AES)")
    with st.expander("Fernet key (do NOT share in production)"):
        st.code(st.session_state["fernet_key"].decode())
        if st.button("Regenerate Fernet Key"):
            st.session_state["fernet_key"] = Fernet.generate_key()
            st.experimental_rerun()

    col1, col2 = st.columns(2)
    with col1:
        plain = st.text_area("Plaintext to encrypt")
        if st.button("Encrypt Text"):
            if not plain:
                st.error("Enter plaintext.")
            else:
                f = Fernet(st.session_state["fernet_key"])
                token = f.encrypt(plain.encode()).decode()
                st.success("Encrypted (base64)")
                st.code(token)
                st.download_button("Download encrypted text", token, file_name="encrypted.txt")
    with col2:
        token_in = st.text_area("Ciphertext to decrypt")
        if st.button("Decrypt Text"):
            try:
                f = Fernet(st.session_state["fernet_key"])
                pt = f.decrypt(token_in.encode()).decode()
                st.success("Decrypted plaintext:")
                st.code(pt)
            except Exception as e:
                st.error("Decryption failed. Check key and ciphertext.")

    st.markdown("---")
    st.subheader("RSA keypair (2048) + encrypt/decrypt")
    if "rsa_key" not in st.session_state:
        st.session_state["rsa_key"] = None
    if st.button("Generate RSA Keypair (2048)"):
        key = RSA.generate(2048)
        st.session_state["rsa_key"] = {"priv": key.export_key(), "pub": key.publickey().export_key()}
        st.success("RSA keypair generated.")
    if st.session_state.get("rsa_key"):
        st.markdown("Public key:")
        st.code(st.session_state["rsa_key"]["pub"].decode())
        st.markdown("Private key (keep secret):")
        st.code(st.session_state["rsa_key"]["priv"].decode())

    rsa_plain = st.text_input("Text to RSA-encrypt")
    if st.button("RSA Encrypt"):
        if not st.session_state.get("rsa_key"):
            st.error("Generate RSA keypair first.")
        else:
            pub = RSA.import_key(st.session_state["rsa_key"]["pub"])
            cipher = PKCS1_OAEP.new(pub)
            ct = cipher.encrypt(rsa_plain.encode())
            st.code(base64.b64encode(ct).decode())

    rsa_ct = st.text_input("RSA ciphertext (base64) to decrypt")
    if st.button("RSA Decrypt"):
        if not st.session_state.get("rsa_key"):
            st.error("Generate RSA keypair first.")
        else:
            try:
                priv = RSA.import_key(st.session_state["rsa_key"]["priv"])
                cipher = PKCS1_OAEP.new(priv)
                pt = cipher.decrypt(base64.b64decode(rsa_ct))
                st.success(pt.decode())
            except Exception as e:
                st.error("Decryption failed: " + str(e))

    st.markdown("---")
    st.subheader("Image steganography (LSB — simple)")
    steg_col1, steg_col2 = st.columns(2)
    with steg_col1:
        steg_image = st.file_uploader("Upload an image to hide text (PNG preferred)", type=["png","jpg","jpeg"])
        steg_text = st.text_area("Text to hide")
        if st.button("Embed text into image"):
            if not steg_image or not steg_text:
                st.error("Provide image and text.")
            else:
                img = Image.open(steg_image).convert("RGBA")
                pixels = img.getdata()
                message = steg_text + chr(0)
                bmsg = ''.join([format(ord(c), "08b") for c in message])
                new_pixels = []
                idx = 0
                for p in pixels:
                    if idx < len(bmsg):
                        r,g,b,a = p
                        new_b = (b & ~1) | int(bmsg[idx])
                        new_pixels.append((r,g,new_b,a))
                        idx += 1
                    else:
                        new_pixels.append(p)
                img.putdata(new_pixels)
                out = io.BytesIO()
                img.save(out, format="PNG")
                out.seek(0)
                st.success("Text embedded. Download the new image.")
                st.download_button("Download stego image", out, file_name="stego.png", mime="image/png")
    with steg_col2:
        steg_img2 = st.file_uploader("Upload stego image to extract text", type=["png","jpg","jpeg"], key="extract")
        if st.button("Extract hidden text"):
            if not steg_img2:
                st.error("Upload an image first.")
            else:
                img = Image.open(steg_img2).convert("RGBA")
                pixels = img.getdata()
                bits = []
                for p in pixels:
                    bits.append(str(p[2] & 1))
                chars = []
                for i in range(0, len(bits), 8):
                    byte = bits[i:i+8]
                    if len(byte) < 8:
                        break
                    c = chr(int(''.join(byte), 2))
                    if c == chr(0):
                        break
                    chars.append(c)
                extracted = ''.join(chars)
                if extracted:
                    st.success("Extracted text:")
                    st.code(extracted)
                else:
                    st.info("No hidden text found with this method.")

    st.markdown("---")
    st.subheader("File hash generator & temporary share (prototype)")
    f = st.file_uploader("Upload file to hash / share", type=None, key="hashfile")
    if f:
        b = f.getvalue()
        md5, sha256 = compute_md5_sha256(b)
        st.write("MD5:", md5)
        st.write("SHA256:", sha256)
        st.download_button("Download hash text", f"MD5: {md5}\nSHA256: {sha256}", file_name="hashes.txt")
    share = st.file_uploader("Upload file to create a temporary local share", key="share")
    if share:
        b = share.getvalue()
        identifier = str(uuid.uuid4())
        filename = f"{identifier}_{share.name}"
        path = save_temp_file(b, filename)
        expiry_ts = time.time() + 60*60
        st.session_state.setdefault("shared_files", {})[identifier] = {"path": path, "expires": expiry_ts, "name": share.name}
        st.write("Temporary share ID:", identifier)
        st.download_button("Download shared file (local)", open(path,"rb").read(), file_name=share.name)

# ---------------------------
# AWARENESS & QUIZZES
# ---------------------------
if menu == "Awareness & Quizzes":
    st.header("🎓 Awareness & Learning")
    lessons = {
        "Phishing 101": "Phishing is when attackers trick you into revealing sensitive information...",
        "Password Hygiene": "Use a password manager, enable multi-factor authentication (2FA)...",
        "Safe Browsing Tips": "Keep browser updated, avoid suspicious downloads, prefer HTTPS..."
    }
    sel = st.selectbox("Choose lesson", list(lessons.keys()))
    st.write(lessons[sel])

    st.markdown("---")
    st.subheader("Interactive Quiz")
    if "quiz_score" not in st.session_state:
        st.session_state["quiz_score"] = None
    q1 = st.radio("Q1: Best way to store many strong passwords?", ["Text file", "One password", "Password manager", "Write on paper"])
    q2 = st.radio("Q2: 2FA stands for?", ["Two-Factor Authentication", "Two-Federation Access", "Two-File Agreement", "None"])
    q3 = st.radio("Q3: Unexpected bank email with attachment — you should:", ["Open it", "Reply", "Contact bank via official channels", "Forward"])
    if st.button("Submit Quiz"):
        score = 0
        if q1 == "Password manager": score += 1
        if q2 == "Two-Factor Authentication": score += 1
        if q3 == "Contact bank via official channels": score += 1
        st.session_state["quiz_score"] = score
        st.success(f"You scored {score}/3")
        if score == 3:
            st.balloons()
            st.write("🏅 Badge: CyberAware Beginner")

# ---------------------------
# REPORTING & SUPPORT
# ---------------------------
if menu == "Reporting & Support":
    st.header("📫 Reporting & Support")
    st.markdown("- Official Indian cybercrime portal: https://cybercrime.gov.in")
    st.subheader("Create local report (for your records)")
    rep_item = st.text_input("Suspicious URL / email")
    rep_desc = st.text_area("Description")
    if st.button("Create local report"):
        if not rep_item or not rep_desc:
            st.error("Provide both.")
        else:
            reports_dir = "reports"
            os.makedirs(reports_dir, exist_ok=True)
            report_id = str(int(time.time()))
            content = f"REPORT ID: {report_id}\nTIME: {datetime.now()}\nITEM: {rep_item}\nDESC:\n{rep_desc}\n"
            path = os.path.join(reports_dir, f"report_{report_id}.txt")
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
            st.success(f"Local report saved: {path}")
            st.info("For legal action, use the official portal or local police.")

# ---------------------------
# DASHBOARD
# ---------------------------
if menu == "Dashboard":
    st.header("📊 Dashboard")
    score = 50
    if st.session_state.get("quiz_score") is not None:
        score += st.session_state["quiz_score"] * 5
    if st.session_state.get("rsa_key"):
        score += 10
    if st.session_state.get("shared_files"):
        score -= 5
    score = max(0, min(100, score))
    st.metric("Cyber Safety Score", f"{score}/100")
    st.subheader("Tips")
    if score < 60:
        st.write("- Enable 2FA on critical accounts.")
        st.write("- Use a password manager.")
    else:
        st.write("- Good job. Consider periodic security audits.")

st.markdown("---")
st.caption("Prototype for learning. Not a replacement for professional cybersecurity services.")