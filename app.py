import streamlit as st
import boto3
from botocore.exceptions import NoCredentialsError, ClientError
from cryptography.fernet import Fernet
import os
import uuid
import time
from datetime import datetime, timedelta

# --------------------------------------------------------------------------------
# STREAMLIT CONFIG
# --------------------------------------------------------------------------------
st.set_page_config(page_title="CloudBridge", layout="wide")

# --------------------------------------------------------------------------------
# CONFIGURATION
# --------------------------------------------------------------------------------
# Provide your AWS credentials here (NOT recommended for production; use env vars or IAM roles)
AWS_ACCESS_KEY_ID = "AKIA2Q6Y4SIZMZKYELD6	"
AWS_SECRET_ACCESS_KEY = "mFTswia6VLmBATBPXvnN4w5XuobyUeDDLtkX9jX7"

# S3 details
S3_BUCKET = "sumanthappliedproject"
S3_REGION = "us-east-2"

# For encryption, use a 32-byte URL-safe base64-encoded key.
# WARNING: In production, store this key securely and persist it!
FERNET_KEY = os.getenv("FERNET_KEY")
if FERNET_KEY is None:
    FERNET_KEY = Fernet.generate_key()
fernet = Fernet(FERNET_KEY)

# Initialize the S3 client with explicit credentials
s3 = boto3.client(
    's3',
    region_name=S3_REGION,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY
)

# --------------------------------------------------------------------------------
# HELPER FUNCTIONS
# --------------------------------------------------------------------------------
def encrypt_file(file_bytes):
    """Encrypt file bytes using Fernet symmetric encryption."""
    return fernet.encrypt(file_bytes)

def upload_file_to_s3(file_bytes, filename, expiration_days=0):
    """
    Upload encrypted file bytes to S3 with optional expiration metadata.
    Returns the S3 key if successful.
    """
    try:
        s3_key = f"uploads/{uuid.uuid4()}_{filename}"
        metadata = {}
        if expiration_days > 0:
            expire_date = (datetime.utcnow() + timedelta(days=expiration_days)).isoformat()
            metadata['expiration_date'] = expire_date

        s3.put_object(
            Bucket=S3_BUCKET,
            Key=s3_key,
            Body=file_bytes,
            ServerSideEncryption='AES256',
            Metadata=metadata
        )
        return s3_key

    except NoCredentialsError:
        st.error("AWS credentials not found. Please configure your AWS credentials.")
        return None
    except ClientError as e:
        st.error(f"Failed to upload to S3: {e}")
        return None

def generate_presigned_url(s3_key, expiration=3600):
    """Generate a presigned URL for the uploaded file with a default expiration of 1 hour."""
    try:
        url = s3.generate_presigned_url(
            ClientMethod='get_object',
            Params={'Bucket': S3_BUCKET, 'Key': s3_key},
            ExpiresIn=expiration
        )
        return url
    except ClientError as e:
        st.error(f"Failed to generate presigned URL: {e}")
        return None

# --------------------------------------------------------------------------------
# UI STYLING & SIDEBAR
# --------------------------------------------------------------------------------
st.markdown(
    """
    <style>
    .main {
        background-color: #f9f9f9;
        padding: 2rem;
    }
    .sidebar .sidebar-content {
        background-color: #f0f0f0;
    }
    .upload-section {
        background-color: #fff;
        padding: 1rem;
        border-radius: 10px;
        box-shadow: 0px 2px 5px rgba(0,0,0,0.1);
    }
    </style>
    """,
    unsafe_allow_html=True
)

# Sidebar Navigation
st.sidebar.title("Navigation")
page = st.sidebar.selectbox("Go to", ["Upload & Encrypt", "Download from S3 URI"])

st.sidebar.header("CloudBridge Info")
st.sidebar.info(
    """
    **CloudBridge** is a secure file sharing solution leveraging AWS S3 for storage,
    Fernet encryption, and optional file expiration.
    """
)

# --------------------------------------------------------------------------------
# PAGE 1: UPLOAD & ENCRYPT WITH EXPIRATION
# --------------------------------------------------------------------------------
def page_upload_encrypt():
    st.title("CloudBridge: Secure File Sharing Platform")
    st.markdown("#### Securely upload, encrypt, and share your files with ease.")

    with st.expander("About CloudBridge"):
        st.markdown(
            """
            Upload a file to see it encrypted and stored in an S3 bucket.
            You can also specify an expiration time (in days), after which the file
            should be considered expired. A presigned URL will be generated for sharing.
            """
        )

    col1, col2 = st.columns([2, 1])

    with col1:
        st.markdown('<div class="upload-section">', unsafe_allow_html=True)
        st.header("File Upload & Encryption")
        with st.form(key="upload_form"):
            uploaded_file = st.file_uploader(
                "Choose a file to upload",
                type=["txt", "pdf", "png", "jpg", "jpeg", "docx", "xlsx", "csv"]
            )
            expiration_days = st.number_input(
                "Expire after (days, 0 for no expiration)",
                min_value=0, value=0, step=1
            )
            submit_button = st.form_submit_button(label="Upload and Encrypt")
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.header("Upload Status")
        status_placeholder = st.empty()
        progress_bar = st.progress(0)

    if uploaded_file and submit_button:
        file_details = {"filename": uploaded_file.name, "filetype": uploaded_file.type}
        st.write("**File Details:**", file_details)

        file_bytes = uploaded_file.read()

        status_placeholder.info("Encrypting your file...")
        progress_bar.progress(25)
        time.sleep(1)
        encrypted_bytes = encrypt_file(file_bytes)

        status_placeholder.info("Uploading encrypted file to S3...")
        progress_bar.progress(50)
        time.sleep(1)
        s3_key = upload_file_to_s3(encrypted_bytes, uploaded_file.name, expiration_days)

        if s3_key:
            progress_bar.progress(75)
            status_placeholder.info("Generating secure shareable link...")
            time.sleep(1)
            shareable_link = generate_presigned_url(s3_key)

            if shareable_link:
                progress_bar.progress(100)
                status_placeholder.success("File successfully uploaded to S3!")
                # Display the presigned URL and S3 URI
                st.markdown("### Shareable Link (valid for 1 hour):")
                st.code(shareable_link)
                s3_uri = f"s3://{S3_BUCKET}/{s3_key}"
                st.markdown("### S3 URI:")
                st.code(s3_uri)

                if expiration_days > 0:
                    expire_date = (datetime.utcnow() + timedelta(days=expiration_days)).strftime("%Y-%m-%d %H:%M:%S UTC")
                    st.markdown(f"**Expires on:** {expire_date}")
            else:
                status_placeholder.error("Error generating shareable link.")
        else:
            status_placeholder.error("File upload failed.")

    st.markdown("---")
    st.markdown("© 2025 CloudBridge | Secure File Sharing Platform")

# --------------------------------------------------------------------------------
# PAGE 2: DOWNLOAD FROM S3 URI
# --------------------------------------------------------------------------------
def page_download_link():
    st.title("Download a File from an S3 URI")
    st.markdown("Enter a valid S3 URI (e.g., `s3://sumanthappliedproject/uploads/your_file.ext`) to fetch the file directly from S3.")

    with st.form("download_form"):
        s3_uri = st.text_input("Paste your S3 URI here:")
        download_button = st.form_submit_button("Download File")

    if download_button and s3_uri:
        if not s3_uri.startswith("s3://"):
            st.error("Invalid S3 URI. It should start with 's3://'.")
        else:
            try:
                # Parse the S3 URI into bucket and key
                uri_parts = s3_uri[5:].split("/", 1)
                bucket_name, key = uri_parts[0], uri_parts[1]
            except Exception:
                st.error("Invalid S3 URI format. It should be in the format: s3://bucket/key")
                return

            with st.spinner("Fetching file from S3..."):
                try:
                    response = s3.get_object(Bucket=bucket_name, Key=key)
                    file_content = response["Body"].read()
                    filename = key.split("/")[-1]
                    st.success("File fetched successfully!")
                    st.download_button(
                        label="Click to Save File",
                        data=file_content,
                        file_name=filename,
                        mime=response.get("ContentType", "application/octet-stream")
                    )
                except Exception as e:
                    st.error(f"Error fetching file: {e}")

    st.markdown("---")
    st.markdown("© 2025 CloudBridge | Secure File Sharing Platform")

# --------------------------------------------------------------------------------
# MAIN LOGIC: RENDER THE SELECTED PAGE
# --------------------------------------------------------------------------------
if page == "Upload & Encrypt":
    page_upload_encrypt()
else:
    page_download_link()
