import os
import re
from dotenv import load_dotenv
load_dotenv()

API_KEY = os.getenv('API_KEY')
LOG_FILE_PATH = os.getenv('LOG_FILE_PATH')
FILE_PATH_PATTERN = re.compile(r'(?i)^.*\.(txt|json|xml)$')
BASE_URL = os.getenv('API_BASE_URL')
IP_ADDRESS_ENDPOINT = os.getenv('IP_ADDRESS_ENDPOINT')
URL_ADDRESS_ENDPOINT = os.getenv('URL_ADDRESS_ENDPOINT')
IP_PATTERN = re.compile(
    r'((?:\d{1,3}\.){3}\d{1,3})'
)
URL_PATTERN = re.compile(
    r'https?://([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:[0-9]+)?(/[^\s]*)?(\?[^\s]*)?$'
)
