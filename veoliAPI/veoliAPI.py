import os
import aiohttp
import base64
import hashlib
import logging
from urllib.parse import urlencode, urlparse, parse_qs

class VeoliAPI:
    LOGIN_URL = "https://login.eau.veolia.fr"
    BASE_URL = "https://www.eau.veolia.fr"
    CLIENT_ID = "tHBtoPOLiI2NSbCzqYz6pydZ1Xil0Bw2"
    REDIRECT_URI = "https://www.eau.veolia.fr/callback"

    def __init__(self, username, password):
        self.username = username
        self.password = password
        self.session = aiohttp.ClientSession()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.access_token = None
        self.code = None
        self.verifier = None
        self.id_abonnement = None
        self.numero_pds = None
        self.date_debut_abonnement = None

        self.api_flow = {
            "/authorize": {
                "method": "GET",
                "params": self._get_authorize_params,
                "success_status": 302,
            },
            "/u/login/identifier": {
                "method": "POST",
                "params": lambda state: {
                    "username": self.username,
                    "js-available": "true",
                    "webauthn-available": "true",
                    "is-brave": "false",
                    "webauthn-platform-available": "true",
                    "action": "default",
                    "state": state,
                },
                "success_status": 302,
            },
            "/u/login/password": {
                "method": "POST",
                "params": lambda state: {
                    "username": self.username,
                    "password": self.password,
                    "action": "default",
                    "state": state,
                },
                "success_status": 302,
            },
            "/authorize/resume": {
                "method": "GET",
                "params": None,
                "success_status": 302,
            },
            "/u/mfa-detect-browser-capabilities": {
                "method": "POST",
                "params": lambda state: {
                    "js-available": "true",
                    "webauthn-available": "true",
                    "is-brave": "false",
                    "webauthn-platform-available": "true",
                    "action": "default",
                    "state": state,
                },
                "success_status": 302,
            },
            "/u/mfa-webauthn-platform-enrollment": {
                "method": "POST",
                "params": lambda state: {
                    "action": "refuse-add-device",
                    "state": state,
                },
                "success_status": 302,
            },
            "/callback": {
                "method": "GET",
                "params": lambda state: {
                    "code": self.code,
                    "state": state,
                },
                "success_status": 200,
            },
        }

    @staticmethod
    def _base64URLEncode(data):
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

    @staticmethod
    def _sha256(data):
        return hashlib.sha256(data).digest()

    def _get_authorize_params(self, state=None):
        state = self._base64URLEncode(os.urandom(32))
        nonce = self._base64URLEncode(os.urandom(32))
        verifier = self._base64URLEncode(os.urandom(32))
        challenge = self._base64URLEncode(self._sha256(verifier.encode('utf-8')))
        self.verifier = verifier
        return {
            "audience": "https://prd-ael-sirius-backend.istefr.fr",
            "redirect_uri": self.REDIRECT_URI,
            "client_id": self.CLIENT_ID,
            "scope": "openid profile email offline_access",
            "response_type": "code",
            "state": state,
            "nonce": nonce,
            "response_mode": "query",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "auth0Client": self._base64URLEncode(b'{"name": "auth0-react", "version": "1.11.0"}')
        }

    async def make_request(self, url, method, params=None):
        self.logger.info(f"Making {method} request to {url} with params: {params}")
        if method == "GET":
            async with self.session.get(url, params=params, allow_redirects=False) as response:
                self.logger.info(f"Received response with status code {response.status}")
                return response
        elif method == "POST":
            headers = {"Content-Type": "application/x-www-form-urlencoded", "Cache-Control": "no-cache"}
            async with self.session.post(url, headers=headers, data=urlencode(params), allow_redirects=False) as response:
                self.logger.info(f"Received response with status code {response.status}")
                return response
        else:
            raise ValueError(f"Unsupported HTTP method: {method}")

    async def execute_flow(self):
        next_url = "/authorize"
        state = None

        while next_url:
            config = self.api_flow[next_url]
            full_url = f"{self.LOGIN_URL}{next_url}" if next_url != "/callback" else f"{self.BASE_URL}{next_url}"

            if config["params"]:
                params = config["params"](state)
            else:
                params = {}

            if state:
                full_url = f"{full_url}?state={state}"

            response = await self.make_request(full_url, config["method"], params)

            if response.status != config["success_status"]:
                self.logger.error(f"API call to {full_url} failed with status {response.status}")
                raise Exception(f"API call to {full_url} failed")

            if response.status == 302:
                redirect_url = urlparse(response.headers.get('Location'))
                next_url = redirect_url.path
                new_state = parse_qs(redirect_url.query).get('state')
                if new_state:
                    state = new_state[0]
                
                if next_url == "/callback":
                    self.code = parse_qs(redirect_url.query).get('code', [None])[0]
                    if not self.code:
                        self.logger.error("Authorization code not found in callback URL")
                        raise Exception("Authorization code not found")
                    self.logger.info("Authorization code received")
            elif response.status == 200 and next_url == "/callback":
                next_url = None
            else:
                self.logger.error(f"Unexpected 200 response from {full_url}")
                raise Exception("Unexpected 200 response")

    async def login(self):
        self.logger.info("Starting login process...")
        await self.execute_flow()
        await self.request_access_token()

    async def request_access_token(self):
        token_url = f"{self.LOGIN_URL}/oauth/token"
        self.logger.info("Requesting access token...")
        async with self.session.post(token_url, json={
            "client_id": self.CLIENT_ID,
            "grant_type": "authorization_code",
            "code_verifier": self.verifier,
            "code": self.code,
            "redirect_uri": self.REDIRECT_URI
        }) as token_response:

            if token_response.status != 200:
                self.logger.error("Token API call error")
                raise Exception("Token API call error")

            token_data = await token_response.json()
            self.access_token = token_data.get("access_token")
            if not self.access_token:
                self.logger.error("Access token not found in the token response")
                raise Exception("Access token not found")
            
            self.logger.info("Access token received")
            
            headers = {"Authorization": f"Bearer {self.access_token}"}
            async with self.session.get(url="https://prd-ael-sirius-backend.istefr.fr/espace-client?type-front=WEB_ORDINATEUR", headers=headers) as userdata_response:
                if userdata_response.status != 200:
                    self.logger.error("Espace-client call error")
                    raise Exception("Espace-client call error")

                userdata = await userdata_response.json()
                self.id_abonnement = userdata.get("contacts")[0].get("tiers")[0].get("abonnements")[0].get("id_abonnement")
                if not self.id_abonnement:
                    self.logger.error("id_abonnement not found in the response")
                    raise Exception("id_abonnement not found in the response")

            # Facturation request
            async with self.session.get(url=f"https://prd-ael-sirius-backend.istefr.fr/abonnements/{self.id_abonnement}/facturation", headers=headers) as facturation_response:
                if facturation_response.status != 200:
                    self.logger.error("Facturation call error")
                    raise Exception("Facturation call error")

                facturation_data = await facturation_response.json()
                self.numero_pds = facturation_data.get("numero_pds")
                if not self.numero_pds:
                    self.logger.error("numero_pds not found in the response")
                    raise Exception("numero_pds not found in the response")

                self.date_debut_abonnement = facturation_data.get("date_debut_abonnement")
                if not self.date_debut_abonnement:
                    self.logger.error("date_debut_abonnement not found in the response")
                    raise Exception("date_debut_abonnement not found in the response")

    async def get_data(self, year, month):
        headers = {"Authorization": f"Bearer {self.access_token}"}
        async with self.session.get(url=f"https://prd-ael-sirius-backend.istefr.fr/consommations/{self.id_abonnement}/journalieres?mois={month}&annee={year}&numero-pds={self.numero_pds}&date-debut-abonnement={self.date_debut_abonnement}", headers=headers) as data_response:
            if data_response.status != 200:
                self.logger.error("Get data call error")
                raise Exception("Get data call error")
            return await data_response.json()

    async def close(self):
        await self.session.close()
