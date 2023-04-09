"""
Description: Auto renew certificate for Brother Printer. Tested for MFC-L2750CDW
Author: @davidlebr1, updated by @yaleman Apr 2023
"""

import json
from pathlib import Path
import re
from ssl import SSLCertVerificationError
import sys
from typing import Any, Dict, Optional, Tuple

import click
from loguru import logger
from pydantic import BaseSettings, Field
import requests.exceptions
from requests_html import HTMLSession # type: ignore
import urllib3

# Remove insecure warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


DATEMATCHER = re.compile(r"(?P<expiry>\d+\/\d{1,2}\/\d{2,4})")

class AppConfig(BaseSettings):
    """settsings"""

    hostname: str = Field("example.com")
    password: str = Field("")
    protocol: str = Field("https")
    certificate_path: str = Field(default="./cert.pfx")
    certificate_password: str = Field("")

    class Config:
        """metaconfig"""

        env_file = ".env"
        env_file_encoding = "utf-8"

    def url(self, endpoint: Optional[str] = None) -> str:
        """get the base URL for the device"""
        if endpoint is None:
            return "{}://{}".format(self.protocol, self.hostname)
        return "{}://{}{}".format(self.protocol, self.hostname, endpoint)


class AuthError(Exception):
    """failed to login"""
class DeleteError(Exception):
    """failed to delete the cert"""
class SelectError(Exception):
    """failed to select the cert"""
class UploadError(Exception):
    """failed to delete the cert"""


def authenticate(session: HTMLSession, config: AppConfig) -> None:
    """returns the login field name"""
    # Get CSRF token from login
    logger.debug("Logging in...")
    response = session.get(
        config.url("/general/status.html"), verify=False
    )
    token = response.html.xpath('//*[@id="CSRFToken"]')[0].attrs["value"]
    logger.trace(f"CSRF token is: {token}")
    # Authenticate
    # <input type="password" id="LogBox" name="Baf5" />
    logbox = response.html.xpath('//*[@id="LogBox"]')
    if not logbox:
        raise (AuthError("Couldn't find login field"))
    login_field = logbox[0].attrs["name"]
    paramsPost = {
        login_field: config.password,
        "CSRFToken": token,
        "loginurl": "/general/status.html",
    }
    response = session.post(
        config.url("/general/status.html"), data=paramsPost, verify=False
    )

    # if the login box shows up again then they've failed to login
    if response.html.xpath('//*[@id="LogBox"]'):
        logger.error("Couldn't login")
        raise AuthError("Couldn't login for some reason...")
    else:
        logger.success("Login OK")


def get_certs(session: HTMLSession, config: AppConfig) -> Dict[int, Dict[str, Any]]:
    """ get the list of certificates"""
    response = session.get(
        config.url("/net/security/certificate/certificate.html"),
        verify=False,
    )

    results = {}
    rows = response.html.xpath('//tr')
    for row in rows:
        if "Export" not in row.text:
            # we've got the header
            continue
        name = row.xpath('//td')[0].text
        expired = row.xpath('//span[@class="expired"]')
        # TODO: include the expiry date
        idx = list(row.links)[-1].split("=")[-1]
        logger.debug(row.text)
        result = {
            "name" : name,
            "expired" : len(expired) > 0,
        }

        date = DATEMATCHER.search(row.text)
        if date is not None:
            logger.debug("Cert Expiry Date: {}", date.groupdict().get("expiry"))
            result["expiry"] = date.groupdict().get("expiry")
        results[idx] = result

    return results

def delete_expired(session: HTMLSession, config: AppConfig, certs: Dict[int, Any]) -> None:
    """ deletes all the expired certs """
    for idx, cert in certs.items():
        if not cert['expired']:
            logger.info("Skipping not-expired certificate {}", cert)
            continue
        logger.info("Deleting idx={} cert={}", idx, cert)
        # Get CSRF from delete page
        response = session.get(
            config.url(f"/net/security/certificate/delete.html?idx={idx}"),
            verify=False,
        )

        paramsPost = {
            "pageid" : 380, # TODO: this is probably unneeded?
            "CSRFToken" : get_csrf_token(response),
        }
        input_fields = response.html.xpath(
            "//*[@class=\"contentsGroup\"]//input"
        )
        for field in input_fields:
            if field.attrs['id'] == 'hidden_certificate_idx':
                paramsPost['hidden_certificate_idx'] = idx
            else:
                paramsPost[field.attrs['name']] = field.attrs['value']
        response = session.post(
            config.url("/net/security/certificate/delete.html"),
            data=paramsPost,
        )

        # Check if cert was deleted
        response = session.get(
            config.url(f"/net/security/certificate/delete.html?idx={idx}"),
            verify=False,
        )
        is_deleted = response.html.xpath(
            "/html/body/div/div/div[2]/div[2]/div[2]/div/div/div[2]/form/div[3]/p"
        )
        if is_deleted:
            logger.success("The certificate idx {} was successfully deleted", idx)
        else:
            raise DeleteError(f"The certificate idx {idx} has not been deleted")


def upload_cert(session: HTMLSession, config: AppConfig) -> None:
    """ Upload the new certificate """

    # get the page ID
    response = session.get(
        config.url("/net/security/certificate/certificate.html")
    )
    importlink = response.html.xpath('//*[@id="pageContents"]/form/div[6]/p/a')
    logger.debug("Import link: {}", importlink)
    if not importlink:
        raise UploadError("Couldn't find import link!")

    importlink = importlink[0].attrs['href']

    pageid = importlink.split("=")[-1]

    # Get CSRF token to submit new cert
    response = session.get(
        config.url(f"/net/security/certificate/{importlink}"),
        verify=False,
    )
    token = response.html.xpath(
        '//div[contains(@class, "CSRFToken")]' #
    )[0].xpath("//input")[0].attrs['value']
    logger.trace("CSRF token {}",  token)

    input_fields = response.html.xpath(
        "//*[@class=\"contentsGroup\"]//input"
    )

    payload = {
        "CSRFToken": token,
        "pageid": pageid,
    }
    for field in input_fields:
        if field.attrs.get("type") == "password":
            payload[field.attrs['name']] = config.certificate_password
        elif field.attrs.get("type") == "file":
            logger.debug("file field: {}", field.attrs.get('id'))
            file_field = field.attrs.get('id')
        elif field.attrs.get('id') == 'hidden_cert_import_password':
            payload[field.attrs['name']] = config.certificate_password
        else:
            payload[field.attrs['name']] = field.attrs.get("value")

    headers = {
        "Origin": config.url(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0",
        "Referer": config.url("/net/security/certificate/import.html?pageid=387"),
        "Connection": "close",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Site": "same-origin",
        "Accept-Encoding": "gzip, deflate",
        "Dnt": "1",
        "Sec-Fetch-Mode": "navigate",
        "Te": "trailers",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Gpc": "1",
        "Sec-Fetch-User": "?1",
        "Accept-Language": "en-CA,en-US;q=0.7,en;q=0.3",
    }

    paramsMultipart = {
        file_field: open(config.certificate_path, "rb"),
        }
    response = session.post(
        config.url("/net/security/certificate/import.html"),
        data=payload,
        files=paramsMultipart,
        headers=headers,
        allow_redirects=True,
        verify=False,
    )
    logger.debug("Upload response: {}", response.text)

    error = response.html.find("div", containing="rejected")
    if not error:
        error = response.html.xpath("//p[@class=\"errorMessage\"]")
    if error:
        if isinstance(error, list):
            error = error[0].text
        raise UploadError(f"An error occured in the upload: {error}")

    else:
        logger.success("The certificate has been successfully uploaded!")

def get_error(response: Any, exception: Any, message: str) -> Optional[Any]:
    error = response.html.find("div", containing="rejected")
    if not error:
        error = response.html.xpath("//p[@class=\"errorMessage\"]")
    if error:
        if isinstance(error, list):
            error = error[0].text
        raise exception(message.format(error))
    return error

def get_csrf_token(response: Any) -> str:
    """ Gets the CSRF token"""
    token: str = response.html.xpath(
        '//div[contains(@class, "CSRFToken")]' #
    )[0].xpath("//input")[0].attrs['value']
    logger.debug("token {}",  token)
    return token

def select_cert(session: HTMLSession, config: AppConfig) -> None:
    """ Select certificate in HTTP Server Settings"""
    # Get CSRF Token
    response = session.get(
        config.url("/net/net/certificate/http.html"), verify=False
    )
    token = response.html.xpath(
        "/html/body/div/div/div[2]/div[2]/div[2]/div/div/div[2]/form/div[2]/input"
    )[0].attrs["value"]

    # Get the Cert from dropdown
    cert_dropdown_id = response.html.xpath(
        "/html/body/div/div/div[2]/div[2]/div[2]/div/div/div[2]/form/div[4]/dl[1]/dd/select/option[2]" # TODO: this is ... not what we wanted
    )[0].attrs["value"]


    input_fields = response.html.xpath(
        "//*[@class=\"contentsGroup\"]//input"
    )

    selectbox = response.html.xpath(
        "//select[contains(@name,\"B\")]"
    )

    if not selectbox:
        raise SelectError("Couldn't find the select box!")

    selectbox = selectbox[0].attrs['id']

    payload = {
        "CSRFToken": token,
        "pageid": 325,
        selectbox : cert_dropdown_id,
        "http_page_mode": 0
    }
    for field in input_fields:
        logger.debug("{}", field)
        if field.attrs.get("type") == "password":
            payload[field.attrs['name']] = config.certificate_password
        elif field.attrs.get('id') == 'hidden_cert_import_password':
            payload[field.attrs['name']] = config.certificate_password
        else:
            if field.attrs.get('checked'):
                payload[field.attrs['name']] = 1
            else:
                payload[field.attrs['name']] = field.attrs['value']

    logger.debug("Cert selection screen payload: {}", json.dumps(payload, indent=4))

    response = session.post(
        config.url("/net/net/certificate/http.html"), data=payload
    )

    token = get_csrf_token(response)


    headers = {
        "Origin": config.url(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0",
        "Referer": config.url("/net/net/certificate/http.html"),
        "Connection": "close",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Site": "same-origin",
        "Accept-Encoding": "gzip, deflate",
        "Dnt": "1",
        "Sec-Fetch-Mode": "navigate",
        "Te": "trailers",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Gpc": "1",
        "Sec-Fetch-User": "?1",
        "Accept-Language": "en-CA,en-US;q=0.7,en;q=0.3",
    }
    input_fields = response.html.xpath(
            "//*[@class=\"contentsButtons\"]//input"
        )
    logger.debug(input_fields)

    # here we need to then click the yes button.
    payload = {
            "CSRFToken" : token,
            "pageid" : 325, # <input type="hidden" id="pageid" name="pageid" value="325">
            "http_page_mode" : 5,
        }
    for input in input_fields:
        if input.attrs.get('id', "").startswith("B"):
            payload[input.attrs['id']] = input.attrs['value']
    logger.debug("Finalizing cert selection, payload: {}", json.dumps(payload, indent=4))
    response = session.post(
        config.url("/net/net/certificate/http.html"), data=payload, headers=headers,
    )
    get_error(response, SelectError, "Failed to do the final submit: {}")
    if  "seconds" not in response.text.lower():
        raise SelectError(f"Failed to find reference to seconds in select response! {response.text}")


def startup(debug: bool, skip_auth: bool=False) -> Tuple[Any, AppConfig,]:
    """ shared startup things """
    if not debug:
        logger.remove(0)
        # <green>{time:YYYY-MM-DD HH:mm::ss}</green>
        logger.add(level="INFO", sink=sys.stderr, colorize=True, format="<level>{message}</level>")
    session = HTMLSession()
    config = AppConfig()
    logger.debug("Configuring: {}://{}", config.protocol, config.hostname)

    if not skip_auth:
        authenticate(session, config)
    return (session, config,)

@click.group()
def cli() -> None:
    pass

# @logger.catch
@click.command()
@click.option("-d", "--debug", is_flag=True, default=False, help="Debug mode.")
def update(debug: bool=False) -> bool:
    """ Update the certificate file. """
    session, config = startup(debug)
    # grab the list of certs
    certs = get_certs(session, config)
    if not Path(config.certificate_path).exists():
        print(
            "Couldn't find certificate at {}, bailing!".format(config.certificate_path)
        )
        sys.exit(1)
    delete_expired(session, config, certs)

    # update the list again so we can check
    certs = get_certs(session, config)
    upload_cert(session, config)

    select_cert(session, config)
    logger.success("Completed cert update!")
    return True

@click.command()
@click.option("-d", "--debug", is_flag=True, default=False, help="Debug mode.")
def clean(debug: bool=False) -> None:
    """ Clean out expired certificates """
    session, config = startup(debug)
    delete_expired(session, config, get_certs(session, config))

@click.command()
@click.option("-d", "--debug", is_flag=True, default=False, help="Debug mode.")
@click.option("-j", "--json", "json_format", is_flag=True, default=False, help="Output in JSON format")
def show(debug: bool=False, json_format: bool=False) -> bool:
    """ Show the certificates which are installed """
    session, config = startup(debug)
    certs = get_certs(session,config)

    if json_format:
        print(json.dumps(certs, default=str))
        return True
    if not certs:
        logger.warning("No certificates found!")
        return True

    logger.info("Index\tExpiry    \tName")
    for idx, cert in certs.items():
        if cert['expired']:
            logfunc = logger.error
        else:
            logfunc = logger.info
        logfunc("{}  \t{}\t{}", idx, cert.get("expiry", ""), cert['name'])

    return True

@click.command()
@click.option("-h", "--hostname")
@click.option("-d", "--debug", is_flag=True, default=False, help="Debug mode.")
def ping(hostname: Optional[str] = None, debug: bool=False) -> None:
    """ Check to see if you can connect """
    session, config = startup(debug, skip_auth=True)

    if hostname is not None:
        config.hostname = hostname

    logger.debug("Checking {}", config.hostname)

    try:
        response = session.get(config.url(), verify=True)
        response.raise_for_status()
        logger.success("OK")
        return
    except SSLCertVerificationError as tls_error:
        logger.error("TLS Error connecting: {}", tls_error)
    except requests.exceptions.SSLError as tls_error:
        logger.error("TLS Error connecting: {}", tls_error)
    sys.exit(1)

@click.command()
@click.option("-d", "--debug", is_flag=True, default=False, help="Debug mode.")
def check(debug: bool=False) -> None:
    """ Check to see if there's any expired certs """
    session, config = startup(debug)
    logger.debug("Checking {}", config.hostname)

    try:
        certs = get_certs(session, config)
        has_expired = False
        for _, cert in certs.items():
            if cert['expired']:
                has_expired = True

        if has_expired:
            logger.error("FAIL")
            sys.exit(1)
        logger.success("OK")
        return
    except SSLCertVerificationError as tls_error:
        logger.error("TLS Error connecting: {}", tls_error)
    except requests.exceptions.SSLError as tls_error:
        logger.error("TLS Error connecting: {}", tls_error)
    sys.exit(1)


def main() -> None:
    """ main function """
    cli.add_command(update)
    cli.add_command(show)
    cli.add_command(check)
    cli.add_command(clean)
    cli.add_command(ping)

    try:
        if cli():
            sys.exit(0)
    except AuthError as error:
        logger.error("Failed to authenticate: {}", error)
    except DeleteError as error:
        logger.error("Failed to delete cert: {}", error)
    except UploadError as error:
        logger.error("Failed to upload cert: {}", error)
    sys.exit(1)

if __name__ == "__main__":
    main()
