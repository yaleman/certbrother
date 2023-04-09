# certbrother

Certificate manager utility for Brother devices.

Commands:

* update - update the certs
* show - show the cert status
* clean - remove any expired certs from the configuration
* check - check if there's any expired certs
* ping - attempt to connect to the configured printer

For help, run `certbrother --help`.

Example showing a printer with an expired and a valid cert:

```shell
11:34:23 ❯ poetry run python certbrother.py show
2023-04-09 11:35:38.417 | SUCCESS  | certbrother:authenticate:83 - Login OK
2023-04-09 11:35:39.811 | INFO     | certbrother:show:439 - Index  Expired  Name
2023-04-09 11:35:39.811 | INFO     | certbrother:show:445 - 13     False    printer.example.com
2023-04-09 11:35:39.812 | ERROR    | certbrother:show:445 - 18     True     printer.example.com
```

## Configuration

Copy `.env.example` to `.env` and edit it.

## Supported devices

This script has been tested with the following models of Brother devices:

* MFC-L2750DW

If you test it and find any issues I should be able to help.

## Certificate details

The certificate seems to need to be under 4KB in size (at least for my MFC-L2750DW series), in PKCS12 format with a password.

To create the PCKS12 / PFX file for your printer from a letsencrypt cert issued using certbot for `example.com`, run this command:

```shell
openssl pkcs12 -export \
    -out ./printer.pfx \
    -inkey /etc/letsencrypt/live/example.com/privkey.pem \
    -in /etc/letsencrypt/live/example.com/cert.pem \
    -passout pass:Hunter2
```

It'll create the cert file called `printer.pfx` in the local directory with the password `Hunter2`.

## Installation

This *should* install directly from git or you can clone and then install.

```shell
git clone https://github.com/yaleman/certbrother
python -m pip install ./certbrother
certbrother --help
```
