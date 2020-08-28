#! /Library/Frameworks/Python.framework/Versions/3.6/bin/python3.6

import sys
import ssl
from OpenSSL import crypto
from datetime import datetime, timezone
import pytz
import getopt
import socket
from dateutil import relativedelta
import re
import json


class Certificate:
    """ creates a certificate object, providing formatted access to the main certificate properties """

    def __init__(self, cert):

        self._x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        self.expiry = self.get_expiry()
        self.issuer = self.get_issuer()
        self.serial = self.get_serial()
        self.start = self.get_start()
        self.countdown = self.get_countdown()
        self.subject_org = self.get_organisation_subject()

    def get_expiry(self):
        """ formats the expiration datetime object """
        py_date = self.ssl_property_to_py("expiry")
        formatted_date = self.format_date(py_date)
        return formatted_date

    def ssl_property_to_py(self, x509_property):
        """ returns an x509 date a datetime object """
        if x509_property == "start":
            x509_date = self._x509.get_notBefore().decode('utf-8')
            py_date = self.convert_x509_to_dt(x509_date)
            return py_date
        elif x509_property == "expiry":
            x509_date = self._x509.get_notAfter().decode('utf-8')
            py_date = self.convert_x509_to_dt(x509_date)
            return py_date
        elif x509_property == "issuer":
            binary_issuer = self._x509.get_issuer().get_components()  # returns a tuple of issuer components in binary
            utf8_issuer = [(prop.decode('utf-8'), value.decode('utf-8')) for prop, value in binary_issuer]  # List Comp > Converts binary tuple to utf-8
            return utf8_issuer
        elif x509_property == "serial":
            serial_number = self._x509.get_serial_number()  # returns an integer (see get_serial() for hexcode)
            return serial_number
        elif x509_property == "subject":
            binary_issuer = self._x509.get_subject().get_components()  # returns a tuple of issuer components in binary
            utf8_issuer = [(prop.decode('utf-8'), value.decode('utf-8')) for prop, value in binary_issuer]  # List Comp > Converts binary tuple to utf-8
            return utf8_issuer

        else:
            raise Exception("x509 property not recognised: {0}".format(x509_property))

    def get_issuer(self):
        """ returns formatted string """
        issuer_tuple = self.ssl_property_to_py("issuer")
        formatted_issuer = self.format_issuer(issuer_tuple)
        return formatted_issuer

    @staticmethod
    def format_issuer(components):
        """ formats the decoded component tuple. Creates a single string with each tuple pair ', ' separated.
        Converts issuer codes to full names e.g 'C' to 'Country'. Inserts a character between each key and value
        such as '=' or ':' to aid string readability. Has the option to return a dictionary rather than a
        string to help with API integration. """

        issuer_property = {
            "C": "Country",
            "ST": "State",
            "L": "Location",
            "O": "Organisation",
            "OU": "Organisational Unit",
            "CN": "Common Name"
        }

        # Return a dictionary with the issuer details. Not currently used but could help for API integration
        issuer_dict = {}
        for prop, value in components:
            issuer_dict[prop] = value

        # Return a string with the issuer details.
        kv_separator = ": "  # char(s) used to separate the key from the value in the output . e.g. ':', '=', '>'
        if issuer_cn:
            issuer_string = ", ".join([value for key, value in reversed(components) if key == "CN"])  # reverse list and return only the common name
        else:
            issuer_string = ", ".join([issuer_property[key] + kv_separator + value for key, value in reversed(components)])

        return issuer_string  # e.g. Country=GB, State=Greater Manchester, Location=Salford, Organisation=COMODO CA Limited

    def get_serial(self):
        serial_number = self.ssl_property_to_py("serial")
        # hex_number = format(serial_number, 'x')  # format serial as hexcode (optional)
        return serial_number

    def get_start(self):
        py_date = self.ssl_property_to_py("start")
        formatted_date = self.format_date(py_date)
        return formatted_date

    @staticmethod
    def convert_x509_to_dt(x509_date):
        """ converts the x509 date format to a python datetime object """
        utc_date = x509_date.replace('Z', "+0000")  # UTC offset 'Z' (Zulu) is not understood by strptime(). This replaces it with the standard notation of "+0000". All x509 dates are UTC.
        py_date = datetime.strptime(utc_date, "%Y%m%d%H%M%S%z")
        return py_date

    @staticmethod
    def format_date(python_date):
        """ format the python date for readability. return a timestamp by default."""
        date = python_date
        if local:
            date = python_date.astimezone(pytz.timezone("Europe/London"))
        if readable:
            human_format = "%c"  # Locale’s appropriate date and time representation: Tue Aug 16 21:30:00 1988 (en_US);
            date = date.strftime(human_format)
        else:
            date = date.timestamp()
        return date

    def get_countdown(self):
        """ return the time until the ssl expires"""
        expiry_time = self.ssl_property_to_py("expiry")
        time_now = datetime.now(timezone.utc)
        remain = relativedelta.relativedelta(expiry_time, time_now)
        if remain.years == 0:
            rem_yr = None
        else:
            rem_yr = "%d year" % remain.years if (remain.years == 1) or (remain.years == -1) else "%d years" % remain.years  # if singular, use singular

        rem_mth = "%d month" % remain.months if (remain.months == 1) or (remain.months == -1) else "%d months" % remain.months
        rem_wks = "%d week" % remain.weeks if (remain.weeks == 1) or (remain.weeks == -1) else "%d weeks" % remain.weeks
        seven = 7 if remain.days >= 0 else -7  # needs to be a minus to get correct modulus if number of days is a minus (i.e. certificate has expired)
        rem_days = "%d day" % (remain.days % seven) if (remain.days % seven == 1) or (remain.days % seven == -1) else "%d days" % (remain.days % seven)  # modulus of dividing days by 7

        if rem_yr:
            countdown_string = "{0}, {1}, {2}, {3}".format(rem_yr, rem_mth, rem_wks, rem_days)  # only show years if years are relevant
        else:
            countdown_string = "{0}, {1}, {2}".format(rem_mth, rem_wks, rem_days)
        return countdown_string

    def get_organisation_subject(self):
        """ returns organisation name for subject. if not found, returns common name.
        if still not found returns 'NA' as a string """

        org_components = self.ssl_property_to_py("subject")

        for k, v in org_components:
            if k == "O":
                return v
        else:
            for k, v in org_components:
                if k == "CN":
                    return v
            else:
                return "NA"  # implement url


address = sys.argv[1]  # first parameter after script name
options = sys.argv[2:]  # optional arguments passed into the script (all args after the address parameter)

port = 443
readable = False
local = False
expiry = True
start = False
issuer = False
issuer_cn = False
number = False
countdown = False
subject_name = False
timeout = 5

error_message = []

# TODO correct or remove the OR in the below - both clauses need to as per "--all"

opts, unknown = getopt.getopt(options, "p:ferlsitnco:a", ["for", "port=", "expiry", "ts_to_readable", "local", "start", "issuer", "issuercn", "number", "countdown", "countdownshort", "timeout=", "all"])  # looks for -p or --port in provided arguments

for opt, arg in opts:
    if opt == ("-p" or "--port"):
        port = int(arg)  # set port from provided arguments
    elif opt == ("-e" or "--expiry"):
        expiry = True
    elif opt == ("-r" or "--ts_to_readable"):
        readable = True
    elif opt == ("-l" or "--local"):
        local = True
    elif opt == ("-s" or "--start"):
        start = True
    elif opt == ("-i" or "--issuer"):
        issuer = True
    elif opt == ("-t" or "--issuercn"):
        issuer_cn = True
    elif opt == ("-n" or "--number"):
        number = True
    elif opt == ("-c" or "--countdown"):
        countdown = True
    elif opt == ("-f" or "--for"):
        subject_name = True
    elif opt == "--timeout":
        timeout = int(arg)
    elif opt == "-a" or opt == "--all":
        local = True
        expiry = True
        start = True
        issuer_cn = True
        number = True
        countdown = True
        subject_name = True

# TODO move this up/down?

if unknown:
    unknown_error = "Unknown arguments provided: {0}".format(unknown)
    error_message.append(unknown_error)
    # exit(1)  # TODO return exit code at bottom if messages are present


def clean_url(address):
    """ remove the protocol and subdirectorires for uniformity """
    domain_pattern = r"(?i)\b([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\b"
    domain = re.search(domain_pattern, address)  # return only the domain in instances where the protocol was included
    if domain:
        clean_hostname = domain.group(0)  # strip out any protocol found (and maybe subdirectory)
    else:
        clean_hostname = address  # if not matched by RegEx, still pass through, just in case it's valid
    return clean_hostname


hostname = clean_url(address)


def get_pem_cert(_hostname, _port, _timeout, sslv23=False, error_count=0):
    """ retrieves SSL certificate. if an invalid certificate error is encountered
     1. the message is logged.
     2. the function will try again with sslv23=True (depending on reason for failure) to try and retrieve the data anyway.
     (sslv23 is needed to return ssl information on invalid certificates)

    The function will try a maximum of three times. """

    error_count = error_count

    if error_count < 2:
        if sslv23:
            context = ssl.SSLContext(
                ssl.PROTOCOL_SSLv23)  # SSLv23 deprecated in Python 3.6 but works see above. This version is used to return expired SSLs
        else:
            context = ssl.create_default_context()  # Python Mac OS issue. Install Certificates.command from Applications/Python 3.6 folder or use SSLv23. https://stackoverflow.com/questions/41691327/ssl-sslerror-ssl-certificate-verify-failed-certificate-verify-failed-ssl-c  #TODO add this to the readme?
        try:
            with socket.create_connection((_hostname, _port), timeout=_timeout) as sock:  # create a socket (port and url)
                with context.wrap_socket(sock, server_hostname=_hostname) as ssock:  # add a context to the socket (handshake information)
                    _pem_cert = ssl.DER_cert_to_PEM_cert(ssock.getpeercert(True))  # use the socket to get the peer certificate
            return _pem_cert
        except socket.timeout:
            timeout_error = "Timed out during certificate retrieval. "
            error_message.append(timeout_error)
            return None
        except ssl.CertificateError as cert_err:
            print("cert error")
            error_count += 1
            certificate_error = "CertificateError: {0}. ".format(cert_err)
            error_message.append(certificate_error)
            _pem_cert = get_pem_cert(_hostname, _port, _timeout, sslv23=True, error_count=error_count)
            return _pem_cert
        except ssl.SSLError as ssl_err:
            print("ssl error")
            error_count += 1
            ssl_error = "SSLError: {0}. ".format(ssl_err)
            error_message.append(ssl_error)
            _pem_cert = get_pem_cert(_hostname, _port, _timeout, sslv23=True, error_count=error_count)
            return _pem_cert
        except:
            connection_error = "Unable to connect to {0}. ".format(_hostname)
            error_message.append(connection_error)
            return None
    else:
        # Maximum error count exceeded
        return None


# get PEM certificate
pem_cert = get_pem_cert(hostname, port, timeout)

if not pem_cert:
    connection_error = "Could not retrieve certificate for host: {0} on port: {1}.".format(hostname, port)
    error_message.append(connection_error)


# create result log
result_log = {}

if pem_cert and ("BEGIN CERTIFICATE" in pem_cert):
    certificate = Certificate(pem_cert)

    organisation = certificate.get_organisation_subject()

    if subject_name:
        result_log["name"] = certificate.subject_org
    if expiry:
        result_log["expiry"] = certificate.expiry
    if start:
        result_log["start"] = certificate.start
    if issuer or issuer_cn:
        result_log["issuer"] = certificate.issuer
    if number:
        result_log["number"] = certificate.serial
    if countdown:
        result_log["countdown"] = certificate.countdown

if error_message:
    error_message.reverse()  # print the last error first
    # result_log["error"] = ", ".join(error_message)  # get a single string of errors
    result_log["error"] = error_message  # get a single string of errors


print(json.dumps(result_log))
