"""NOT FOR NOW: #! /Library/Frameworks/Python.framework/Versions/3.6/bin/python3.6"""

import ssl
from OpenSSL import crypto
from datetime import datetime, timezone
import pytz
import socket
from dateutil import relativedelta
import re
import json
import argparse


error_message = []  # global placeholder


class Certificate:
    """ creates a certificate object, providing formatted access to the main certificate properties """

    def __init__(self, cert, arguments):

        self.arguments = arguments
        self._x509 = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
        self.expiry = self.get_timestamp("expiry")
        self.readable_expiry = self.get_readable("expiry")
        self.issuer = self.get_issuer()
        self.issuercn = self.get_issuer("cn")
        self.serial = self.get_serial()
        self.start = self.get_timestamp("start")
        self.readable_start = self.get_readable("start")
        self.countdown = self.get_countdown()
        self.subject_org = self.get_organisation_subject()

    def get_expiry(self):
        """ returns expiration date as timestamp """
        py_timestamp = self.ssl_property_to_py("expiry").timestamp()
        return py_timestamp

    def get_timestamp(self, start_expiry):
        if start_expiry == "start":
            py_date = self.ssl_property_to_py("start")
        else:
            py_date = self.ssl_property_to_py("expiry")
        return py_date.timestamp()

    def get_start(self):
        py_date = self.ssl_property_to_py("start")
        formatted_date = self.format_date(py_date)
        return formatted_date

    def get_readable(self, start_expiry):
        """returns the ssl dates (start and readable_expiry) in a readable date format."""
        if start_expiry == "start":
            py_date = self.ssl_property_to_py("start")
        else:
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

    def get_issuer(self, common_name=None):
        """ returns formatted string """
        issuer_tuple = self.ssl_property_to_py("issuer")
        formatted_issuer = self.format_issuer(issuer_tuple, common_name)
        return formatted_issuer

    @staticmethod
    def format_issuer(components, common_name=None):
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
        if common_name:
            issuer_string = ", ".join([value for key, value in reversed(components) if key == "CN"])  # reverse list and return only the common name
        else:
            issuer_string = ", ".join([issuer_property[key] + kv_separator + value for key, value in reversed(components)])

        return issuer_string  # e.g. Country=GB, State=Greater Manchester, Location=Salford, Organisation=COMODO CA Limited

    def get_serial(self):
        serial_number = self.ssl_property_to_py("serial")
        return serial_number

    @staticmethod
    def convert_x509_to_dt(x509_date):
        """ converts the x509 date format to a python datetime object """
        utc_date = x509_date.replace('Z', "+0000")  # UTC offset 'Z' (Zulu) is not understood by strptime(). This replaces it with the standard notation of "+0000". All x509 dates are UTC.
        py_date = datetime.strptime(utc_date, "%Y%m%d%H%M%S%z")
        return py_date

    def format_date(self, python_date):
        """ make the python date readable. optionally change to local timezone."""
        date = python_date

        if self.arguments.local:
            date = python_date.astimezone(pytz.timezone(self.arguments.local))

        human_format = "%c"  # Locale’s appropriate date and time representation: Tue Aug 16 21:30:00 1988 (en_US);
        date = date.strftime(human_format)
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


def clean_url(address):
    """ remove the protocol and subdirectorires for uniformity """
    domain_pattern = r"(?i)\b([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}\b"
    domain = re.search(domain_pattern, address)  # return only the domain in instances where the protocol was included
    if domain:
        clean_hostname = domain.group(0)  # strip out any protocol found (and maybe subdirectory)
    else:
        clean_hostname = address  # if not matched by RegEx, still pass through, just in case it's valid
    return clean_hostname


def get_pem_cert(_hostname, _port, _timeout, protocol_tls=False, error_count=0):
    """ retrieves SSL certificate. if an invalid certificate error is encountered
     1. the error message is logged.
     2. the function will try again with protocol_tls=True (depending on reason for failure) to retrieve the ssl data anyway.

    The function will try a maximum of three times. """

    if error_count < 3:
        if protocol_tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS)  # used to return the ssl information from an expired ssl certificate
        else:
            context = ssl.create_default_context()  # Python Mac OS issue. Install Certificates.command from Applications/Python 3.6 folder https://stackoverflow.com/questions/41691327/ssl-sslerror-ssl-certificate-verify-failed-certificate-verify-failed-ssl-c  #TODO add this to the readme?
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
            error_count += 1
            certificate_error = "CertificateError: {0}. ".format(cert_err)
            error_message.append(certificate_error)
            _pem_cert = get_pem_cert(_hostname, _port, _timeout, protocol_tls=True, error_count=error_count)
            return _pem_cert
        except ssl.SSLError as ssl_err:
            error_count += 1
            ssl_error = "SSLError: {0}. ".format(ssl_err)
            error_message.append(ssl_error)
            _pem_cert = get_pem_cert(_hostname, _port, _timeout, protocol_tls=True, error_count=error_count)
            return _pem_cert
        except:
            connection_error = "Unable to connect to {0}. ".format(_hostname)
            error_message.append(connection_error)
            return None
    else:
        # Maximum error count exceeded
        return None


def main(arguments=None):
    hostname = clean_url(arguments.address)

    # get PEM certificate
    pem_cert = get_pem_cert(hostname, arguments.port, arguments.timeout)

    if not pem_cert:
        connection_error = "Could not retrieve certificate for host: {0} on port: {1}.".format(hostname, arguments.port)
        error_message.append(connection_error)

    # create result log
    result_log = {}

    if pem_cert and ("BEGIN CERTIFICATE" in pem_cert):
        certificate = Certificate(pem_cert, arguments)

        if arguments.subject:
            result_log["subject"] = certificate.subject_org
        if not arguments.expiry == False:
            result_log["expiry"] = certificate.expiry
        if arguments.expiryreadable:
            result_log["readable_expiry"] = certificate.readable_expiry
        if arguments.start:
            result_log["start"] = certificate.start
        if arguments.startreadable:
            result_log["readable_start"] = certificate.readable_start
        if arguments.issuer:
            result_log["issuer"] = certificate.issuer
        if arguments.issuercn:
            result_log["issuer_cn"] = certificate.issuercn

        if arguments.number:
            result_log["number"] = certificate.serial
        if arguments.countdown:
            result_log["countdown"] = certificate.countdown

    if error_message:
        error_message.reverse()  # print the last error first
        result_log["error"] = error_message  # get a single string of errors

    print(json.dumps(result_log))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("address", help="enter the web address/domain to be used")
    parser.add_argument("-p", "--port", help="the port to be used", default=443)
    parser.add_argument("-e", "--expiry", help="output will include the ssl expiration date as a timestamp", default=True)
    parser.add_argument("-r", "--expiryreadable", help="output will include a readable date format ssl expiration date (UTC)",  action="store_const", const=True)
    parser.add_argument("-l", "--local", help="enter a valid pytz timezone for readable date formats (start and expiry). Defaults to UTC when not included. Defaults to Europe/London when included", nargs='?', const="Europe/London")
    parser.add_argument("-s", "--start", help="output will include the ssl start date", action="store_const", const=True)
    parser.add_argument("-d", "--startreadable", help="output will include the ssl start date in a readable format", action="store_const", const=True)
    parser.add_argument("-i", "--issuer", help="output will include the full ssl issuer - Common Name, Location, State, Organisation and Country", action="store_const", const=True)
    parser.add_argument("-t", "--issuercn", help="output will include the ssl issuer by their Common Name", action="store_const", const=True)
    parser.add_argument("-n", "--number", help="output will include the serial number of the ssl certificate", action="store_const", const=True)
    parser.add_argument("-c", "--countdown", help="output will include the remaining years/months/weeks/days until ssl expiration", action="store_const", const=True)
    parser.add_argument("-f", "--subject", help="output will include the ssl subject (Organisation)", action="store_const", const=True)
    parser.add_argument("-o", "--timeout", help="enter the connection timeout in seconds", default=5, type=int)
    parser.add_argument("-a", "--allitems", help="output will include all ssl certificate attributes (uses UTC timezone unless --local is also specified)", action="store_const", const=True)

    args = parser.parse_args()

    if args.local and args.local not in pytz.all_timezones:
        print("--local: {} is not a valid timezone (pytz)".format(args.local))
        exit(1)

    # return all ssl certificate attributes
    if args.allitems:
        args.expiry = True
        args.expiryreadable = True
        args.start = True
        args.startreadable = True
        args.issuer = True
        args.issuercn = True
        args.number = True
        args.countdown = True
        args.subject = True

    main(arguments=args)
