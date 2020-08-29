
# Get_SSL

Get_SSL is a Python script that returns SSL certificate information in JSON format. 

SSL information retrieved:

* Expiry date (timestamp and human readable format)
* Start date (timestamp and human readable format)
* Issuer (Full and/or Common Name)
* Serial Number
* Subject of certificate
* Time remaining until SSL expires (human readable format)

It can also return SSL dates in any given timezone. Clever eh?

## Installation

1. Copy `get_ssl.py` to your chosen installation directory
2. Run it (see Usage).

## Usage

To use, simply specify the domain to check. We'll use *example.com* as an... example.... 

`$python3 get_ssl.py example.com`

The default output returns the SSL expiration as a timestamp:

`{"domain": "example.com", "expiry": 1606910400.0}`

## Options

That's a bit boring. So there are a number of options to enhance your SSL retrieval experience:

**`-p`, `--port`**: Specify the port used to retrieve the SSL certificate. This defaults to 443

**`-r`, `--expiryreadable`**:  Include the SSL expiry date in a human readable date format (defaults to UTC timezone)  
*Example*: `python3 get_ssl.py example.com -r`  
*Output*: `{"domain": "example.com", "expiry": 1606910400.0, "readable_expiry": "Wed Dec  2 13:00:00 2020"}`  

**`-l`, `--local`** Specify a valid *pytz* timezone for readable date formats (start and expiry)  
*Example*: `python3 get_ssl.py example.com -r --local "Europe/Rome"`  
*Output*: `{"domain": "example.com", "expiry": 1606910400.0, "readable_expiry": "Wed Dec  2 13:00:00 2020"}`  

**`-s, --start`**: Include the SSL start date  
**`-d, --startreadable`**:   Include the SSL start date in a readable format  
**`-i, --issuer`**: Include the full SSL issuer - Common Name, Location, State, Organisation and Country  
**`-t, --issuercn`**: Include the SSL issuer by their Common Name  
**`-n, --number`**: Include the serial number of the SSL certificate  

**`-c, --countdown`**: Include the remaining years/months/weeks/days until SSL expiration  
*Example*: `python3 get_ssl.py example.com -c`  
*Output*: `{"domain": "example.com", "expiry": 1606910400.0, "countdown": "3 months, 0 weeks, 2 days"} `  

**`-f, --subject`**: Include the SSL subject (Organisation)  
**`-o, --timeout`**: Specify the connection timeout in seconds  

**`-a, --allitems`**: Include all SSL certificate attributes. UTC timezone is used unless '--local' is also specified  
*Example*: `python3 get_ssl.py example.com -a`  
*Output*:  
 ```{"domain": "example.com", "subject": "Internet Corporation for Assigned Names and Numbers", "expiry": 1606910400.0, "readable_expiry": "Wed Dec  2 12:00:00 2020", "start": 1543363200.0, "readable_start": "Wed Nov 28 00:00:00 2018", "issuer": "Common Name: DigiCert SHA2 Secure Server CA, Organisation: DigiCert Inc, Country: US", "issuer_cn": "DigiCert SHA2 Secure Server CA", "number": 21020869104500376438182461249190639870, "countdown": "3 months, 0 weeks, 2 days"}```  

## License
This script is made available with the permissions set out under **GNU General Public License v3.0**