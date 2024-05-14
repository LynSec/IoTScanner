## Django IoT Scanner

Django IoT Scanner is a web app developed in python with Django for vulnerabilities scanning of IoT devices, with the D-Link DCS cameras as the main target.


## Features

Quickly boasts more than the whole IP range or port ranges at the same time.

Output images of scans into web interface.

Analyze web application fo D-Link DCS cameras using the dlkploit600 utility.

View in-depth attack surface scans report

## Installation

Clone the repository:


git clone https://github.com/username/iot-scanner.git

Install the required Python packages:Install the required Python packages:

pip install -r requirements.txt

## Set up Django:


1. python manage.py migrate
2. python manage.py createsuperuser
 - Start the development server:
4. python manage.py runserver

Access the web interface at http://localhost:8000/


## Usage

Identifying IP/Ports A scan.

- As a superuser, you should log in to the web interface using the built-in superuser account details.
- Select "Scan" from the “Main” menu.
- Specify the IP address range and TCP port range you would like to target in the input field.

Tap the "Scan" button to start the scan.

- Consider the “Scans” section where the scan results are displayed.

## Testing D-Link DCS Cameras

Examine D-Link DC global standard cameras for vulnerabilities with the dlkploit600 vulnerability finder.
Let https://consoledc-cameras-ao-2.personalok.co.zm/ be the digital camera sensor (DCS Cameras) IP address / IP range to allow.

## Run the dls program with suitable parameters.


Click the “Vulnerability Scan Reports” option on the web UI.


## Contributing

## License







