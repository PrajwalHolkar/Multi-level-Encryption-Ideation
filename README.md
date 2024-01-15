# Multi-level-Encryption-Ideation
Multi Level Encryption is a security-oriented Ideation project designed to provide a robust and multi-layered encryption mechanism for sensitive data. The project employs a combination of AES (Advanced Encryption Standard) and RSA (Rivest–Shamir–Adleman) algorithms to ensure both symmetric and asymmetric encryption.


# Multi Level Encryption (Ideation)

## Overview

Multi Level Encryption (Ideation) is a Flask-based web application that allows users to securely encrypt and decrypt their files using a combination of AES and RSA encryption algorithms. The project aims to provide a user-friendly interface for encrypting sensitive data and storing it securely in a database.

## Table of Contents

- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
- [Features](#features)
- [Deployment](#deployment)
- [Built With](#built-with)
- [Contributing](#contributing)

## Getting Started

### Prerequisites

Before you begin, ensure you have the following installed:

- [Python](https://www.python.org/) - The programming language used
- [MySQL](https://www.mysql.com/) - Database for storing encrypted data

### Installation

1. Clone the repository:
   `git clone https://github.com/21Sandesh/Multi-Level-Encryption-Ideation.git`

2. Navigate to the Project Directory
   `cd multi-level-encryption`

3. Install Dependencies
   [requirements.txt](https://github.com/21Sandesh/Multi-Level-Encryption-Ideation/blob/main/requirements.txt)
  `pip install -r requirements.txt`

5. Change the Database Credentials for MySQL Connection
   [credentials.txt](https://github.com/21Sandesh/Multi-Level-Encryption-Ideation/blob/main/credentials.txt)
   1. `host: 127.0.0.1` - Connecting to Local Database
   2. `user: <user>`
   3. `password: <User Password>`
   4. `database: <Database to Use>`

### Usage
1. Run the Flash Application:
   `python app.py`

2. Open your web browser and go to http://localhost:5000
3. Register or log in to your account.
4. Encrypt files using the provided interface.
5. View and decrypt your encrypted files on the dashboard.

### Features
- Multi-Level Encryption: Utilizes both AES and RSA encryption algorithms for enhanced security.
- User Authentication: Secure user accounts with login and registration functionality.
- File Encryption: Easily encrypt and decrypt files through the web interface.
- Database Storage: Store encrypted data securely in a MySQL database.

### Built With 
- [Flask](https://flask.palletsprojects.com/en/3.0.x/) - Web Framework
- [MySQL](https://www.mysql.com/) - Database
- [Crypto (PyCryptodome)](https://www.pycryptodome.org/) - Cryptographic library for AES encryption
- [Cryptography](https://cryptography.io/en/latest/) - Cryptographic library for RSA encryption
