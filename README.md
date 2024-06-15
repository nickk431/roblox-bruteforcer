# Roblox Bruteforcer

A tool to brute force Roblox account credentials using a multi-threaded approach and CAPTCHA solving. This project
leverages concurrent processing to speed up the login attempts and uses CapSolver for CAPTCHA challenges.

## Features

- Multithreaded credential brute-forcing
- CAPTCHA solving with CapSolver
- Proxy support for making requests

## Requirements

- Python 3.6+
- Required Python packages listed in `requirements.txt`

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/nickk431/roblox-bruteforcer.git
   cd roblox-bruteforcer
   ```

2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up your environment:
    - Add your CapSolver API key in the `capsolver.api_key` variable.
    - Create `proxies.txt` file with a list of proxies (one per line).
    - Create `usernames.txt` and `passwords.txt` files with usernames and passwords to test.

## Usage

To run the bruteforcer, simply execute the main script:

```bash
python roblox_bruteforcer.py
```

### Configuration

- `num_threads`: Adjust the number of threads for concurrent execution.
- `capsolver.api_key`: Add your CapSolver API key here.

## Example `proxies.txt`

```
123.123.123.123:8080
124.124.124.124:8080
```

## Example `usernames.txt`

```
username1
username2
```

## Example `passwords.txt`

```
password1
password2
```

## License

This project is licensed under the MIT License.

## Disclaimer

This tool is for educational purposes only. The use of this tool to brute force accounts without permission is illegal
and unethical. The author is not responsible for any misuse of this tool.