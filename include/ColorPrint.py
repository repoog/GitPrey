#!/usr/bin/env python

try:
    from colorama import init, Fore
except ImportError:
    print("[!]Error: You have to install colorama module.")
    exit()

import logging

init(autoreset=True)

logger = logging.getLogger('')
logger.setLevel(logging.INFO)
file_handle = logging.FileHandler('GitPrey.log')
file_handle.setLevel(logging.INFO)
formatter = logging.Formatter('%(message)s')
file_handle.setFormatter(formatter)
logger.addHandler(file_handle)


def error_print(string):
    # Print error information with red color
    print(Fore.RED + string)
    logger.error(string)


def info_print(string):
    # Print information with green color
    print(Fore.GREEN + string)
    logger.info(string)


def project_print(string):
    # Print project information with deep green color
    print(Fore.CYAN + string)
    logger.info(string)


def file_print(string):
    # Print file url with yellow color
    print(Fore.YELLOW + string)
    logger.info(string)


def code_print(string):
    # Print code line with white color
    print(Fore.WHITE + string)
    logger.info(string)


if __name__ == "__main__":
    pass
