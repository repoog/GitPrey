#!/usr/bin/env python

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    print("[!]Error: You have to install requests module.")
    exit()

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[!]Error: You have to install BeautifulSoup module.")
    exit()

import os
import re
import math
import sys
import time
import importlib.util
import argparse

try:
    from config.Config import *
except ImportError:
    print("[!]Error: Can't find Config file for searching.")
    exit()

try:
    from include.ColorPrint import *
except ImportError:
    print("[!]Error: Can't find ColorPrint file for printing.")
    exit()

HOST_NAME = "https://github.com/"
RAW_NAME = "https://raw.githubusercontent.com/"
SCAN_DEEP = [10, 30, 50, 70, 100]  # Scanning deep according to page searching count and time out seconds
SEARCH_LEVEL = 1  # Code searching level within 1-5, default is 1
MAX_PAGE_NUM = 100  # Maximum results of code searching
MAX_RLT_PER_PAGE = 10  # Maximum results count of per page


class GitPrey(object):
    """
     $$$$$$\  $$$$$$\ $$$$$$$$\ $$$$$$$\  $$$$$$$\  $$$$$$$$\ $$\     $$ \\
    $$  __$$\ \_$$  _|\__$$  __|$$  __$$\ $$  __$$\ $$  _____|\$$\   $$  |
    $$ /  \__|  $$ |     $$ |   $$ |  $$ |$$ |  $$ |$$ |       \$$\ $$  /
    $$ |$$$$\   $$ |     $$ |   $$$$$$$  |$$$$$$$  |$$$$$\      \$$$$  /
    $$ |\_$$ |  $$ |     $$ |   $$  ____/ $$  __$$< $$  __|      \$$  /
    $$ |  $$ |  $$ |     $$ |   $$ |      $$ |  $$ |$$ |          $$ |
    \$$$$$$  |$$$$$$\    $$ |   $$ |      $$ |  $$ |$$$$$$$$\     $$ |
     \______/ \______|   \__|   \__|      \__|  \__|\________|    \__|

    Author: repoog
    Version: 2.6
    Create Date: 2016-03-15
    Update Date: 2019-05-20
    Python Version: v3.6.4
    """

    def __init__(self, keyword):
        self.keyword = keyword
        self.search_url = "https://github.com/search?o=desc&p={page}&q={keyword}&ref=searchresults&s=indexed&type=Code&utf8=%E2%9C%93"
        self.headers = {'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36"}
        self.cookies = ""

    def search_project(self):
        """
        Search related projects with recently indexed sort according to keyword
        :returns: Related projects list
        """
        unique_project_list = []
        self.__auto_login(USER_NAME, PASSWORD)
        info_print('[*] Searching hard for projects...')

        # Get unique project list of first page searched results
        total_progress = SCAN_DEEP[SEARCH_LEVEL - 1]
        query_string = self.keyword + " in:file,path"
        for i in range(total_progress):
            # Print process of searching project
            progress_point = int((i + 1) * (100 / total_progress))
            sys.stdout.write(str(progress_point) + '%|' + '#' * progress_point + '|\r')
            sys.stdout.flush()
            # Search project in each page
            code_url = self.search_url.format(page=1, keyword=query_string)
            page_html_parse = self.__get_page_html(code_url)
            project_list = self.__page_project_list(page_html_parse)    # Project list of per result page
            page_project_num, project_list = len(project_list), list(set(project_list))
            unique_project_list.extend(project_list)    # Extend unique project list of per page
            if page_project_num < MAX_RLT_PER_PAGE:
                break
            project = " -repo:" + " -repo:".join(project_list)
            query_string += project
        # Deal with last progress bar stdout
        sys.stdout.write('100%|' + '#' * 100 + '|\r')
        sys.stdout.flush()
        return unique_project_list

    @staticmethod
    def __page_project_list(page_html):
        """
        Get project list of one searching result page
        :param page_html: Html page content
        :returns: Project list of per page
        """
        cur_par_html = BeautifulSoup(page_html, "lxml")
        project_info = cur_par_html.select("a.link-gray")
        page_project = [project.text.strip() for project in project_info]
        return page_project

    def sensitive_info_query(self, project_string, mode):
        """
        Search sensitive information and sensitive file from projects
        :param project_string: Key words string for querying
        :param mode: Searching mode within "content" or "filename"
        :returns: Code segments or file lists
        """
        if mode == "content":
            # Output code line with sensitive key words like username.
            info_sig_list = self.__pattern_db_list(INFO_DB)
            file_sig_list = self.__pattern_db_list(FILE_DB)
            file_pattern = " filename:" + " filename:".join(file_sig_list)
            code_dic = {}
            # Most five AND/OR operators in search function.
            for i in range(math.floor(len(info_sig_list)/5)+1):
                project_pattern = info_sig_list[i*5:i*5+5]
                repo_code_dic = self.__file_content_inspect(project_string, file_pattern, project_pattern)
                code_dic.update(repo_code_dic)
            return code_dic

        if mode == "filename":
            # Search project according to file path.
            path_sig_list = self.__pattern_db_list(PATH_DB)
            path_string = "filename:" + " filename:".join(path_sig_list) + project_string
            repo_file_dic = self.__file_name_inspect(path_string, print_mode=1)
            return repo_file_dic

    def __file_content_inspect(self, project_string, file_pattern, project_pattern):
        """
        Check sensitive code in particular project
        :param project_string: Projects for searching
        :param file_pattern: File string for searching
        :param project_pattern: Content signature match regular
        :returns: Code segments
        """
        query_string = " OR ".join(project_pattern)
        repo_file_dic = self.__file_name_inspect(query_string + project_string + file_pattern)
        repo_code_dic = {}
        for repo_name in repo_file_dic:
            self.__output_project_info(repo_name)
            repo_code_dic[repo_name] = {}  # Set code line dictionary
            for file_url in repo_file_dic[repo_name]:
                file_url_output = "[-] Compromise File: {file_url}"
                file_print(file_url_output.format(file_url=file_url))
                repo_code_dic[repo_name][file_url] = []  # Set code block of project file
                # Read codes from raw file by replace host to raw host.
                code_file = self.__get_page_html(file_url.replace(HOST_NAME, RAW_NAME).replace('blob/', ''))
                for code_line in code_file.split('\n'):
                    account_code = re.search('|'.join(project_pattern), code_line, re.I)
                    if account_code:
                        code_print(">> " + code_line.strip())
                        repo_code_dic[repo_name][file_url].append(code_line.encode('utf-8').strip())
                    else:
                        continue

        return repo_code_dic

    def __file_name_inspect(self, file_query_string, print_mode=0):
        """
        Inspect sensitive file in particular project
        :param file_query_string: File string for searching
        :param print_mode: 1 means print file, 0 means print code
        :returns: Files lists
        """
        page_num = 1
        repo_file_dic = {}
        while page_num <= SCAN_DEEP[SEARCH_LEVEL - 1]:
            check_url = self.search_url.format(page=page_num, keyword=file_query_string)
            page_html = self.__get_page_html(check_url)
            project_html = BeautifulSoup(page_html, 'lxml')
            repo_list = project_html.select('a[data-hydro-click-hmac]')
            if not repo_list:
                break
            # Handle file links for each project
            for repo in repo_list:
                file_url = repo.attrs['href']
                cur_project_name = "/".join(file_url.split("/")[1:3])
                if cur_project_name not in repo_file_dic.keys():
                    if print_mode:
                        self.__output_project_info(cur_project_name)
                        file_print("[-] Compromise File:")
                    repo_file_dic[cur_project_name] = []  # Set compromise project item
                else:
                    repo_file_dic[cur_project_name].append(HOST_NAME + file_url[1:])  # Set compromise project file item
                    if print_mode:
                        file_print(HOST_NAME + file_url[1:])
            page_num += 1

        return repo_file_dic

    @staticmethod
    def __pattern_db_list(file_path):
        """
        Read file name pattern item from signature file
        :param file_path: Pattern file path
        :returns: Signature item list
        """
        item_list = []
        with open(os.path.join(os.path.dirname(__file__), file_path), 'r') as pattern_file:
            item_line = pattern_file.readline()
            while item_line:
                item_list.append(item_line.strip())
                item_line = pattern_file.readline()
        return item_list

    @staticmethod
    def __output_project_info(project):
        """
        Output user information and project information of particular project
        :returns: None
        """
        user_name, project_name = project.split(r"/")
        user_info = "[+] User Nickname: {nickname}"
        project_print(user_info.format(nickname=user_name))
        project_info = "[+] Project Name: {name}"
        project_print(project_info.format(name=project_name))
        project_info = "[+] Project Link: {link}"
        project_print(project_info.format(link=HOST_NAME + project))

    def __auto_login(self, username, password):
        """
        Get cookie for logining GitHub
        :returns: None
        """
        login_request = requests.Session()
        login_html = login_request.get("https://github.com/login", headers=self.headers)
        post_data = {}
        soup = BeautifulSoup(login_html.text, "lxml")
        input_items = soup.find_all('input')
        for item in input_items:
            post_data[item.get('name')] = item.get('value')
        post_data['login'], post_data['password'] = username, password
        login_request.post("https://github.com/session", data=post_data, cookies=login_html.cookies, headers=self.headers)
        self.cookies = login_request.cookies
        if self.cookies['logged_in'] == 'no':
            error_print('[!] Error: Login Github failed, please check account in config file.')
            exit()

    def __get_page_html(self, url):
        """
        Get parse html page from requesting url
        :param url: Requesting url
        :returns: Parsed html page
        """
        try:
            page_html = requests.get(url, headers=self.headers, cookies=self.cookies, timeout=SCAN_DEEP[SEARCH_LEVEL - 1])
            if page_html.status_code == 429:
                time.sleep(SCAN_DEEP[SEARCH_LEVEL - 1])
                self.__get_page_html(url)
            return page_html.text
        except requests.ConnectionError as e:
            error_print("[!] Error: There is '%s' problem in requesting html page." % str(e))
            exit()
        except requests.ReadTimeout:
            return ''


def is_keyword_valid(keyword):
    """
    Verify input/config keywords are valid
    :param keyword: Keyword for searching
    :returns: False if invalid, True if valid
    """
    keyword_valid = re.match(r'^[a-zA-Z0-9].*$', keyword, re.I)
    if keyword_valid:
        return True
    else:
        return False


def init():
    """
    Initialize GitPrey with module inspection and input inspection
    :return: Key words
    """
    if not importlib.util.find_spec('lxml'):
        error_print('[!] Error: You have to install lxml module.')
        exit()

    # Get command parameters for searching level and key words
    parser = argparse.ArgumentParser(description="Searching sensitive file and content in GitHub.")
    parser.add_argument("-l", "--level", type=int, choices=range(1, 6), default=1, metavar="level", help="Set search level within 1~5, default is 1.")
    parser.add_argument("-k", "--keywords", metavar="keywords", required=True, help="Set key words to search projects.")
    args = parser.parse_args()

    SEARCH_LEVEL = args.level if args.level else 1
    key_words = args.keywords if args.keywords else ""

    # Print GitPrey digital logo and version information.
    info_print(GitPrey.__doc__)

    if not is_keyword_valid(key_words):
        error_print("[!] Error: The key word you input is invalid. Please try again.")
        exit()
    else:
        keyword_output = "[*] The key word for searching is: {keyword}"
        info_print(keyword_output.format(keyword=key_words))

    return key_words

def project_miner(key_words):
    """
    Search projects for content and path inspection later.
    :param key_words: key words for searching
    :return:
    """
    # Search projects according to key words and searching level
    _gitprey = GitPrey(key_words)
    total_project_list = _gitprey.search_project()

    project_info_output = "\n[*] Found {num} public projects related to the key words.\n"
    info_print(project_info_output.format(num=len(total_project_list)))

    if (len(total_project_list) == 0):
        exit(0)

    # Join all projects to together to search
    repo_string = " repo:" + " repo:".join(total_project_list)

    # Scan all projects with pattern filename
    info_print("[*] Begin searching sensitive file.")
    _gitprey.sensitive_info_query(repo_string, "filename")
    info_print("[*] Sensitive file searching is done.\n")

    # Scan all projects with pattern content
    info_print("[*] Begin searching sensitive content.")
    _gitprey.sensitive_info_query(repo_string, "content")
    info_print("[*] Sensitive content searching is done.\n")


if __name__ == "__main__":
    # Initialize key words input.
    key_words = init()
    # Search related projects depend on key words.
    project_miner(key_words)
