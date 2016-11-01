#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    print "[!_!]ERROR INFO: You have to install requests module."
    exit()

try:
    from bs4 import BeautifulSoup
except ImportError:
    print "[!_!]ERROR INFO: You have to install BeautifulSoup module."
    exit()

import sys
import re
import time
import imp
import getopt

try:
    from config.Config import *
except ImportError:
    print "[!_!]ERROR INFO: Can't find Config file for searching."
    exit()

try:
    from include.ColorPrint import *
except ImportError:
    print "[!_!]ERROR INFO: Can't find ColorPrint file for printing."
    exit()


HOST_NAME = "https://github.com/"
SCAN_DEEP = [10, 30, 50, 70, 100]  # Scanning deep according to page searching count and time out seconds
SEARCH_LEVEL = 1  # Code searching level within 1-5, default is 1
MAX_PAGE_NUM = 100  # Maximum results of code searching
MAX_RLT_PER_PAGE = 10  # Maximum results count of per page


class GitPrey(object):
    """
     $$$$$$\  $$$$$$\ $$$$$$$$\       $$$$$$$\  $$$$$$$\  $$$$$$$$\ $$\     $$ \\
    $$  __$$\ \_$$  _|\__$$  __|      $$  __$$\ $$  __$$\ $$  _____|\$$\   $$  |
    $$ /  \__|  $$ |     $$ |         $$ |  $$ |$$ |  $$ |$$ |       \$$\ $$  /
    $$ |$$$$\   $$ |     $$ |         $$$$$$$  |$$$$$$$  |$$$$$\      \$$$$  /
    $$ |\_$$ |  $$ |     $$ |         $$  ____/ $$  __$$< $$  __|      \$$  /
    $$ |  $$ |  $$ |     $$ |         $$ |      $$ |  $$ |$$ |          $$ |
    \$$$$$$  |$$$$$$\    $$ |         $$ |      $$ |  $$ |$$$$$$$$\     $$ |
     \______/ \______|   \__|         \__|      \__|  \__|\________|    \__|

    Author; Cooper Pei
    Version: 2.4
    Create Date: 2016-03-15
    Update Date: 2016-11-05
    Python Version: v2.7.10
    """

    def __init__(self, keyword):
        self.keyword = keyword
        self.search_url = "https://github.com/search?o=desc&p={page}&q={keyword}&ref=searchresults&s=indexed&type=Code&utf8=%E2%9C%93"
        self.headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36"}
        self.cookies = ""

    def search_project(self):
        """
        Search related projects with recently indexed sort according to keyword
        :returns: Related projects list
        """
        unique_project_list = []
        self.__auto_login(USER_NAME, PASSWORD)
        info_print('[@_@]Searching related projects hard...')
        # Get unique project list of first page searched results
        query_string = self.keyword + " in:file,path"
        for i in xrange(SCAN_DEEP[SEARCH_LEVEL - 1]):
            # Print process of searching project
            total_progress = SCAN_DEEP[SEARCH_LEVEL - 1]
            progress_point = int((i + 1) * (100 / total_progress))
            sys.stdout.write(str(progress_point) + '%|' + '#' * progress_point + '|\r')
            sys.stdout.flush()
            # Search project in each page
            code_url = self.search_url.format(page=1, keyword=query_string)
            page_html_parse = self.__get_page_html(code_url)
            project_list = self.__page_project_list(page_html_parse)
            page_project_num = len(project_list)
            project_list = list(set(project_list))
            unique_project_list.extend(project_list)
            if page_project_num < MAX_RLT_PER_PAGE:
                break
            project = " -repo:"
            project = project.join(project_list)
            project = " -repo:" + project
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
        page_project = []
        cur_par_html = BeautifulSoup(page_html, "lxml")
        project_info = cur_par_html.select("p.title > a:nth-of-type(1)")
        for key, project in enumerate(project_info):
            page_project.append(project.text)
        return page_project

    def sensitive_info_query(self, project_string, mode):
        """
        Search sensitive information and sensitive file of project
        :param project_string: Key words string for querying
        :param mode: Searching mode within "content" or "filename"
        :returns: None
        """
        if mode == "content":
            # Search project according to password and filename words.
            pass_sig_list = self.__pattern_db_list(PASS_DB)
            split_string = " OR "
            pass_string = split_string.join(pass_sig_list)
            file_sig_list = self.__pattern_db_list(FILE_DB)
            split_string = " filename:"
            content_string = split_string.join(file_sig_list)
            content_string = pass_string + split_string + content_string + project_string

            # Output code line with sensitive key words like username.
            info_sig_list = self.__pattern_db_list(INFO_DB)
            info_sig_list.extend(pass_sig_list)
            self.__file_content_inspect(content_string, info_sig_list)

        if mode == "filename":
            # Search project according to file path.
            path_sig_list = self.__pattern_db_list(PATH_DB)
            split_string = " filename:"
            path_string = split_string.join(path_sig_list)
            path_string = split_string + path_string + project_string
            self.__file_name_inspect(path_string)

    def __file_content_inspect(self, content_query_string, info_sig_list):
        """
        Check sensitive code in particular project
        :param content_query_string: Content string for searching
        :returns: None
        """
        re_match = "|".join(info_sig_list)
        page_num = 1
        while page_num <= MAX_PAGE_NUM:
            check_url = self.search_url.format(page=page_num, keyword=content_query_string)
            page_html = self.__get_page_html(check_url)
            file_info = BeautifulSoup(page_html, 'lxml')
            code_frag = file_info.select('tr .blob-code.blob-code-inner')
            if not code_frag:
                break
            project_info = project_file_url = ""
            for key, code_line in enumerate(code_frag):
                cur_file_url = code_line.previous_sibling.previous_sibling.a['href'].split("#")[0]
                cur_project_info = "/".join(cur_file_url.split("/")[1:3])
                # Deal with code content for every project
                if project_info != cur_project_info:
                    project_info = cur_project_info
                    self.__output_project_info(cur_project_info)
                if project_file_url != cur_file_url:
                    project_file_url = cur_file_url
                    file_url_output = "[-]Compromise File: {file_url}"
                    file_print(file_url_output.format(file_url=HOST_NAME + cur_file_url[1:]))
                account_code = re.search(re_match, code_line.text, re.I)
                if account_code:
                    code_print(">> " + code_line.text.encode('utf-8').strip())
                else:
                    continue
            page_num += 1

    def __file_name_inspect(self, file_query_string):
        """
        Inspect sensitive file in particular project
        :param file_query_string: File string for searching
        :returns: None
        """
        page_num = 1
        while page_num <= MAX_PAGE_NUM:
            check_url = self.search_url.format(page=page_num, keyword=file_query_string)
            page_html = self.__get_page_html(check_url)
            project_html = BeautifulSoup(page_html, 'lxml')
            repo_list = project_html.select('div .full-path > a')
            if not repo_list:
                break
            project_info = ""
            for key, repo in enumerate(repo_list):
                file_url = repo.attrs['href']
                cur_project_info = "/".join(file_url.split("/")[1:3])
                # Deal with code content for every project
                if project_info != cur_project_info:
                    project_info = cur_project_info
                    self.__output_project_info(cur_project_info)
                    file_print("[-]Compromise File:")
                file_print(HOST_NAME + file_url[1:])
            page_num += 1

    @staticmethod
    def __pattern_db_list(file_path):
        """
        Read file name pattern item from signature file
        :param file_path: Pattern file path
        :returns: Signature item list
        """
        item_list = []
        with open(file_path, 'r') as pattern_file:
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
        user_info = "[+_+]User Nickname: {nickname}"
        project_print(user_info.format(nickname=user_name))
        project_info = "[+_+]Project Name: {name}\n[+_+]Project Link: {link}"
        project_print(project_info.format(name=project_name, link=HOST_NAME + project))

    def output_user_info(self, username):
        """
        Output detail information of specific username
        :param username: Specific username
        :return: User information include nickname, real name, avatar and email
        """
        user_info_dic = {}
        page_html = self.__get_page_html(HOST_NAME + username)
        parse_file = BeautifulSoup(page_html, 'lxml')
        user_info_dic['nickname'] = username
        # Get real name from personal page
        realname = parse_file.select('div .vcard-fullname')
        if realname:
            user_info_dic['realname'] = realname[0].text.encode('utf-8')
        else:
            user_info_dic['realname'] = ''
        # Get avatar from personal page
        avatar = parse_file.select('a[itemprop="image"]')
        if avatar:
            user_info_dic['avatar'] = avatar[0].attrs['href'].encode('utf-8')
        else:
            avatar = parse_file.select('img[itemprop="image"]')
            user_info_dic['avatar'] = avatar[0].attrs['src'].encode('utf-8')
        # Get email from personal page
        email = parse_file.select('ul .vcard-detail a[href^="mailto"]')
        if email:
            user_info_dic['email'] = email[0].text.encode('utf-8')
        else:
            user_info_dic['email'] = ''
        return user_info_dic

    def __auto_login(self, username, password):
        """
        Get cookie for auto login GitHub
        :returns: None
        """
        login_request = requests.Session()
        login_html = login_request.get("https://github.com/login", headers=self.headers)
        post_data = {}
        soup = BeautifulSoup(login_html.text, "lxml")
        input_items = soup.find('form').findAll('input')
        for item in input_items:
            post_data[item.get('name')] = item.get('value')
        post_data['login'] = username
        post_data['password'] = password
        login_request.post("https://github.com/session", data=post_data, headers=self.headers)
        self.cookies = login_request.cookies

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
        except requests.ConnectionError:
            error_print("[!_!]ERROR INFO: There is a problem in requesting html page.")
            exit()


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


def is_level_valid(level):
    """
    Verify search level config is valid
    :param level: Search level
    :returns: False if invalid, True if valid
    """
    if isinstance(level, int) and level in range(1, 6):
        return True
    else:
        return False


def usage():
    print 'USAGE:'
    print '\t-l\tSet level for searching within 1~5, default level is 1.'
    print '\t-k\tSet key words for searching projects.'
    print '\t-h\tShow help information.'
    exit()

if __name__ == "__main__":
    # Verify lxml module is installed
    try:
        imp.find_module('lxml')
    except ImportError:
        error_print('[!_!]ERROR INFO: You have to install lxml module.')
        exit()

    # Get command parameters for searching level and key words
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hl:k:")
        if not opts:
            usage()
    except getopt.GetoptError:
        usage()

    keyword_string = ""
    execution_user = ""
    for op, value in opts:
        if op == '-l':
            SEARCH_LEVEL = int(value)
        elif op == '-k':
            keyword_string = value
        elif op == '-h':
            usage()

    # Print GitPrey digital logo and version information.
    info_print(GitPrey.__doc__)

    if not is_keyword_valid(keyword_string):
        error_print("[!_!]ERROR INFO: The key words you input are invalid. Please input again.")
        exit()
    elif not is_level_valid(SEARCH_LEVEL):
        error_print("[!_!]ERROR INFO: Searching level must in 1~5.")
        exit()
    else:
        keyword_output = "[^_^]START INFO: The key words for searching are: {keyword}"
        info_print(keyword_output.format(keyword=keyword_string))

    # Search projects according to key words and searching level
    total_project_list = []
    _gitprey = GitPrey(keyword_string)
    total_project_list = _gitprey.search_project()
    project_info_output = "\n[*_*]PROJECT INFO: Found {num} public projects related to the key words.\n"
    info_print(project_info_output.format(num=len(total_project_list)))
    if not total_project_list:
        exit()

    # Join all projects to together to search
    split_string = " repo:"
    repo_string = split_string.join(total_project_list)
    repo_string = split_string + repo_string

    # Scan all projects with pattern filename
    info_print("[^_^]START INFO: Begin searching sensitive file.")
    _gitprey.sensitive_info_query(repo_string, "filename")
    info_print("[^_^]END INFO: Sensitive file searching is done.\n")

    # Scan all projects with pattern content
    info_print("[^_^]START INFO: Begin searching sensitive content.")
    _gitprey.sensitive_info_query(repo_string, "content")
    info_print("[^_^]END INFO: Sensitive content searching is done.\n")
