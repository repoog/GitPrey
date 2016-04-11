#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
from bs4 import BeautifulSoup
import re
import json
import time
from requests.auth import HTTPBasicAuth
from Config import *
from ColorPrint import *

SCAN_DEEP = [10, 30, 50, 70, 100]      # scan deep according to page searching count and time out seconds
MAX_PAGE_NUM = 100     # maximum results of code searching
MAX_RLT_PER_PAGE = 10   # maximum results count of per page
HOST_NAME = "https://github.com"

unique_project_list = []
file_sig_list = []
info_sig_list = ['config', 'credential', 'properties', 'backup', 'dump', 'password', 'secret', 'setting', 'log', 'sql']
user_sig_list = ['ip', 'host', 'domain', 'url', 'proxy', 'port', 'auth', 'user', 'login', 'email', 'jdbc']
pass_sig_list = ['password', 'passwd', 'pass', 'pwd']

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
    Version: 2.1
    Create Date: 2016-03-31
    Python Version: v2.7.10
    """
    def __init__(self, keyword):
        self.keyword = keyword
        self.search_url = "https://github.com/search?o=desc&p={page}&q={keyword}&ref=searchresults&s=indexed&type=Code&utf8=%E2%9C%93"
        self.user_info_url = "https://api.github.com/users/{username}"
        self.headers = {'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36"}
        self.cookies = ""

    def search_project(self):
        """
        Search related projects with recently indexed sort according to keyword
        Returns: return related projects queue
        """
        global unique_project_list
        self.__auto_login_github(USER_NAME, PASSWORD)
        # Get unique project info of first page search results
        query_string = self.keyword + " in:file,path"
        for i in xrange(SCAN_DEEP[SEARCH_LEVEL-1]):
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

    def __page_project_list(self, page_html):
        """
        Get project list of one searching result page
        Returns: project list of per page
        """
        page_project = []
        cur_par_html = BeautifulSoup(page_html, "lxml")
        project_info = cur_par_html.select("p.title > a:nth-of-type(1)")
        for project in project_info:
            page_project.append(project.text)
        return page_project

    def sensitive_info_check(self, keyword_string, mode):
        """
        Search sensitive information and sensitive file of project
        Returns: None
        """
        if mode == "content":
            content_keyword_string = keyword_string
            for file in info_sig_list:
                content_keyword_string += " filename:" + file
            self.__file_content_check(content_keyword_string)

        if mode == "filename":
            global file_sig_list
            file_sig_list = self.__pattern_db_list("PATTERN_DB/path.db")
            file_keyword_string = keyword_string
            for file in file_sig_list:
                file_keyword_string += " filename:" + file
            self.__file_name_check(file_keyword_string)

    def __file_content_check(self, keyword_string):
        """
        Check sensitive code in particular project
        Returns: None
        """
        user_sig_list.extend(pass_sig_list)
        re_match = "|".join(user_sig_list)
        page_num = 1
        while page_num <= MAX_PAGE_NUM:
            check_url = self.search_url.format(page=page_num, keyword=keyword_string)
            page_html = self.__get_page_html(check_url)
            file_info = BeautifulSoup(page_html, 'lxml')
            code_frag = file_info.select('tr .blob-code.blob-code-inner')
            if not code_frag:
                break
            project_info = project_file_url =""
            for code_line in code_frag:
                cur_file_url = code_line.previous_sibling.previous_sibling.a['href'].split("#")[0]
                cur_project_info = "/".join(cur_file_url.split("/")[1:3])
                # deal with code content for every project
                if project_info != cur_project_info:
                    project_info = cur_project_info
                    self.__output_project_info(cur_project_info)
                if project_file_url != cur_file_url:
                    project_file_url = cur_file_url
                    file_url_output = "[-]Compromise File: {file_url}"
                    FilePrint(file_url_output.format(file_url=HOST_NAME + cur_file_url))
                account_code = re.search(re_match, code_line.text, re.I)
                if account_code:
                    CodePrint(">> " + code_line.text.strip())
                else:
                    continue
            page_num += 1

    def __file_name_check(self, keyword_string):
        """
        Check sensitive file in particular project
        Returns: None
        """
        page_num = 1
        while page_num <= MAX_PAGE_NUM:
            check_url = self.search_url.format(page=page_num, keyword=keyword_string)
            page_html = self.__get_page_html(check_url)
            file_name = BeautifulSoup(page_html, 'lxml')
            file_name_list = file_name.select('div .full-path > a')
            if not file_name_list:
                break
            project_info = ""
            for file in file_name_list:
                file_url = file.attrs['href']
                cur_project_info = "/".join(file_url.split("/")[1:3])
                # deal with code content for every project
                if project_info != cur_project_info:
                    project_info = cur_project_info
                    self.__output_project_info(cur_project_info)
                    FilePrint("[-]Compromise File:")
                FilePrint(HOST_NAME + file_url)
            page_num += 1

    def __pattern_db_list(self, file_path):
        """
        Read file name pattern item from signature file
        Returns: signature item list
        """
        item_list = []
        file = open(file_path, 'r')
        try:
            item_line = file.readline()
            while item_line:
                item_list.append(item_line.strip())
                item_line = file.readline()
        finally:
            file.close()
        return item_list

    def __output_project_info(self, project):
        """
        Output user information and project information of particular project
        Returns: None
        """
        user_name, project_name = project.split(r"/")
        user_info_url = self.user_info_url.format(username=user_name)
        user_page = self.__get_page_html(user_info_url, token=ACCESS_TOKEN)
        user_data = json.loads(user_page)
        user_info_ouput = "[+_+]User Nickname: {nickname}\n[+_+]User Realname: {realname}\n[+_+]Avatar Link: {avatar}\n[+_+]Email Address: {email}"
        ProjectPrint(user_info_ouput.format(nickname=user_data["login"], realname=user_data["name"], avatar=user_data["avatar_url"], email=user_data["email"]))
        project_info_output = "[+_+]Project Name: {name}\n[+_+]Project Link: {link}"
        ProjectPrint(project_info_output.format(name=project_name, link=HOST_NAME + "/" + project))

    def __auto_login_github(self, username, password):
        """
        Get cookie for auto login github
        Returns: none
        """
        login_request = requests.Session()
        login_html = login_request.get("https://github.com/login", headers=self.headers)
        post_data = {}
        soup = BeautifulSoup(login_html.text, "lxml")
        inputs = soup.find('form').findAll('input')
        for input in inputs:
            name = input.get('name')
            value = input.get('value')
            post_data[name] = value
        post_data['login'] = username
        post_data['password'] = password
        login_request.post("https://github.com/session", data=post_data, headers=self.headers)
        self.cookies= login_request.cookies

    def __get_page_html(self, url, token=None):
        """
        Get parse html page from requesting url
        Returns: parse html page
        """
        try:
            if token:
                auth = HTTPBasicAuth(USER_NAME, token)
                page_html = requests.get(url, headers=self.headers, cookies=self.cookies, auth=auth)
                if page_html.status_code == 429:
                    time.sleep(SCAN_DEEP[SEARCH_LEVEL-1])
                    self.__get_page_html(url, token)
            else:
                page_html = requests.get(url, headers=self.headers, cookies=self.cookies, timeout=SCAN_DEEP[SEARCH_LEVEL-1])
                if page_html.status_code == 429:
                    time.sleep(SCAN_DEEP[SEARCH_LEVEL-1])
                    self.__get_page_html(url)

        except requests.exceptions.ConnectionError:
            ErrorPrint("[!_!]SOMETHING IS WRONG.")
            exit()
        except requests.exceptions.ConnectTimeout:
            pass
        except requests.exceptions.RequestException:
            pass
        return page_html.text

def is_keyword_valid(keyword):
    """
    Check keyword input/config is valid or invalid
    Returns: False if invalid, True if valid
    """
    if keyword.strip() == "" or keyword is None:
        return False
    else:
        return True

def is_level_valid(level):
    """
    Check search level config is valid or invalid
    Returns: False if invalid, True if valid
    """
    if isinstance(level, int) and level in range(1, 6):
        return True
    else:
        return False

if __name__ == "__main__":
    InfoPrint(GitPrey.__doc__)

    # get key word config or input key word
    if not is_keyword_valid(KEY_WORD):
        keyword = raw_input("[*_*]Please input keywords of company for searching: ")
        if not is_keyword_valid(keyword):
            ErrorPrint("[!_!]ERROR INFO: There is not any key word.Please try again.")
            exit()
    else:
        keyword = KEY_WORD
        keyword_output = "[^_^]The configure keywords are: {keyword}"
        InfoPrint(keyword_output.format(keyword=keyword))

    # get search level config
    if not is_level_valid(SEARCH_LEVEL):
        ErrorPrint("[!_!]ERROR INFO: Search level config is invalid.")
        exit()

    # search projects according to key word and searching level
    _gitprey = GitPrey(keyword)
    _gitprey.search_project()
    if unique_project_list:
        project_info_output = "[*_*]PROJECT INFO: Found {num} public projects relating to the key word."
        InfoPrint(project_info_output.format(num=len(unique_project_list)))
    else:
        InfoPrint("[^_^]END INFO: There is not any project relating to the key word.")
        exit()

    keyword_string = " repo:"
    keyword_string = keyword_string.join(unique_project_list)
    keyword_string = " repo:" + keyword_string
    # scan all projects with pattern content
    pass_string = " OR "
    pass_string = pass_string.join(pass_sig_list)
    content_keyword_string = pass_string + keyword_string
    _gitprey.sensitive_info_check(content_keyword_string, "content")

    # scan all projects with pattern filename
    _gitprey.sensitive_info_check(keyword_string, "filename")