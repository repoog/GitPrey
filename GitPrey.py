#!/usr/bin/env python
# -*- coding: utf-8 -*-

import Queue
from urllib import quote
import urllib
import urllib2
from bs4 import BeautifulSoup
import threading
import cookielib
import json
import base64
from Config import *

MAX_PAGE_NUM = [10, 20, 50, 70, 100]  # maximum page number of github project searching
MAX_CODE_PAGE = 100     # maximum results of code searching
MAX_RLT_PER_PAGE = 10   # maximum results count of per page
HOST_NAME = "https://github.com/"

project_queue = Queue.Queue(0)
cookie = cookielib.CookieJar()
request_time = 0

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
    Version: 2.0
    Create Date: 2016-03-16
    Python Version: v2.7.10
    """
    def __init__(self, keyword):
        self.keyword = quote(keyword)
        self.search_url = "https://github.com/search?o=desc&p={page}&q={keyword}+in%3Afile%2Cpath&ref=searchresults&type=Code&utf8=%E2%9C%93"
        self.user_info_url = "https://api.github.com/users/{username}"
        self.filename_check_url = "https://github.com/{project}/search?p={page}&utf8=%E2%9C%93&q=filename%3A{filename}"
        self.content_check_url = "https://github.com/{project}/search?p={page}&utf8=%E2%9C%93&q={content}%20in:file"

    def search_project(self):
        """
        Search related projects with recently indexed sort according to keyword
        Returns: return related projects queue
        """
        self.__auto_login_github(USER_NAME, PASSWORD)  # get cookie of logining for crawling projects
        for i in range(1, MAX_PAGE_NUM[SEARCH_LEVEL]+1):
            code_url = self.search_url.format(page=i, keyword=self.keyword)
            page_html = self.__get_page_html(code_url)
            cur_par_html = BeautifulSoup(page_html, "html.parser")
            project_info = cur_par_html.select("p.title > a:nth-of-type(1)")
            project_count = len(project_info)
            for j in range(0, project_count):
                if project_info[j].string not in project_queue.queue:
                    project_queue.put(project_info[j].string)
            # deal the last page results with quiting page crawler
            if project_count < MAX_RLT_PER_PAGE:
                break

    def sensitive_info_check(self, project_info):
        """
        Search sensitive information of project
        Returns: None
        """
        self.__output_project_info(project_info)
        self.__path_name_check(project_info)
        self.__file_content_check(project_info)

    def __path_name_check(self, project):
        """
        Check sensitive filename items in particular project
        Returns: None
        """
        item_list = self.__pattern_db_list("PATTERN_DB/path.db")
        for i in xrange(len(item_list)):
            info_dic = {}
            for j in range(1, MAX_CODE_PAGE+1):
                check_url = self.filename_check_url.format(project=project, page=j, filename=item_list[i])
                page_html = self.__get_page_html(check_url)
                cur_par_html = BeautifulSoup(page_html, "html.parser")
                file_info = cur_par_html.select("p.title > a:nth-of-type(1)")
                file_count = len(file_info)
                for file in file_info:
                    name = file.get("title")
                    html_url = file.get("href")
                    info_dic[name] = html_url
                self.__output_match_result(info_dic)
                # deal the last page results with quiting page crawler
                if file_count < MAX_RLT_PER_PAGE:
                    break

    def __file_content_check(self, project):
        """
        Check sensitive content items in particular project
        Returns: None
        """
        item_list = self.__pattern_db_list("PATTERN_DB/content.db")
        for i in xrange(len(item_list)):
            info_dic = {}
            for j in range(1, MAX_CODE_PAGE+1):
                check_url = self.content_check_url.format(project=project, page=j, content=item_list[i])
                page_html = self.__get_page_html(check_url)
                cur_par_html = BeautifulSoup(page_html, "html.parser")
                file_info = cur_par_html.select("p.title > a:nth-of-type(1)")
                file_count = len(file_info)
                for file in file_info:
                    name = file.get("title")
                    html_url = file.get("href")
                    info_dic[name] = html_url
                self.__output_match_result(info_dic, item=item_list[i])
                # deal the last page results with quiting page crawler
                if file_count < MAX_RLT_PER_PAGE:
                    break

    def __pattern_db_list(self, file_path):
        """
        Read pattern item from signature file
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
        print "[+_+]User Nickname: %s" % user_data["login"]
        print "[+_+]User Realname: %s" % user_data["name"]
        print "[+_+]Avatar Link: %s" % user_data["avatar_url"]
        print "[+_+]Email Address: %s" % user_data["email"]
        print "[+_+]Project Name: %s" % project_name
        print "[+_+]Project Link: %s%s" % (HOST_NAME, project)

    def __output_match_result(self, file_dic, item=None):
        """
        Output matching results from particular json data
        Returns: None
        """
        for key in file_dic:
            if item:
                print "[-]Sensitive Word: %s" % item
                print "[-]Compromise File: %s" % key
            else:
                print "[-]Sensitive File: %s" % key
            print "[-]Compromise URL: %s%s" % (HOST_NAME, file_dic[key])

    def __auto_login_github(self, username, password):
        """
        Get cookie for auto login github
        Returns: cookie
        """
        parse_html = self.__get_page_html("https://github.com/login")
        post_data = self.__get_hidden_form_data(parse_html)
        post_data['login'] = username
        post_data['password'] = password
        del post_data['utf8']
        self.__get_page_html("https://github.com/session", post_data)

    def __get_page_html(self, url, data={}, token=None):
        """
        Get parse html page from requesting url
        Returns: parse html page
        """
        url = url.strip()
        handler = urllib2.HTTPCookieProcessor(cookie)
        opener = urllib2.build_opener(handler)
        headers = {'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36"}
        if data:
            postdata = urllib.urlencode(data)
            request = urllib2.Request(url, data=postdata, headers=headers)
        else:
            request = urllib2.Request(url, headers=headers)
        if token:
            base64string = base64.encodestring('%s:%s' % (USER_NAME, token)).strip()
            request.add_header("Authorization", "Basic %s" % base64string)
        try:
            page_html = opener.open(request).read()
        except urllib2.URLError, e:
            print "Error code: %s\nError reason: %s" % (e.code, e.reason)
            exit()
        return page_html

    def __get_hidden_form_data(self, html_page):
        """
        Get hidden item from form table in html page
        Returns: default post data dictionary
        """
        data = {}
        soup = BeautifulSoup(html_page, "html.parser")
        inputs = soup.find('form').findAll('input')
        for input in inputs:
            name = input.get('name')
            value = input.get('value')
            data[name] = value
        return data

class MultipleThread(threading.Thread):
    def __init__(self, target):
        super(MultipleThread, self).__init__()
        self.target = target

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
    print GitPrey.__doc__

    # get key word config or input key word
    if not is_keyword_valid(KEY_WORD):
        keyword = raw_input("[*_*]Please input keywords of company for searching: ")
        if not is_keyword_valid(keyword):
            print "[!_!]ERROR INFO: There is not any key word.Please try again."
            exit()
    else:
        keyword = KEY_WORD

    # get search level config
    if not is_level_valid(SEARCH_LEVEL):
        print "[!_!]ERROR INFO: search level config is invalid."
        exit()

    # search projects according to key word and searching level
    _gitprey = GitPrey(keyword)
    _gitprey.search_project()
    if not project_queue.empty():
        project_queue_size = project_queue.qsize()
        print "[^_^]PROJECT INFO: Found [%d] public projects relating to the key word." % project_queue_size
    else:
        print "[^_^]END INFO: There is not any project relating to the key word."
        exit()

    # scan all projects with pattern path and pattern content
    thread_list = []
    for i in xrange(project_queue_size):
        thread = MultipleThread(_gitprey.sensitive_info_check(project_queue.get()))
        thread.start()
        thread_list.append(thread)
    for thread in thread_list:
        thread.join()