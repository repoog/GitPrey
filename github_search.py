# coding = UTF-8
import requests
import bs4
from bs4 import BeautifulSoup
import re

# there are 10 results in each results page
PAGE_RESULT_COUNT = 10
# GitHub host name
GITHUB_HOST = "https://github.com"

# input key words for searching
key_words = raw_input("Please input key words with plus sign for searching:")
if key_words is None:
    print "Please input key words with plus sign for searching again."
    exit()

# get information count
pre_res_html = requests.get("https://github.com/search?o=desc&q=" + key_words +"&ref=searchresults&s=indexed&type=Code&utf8=%E2%9C%93")
if pre_res_html.status_code != 200:
    print "Requesting URL is with wrong response status."
    exit()
pre_par_html = bs4.BeautifulSoup(pre_res_html.text, "html.parser")

# print search results counts
links_sum = pre_par_html.select('div.sort-bar h3')
links_sum = links_sum[0].string
reg_num = re.compile("\w\d")
rlt_count = int(reg_num.search(links_sum).group())
print "The links results count is: %d" % rlt_count

# get results page count
if rlt_count % PAGE_RESULT_COUNT != 0:
    page_count = rlt_count / PAGE_RESULT_COUNT + 1
else:
    page_count = rlt_coutn / PAGE_RESULT_COUNT

# print linking contents in results with looping page's results
page_num = 1    # page number of all pages
rlt_num = 1     # result number of all results
for page_num in range(1, page_count + 1):
    # get html text from each page
    res_html = requests.get("https://github.com/search?o=desc&p=" + str(page_num) + "&q=" + key_words + "&ref=searchresults&s=indexed&type=Code&utf8=%E2%9C%93")
    par_html = bs4.BeautifulSoup(res_html.text, "html.parser")
    project_info = par_html.select('p.title a')
    index_info = par_html.select('p.title span > time')

    page_rlt_num = 0     # result number of each page results
    while (page_rlt_num < PAGE_RESULT_COUNT * 2) and (rlt_num <= rlt_count):
        user_name = project_info[page_rlt_num].string
        file_name = project_info[page_rlt_num + 1].string
        file_url = GITHUB_HOST + project_info[page_rlt_num + 1]['href']
        index_time = index_info[page_rlt_num / 2]['datetime']
        print "%dth result list:" % rlt_num
        print "\tindex time: %s" % index_time
        print "\tusername/project: %s" % user_name
        print "\tsuspected file name: %s" % file_name
        print "\tsuspected file URL: %s" % file_url

        page_rlt_num += 2
        rlt_num += 1