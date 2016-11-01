#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from config.Config import *
except ImportError:
    print "[!_!]ERROR INFO: Can't find Config file for searching."
    exit()

def error_print(string):
    # Print error information with red color
    print "\033[1;31;40m%s\033[0m" % string


def info_print(string):
    # Print information with green color
    print "\033[1;32;40m%s\033[0m" % string


def project_print(string):
    # Print project information with deep green color
    print "\033[1;36;40m%s\033[0m" % string
    __output_result(string)


def file_print(string):
    # Print file url with yellow color
    print "\033[1;33;40m%s\033[0m" % string
    __output_result(string)


def code_print(string):
    # Print code line with white color
    print "\033[1;37;40m%s\033[0m" % string
    __output_result(string)


def __output_result(string):
    """
    Output search results to text file
    :param results: search results
    :return: None
    """
    with open(OUTPUT_FILE, 'a+') as file_obj:
        file_obj.write(string + '\r\n')

if __name__ == "__main__":
    pass
