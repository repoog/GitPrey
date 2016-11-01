#!/usr/bin/env python
# -*- coding: utf-8 -*-


def error_print(string):
    # Print error information with red color
    print "\033[1;31;40m%s\033[0m" % string


def info_print(string):
    # Print information with green color
    print "\033[1;32;40m%s\033[0m" % string


def project_print(string):
    # Print project information with deep green color
    print "\033[1;36;40m%s\033[0m" % string


def file_print(string):
    # Print file url with yellow color
    print "\033[1;33;40m%s\033[0m" % string


def code_print(string):
    # Print code line with white color
    print "\033[1;37;40m%s\033[0m" % string


if __name__ == "__main__":
    pass
