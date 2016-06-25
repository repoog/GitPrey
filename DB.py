#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    import MySQLdb
except ImportError:
    print "[!_!]ERROR INFO: You need to install MySQLdb module."
    exit()

try:
    from Config import *
except ImportError:
    print "[!_!]ERROR INFO: Missing Config file or ColorPrint file."
    exit()

HOST_NAME = "https://github.com/"

class DBOP(object):
    """
    MySQL operation class for logging command logs and searching logs
    """
    def __init__(self):
        self.db = MySQLdb.connect(HOST, USER, PASS, DATABASE, PORT, charset='utf8')
        self.cursor = self.db.cursor()

    def __del__(self):
        self.db.close()

    def record_command_log(self, pra_level, pra_keywords, pra_date):
        """
        Record command executing information which includes search level,keywords and executed date
        :param pra_level: Searching level
        :param pra_keywords: Searching keywords
        :param pra_date: Executing date
        :return: None
        """
        command_log_sql = 'INSERT INTO prey_execution_log(search_level, search_keyword, execute_date) ' \
                          'VALUES(%s, %s, %s)'

        self.cursor.execute(command_log_sql, (pra_level, pra_keywords, pra_date))
        self.db.commit()

    def record_project_info(self, project_list):
        """
        Record projects information which includes project name and project url
        :param project_list: Projects list
        :return: None
        """
        project_info_sql = 'INSERT INTO prey_related_projects(uid, eid, project_name, project_url) ' \
                           'VALUES (%s, %s, %s, %s)'

        project_info_pram = []
        for project in project_list:
            uid_eid_sql = 'SELECT MAX(uid), MAX(eid) FROM prey_related_users WHERE nickname = %s'
            self.cursor.execute(uid_eid_sql, [project.split("/")[0]])
            uid_eid = self.cursor.fetchone()
            project_info_pram.append([uid_eid[0], uid_eid[1], project, HOST_NAME + project])

        self.cursor.executemany(project_info_sql, project_info_pram)
        self.db.commit()

    def record_user_info(self, user_list):
        """
        Record user information which includes nickname, realname, avatar url and email,
        :param user_list: User information dictionary list
        :return: None
        """
        user_info_sql = 'INSERT INTO prey_related_users(eid, nickname, realname, avatar, email) ' \
                        'VALUES(%s, %s, %s, %s, %s)'

        user_info_pram = []
        for user in user_list:
            eid_sql = 'SELECT MAX(eid) FROM prey_execution_log'
            self.cursor.execute(eid_sql)
            eid = self.cursor.fetchone()
            user_info_pram.append([eid[0], user['nickname'], user['realname'], user['avatar'], user['email']])

        self.cursor.executemany(user_info_sql, user_info_pram)
        self.db.commit()

    def record_compromise_file(self, repo_file_dic):
        """
        Record compromise files which includes file name and file url
        :param repo_file_dic: Project dictionary of files
        :return: None
        """
        compromise_file_sql = 'INSERT INTO prey_pattern_files(pid, eid, file_url) ' \
                              'VALUES(%s, %s, %s)'

        file_info_pram = []
        for repo in repo_file_dic:
            pid_eid_sql = 'SELECT MAX(pid), MAX(eid) FROM prey_related_projects WHERE project_name = %s'
            self.cursor.execute(pid_eid_sql, [repo])
            pid_eid = self.cursor.fetchone()
            for file_url in repo_file_dic[repo]:
                file_info_pram.append([pid_eid[0], str(pid_eid[1]), file_url])

        self.cursor.executemany(compromise_file_sql, file_info_pram)
        self.db.commit()

    def record_code_block(self, repo_code_dic):
        """
        Record compromise code blocks which includes file url and code blocks
        :param repo_code_dic: Project dictionary of code blocks
        :return: None
        """
        code_block_sql = 'INSERT INTO prey_code_blocks(pid, eid, file_url, code_block)' \
                         'VALUES(%s, %s, %s, %s)'

        code_block_pram = []
        for repo in repo_code_dic:
            pid_eid_sql = 'SELECT MAX(pid), MAX(eid) FROM prey_related_projects WHERE project_name = %s'
            self.cursor.execute(pid_eid_sql, [repo])
            pid_eid = self.cursor.fetchone()
            for file_url in repo_code_dic[repo]:
                for code_line in repo_code_dic[repo][file_url]:
                    code_block_pram.append([pid_eid[0], pid_eid[1], file_url, code_line])

        self.cursor.executemany(code_block_sql, code_block_pram)
        self.db.commit()

    def get_ignore_projects(self, execute_user):
        """
        Get ignore projects of particular execute user
        :param execute_user: Execute user
        :return: Ignore projects list
        """
        ignore_project_list = 'SELECT project_name ' \
                              'FROM prey_ignore_projects ' \
                              'WHERE execute_user = %s'

        ignore_repo_list = []
        self.cursor.execute(ignore_project_list, [''])
        project_set = self.cursor.fetchall()
        for project in project_set:
            ignore_repo_list.append(project[0])

        return ignore_repo_list

if __name__ == "__main__":
    pass
