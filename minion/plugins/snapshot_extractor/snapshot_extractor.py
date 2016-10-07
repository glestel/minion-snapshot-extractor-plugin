# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# -*- coding: utf-8 -*-

import csv
import logging
import requests
import socket
import urlparse
import uuid

from minion.plugins.base import BlockingPlugin
from pymongo import MongoClient


class SnapshotExtractorPlugin(BlockingPlugin):
    PLUGIN_NAME = "Snapshot extractor plugin"
    PLUGIN_VERSION = "0.1"

    API_PATH = "http://127.0.0.1:8383"

    # Instantiation of output
    report_dir = "/tmp/artifacts/"
    output_id = str(uuid.uuid4())
    schedule_stderr = ""
    logger = None
    logger_path = ""

    CSV_FILE = "extract.csv"

    MONGO_HOST = '127.0.0.1'
    MONGO_PORT = 27017
    mongodb = None

    """:type : list[str]    Array of groups where the search will be done"""
    group_scope = []
    """:type : list[str]    Array of plan where the search will be done"""
    plan_scope = []
    """:type : list[str]    Array of issues wanted for the extract"""
    wanted_issues = []
    """:type : bool         Aggregate issues, otherwise the extract will contains for each target one entry by issue"""
    detail_issues = False
    """:type : list[str]    Array of tags linked to the target"""
    target_tags = []

    """:type : list[str]    type of severity of issues needed for extract"""
    type_issue = []
    """:type : bool         remove target with zero count"""
    ignore_null = True

    available_actions = ["count", "find"]
    planned_action = None
    csv_creator = None

    """
    :type : dict

    aggregation of results that will be in the extract, two format possible according to action
    count :
        {
            target: {severity: 0, }
        }

    find :
        {
            target: ["issue", ]
        }
    """
    found = {}

    def initialize_logger(self):
        # create logger
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.DEBUG)

        # create console handler and set level to debug
        ch = logging.FileHandler(self.logger_path)
        ch.setLevel(logging.DEBUG)

        # create formatter
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

        # add formatter to ch
        ch.setFormatter(formatter)

        # add ch to logger
        self.logger.addHandler(ch)

        # self.logger.debug('debug message')
        # self.logger.info('info message')
        # self.logger.warn('warn message')
        # self.logger.error('error message')
        # self.logger.critical('critical message')

    def start_mongo_connexion(self):
        self.mongodb = MongoClient(host=self.MONGO_HOST, port=self.MONGO_PORT).minion

    def open_csv(self, fields):
        """
        Create csv file and write headers
        :param fields: headers for column of csv file like ["target", "ip", "fqdn"]
        :type fields: list[str]
        :return: writer on csv file
        :rtype DictWriter
        """
        f = open(self.CSV_FILE, 'wb')
        writer = csv.DictWriter(f, delimiter=';', fieldnames=fields)
        writer.writeheader()

        return writer

    def report_error(self, message, exception="Plugin failed"):
        """
        Report an error during execution of the plugin and stop execution
        :param message: information to display with the error
        :type message: str
        :param exception: additional title of the exception to display
        :type exception: str
        """
        failure = {
            "hostname": "Utils plugins",
            "exception": exception,
            "message": message
        }

        self._save_artifacts()
        self.report_finish("FAILED", failure)

    def do_run(self):
        # Get the path to save output
        if 'report_dir' in self.configuration:
            self.report_dir = self.configuration['report_dir']
        # FIXME add date to file name
        self.logger_path = "{dir}logging_{output}.txt".format(dir=self.report_dir, output=self.output_id)
        self.CSV_FILE = "{dir}extract_{output}.csv".format(dir=self.report_dir, output=self.output_id)

        # start logger
        self.initialize_logger()

        # Get the groups where to look for issues, if empty every group will be searched
        if "group_scope" in self.configuration:
            self.group_scope = self.configuration.get('group_scope')
            self.logger.debug("Group scope set to {scope}".format(scope=self.group_scope))

        # Get the plan scope (mandatory option)
        if "plan_scope" in self.configuration:
            self.plan_scope = self.configuration.get('plan_scope')
            self.logger.debug("Plan scope set to {scope}".format(scope=self.plan_scope))

        # Check mandatory options have been defined
        if not self.plan_scope:
            self.report_error("No plan defined for extract", "Missing argument")

        # Get the wished tag for target
        if "target_tags" in self.configuration:
            self.target_tags = self.configuration.get('target_tags')
            self.logger.debug("Target tags set to {tags}".format(tags=self.target_tags))

        # Get the action to conduct for the extract (mandatory option)
        action = self.configuration.get('action')

        # Check action is possible
        if action not in self.available_actions:
            self.report_error("No or wrong action defined for extract", "Missing argument")

        if action == "find":
            # Get the wanted issues (mandatory option)
            if "wanted_issues" in self.configuration:
                self.wanted_issues = self.configuration.get('wanted_issues')
                self.logger.debug("Wanted issues set to {wanted}".format(wanted=self.wanted_issues))

            # Get the aggregation option
            if "detail_issues" in self.configuration:
                self.detail_issues = self.configuration.get('detail_issues')
                self.logger.debug("detail_issues set to {detail}".format(detail=self.detail_issues))
            if not self.wanted_issues:
                self.report_error("No issue defined for extract", "Missing argument")

            # Set action function
            self.planned_action = self.find_issue
            self.csv_creator = self.find_to_csv

        elif action == "count":
            # Get the severity of issues needed (mandatory option)
            if "type_issue" in self.configuration:
                self.type_issue = self.configuration.get('type_issue')
                self.logger.debug("Type issues set to {type}".format(type=self.type_issue))

            # Get the ignore null flag
            if "ignore_null" in self.configuration:
                self.ignore_null = self.configuration.get('ignore_null')
                self.logger.debug("ignore_null set to {flag}".format(flag=self.ignore_null))

            if not self.type_issue:
                self.report_error("No issue type defined for extract", "Missing argument")

            # Set action function for issue browsing
            self.planned_action = self.count_issue
            self.csv_creator = self.count_to_csv

        # Initialize db connexion
        self.start_mongo_connexion()

        # Get list of concerned targets
        targets = self.find_targets()

        self.logger.debug("Found {nb} targets for checking".format(nb=len(targets)))

        # Lookup in last scan for wanted issue
        self.search_targets(targets)

        self.logger.debug("Found {nb} results after checking".format(nb=len(self.found)))

        # Create csv
        self.csv_creator()

        # Exit
        self.logger.info("Extract over")

        self._save_artifacts()

    def find_targets(self):
        """
        Fetch target needed for the search defined in group_scope
        :return: list of targets
        :rtype: list[str]
        """
        targets = set()

        # Look up target for each group if defined
        if self.group_scope:
            for group in self.group_scope:
                r = requests.get(self.API_PATH + "/groups/" + group)

                # Check request worked
                try:
                    r.raise_for_status()
                    res = r.json()["group"]['sites']
                    targets.update(res)

                except Exception as e:
                    msg = "Error occurred while retrieving targets for group {group}".format(group=group)
                    self.logger.error(msg)
                    self.logger.error(e.message)
                    self.report_error(msg, e.message)

        else:
            # Get all targets from database
            for target in self.mongodb.sites.find():
                url = target.get('url')
                targets.add(url)

        return list(targets)

    def search_targets(self, targets):
        """
        Search wanted issues in targets scan
        :param targets: list of target in scope for the search
        :type targets: list[str]
        :return: list of result
        """

        for target in targets:
            for plan in self.plan_scope:
                list_scan = list(self.mongodb.scans.find({'configuration.target': target, 'plan.name': plan})
                                 .sort("created", -1))

                # Check at least one scan has been run
                if len(list_scan) == 0:
                    self.logger.debug("No scan result for {t} with {p}".format(t=target, p=plan))
                    continue

                last_scan = list_scan[0]

                self.logger.debug("Inspecting {t} with {p}".format(t=target, p=plan))

                # Browse each session in last scan
                for session in last_scan['sessions']:
                    # Get each issue in last scan (in each session)
                    for issue in session['issues']:
                        # Find info about the issue
                        full_issue = self.mongodb.issues.find_one({"Id": issue})

                        # Check that the issue is active
                        if full_issue["Status"] == "Current" and \
                                not full_issue.get("Ignored") and not full_issue.get("False_positive"):
                                    # Handle according to research mode
                                    self.planned_action(full_issue, target)

    def find_issue(self, issue, target):
        """
        Check if issue summary is needed for the extract
        :param issue: issue from minion that need to be checked
        :param target: target having the issue
        """

        # Check title of the issue
        for wanted in self.wanted_issues:
            if wanted in issue["Summary"]:
                # Add the winner to the found list
                if target not in self.found:
                    self.found[target] = [issue["Summary"]]
                else:
                    self.found[target].append(issue["Summary"])
                self.logger.debug("Found one issue : {iss}".format(iss=issue["Summary"]))

    def count_issue(self, issue, target):
        """
        Count issue type by target
        :param issue: current minion issue
        :param target: target having the issue
        """
        # Check if target has record initialized
        if target not in self.found:
            # Create counters
            counts = {}
            for sev in self.type_issue:
                counts[sev] = 0

            self.found[target] = counts

        # Get severity of the issue
        severity = issue["Severity"]

        # Check if we have a winner
        if severity in self.type_issue:
            self.found[target][severity] += 1

    def find_to_csv(self):
        """
        Generate the CSV from the search of issues
        """
        # Build header
        fields = ["target", "ip", "fqdn"]

        # Add tags
        fields.extend(self.target_tags)

        # Add extract info if needed
        if self.detail_issues:
            fields.append("issue")

        # Open csv
        writer = self.open_csv(fields)

        for target in self.found:
            # Get tags for target
            tags = self.fetch_tags(target)

            # Clean the target for resolution
            host = urlparse.urlparse(target).hostname

            # Get the ip of the target
            # TODO extract into a new function
            try:

                physical_name, null, [target_ip] = socket.gethostbyaddr(host)

            except Exception as e:
                self.logger.debug(e)
                self.logger.info("No RDNS for {t}".format(t=host))

                physical_name = "Not available"

                try:
                    target_ip = socket.gethostbyname(host)
                except Exception as e:
                    target_ip = "error"
                    self.logger.info("Could not resolve {t}".format(t=host))

            # Build csv
            line = {"target": target, "ip": target_ip, "fqdn": physical_name}

            # add tags
            line.update(tags)

            try:

                for key in line.keys():
                    if line[key] and type(line[key]) is unicode:
                        line[key] = line[key].encode("utf8")

                # Add issue detail if needed
                if self.detail_issues:
                    for issue in self.found[target]:
                        to_write = line.copy()
                        to_write["issue"] = issue

                        writer.writerow(to_write)
                else:
                    writer.writerow(line)

            except Exception as e:
                self.logger.debug(e)
                msg = "Could not write line for {target}".format(target=host)
                self.logger.info(msg)
                continue

    def count_to_csv(self):
        """
        Generate the CSV from the count of issues
        """
        # Build header
        fields = ["target", "ip", "fqdn"]

        # Add tags
        fields.extend(self.target_tags)

        # Add type of severity
        fields.extend(self.type_issue)

        self.logger.debug("Field used {f}".format(f=fields))

        # Open csv
        writer = self.open_csv(fields)

        for target in self.found:
            # get count result
            summary = self.found[target]

            # Avoid null result if needed
            if self.ignore_null:
                total = sum(summary.values())

                if total == 0:
                    self.logger.debug("Null result for {t}".format(t=target))
                    continue

            # Get tags for target
            tags = self.fetch_tags(target)

            # Clean the target for resolution
            host = urlparse.urlparse(target).hostname

            # Get the ip of the target
            try:
                physical_name, null, [target_ip] = socket.gethostbyaddr(host)

            except Exception as e:
                self.logger.debug(e)
                self.logger.info("No RDNS for {t}".format(t=host))

                physical_name = "Not available"

                try:
                    target_ip = socket.gethostbyname(host)
                except Exception as e:
                    target_ip = "error"
                    self.logger.info("Could not resolve {t}".format(t=host))

            # Build csv
            line = {"target": target, "ip": target_ip, "fqdn": physical_name}

            # add tags
            line.update(tags)

            # Add results
            line.update(summary)

            try:
                for key in line.keys():
                    if line[key] and type(line[key]) is unicode:
                        line[key] = line[key].encode("utf8")

                writer.writerow(line)

            except Exception as e:
                msg = "Could not write line for {target}".format(target=host)
                self.logger.info(msg)
                self.logger.debug(e)
                continue

    def fetch_tags(self, target):
        """
        fetch tags linked to a target
        :param target: url in minion
        :type target: str
        :return: dict with tags and values
        :rtype: dict
        """
        # Get info for target
        uri = "{api}/sites?url={url}".format(api=self.API_PATH, url=target)
        r = requests.get(uri)

        # Check request worked
        try:
            r.raise_for_status()
        except Exception as e:
            msg = "Error occurred while retrieving info for {site}".format(site=target)
            self.logger.error(msg)
            self.logger.error(e.message)
            self.report_error(msg, e.message)

        filtered_tags = {}

        res = r.json()["sites"][0]
        if "tags" in res:
            existing_tags = res["tags"]

            # Build result
            for tag in self.target_tags:
                filtered_tags[tag] = existing_tags.get(tag)

        return filtered_tags

    def do_stop(self):
        # Save artifacts
        self._save_artifacts()

        # Call parent method
        BlockingPlugin.do_stop(self)

    def _save_artifacts(self):
        """
        Function used to save output of the plugin
        Must be called before shutting down the plugin
        """
        output_artifacts = [self.logger_path, self.CSV_FILE]

        if output_artifacts:
            self.report_artifacts(self.PLUGIN_NAME, output_artifacts)


