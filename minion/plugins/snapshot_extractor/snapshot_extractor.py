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
import json

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
    
    # targets for an everywhere use
    # FIXME clean this global attribute elsewhere
    targets = []
    CSV_FILE = "extract.csv"
    JSON_FILE = "extract.json"

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

    # FIXME duplicate of wanted issue, merge two fields
    """:type : list[str]    text of issues needed for extract"""
    texts_issues = []
    """:type : list[str]    label of the rows where text of the issues will be looked up for extract"""
    row_labels = []
    """:type : bool         remove target with zero count"""
    ignore_null = True

    available_actions = ["count", "find"]

    # Function pointers used for processing according to action
    planned_action = None
    csv_creator = None
    json_creator = None

    """
    :type : dict

    aggregation of results that will be in the extract, two format possible according to action
    count :
        {
            target: {text: 0, }
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
        self.JSON_FILE = "{dir}extract_{output}.json".format(dir=self.report_dir, output=self.output_id)

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

        # Get the label of the rows where issues will be looked up (mandatory option)
        if "row_labels" in self.configuration:
            self.row_labels = self.configuration.get('row_labels')
            self.logger.debug("Row labels set to {label}".format(label=self.row_labels))
            
        if action == "find":
            # Get the wanted issues (mandatory option)
            if "wanted_issues" in self.configuration:
                self.wanted_issues = self.configuration.get('wanted_issues')
                self.logger.debug("Wanted issues set to {wanted}".format(wanted=self.wanted_issues))

            if not self.wanted_issues:
                self.report_error("No issue defined for extract", "Missing argument")

            # Get the aggregation option
            if "detail_issues" in self.configuration:
                self.detail_issues = self.configuration.get('detail_issues')
                self.logger.debug("detail_issues set to {detail}".format(detail=self.detail_issues))

            # Set action function
            self.planned_action = self.find_issue
            self.csv_creator = self.find_to_csv
            self.json_creator = self.find_to_json

        elif action == "count":
            # Get the texts of issues needed (mandatory option)
            if "texts_issues" in self.configuration:
                self.texts_issues = self.configuration.get('texts_issues')
                self.logger.debug("Text issues set to {text}".format(text=self.texts_issues))

            if not self.texts_issues:
                self.report_error("No issue type defined for extract", "Missing argument")

            # Get the ignore null flag
            if "ignore_null" in self.configuration:
                self.ignore_null = self.configuration.get('ignore_null')
                self.logger.debug("ignore_null set to {flag}".format(flag=self.ignore_null))

            # Set action function for issue browsing
            self.planned_action = self.count_issue
            self.csv_creator = self.count_to_csv
            self.json_creator = self.count_to_json

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

        # Create json
        self.json_creator()

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
        self.targets = targets
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

        # Look ip in every row specified
        for row in self.row_labels:

            for wanted in self.wanted_issues:

                # Check title of the issue
                if wanted in issue[row]:
                    # Add the winner to the found list
                    if target not in self.found:
                        self.found[target] = [issue[row]]
                    else:
                        self.found[target].append(issue[row])

                    self.logger.debug("Found one issue : {iss}".format(iss=issue[row]))

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
            for sev in self.texts_issues:
                counts[sev] = 0

            self.found[target] = counts

        # Look up in every specified row
        for row in self.row_labels:
            # Get text of the issue
            text_cell = issue[row]

            # Check if we have a winner
            for text_issue in self.texts_issues:
                if text_issue in text_cell:
                    self.found[target][text_issue] += 1

    def count_to_json(self):
        """
        Generate the JSON from the count of issues
        """
        # dictionary of data for building json dump
        data = {}
        sum_found = 0
        sum_targets = 0
        sum_tested_targets = 0
        text_file = open(self.JSON_FILE, "w")
        
        # Build info for each found target
        for target in self.found:
            summary = self.found[target]

            # Sum issues for every find of the target
            total = sum(summary.values())
            sum_found += total
            
            sum_tested_targets += 1

            # Drop result where count is null if needed
            if self.ignore_null:

                if total == 0:
                    self.logger.debug("Null result for {t}".format(t=target))
                    continue

            host = urlparse.urlparse(target).hostname
            get_ip = self.get_network_info_target(host)
            
            sum_targets += 1

            # build a data
            data.__setitem__(host, {
                "host": host,
                "target_ip": get_ip[0],
                "url": target,
                "reverse_dns": get_ip[1],
                "issues": summary,
                "sum_issues": total,
                "tags": self.fetch_tags(target)
            })
        
        # Create a dictionary of metadata
        meta = {}
        meta.__setitem__("sum_targets",sum_targets)
        meta.__setitem__("sum_tested_targets",sum_tested_targets)
        meta.__setitem__("sum_found_issues",sum_found)
        
        # Build final json structure
        json_dict = {
            "meta": meta,
            "data": data
        }

        # Write result
        text_file.write(json.dumps(json_dict))
        text_file.close()

    def find_to_json(self):
        """
        Generate the JSON from the search of issues
        """
        # Dictionary used to build the data to dump in json
        data = {}

        sum_targets = 0
        sum_found_issues = 0
        text_file = open(self.JSON_FILE, "w")

        # Build info for each found target
        for target in self.found:
            host = urlparse.urlparse(target).hostname
            get_ip = self.get_network_info_target(host)
            
            sum_targets += 1

            # Build info for target
            total_issues = len(self.found[target])
            sum_found_issues += total_issues

            data.__setitem__(host, {
                "host": host,
                "url": target,
                "target_ip": get_ip[0],
                "reverse_dns": get_ip[1],
                "issues": self.found[target],
                "total_issues": total_issues,
                "tags": self.fetch_tags(target)
            })

        # Create a dictionary of metadata
        meta = {}
        meta.__setitem__("sum_found_targets", sum_targets)
        meta.__setitem__("sum_found_issues", sum_found_issues)
        meta.__setitem__("sum_tested_targets", len(self.targets))

        # Build dump result
        json_dict = {
            "meta": meta,
            "data": data
        }
        text_file.write(json.dumps(json_dict))
        text_file.close()
        
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

            get_ip = self.get_network_info_target(host)
            target_ip =get_ip[0]
            physical_name = get_ip[1]

            # Build csv
            line = {"target": target, "ip": target_ip, "fqdn": physical_name}

            # add tags
            line.update(tags)

            try:
                # Normalize string for encoding
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

        # Add type of issue
        fields.extend(self.texts_issues)

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

            getip = self.get_network_info_target(host)
            target_ip = getip[0]
            physical_name = getip[1]

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

    def get_network_info_target(self, host):
        """
        Get the ip of the target
        :param host: url of the target
        :type host: str
        :return: tuple with ip, hostname
        :rtype: tuple
        """

        # Resolve given url
        try:
            physical_name, null, [target_ip] = socket.gethostbyaddr(host)

        except Exception as e:
            self.logger.debug(e)
            self.logger.info("No RDNS for {t}".format(t=host))

            physical_name = "Not available"

            # Try to get the ip if reverse dns is not set
            try:
                target_ip = socket.gethostbyname(host)
            except Exception as e:
                target_ip = "error"
                self.logger.info("Could not resolve {t}".format(t=host))

        return target_ip, physical_name

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
        output_artifacts = [self.logger_path, self.CSV_FILE,self.JSON_FILE]

        if output_artifacts:
            self.report_artifacts(self.PLUGIN_NAME, output_artifacts)


