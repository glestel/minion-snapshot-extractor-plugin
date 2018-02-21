# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
# -*- coding: utf-8 -*-

import logging
import requests


class TargetManager:

    def __init__(self):
        # URL of the Minion Backend API
        self.API_PATH = "http://127.0.0.1:8383"

        # Target index to get id for url {"https://evil.corp": "1234-abcd-4321", ...}
        self.target_index = {}

        # Plan index to get id for the plan name {"Network Scan": "1234-abcd-123", ...}
        self.plan_index = {}

    def add_targets(self, target_list):
        """
        Add the given list of target to the manager
        :param target_list: list of target ["http://foo.bar", "https://evil.corp",...]
        :type target_list: list[str]
        """
        for target in target_list:
            # Check if site_id is already know
            if target not in self.target_index:
                # Get target id from Minion
                res = self.request_api("sites?url={t}".format(t=target))
                site_id = res.get("sites")[0].get('id')

                # Add to list
                self.target_index[target] = site_id

    def add_plans(self, plan_list):
        """
        Add the given list of plan to the manager
        :param plan_list: list of plans ["Network Scan", "TLS Audit", ...]
        :type plan_list: list[str]
        """
        for plan in plan_list:
            # Check if plan_id is already known
            if plan not in self.plan_index:
                # Get plan id from Minion
                res = self.request_api("/plans/{name}".format(name=plan))

                # Check plan exist
                if res.get('success'):
                    plan_id = res["plan"]["id"]
                    self.plan_index[plan] = plan_id
                else:
                    # Raise error
                    logging.error(res.get('reason'))

    def request_api(self, uri):
        """
        Run request at Minion Backend API, handle errors and return JSON result
        :param uri: action of the URI like "sites?url=evil.corp"
        :type uri:  str
        :return: json of the result
        :rtype: dict
        """
        r = requests.get("{api}/{req}".format(api=self.API_PATH, req=uri))

        # Check request worked
        try:
            r.raise_for_status()
            return r.json()

        except Exception as e:
            msg = "Error occurred while requesting {api}/{req}".format(api=self.API_PATH, req=uri)
            logging.error(msg)
            logging.error(e.message)

            # FIXME raise exception ?
            # self.report_error(msg, e.message)
