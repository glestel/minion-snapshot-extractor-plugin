# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

from setuptools import setup

install_requires = []

setup(name="minion-snapshot-extractor-plugin",
      version="0.0",
      description="Snapshot extractor plugin Plugin for Minion",
      url="",
      author="",
      author_email="",
      packages=['minion', 'minion.plugins', 'minion.plugins.snapshot_extractor'],
      namespace_packages=['minion', 'minion.plugins'],
      include_package_data=True,
      install_requires=install_requires)
