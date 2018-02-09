#
# Copyright (c) 2018 nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/scancode-toolkit/
# The ScanCode software is licensed under the Apache License version 2.0.
# Data generated with ScanCode require an acknowledgment.
# ScanCode is a trademark of nexB Inc.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with ScanCode or any ScanCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with ScanCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  ScanCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  ScanCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/scancode-toolkit/ for support and download.

from __future__ import absolute_import
from __future__ import unicode_literals

from os.path import dirname
from os.path import join

from commoncode.testcase import FileDrivenTesting
from scancode.cli_test_utils import check_json_scan
from scancode.cli_test_utils import load_json_result
from scancode.cli_test_utils import run_scan_click

from plugincode import output
output._TEST_MODE = True


class TestFingerprint(FileDrivenTesting):

    test_data_dir = join(dirname(__file__), 'data')

    def test_scan_fingerprint_with_info(self):
        test_dir = self.extract_test_tar('plugin_fingerprint/dust.js-0.1.0.tgz')
        result_file = self.get_temp_file('json')
        expected_file = self.get_test_loc('plugin_fingerprint/expected.json')
        expected_results = load_json_result(expected_file)

        run_scan_click(['-ig', test_dir, '--json', result_file])
        results = load_json_result(result_file)

        for expected_result, result in zip(expected_results['files'], results['files']):
            assert expected_result.get('bah128') == result.get('bah128')
            assert expected_result.get('hailstorm') == result.get('hailstorm')
            assert expected_result.get('merkle_bah128') == result.get('merkle_bah128')
            assert expected_result.get('merkle_sha1') == result.get('merkle_sha1')

    def test_scan_fingerprint_empty_file(self):
        empty_file = self.get_test_loc('plugin_fingerprint/empty')
        result_file = self.get_temp_file('result_file')

        run_scan_click(['-ig', empty_file, '--json', result_file])

        results = load_json_result(result_file)
        for result in results['files']:
            assert result.get('bah128') is None
            assert result.get('hailstorm') is None
            assert result.get('merkle_bah128') is None
            assert result.get('merkle_sha1') is None
