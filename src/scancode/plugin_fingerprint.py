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
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from collections import OrderedDict

import attr

from commoncode import filetype
from plugincode.post_scan import PostScanPlugin
from plugincode.post_scan import post_scan_impl
from plugincode.scan import ScanPlugin
from plugincode.scan import scan_impl
from scancode import CommandLineOption
from scancode import OTHER_SCAN_GROUP


@scan_impl
class FingerprintScanner(ScanPlugin):
    """
    Calculate the Halo Hash and Hailstorm fingerprint values of a Resource.
    """
    attributes = OrderedDict([
        ('bah128', attr.ib(default=None)),
        ('hailstorm', attr.ib(default=None)),
    ])

    options = [
        CommandLineOption(('-g', '--fingerprint',),
            is_flag=True, default=False,
            requires=['info'],
            help='Calculate the Halo Hash and Hailstorm fingerprint values for <input>.',
            help_group=OTHER_SCAN_GROUP)
    ]

    def is_enabled(self, fingerprint, **kwargs):
        return fingerprint

    def get_scanner(self, **kwargs):
        return get_fingerprints


def get_fingerprints(location, **kwargs):
    """
    Return a list with a single OrderedDict that contains the bit average
    Halo hash and Hailstorm fingerprint values.
    """
    from licensedcode.tokenize import ngrams
    from licensedcode.tokenize import select_ngrams
    from scancode.halohash import BitAverageHaloHash

    chunk_size = 1024
    ngram_length = 4

    if filetype.is_file(location):
        bah = BitAverageHaloHash()
        slices = []
        with open(location, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break

                # Process data
                bah.update(chunk)
                slices.extend(ngrams(chunk, ngram_length))

        selected_slices = list(select_ngrams(slices))

        # Check to see if the first and last ngrams were selected,
        # as stipulated in the Hailstorm algorithm
        assert slices[0] == selected_slices[0]
        assert slices[-1] == selected_slices[-1]

        # Join slices together as a single bytestring
        hashable = b''.join(b''.join(slice) for slice in selected_slices)
        hailstorm = BitAverageHaloHash(hashable)

        # Set values
        fingerprints = OrderedDict()
        fingerprints['bah128'] = bah.hexdigest()
        fingerprints['hailstorm'] = hailstorm.hexdigest()

        return fingerprints


@post_scan_impl
class MerkleTree(PostScanPlugin):
    """
    Compute a Merkle fingerprint for each directory using existing SHA1 and
    Bit Average Halo hash values of the directories and files within the codebase
    """
    attributes = OrderedDict([
        ('merkle_bah128', attr.ib(default=None)),
        ('merkle_sha1', attr.ib(default=None)),
    ])

    def is_enabled(self, fingerprint, info, **kwargs):
        return fingerprint and info

    def process_codebase(self, codebase, **kwargs):
        """
        Compute a Merkle fingerprint for each directory using existing SHA1 and
        Bit Average Halo hash values of the directories and files within the codebase
        """
        from hashlib import sha1
        from scancode.halohash import BitAverageHaloHash

        # We walk bottom-up to ensure we process the children of directories
        # before we calculate and assign the Merkle fingerprint for directories
        for resource in codebase.walk(topdown=False):
            if resource.has_children():
                sha1s = []
                bah128s = []
                for child in resource.children(codebase):
                    if child.bah128:
                        bah128s.append(bytes(child.bah128))
                    if child.merkle_bah128:
                        bah128s.append(bytes(child.merkle_bah128))

                    if child.sha1:
                        sha1s.append(bytes(child.sha1))
                    if child.merkle_sha1:
                        sha1s.append(bytes(child.merkle_sha1))

                resource.merkle_bah128 = BitAverageHaloHash(b''.join(sorted(bah128s))).hexdigest()
                resource.merkle_sha1 = sha1(b''.join(sorted(sha1s))).hexdigest()
