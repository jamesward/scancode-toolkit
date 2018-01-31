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
    sort_order = 4

    options = [
        CommandLineOption(('-g', '--fingerprint',),
            is_flag=True, default=False,
            help='Calculate the Halo Hash and Hailstorm fingerprint values for <input>.',
            help_group=OTHER_SCAN_GROUP)
    ]

    def is_enabled(self):
        return self.is_command_option_enabled('fingerprint')

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

    if not filetype.is_file(location):
        return []

    bah = BitAverageHaloHash()
    slices = []
    with open(location, 'rb') as f:
        first_chunk = None
        last_processed_chunk = None
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break

            # We keep track of the first and last chunk to ensure that the
            # first and last ngrams are selected
            if not first_chunk:
                first_chunk = chunk
            last_processed_chunk = chunk

            # Process data
            bah.update(chunk)
            slices.extend(ngrams(chunk, ngram_length))

    selected_slices = list(select_ngrams(slices))

    # Check to see if the first and last ngrams were selected,
    # as stipulated in the Hailstorm algorithm
    first_ngram = list(ngrams(first_chunk, ngram_length))[0]
    last_ngram = list(ngrams(last_processed_chunk, ngram_length))[-1]
    assert first_ngram == selected_slices[0]
    assert last_ngram == selected_slices[-1]

    # Join slices together as a single bytestring
    hashable = b''.join(b''.join(slice) for slice in selected_slices)
    hailstorm = BitAverageHaloHash(hashable)

    # Set values
    fingerprints = OrderedDict()
    fingerprints['bah128'] = bah.hexdigest()
    fingerprints['hailstorm'] = hailstorm.hexdigest()

    return [fingerprints]


@post_scan_impl
class MerkleTree(PostScanPlugin):
    """
    Compute a Merkle fingerprint for each directory using existing SHA1 and
    Bit Average Halo hash values of the directories and files within the codebase
    """

    needs_info = True

    def is_enabled(self):
        return self.is_command_option_enabled('fingerprint')

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
            if resource.children():
                sha1s = []
                bah128s = []
                for child in resource.children():
                    child_sha1 = child.sha1
                    if sha1:
                        sha1s.append(bytes(child_sha1))
                    m_sha1 = get_fingerprint_field(child, 'merkle_sha1')
                    if m_sha1:
                        sha1s.append(bytes(m_sha1))

                    child_bah128 = get_fingerprint_field(child, 'bah128')
                    if child_bah128:
                        bah128s.append(bytes(child_bah128))
                    m_bah128 = get_fingerprint_field(child, 'merkle_bah128')
                    if m_bah128:
                        bah128s.append(bytes(m_bah128))

                merkle_sha1 = sha1(b''.join(sorted(sha1s))).hexdigest()
                set_fingerprint_field(resource, 'merkle_sha1', merkle_sha1)

                merkle_bah128 = BitAverageHaloHash(b''.join(sorted(bah128s))).hexdigest()
                set_fingerprint_field(resource, 'merkle_bah128', merkle_bah128)


def get_fingerprint_field(resource, field):
    scans = resource.get_scans()
    if not scans:
        return
    fingerprints = scans.get('fingerprints', [])
    if fingerprints:
        fingerprint = fingerprints[0]
        return fingerprint.get(field) or None


def set_fingerprint_field(resource, field, field_value):
    scans = resource.get_scans()
    fingerprints = scans.get('fingerprints', [])
    if fingerprints:
        fingerprint = fingerprints[0]
    else:
        fingerprint = OrderedDict()
        fingerprints.append(fingerprint)
    fingerprint[field] = field_value
    scans['fingerprints'] = fingerprints
    resource.put_scans(scans)
