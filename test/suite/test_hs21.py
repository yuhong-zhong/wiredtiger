#!/usr/bin/env python
#
# Public Domain 2014-present MongoDB, Inc.
# Public Domain 2008-2014 WiredTiger, Inc.
#
# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

import time, re
import wiredtiger, wttest
from wtdataset import SimpleDataSet
from wiredtiger import stat

def timestamp_str(t):
    return '%x' % t

# test_hs21.py
# Test we don't lose any data when idle files with an active history are closed/sweeped.
# Files with active history, ie content newer than the oldest timestamp can be closed when idle.
# We want to ensure that when an active history file is idle closed we can continue reading the
# correct version of data and their base write generation hasn't changed (since we haven't
# restarted the system).
class test_hs21(wttest.WiredTigerTestCase):
    # Configure handle sweeping to occur within a specific amount of time.
    conn_config = 'file_manager=(close_handle_minimum=0,close_idle_time=3,close_scan_interval=1),' + \
            'statistics=(all),operation_tracking=(enabled=false)'
    session_config = 'isolation=snapshot'
    file_name = 'test_hs21'
    numfiles = 10
    nrows = 10000

    def large_updates(self, uri, value, ds, nrows, commit_ts):
        # Update a large number of records, we'll hang if the history store table isn't working.
        session = self.session
        cursor = session.open_cursor(uri)
        for i in range(1, nrows + 1):
            session.begin_transaction()
            cursor[ds.key(i)] = value
            session.commit_transaction('commit_timestamp=' + timestamp_str(commit_ts))
        cursor.close()

    def check(self, check_value, uri, nrows, read_ts):
        # Validate we read an expected value at a given read timestamp.
        session = self.session
        session.begin_transaction('read_timestamp=' + timestamp_str(read_ts))
        cursor = session.open_cursor(uri)
        count = 0
        for k, v in cursor:
            self.assertEqual(v, check_value)
            count += 1
        session.rollback_transaction()
        self.assertEqual(count, nrows)
        cursor.close()

    def parse_run_write_gen(self, uri):
        meta_cursor = self.session.open_cursor('metadata:')
        config = meta_cursor[uri]
        meta_cursor.close()
        # The search string will look like: 'run_write_gen=<num>'.
        # Just reverse the string and take the digits from the back until we hit '='.
        write_gen = re.search('run_write_gen=\d+', config)
        self.assertTrue(write_gen is not None)
        write_gen_str = str()
        for c in reversed(write_gen.group(0)):
            if not c.isdigit():
                self.assertEqual(c, '=')
                break
            write_gen_str = c + write_gen_str
        return int(write_gen_str)

    def test_hs(self):
        active_files = []
        value1 = 'a' * 500
        value2 = 'd' * 500

        # Set up 'numfiles' with 'numrows' entries. We want to create a number of files that
        # contain active history (content newer than the oldest timestamp).
        for f in range(self.numfiles):
            table_uri = 'table:%s.%d' % (self.file_name, f)
            file_uri = 'file:%s.%d.wt' % (self.file_name, f)
            # Create a small table.
            ds = SimpleDataSet(
                self, table_uri, 0, key_format='S', value_format='S', config='log=(enabled=false)')
            ds.populate()
            # Checkpoint to ensure we write the files metadata checkpoint value.
            self.session.checkpoint()
            # Get the base write gen of the file so we can compare after the handles get closed.
            base_write_gen = self.parse_run_write_gen(file_uri)
            active_files.append((base_write_gen, ds))

        # Pin oldest and stable to timestamp 1.
        self.conn.set_timestamp('oldest_timestamp=' + timestamp_str(1) +
            ',stable_timestamp=' + timestamp_str(1))

        # Perform a series of updates over our files to check the history store is
        # working with old and new timestamps.
        for (_, ds) in active_files:
            # Load data.
            self.large_updates(ds.uri, value1, ds, self.nrows // 2 , 1)
            # Check that all updates are seen.
            self.check(value1, ds.uri, self.nrows // 2, 1)

            # Load more data with a later timestamp.
            self.large_updates(ds.uri, value2, ds, self.nrows, 100)
            # Check that the new updates are only seen after the update timestamp.
            self.check(value1, ds.uri, self.nrows // 2, 1)
            self.check(value2, ds.uri, self.nrows, 100)

        # Our sweep scan interval is every 1 second and the amount of idle time needed for a handle to be closed is 3 seconds.
        # It should take roughly 4 seconds for the sweep server to close our file handles. Lets wait at least double
        # that to be safe.
        max = 8
        sleep = 0
        # After waiting for the sweep server to remove our idle handles, the only open
        # handles that should be the metadata file, history store file and lock file.
        final_numfiles = 3
        while sleep < max:
            # We continue doing checkpoints to ensure we sweep the session cache, allowing
            # idle handles to be removed.
            self.session.checkpoint()
            sleep += 0.5
            time.sleep(0.5)
            # Open the stats cursor to get the current dhandle sweep status.
            stat_cursor = self.session.open_cursor('statistics:', None, None)
            curr_files_open = stat_cursor[stat.conn.file_open][2]
            curr_dhandles_removed = stat_cursor[stat.conn.dh_sweep_remove][2]
            curr_dhandle_sweep_closes = stat_cursor[stat.conn.dh_sweep_close][2]
            stat_cursor.close()

            self.pr("==== loop " + str(sleep))
            self.pr("Number of files open: " + str(curr_files_open))
            self.pr("Number of connection sweep dhandles closed: " + str(curr_dhandle_sweep_closes))
            self.pr("Number of connection sweep dhandles removed from hashlist: " + str(curr_dhandles_removed))

            # We've sweeped all the handles we can if we are left with the number of final dhandles
            # that we expect to be always open.
            if curr_files_open == final_numfiles and curr_dhandle_sweep_closes >= self.numfiles:
                break

        stat_cursor = self.session.open_cursor('statistics:', None, None)
        final_dhandle_sweep_closes = stat_cursor[stat.conn.dh_sweep_close][2]
        stat_cursor.close()
        # We want to assert our active history files have all been closed.
        self.assertGreaterEqual(final_dhandle_sweep_closes, self.numfiles)

        # Perform a series of checks over our files to ensure that any transactions before the
        # dhandles were closed/sweeped have been written.
        # Also despite the dhandle is being re-opened, we don't expect the base write generation
        # to have changed since we haven't actually restarted the system.
        for idx, (initial_base_write_gen, ds) in enumerate(active_files):
            # Check that the transactions have the correct data.
            self.check(value1, ds.uri, self.nrows // 2, 1)
            self.check(value2, ds.uri, self.nrows, 100)
            file_uri = 'file:%s.%d.wt' % (self.file_name, idx)
            # Get the current base_write_gen and ensure it hasn't changed since being
            # closed.
            base_write_gen = self.parse_run_write_gen(file_uri)
            self.assertEqual(initial_base_write_gen, base_write_gen)

if __name__ == '__main__':
    wttest.run()
