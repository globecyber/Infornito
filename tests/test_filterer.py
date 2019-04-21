import os, sys
parentPath = os.path.abspath("..")
if parentPath not in sys.path:
    sys.path.insert(0, parentPath)

import unittest
import libs.filterer as filterer

class TestFilterer(unittest.TestCase):

    input_data = 'http://yahoo.com/index.html?news_id=24'

    def test_domain_equal(self):
        result = filterer.domain_equal(self.input_data, 'yahoo.com')
        self.assertNotEqual(result, None)

        result = filterer.domain_equal(self.input_data, 'google.com')
        self.assertEqual(result, None)
    
    def test_tld_equal(self):

        # True Condition
        result = filterer.tld_equal(self.input_data, 'com')
        self.assertNotEqual(result, None)

        # Multiple Input
        result = filterer.domain_equal(self.input_data, 'com,org')
        self.assertNotEqual(result, None)

        # False Condition
        result = filterer.domain_equal(self.input_data, 'net,org')
        self.assertEqual(result, None)

if __name__ == '__main__':
    unittest.main()