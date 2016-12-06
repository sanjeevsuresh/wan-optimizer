import unittest
from utils import get_hash, get_last_n_bits
from random import choice
from string import ascii_uppercase
import lbfs_wan_optimizer

class LBFS(unittest.TestCase):

    def setUp(self):
        self.optimizer = lbfs_wan_optimizer.WanOptimizer()
    def test_chunk_data(self):
        """
        """
        random_data = ''.join(choice(ascii_uppercase) for i in range(16000))
        windows = 16000 - 48
        delimiters = 0
        window = 0
        while window < windows:
            data = random_data[window : window + 48]
            hash = get_hash(data)
            last_bits = get_last_n_bits(hash, 13)
            if last_bits == self.optimizer.GLOBAL_MATCH_BITSTRING:
                delimiters += 1
                window = window + 48
            else:
                window += 1
        print('Test Found {} delimiters'.format(delimiters))
        chunks, returned_delimiters = self.optimizer.chunk_data(random_data)
        self.assertEquals(delimiters, returned_delimiters, '{} != {}'.format(delimiters, returned_delimiters))
        self.assertEquals(''.join(chunks), random_data, 'Chunks are not equal')



