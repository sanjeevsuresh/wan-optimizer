import wan_optimizer
import utils

class WanOptimizer(wan_optimizer.BaseWanOptimizer):
    """ WAN Optimizer that divides data into variable-sized
    blocks based on the contents of the file.

    This WAN optimizer should implement part 2 of project 4.
    """

    # The string of bits to compare the lower order 13 bits of hash to
    GLOBAL_MATCH_BITSTRING = '0111011001010'

    def __init__(self):
        wan_optimizer.BaseWanOptimizer.__init__(self)
        # Add any code that you like here (but do not add any constructor arguments).
		self.buffer = dict() # <Key, Value> <(src, destination), string of data>
		self.seen = dict() # <Key, Value>: <Hash of a Block, Actual Block>
        return

    def receive(self, packet):
        """ Handles receiving a packet.

        Right now, this function simply forwards packets to clients (if a packet
        is destined to one of the directly connected clients), or otherwise sends
        packets across the WAN. You should change this function to implement the
        functionality described in part 2.  You are welcome to implement private
        helper fuctions that you call here. You should *not* be calling any functions
        or directly accessing any variables in the other middlebox on the other side of 
        the WAN; this WAN optimizer should operate based only on its own local state
        and packets that have been received.
        """
        if packet.dest in self.address_to_port:
            # The packet is destined to one of the clients connected to this middlebox;
            # send the packet there.
            self.send(packet, self.address_to_port[packet.dest])
        else:
            # The packet must be destined to a host connected to the other middlebox
            # so send it across the WAN.
            self.send(packet, self.wan_port)

	def handle_outgoing(self, packet):
		""" Handles receiving an outgoing packet.
		
		This function will deal with an outgoing packet in the manner described by the 
		low bandwidth filesystem paper. Namely it will break the file into chunks based off of 
		the SHA-1 hash of the data being sent. 

		Pseudocode:
		1.) Place received data into a buffer for the (source,dest) pair
		2.) when a fin packet is received:
			a.) compute hash of data
			b.) break hashed data at delimiters of `GLOBAL_MATCH_BITSTRING`
			c.) for each chunk of data:
				i. if the chunk has been cached before send the hash of the chunk
				ii. otherwise send the raw data with the raw_data flag as true 
		"""

	def chunk_data(self, data):
		""" Breaks up data based on LBFS method.
		
		This function will implement the breaking of the data in the fashion described in the LBFS
		paper. Actually implements the sliding window approach to breaking data based off a
		delimiter.
		
		Arguments:
			data: a string that contains data.
		Returns:
			ordered list of hashed data chunks
		Side-effects:	
			adds in the <hashed data, raw data> pair to the seen dict.	
		"""
		num_windows = len(data) - 48
		chunk_start = 0
		
		for offset in range(num_windows):
			window = len(data) > offset+48 ? data[offset:offset+48] : data[offset:]	
			hashed = get_hash(window)
			low13 = get_last_n_bits(hashed, 13)
			
			if low13 == GLOBAL_MATCH_BITSTRING:
				# This is where data should be broken up	
				chunk = data[chunk_start:offset+48]	
				h_chunk = get_hash(chunk)
				self.seen[h_chunk] = chunk	
				chunk_start = offset+49
