import wan_optimizer
import utils
from utils import MAX_PACKET_SIZE
from tcp_packet import Packet
import logging

logging.basicConfig()
LOG = logging.getLogger(name='lbfs_wan_optimizer')
LOG.setLevel(logging.INFO)

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
        self.window_size = 48
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
            self.handle_incoming(packet)
        else:
            # The packet must be destined to a host connected to the other middlebox
            # so send it across the WAN.
            self.handle_outgoing(packet)

    def handle_incoming(self, packet):
        """ Handles an incoming packet.

        Responsibility of this method is to add any raw data to the seen list and translate any
        hashed data. It then forwards the data to the client.
        """
        curr_flow = (packet.src, packet.dest)

        if packet.payload in self.seen:
            data = self.seen[packet.payload]
            self.send_packet(packet, self.address_to_port[packet.dest])
        elif packet.is_raw_data:
            delimited_chunks = self.chunk_data(packet.payload)
            first, rest = delimited_chunks[0], delimited_chunks[1:]

            if rest:
                hashed_block = get_hash(self.buffer.get(curr_flow, '') + first)
                self.seen[hashed_block] = self.buffer.get(curr_flow, '') + first
                self.buffer[curr_flow] = ''
                for block in rest[:-1]:
                    hashed_block = get_hash(block)
                    self.seen[hashed_block] = block
                last_chunk = rest[-1]
                last_bits = utils.get_last_n_bits(utils.get_hash(last_chunk), 13)
                if not (last_bits == self.GLOBAL_MATCH_BITSTRING or packet.is_fin):
                    self.buffer[curr_flow] = last_chunk
                else:
                    hashed_block = utils.get_hash(last_chunk)
                    self.seen[hashed_block] = last_chunk
            else:
                bits = utils.get_last_n_bits(utils.get_hash(first), 13)
                if not (bits == self.GLOBAL_MATCH_BITSTRING or packet.is_fin):
                    self.buffer[curr_flow] = first
                else:
                    hashed_block = utils.get_hash(first)
                    self.seen[hashed_block] = first

            self.send(packet, self.address_to_port[packet.dest])
        else:
            LOG.debug('GOT A HASH WE HAVE NEVER SEEN!')


    def handle_outgoing(self, packet, client=False):
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

        curr_flow = (packet.src, packet.dest)
        if packet.is_raw_data:
            data = packet.payload
        else:
            LOG.debug('Received a payload I have seen before')
            data = self.seen[packet.payload]
        # Is there a delimiter in my packet?
        # If so, add the delimited data to my buffer
        # Send what's in my buffer
        # Clear the buffer
        # Add the remainder to the buffer
        # If fin:
        #   send what's in my buffer
        #   clear the buffer

        delimited_chunks = self.chunk_data(data)
        assert len(data) == len(''.join(delimited_chunks)), 'chunk_data is not working'

        # First block needs to be added to my buffer
        if delimited_chunks:
            first, rest = delimited_chunks[0], delimited_chunks[1:]
            self.buffer[curr_flow] = self.buffer.get(curr_flow, '') + first
            if rest:
                LOG.debug('Sending a block')
                self.send_packet(self.buffer[curr_flow], packet.src, packet.dest,
                                 packet.is_raw_data, False, self.wan_port, client=client)
                self.buffer[curr_flow] = ''
                for block in rest[:-1]:
                    self.send_packet(block, packet.src, packet.dest,
                             packet.is_raw_data, False, self.wan_port, client=client)
                last_chunk = rest[-1]
                # If delimited, send, else add to buff
                last_bits = utils.get_last_n_bits(utils.get_hash(last_chunk), 13)
                if last_bits == self.GLOBAL_MATCH_BITSTRING or packet.is_fin:
                    self.send_packet(last_chunk, packet.src, packet.dest,
                             packet.is_raw_data, packet.is_fin, self.wan_port, client=client)
                else:
                    self.buffer[curr_flow] = last_chunk
            else:
                 # The second packet is perfectly delimited (i.e) the delimiter is
                 # at the end of the packet.
                 last_bits = utils.get_last_n_bits(utils.get_hash(self.buffer[curr_flow]), 13)
                 #assert last_bits == self.GLOBAL_MATCH_BITSTRING, "{} != {}".format(last_bits, self.GLOBAL_MATCH_BITSTRING)
                 self.send_packet(self.buffer[curr_flow], packet.src, packet.dest,
                                  packet.is_raw_data, packet.is_fin, self.wan_port, client=client)
                 self.buffer[curr_flow] = ''

        else:
            # No Delimiter, add the rest to buffer
            self.buffer[curr_flow] = self.buffer.get(curr_flow, '') + data
            if packet.is_fin:
                self.send_packet(self.buffer[curr_flow], packet.src, packet.dest,
                                  packet.is_raw_data, packet.is_fin, self.wan_port, client=client)
                self.buffer[curr_flow] = ''


    def handle_outgoing(self, packet, client=False):
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

        curr_flow = (packet.src, packet.dest)
        if packet.is_raw_data:
            data = packet.payload
        else:
            LOG.info('Client sent data that was hashed...')
            data = self.seen[packet.payload]

        delimited_chunks, num_delimiters = self.chunk_data(data)

        if num_delimiters == 0:
            self.buffer[curr_flow] = self.buffer.get(curr_flow, '') + delimited_chunks[0]




    def chunk_data(self, data):
        """ Breaks up data based on LBFS method.

        This function will implement the breaking of the data in the fashion described in the LBFS
        paper. Actually implements the sliding window approach to breaking data based off a
        delimiter.

        Arguments:
            data: a string that contains data.
        Returns:
            ordered list of data that should be sent packet by packet. This is a mix of hashed and
            un-hashed data. Data that has been sent or seen before is hashed, other data is sent raw
        """
        num_windows = len(data) - self.window_size
        chunk_start = 0
        chunk_list = []
        offset = 0
        num_chunks = 0
        while offset < num_windows:
            window = data[offset : offset + self.window_size] if len(data) > offset + self.window_size else data[offset:]
            hashed = utils.get_hash(window)
            low13 = utils.get_last_n_bits(hashed, 13)
            if low13 == self.GLOBAL_MATCH_BITSTRING and len(window) == self.window_size:
                # This is where data should be broken up
                chunk = data[chunk_start : offset + self.window_size]
                chunk_list.append(chunk)
                chunk_start = offset + self.window_size
                offset = chunk_start
                num_chunks += 1
            elif len(window) < self.window_size:
                # last packet to send
                LOG.debug('Are we ever hitting this?')
                chunk = data[chunk_start:]
                chunk_list.append(chunk)
                break
            else:
                offset += 1

        chunk = data[chunk_start:]
        chunk_list.append(chunk)

        return chunk_list, num_chunks

    def send_packet(self, data, src, dest, is_raw_data, is_fin, port, client=False):
        """
        Take in the exact block of data that it's supposed to send!
        (i.e. the end is a delimiter)

        Args:
            self: wan_optimizer
            :string data:
            :string src:
            :string dest:
            :boolean is_raw_data:
            :boolean is_fin:
            port:
            client:

        Returns:
        Send the damn packet
        """
        digest = utils.get_hash(data)
        # Copy src, dest
        if digest in self.seen and not client:
            is_raw_data = False
            assert len(digest) <= MAX_PACKET_SIZE, "Hash is not less than block_size"
            wan_packet = Packet(src, dest, is_raw_data, is_fin, digest)
            self.send(wan_packet, port)
        else:
            self.seen[digest] = data
            if len(data) > MAX_PACKET_SIZE:
                num_blocks = len(data) // MAX_PACKET_SIZE
                rest = len(data) % MAX_PACKET_SIZE
                # Here Blocks are blocks of size MAX_PACKET
                blocks = [data[k * MAX_PACKET_SIZE : (k + 1) * MAX_PACKET_SIZE] for k in range(num_blocks)]
                for block in blocks:
                    assert len(block) <= MAX_PACKET_SIZE, 'Ya fucked up {} != {}'.format(block, MAX_PACKET_SIZE)
                    wan_packet = Packet(src, dest, is_raw_data, False, block)
                    self.send(wan_packet, port)
                if rest:
                    last_packet = Packet(src, dest, is_raw_data, is_fin, data[-rest:])
                    self.send(last_packet, port)
                else:
                    last_packet = Packet(src, dest, is_raw_data, is_fin, '')
                    self.send(last_packet, port)
            else:
                wan_packet = Packet(src, dest, is_raw_data, is_fin, data)
                self.send(wan_packet, port)
