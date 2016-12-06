import wan_optimizer
import utils
from utils import MAX_PACKET_SIZE
from tcp_packet import Packet
import logging

logging.basicConfig()
LOG = logging.getLogger(name='lbfs_wan_optimizer')
LOG.setLevel(logging.DEBUG)

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
            self.send_packet(data, packet.src, packet.dest, True, packet.is_fin, self.address_to_port[packet.dest], client=True)

        elif packet.is_raw_data:
            delimited_chunks, num_delimiters = self.chunk_data(packet.payload)

            if num_delimiters == 0:
                self.buffer[curr_flow] = self.buffer.get(curr_flow, '') + delimited_chunks[0]
                if packet.is_fin:
                    self.send_packet(self.buffer[curr_flow], packet.src, packet.dest, True,
                                     packet.is_fin, self.address_to_port[packet.dest], client=True)
            else:
                # I have a delimited chunk that I need to add (the first index of the array)
                # Send the damn thing
                # Clear my buffer
                # Add the rest
                for i, delimiter in enumerate(delimited_chunks):
                    if i == 0:
                        # first delimited block -> add what is in the buffer and send it
                        block = self.buffer.get(curr_flow, '') + delimiter
                        if num_delimiters == 1:
                            # first and last delimiter -> keep truth of fin packet
                            self.send_packet(block, packet.src, packet.dest, True, packet.is_fin, self.address_to_port[packet.dest], client=True)
                        else:
                            # first delimiter with more to come -> not the last packet
                            self.send_packet(block, packet.src, packet.dest, True, False, self.address_to_port[packet.dest], client=True)
                        self.buffer[curr_flow] = ''
                    elif i < len(delimited_chunks) - 1:
                        # all the in-between chunks
                        self.send_packet(delimiter, packet.src, packet.dest, True, False, self.address_to_port[packet.dest], client=True)
                    else:
                        # last chunk in array.
                        if num_delimiters == i+1 or packet.is_fin:
                            # ends in a delimiter or is the last part of a fin packet -> send the block
                            self.send_packet(delimiter, packet.src, packet.dest, True, packet.is_fin, self.address_to_port[packet.dest], client=True)
                        else:
                            # doesnt end in delimiter and isnt a fin packet -> buffer the data
                            self.buffer[curr_flow] = self.buffer.get(curr_flow, '') + delimiter
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
        if packet.is_fin:
            LOG.debug('Handling fin packet in handle_outgoing')
        curr_flow = (packet.src, packet.dest)
        if packet.is_raw_data and packet.size() != 0:
            data = packet.payload
        elif packet.is_fin and packet.size() == 0:
            self.send_packet(self.buffer.get(curr_flow, ''), packet.src, packet.dest, True, packet.is_fin, self.wan_port)
            # Clear the buffer
            self.buffer[curr_flow] = ''
            return
        else:
            LOG.info('Client sent data that was hashed...')
            data = self.seen[packet.payload]

        delimited_chunks, num_delimiters = self.chunk_data(data)

        if num_delimiters == 0:
            self.buffer[curr_flow] = self.buffer.get(curr_flow, '') + delimited_chunks[0]
            if packet.is_fin:
                LOG.debug('New case for fin packet')
                self.send_packet(self.buffer[curr_flow], packet.src, packet.dest, True,
                                 packet.is_fin, self.wan_port)
        else:
            for i, delimiter in enumerate(delimited_chunks):
                if i == 0:
                    # first delimited block -> add what is in the buffer and send it
                    block = self.buffer.get(curr_flow, '') + delimiter
                    if num_delimiters == 1:
                        # first and last delimiter -> keep truth of fin packet
                        LOG.debug('Sending first block: {}'.format(len(block)))
                        self.send_packet(block, packet.src, packet.dest, True, packet.is_fin, self.wan_port)
                    else:
                        # first delimiter with more to come -> not the last packet
                        self.send_packet(block, packet.src, packet.dest, True, False, self.wan_port)
                    self.buffer[curr_flow] = ''
                elif i < len(delimited_chunks) - 1:
                    # all the in-between chunks
                    self.send_packet(delimiter, packet.src, packet.dest, True, False, self.wan_port)
                else:
                    # last chunk in array.
                    if num_delimiters == i+1 or packet.is_fin:
                        # ends in a delimiter or is the last part of a fin packet -> send the block
                        self.send_packet(delimiter, packet.src, packet.dest, True, packet.is_fin, self.wan_port)
                    else:
                        # doesnt end in delimiter and isnt a fin packet -> buffer the data
                        self.buffer[curr_flow] = self.buffer.get(curr_flow, '') + delimiter



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

    def send_packet(self, block_of_data, src, dest, is_raw_data, is_fin, port, client=False):
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

        hashed_block = utils.get_hash(block_of_data)

        # Copy src, dest
        if hashed_block in self.seen and not client:
            is_raw_data = False
            assert len(hashed_block) <= MAX_PACKET_SIZE, "Hash is not less than block_size"
            if is_fin:
                LOG.debug('Sending hashed fin packet with data ({})'.format(
                    'handle_incoming' if client else 'handle_outgoing'))
            wan_packet = Packet(src, dest, is_raw_data, is_fin, hashed_block)
            self.send(wan_packet, self.wan_port)

        else:
            self.seen[hashed_block] = block_of_data
            if len(block_of_data) > MAX_PACKET_SIZE:
                num_blocks = len(block_of_data) // MAX_PACKET_SIZE
                rest = len(block_of_data) % MAX_PACKET_SIZE
                # Here Blocks are blocks of size MAX_PACKET
                blocks = [block_of_data[k * MAX_PACKET_SIZE : (k + 1) * MAX_PACKET_SIZE] for k in range(num_blocks)]
                for block in blocks:
                    assert len(block) <= MAX_PACKET_SIZE, 'Ya fucked up {} != {}'.format(block, MAX_PACKET_SIZE)
                    wan_packet = Packet(src, dest, is_raw_data, False, block)
                    self.send(wan_packet, port)
                if rest:
                    # Sending fin packet ...
                    if is_fin:
                        LOG.debug('Sending fin packet with data ({})'.format(
                            'handle_incoming' if client else 'handle_outgoing'))
                    last_packet = Packet(src, dest, is_raw_data, is_fin, block_of_data[-rest:])
                    self.send(last_packet, port)
                else:
                    # Sending fin packet ...
                    if is_fin:
                        LOG.debug('Sending fin packet with data ({})'.format(
                            'handle_incoming' if client else 'handle_outgoing'))
                    last_packet = Packet(src, dest, is_raw_data, is_fin, '')
                    self.send(last_packet, port)
            else:
                if is_fin:
                    LOG.debug('Sending fin packet with data ({})'.format(
                        'handle_incoming' if client else 'handle_outgoing'))
                wan_packet = Packet(src, dest, is_raw_data, is_fin, block_of_data)
                self.send(wan_packet, port)
