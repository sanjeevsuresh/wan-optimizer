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
            self.handle_packet(packet, client=True)
        else:
            # The packet must be destined to a host connected to the other middlebox
            # so send it across the WAN.
            self.handle_packet(packet, client=False)

    def handle_packet(self, packet, client=False):
        """ Handles an incoming packet.

        Responsibility of this method is to add any raw data to the seen list and translate any
        hashed data. It then forwards the data to the client.
        """
        if packet.is_fin:
            LOG.debug("Handling FIN packet")

        if packet.dest in self.address_to_port:
            port = self.address_to_port[packet.dest]
        else:
            port = self.wan_port

        curr_flow = (packet.src, packet.dest)

        if packet.payload in self.seen and not packet.is_raw_data:
            data = self.seen[packet.payload]
            self.send_packet(data, packet.src, packet.dest, True, packet.is_fin, port, client=client)

        elif packet.payload == '' and packet.is_fin:
            self.send_packet(self.buffer[curr_flow], packet.src, packet.dest, True, True, port, client=client)
            self.buffer[curr_flow] = ''

        elif packet.is_raw_data:
            left_to_process = self.buffer.get(curr_flow, '') + packet.payload
            offset = max(len(self.buffer.get(curr_flow, '')) - 48, 0)
            self.buffer[curr_flow] = ''

            while left_to_process != '':
                delimiter_res = self.contains_delimiter (left_to_process, offset=offset)
                offset = 0
                if delimiter_res:
                    # Get the first delimited chunk
                    delimited, left_to_process = self.break_on_delimiter(left_to_process, offset=delimiter_res)
                    # Join with anything in the buffer
                    block = self.buffer.get(curr_flow, '') + delimited
                    # Clear buffer
                    self.buffer[curr_flow] = ''
                    if left_to_process:
                        # more data from this packet to come.
                        self.send_packet(block, packet.src, packet.dest, True, False, port, client=client)
                    else:
                        # Last part of this packet -> is_fin matches packets value
                        self.send_packet(block, packet.src, packet.dest, True, packet.is_fin, port, client=client)
                elif packet.is_fin:
                    block = self.buffer.get(curr_flow, '') + left_to_process
                    self.send_packet(block, packet.src, packet.dest, True, True, port, client=client)
                    self.buffer[curr_flow] = ''
                    break
                else:
                    self.buffer[curr_flow] = self.buffer.get(curr_flow, '') + left_to_process
                    break
        else:
            LOG.error("Got a piece of data that has not been seen and is not raw data. Source: {}".format(packet.src))

    def contains_delimiter(self, data, offset=0):
        """ Returns true if the chunk of data has a delimiter in it
        """
        num_windows = len(data) - self.window_size

        while offset+self.window_size <= len(data):
            window = data[offset : offset + self.window_size]
            hashed = utils.get_hash(window)
            low13 = utils.get_last_n_bits(hashed, 13)
            if low13 == self.GLOBAL_MATCH_BITSTRING and len(window) == self.window_size:
                return offset
            else:
                offset += 1
        return False

    def break_on_delimiter(self, data, offset=0):
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
        chunk = data[: offset + self.window_size]
        left = data[offset + self.window_size:]
        return chunk, left

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

        LOG.debug("Block size: {}, Heading to client: {}, Packet destination: {}".format(len(block_of_data), client, dest))

        if len(block_of_data) == 40908:
            contains_delim = self.contains_delimiter(block_of_data)
            stuff = self.break_on_delimiter(block_of_data)
            LOG.debug("BLOCK OF TROUBLE: contains_delimiter {}, length of first break {}".format(contains_delim, len(stuff[0])))

        # Copy src, dest
        if hashed_block in self.seen and not client:
            is_raw_data = False
            LOG.debug("\tSending as hash.")
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
